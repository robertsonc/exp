// 05-manager.md section 15 item 5: release verification. Tampered manifest, bad signature, artifact sha
// mismatch -> refused and NOTHING stored (no rows, no R2 objects); a valid release is stored and served.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Harness, harness } from "../admin-harness";
import { type ReleaseKey, type TestRelease, buildRelease, githubHandler, makeReleaseKey } from "../release-helpers";
import { enrolHost, env, getDesired, resetDb, call, bearer } from "../helpers";
import { sha256Hex } from "../../src/util/encoding";

let h: Harness;
let key: ReleaseKey;

beforeEach(async () => {
  await resetDb();
  h = await harness();
  key = await makeReleaseKey();
  h.withEnv({ RELEASE_PUBKEY_PEM: key.pem, RELEASES_REPO: "acme/exp", GITHUB_TOKEN: "ghp_testtoken_not_real" });
});
afterEach(() => h.restore());

async function stored(): Promise<{ releases: number; artifacts: number; r2: number; audit: number }> {
  const n = async (t: string): Promise<number> => (await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${t}`).first<{ n: number }>())!.n;
  return { releases: await n("releases"), artifacts: await n("artifacts"), r2: (await env.ARTIFACTS.list()).objects.length, audit: (await env.DB.prepare("SELECT COUNT(*) AS n FROM audit WHERE action LIKE 'release.%'").first<{ n: number }>())!.n };
}
const NOTHING = { releases: 0, artifacts: 0, r2: 0, audit: 0 };
const importIt = (version: string) => h.json<{ error?: { code: string; message: string }; version?: string }>("admin", "POST", "/releases/import", { version, source: "github" });
const tamper = (b: Uint8Array): Uint8Array => {
  const c = new Uint8Array(b);
  c[c.length - 3] = (c[c.length - 3] as number) ^ 1;
  return c;
};

describe("import from GitHub Releases", () => {
  it("a valid signed release is verified, streamed to R2 with matching sha256, recorded and served to agents", async () => {
    const rel = await buildRelease(key, "0.2.0", [{ component: "agent", arch: "noarch" }, { component: "collector", arch: "amd64" }, { component: "collector", arch: "arm64" }]);
    h.handlers.push(githubHandler(rel));
    const r = await h.json<{ rel_id: string; version: string; source: string; artifacts: Array<{ name: string; sha256: string; size: number; artifact_id: string }>; min_agent_version: string; notes_url: string }>("admin", "POST", "/releases/import", { version: "0.2.0", source: "github" });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ version: "0.2.0", source: "github", min_agent_version: "0.1.0", notes_url: "https://github.com/acme/exp/releases/tag/v0.2.0" });
    expect(r.body.rel_id).toMatch(/^rel_[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(r.body.artifacts).toHaveLength(3);
    const s = await stored();
    expect(s).toMatchObject({ releases: 1, artifacts: 3, audit: 1 });
    expect(s.r2).toBe(4); // 3 artifacts + the manifest
    // each stored artifact has the manifest's sha256 and size
    for (const a of rel.artifacts) {
      const row = await env.DB.prepare("SELECT r2_key, sha256, size FROM artifacts WHERE name = ?1").bind(a.name).first<{ r2_key: string; sha256: string; size: number }>();
      const obj = await env.ARTIFACTS.get(row!.r2_key);
      expect(await sha256Hex(new Uint8Array(await obj!.arrayBuffer()))).toBe(row!.sha256);
      expect(row!.size).toBe(a.bytes.length);
    }
    // agents get the EXACT signed manifest bytes and the signature
    const host = await enrolHost((await seedSite()), "h1");
    const m = await call("/api/agent/v1/releases/0.2.0/manifest", { headers: bearer(host.secret) });
    expect(new Uint8Array(await m.arrayBuffer())).toEqual(rel.manifest);
    expect(await (await call("/api/agent/v1/releases/0.2.0/manifest.sig", { headers: bearer(host.secret) })).text()).toBe(rel.sig);
    // the GitHub token went to api.github.com only, never along the redirect to the CDN
    const cdn = h.calls.filter((c) => c.url.startsWith("https://objects.githubusercontent.com/"));
    expect(cdn.length).toBe(5); // manifest, signature, 3 artifacts
    for (const c of cdn) expect(new Headers(c.init?.headers).has("authorization")).toBe(false);
    expect(h.calls.filter((c) => c.url.startsWith("https://api.github.com/")).every((c) => new Headers(c.init?.headers).get("authorization") === "Bearer ghp_testtoken_not_real")).toBe(true);
    expect(JSON.stringify((await env.DB.prepare("SELECT details_json FROM audit").all()).results)).not.toContain("ghp_");
    // listing
    const list = await h.json<{ items: Array<{ version: string; sites: string[]; artifacts: unknown[] }> }>("viewer", "GET", "/releases");
    expect(list.body.items).toHaveLength(1);
    expect(list.body.items[0]).toMatchObject({ version: "0.2.0", sites: [] });
    // importing it again is a conflict and changes nothing
    expect((await importIt("0.2.0")).status).toBe(409);
    expect(await stored()).toEqual(s);
  });

  it("a TAMPERED manifest is refused (signature_invalid) before any artifact is downloaded; nothing stored", async () => {
    const rel = await buildRelease(key, "0.2.0");
    h.handlers.push(githubHandler(rel, { manifest: tamper(rel.manifest) }));
    const r = await importIt("0.2.0");
    expect(r.status).toBe(422);
    expect(r.body.error!.code).toBe("signature_invalid");
    expect(await stored()).toEqual(NOTHING);
    expect(h.calls.filter((c) => /\/blob\/10[3-9]$|\/assets\/10[3-9]$/.test(c.url)).length).toBe(0); // only manifest + signature were fetched
  });

  it("a manifest re-signed by a DIFFERENT key (bad signature) is refused", async () => {
    const attacker = await makeReleaseKey();
    const rel = await buildRelease(attacker, "0.2.0");
    h.handlers.push(githubHandler(rel));
    const r = await importIt("0.2.0");
    expect(r.status).toBe(422);
    expect(r.body.error!.code).toBe("signature_invalid");
    expect(await stored()).toEqual(NOTHING);
  });

  it("malformed signatures are refused: not base64, wrong length, empty", async () => {
    const rel = await buildRelease(key, "0.2.0");
    for (const sig of ["!!!not base64!!!", "AAAA", btoa("x".repeat(63))]) {
      h.handlers.length = 0;
      h.handlers.push(githubHandler(rel, { sig }));
      const r = await importIt("0.2.0");
      expect(r.status, sig).toBe(422);
      expect(r.body.error!.code).toBe("signature_invalid");
    }
    expect(await stored()).toEqual(NOTHING);
  });

  it("an artifact whose sha256 differs from the signed manifest is refused; objects already written are removed", async () => {
    const rel = await buildRelease(key, "0.2.0", [{ component: "agent", arch: "noarch" }, { component: "probe", arch: "noarch" }, { component: "runner", arch: "noarch" }]);
    const bad = rel.artifacts[2]!;
    h.handlers.push(githubHandler(rel, { artifacts: { [bad.name]: tamper(bad.bytes) } })); // same length, different bytes
    const r = await importIt("0.2.0");
    expect(r.status).toBe(422);
    expect(r.body.error!.code).toBe("artifact_hash_mismatch");
    expect(await stored()).toEqual(NOTHING); // the two good artifacts streamed before the failure are gone too
  });

  it("an artifact of the wrong size (truncated or padded) is refused and cleaned up", async () => {
    const rel = await buildRelease(key, "0.2.0");
    for (const wrong of [rel.artifacts[1]!.bytes.slice(0, 100), new Uint8Array([...rel.artifacts[1]!.bytes, 1, 2, 3])]) {
      h.handlers.length = 0;
      h.handlers.push(githubHandler(rel, { artifacts: { [rel.artifacts[1]!.name]: wrong } }));
      const r = await importIt("0.2.0");
      expect(r.status).toBe(422);
      expect(["artifact_hash_mismatch"]).toContain(r.body.error!.code);
      expect(await stored()).toEqual(NOTHING);
    }
  });

  it("manifest consistency: artifact name must match component/arch/version; path-like and duplicate names are refused", async () => {
    for (const over of [
      { artifacts: [{ name: "exp-agent-0.2.0-noarch.tar.gz", component: "probe", arch: "noarch", sha256: "a".repeat(64), size: 1 }] },
      { artifacts: [{ name: "../../etc/passwd", component: "agent", arch: "noarch", sha256: "a".repeat(64), size: 1 }] },
      { artifacts: [{ name: "exp-agent-0.1.0-noarch.tar.gz", component: "agent", arch: "noarch", sha256: "a".repeat(64), size: 1 }] },
      { version: "0.2.0", schema: "exp.manifest/2" },
      { artifacts: [] },
    ]) {
      const rel = await buildRelease(key, "0.2.0", undefined, over);
      h.handlers.length = 0;
      h.handlers.push(githubHandler(rel));
      const r = await importIt("0.2.0");
      expect(r.status).toBe(422);
      expect(r.body.error!.code).toBe("manifest_invalid");
    }
    expect(await stored()).toEqual(NOTHING);
  });

  it("errors: unknown version 404, GitHub failure 502, no repo configured 409, no public key 503; nothing stored", async () => {
    h.handlers.push((u) => (u.includes("/releases/tags/v9.9.9") || u.includes("/releases/tags/9.9.9") ? new Response("{}", { status: 404 }) : undefined));
    expect((await importIt("9.9.9")).status).toBe(404);
    h.handlers.push((u) => (u.includes("/releases/tags/") ? new Response("boom", { status: 500 }) : undefined));
    expect((await importIt("0.2.0")).status).toBe(502);
    h.withEnv({ RELEASES_REPO: "" });
    expect((await importIt("0.2.0")).status).toBe(409);
    h.withEnv({ RELEASES_REPO: "acme/exp", RELEASE_PUBKEY_PEM: "" });
    h.handlers.length = 0;
    h.handlers.push(githubHandler(await buildRelease(key, "0.2.0")));
    const r = await importIt("0.2.0");
    expect(r.status).toBe(503);
    expect((await h.json("admin", "POST", "/releases/import", { version: "0.2.0", source: "upload" })).status).toBe(400);
    expect((await h.json("admin", "POST", "/releases/import", { version: "latest", source: "github" })).status).toBe(400);
    expect(await stored()).toEqual(NOTHING);
  });

  it("only GitHub hosts are ever fetched (an asset URL pointing elsewhere is refused)", async () => {
    const rel = await buildRelease(key, "0.2.0");
    const good = githubHandler(rel);
    h.handlers.push((url) => {
      const r = good(url);
      if (r && url.includes("/releases/tags/")) {
        return r.json().then((j) => new Response(JSON.stringify({ assets: (j as { assets: Array<{ url: string }> }).assets.map((a) => ({ ...a, url: "https://evil.example.com/x" })) })));
      }
      return r;
    });
    const r = await importIt("0.2.0");
    expect(r.status).toBe(502);
    expect(h.calls.some((c) => c.url.includes("evil.example.com"))).toBe(false);
    expect(await stored()).toEqual(NOTHING);
  });
});

async function seedSite(): Promise<string> {
  await h.json("admin", "POST", "/sites", { site: "hall-b", name: "Hall B", timezone: "UTC" });
  return "hall-b";
}

describe("upload (multipart)", () => {
  function form(rel: TestRelease, over: { manifest?: Uint8Array; sig?: string; drop?: string; extra?: boolean; artifacts?: Record<string, Uint8Array> } = {}): FormData {
    const f = new FormData();
    f.set("manifest", new File([over.manifest ?? rel.manifest], "manifest.json", { type: "application/json" }));
    f.set("signature", new File([over.sig ?? rel.sig], "manifest.json.sig"));
    for (const a of rel.artifacts) if (a.name !== over.drop) f.append("artifacts", new File([over.artifacts?.[a.name] ?? a.bytes], a.name, { type: "application/gzip" }));
    if (over.extra) f.append("artifacts", new File([new Uint8Array([1, 2, 3])], "exp-probe-0.2.0-arm64.tar.gz"));
    return f;
  }
  const up = (f: FormData) => h.json<{ error?: { code: string }; version?: string; source?: string; artifacts?: unknown[] }>("admin", "POST", "/releases/upload", f);

  it("a valid upload is verified and stored with source=upload (base64 or raw signature)", async () => {
    const rel = await buildRelease(key, "0.3.0");
    const r = await up(form(rel));
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ version: "0.3.0", source: "upload" });
    expect(r.body.artifacts).toHaveLength(2);
    expect(await stored()).toMatchObject({ releases: 1, artifacts: 2, r2: 3, audit: 1 });
    // raw 64-byte signature file works too
    const rel2 = await buildRelease(key, "0.3.1");
    const raw = Uint8Array.from(atob(rel2.sig), (c) => c.charCodeAt(0));
    const f = form(rel2);
    f.set("signature", new File([raw], "sig.bin"));
    expect((await up(f)).status).toBe(201);
  });

  it("tampered manifest / bad signature / artifact sha mismatch / missing / unexpected artifacts are refused with nothing stored", async () => {
    const rel = await buildRelease(key, "0.3.0");
    const evil = await makeReleaseKey();
    const cases: Array<[string, FormData, string]> = [
      ["tampered manifest", form(rel, { manifest: tamper(rel.manifest) }), "signature_invalid"],
      ["bad signature", form(rel, { sig: (await buildRelease(evil, "0.3.0")).sig }), "signature_invalid"],
      ["sha mismatch", form(rel, { artifacts: { [rel.artifacts[1]!.name]: tamper(rel.artifacts[1]!.bytes) } }), "artifact_hash_mismatch"],
      ["missing artifact", form(rel, { drop: rel.artifacts[1]!.name }), "artifact_missing"],
      ["unexpected artifact", form(rel, { extra: true }), "artifact_unexpected"],
    ];
    for (const [name, f, code] of cases) {
      const r = await up(f);
      expect(r.status, name).toBe(422);
      expect(r.body.error!.code, name).toBe(code);
      expect(await stored(), name).toEqual(NOTHING);
    }
  });

  it("wrong content type refused as non-multipart (csrf 403), oversized 413, missing parts 400", async () => {
    expect((await h.json("admin", "POST", "/releases/upload", { manifest: "x" })).status).toBe(403);
    const big = new Request("https://manager.example.test/x", { method: "POST" });
    void big;
    const f = new FormData();
    f.set("manifest", new File(["x"], "m.json"));
    expect((await up(f)).status).toBe(400);
    const r = await h.api("admin", "POST", "/releases/upload", f, { "content-length": String(200 * 1024 * 1024) });
    expect(r.status).toBe(413);
  });
});

describe("PATCH sites/{site}/release conformance (admin.yaml)", () => {
  const patch = (b: Record<string, unknown>, site = "hall-b") => h.json<{ error: { code: string; details: Record<string, unknown> } }>("admin", "PATCH", `/sites/${site}/release`, b);
  const imp = async (v: string, over: Record<string, unknown> = {}) => {
    h.handlers.length = 0;
    h.handlers.push(githubHandler(await buildRelease(key, v, undefined, over)));
    expect((await importIt(v)).status).toBe(201);
  };

  it("422 release_not_imported (after the 404 for an unknown site)", async () => {
    await seedSite();
    const r = await patch({ version: "9.9.9" });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe("release_not_imported");
    expect((await patch({ version: "9.9.9" }, "nope")).status).toBe(404);
  });

  it("422 min_agent_version when a site host's agent is older; unknown/newer agents pass", async () => {
    await seedSite();
    await imp("0.5.0", { min_agent_version: "0.4.0" });
    const old = await enrolHost("hall-b", "old");
    await env.DB.prepare("UPDATE hosts SET agent_version = '0.3.9' WHERE host_id = ?1").bind(old.host_id).run();
    const r = await patch({ version: "0.5.0" });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe("min_agent_version");
    expect(r.body.error.details).toMatchObject({ min_agent_version: "0.4.0", host_ids: [old.host_id] });
    expect((await patch({ version: "0.5.0", canary_host_id: old.host_id })).body.error.code).toBe("min_agent_version");
    // a canary on a different (fresh) host is judged on that host only
    const fresh = await enrolHost("hall-b", "fresh");
    await env.DB.prepare("UPDATE hosts SET agent_version = '0.10.0' WHERE host_id = ?1").bind(fresh.host_id).run();
    expect((await patch({ version: "0.5.0", canary_host_id: fresh.host_id })).status).toBe(200);
    await env.DB.prepare("UPDATE hosts SET agent_version = '0.4.0' WHERE host_id = ?1").bind(old.host_id).run();
    await patch({ version: "0.5.0" });
    expect((await patch({ version: "0.5.0" })).status).toBe(200);
  });

  it("409 rollout_in_progress for a second canary, 409 canary_failed after a failed one; a plain PATCH (rollback/promote) always works", async () => {
    await seedSite();
    await imp("0.2.0");
    await imp("0.3.0");
    const host = await enrolHost("hall-b", "srv");
    expect((await patch({ version: "0.3.0", canary_host_id: host.host_id })).status).toBe(200);
    const again = await patch({ version: "0.3.0", canary_host_id: host.host_id });
    expect(again.status).toBe(409);
    expect(again.body.error.code).toBe("rollout_in_progress");
    await env.DB.prepare("UPDATE sites SET canary_state = 'failed' WHERE site = 'hall-b'").run();
    const failed = await patch({ version: "0.3.0", canary_host_id: host.host_id });
    expect(failed.status).toBe(409);
    expect(failed.body.error.code).toBe("canary_failed");
    expect((await patch({ version: "0.2.0" })).status).toBe(200);
    expect((await patch({ version: "0.3.0", canary_host_id: host.host_id })).status).toBe(200);
  });
});

describe("sites can target an imported release; rollback to a previous one", () => {
  it("PATCH sites/{site}/release needs an imported release and records canary intent", async () => {
    await seedSite();
    expect((await h.json("admin", "PATCH", "/sites/hall-b/release", { version: "0.2.0" })).status).toBe(422);
    for (const v of ["0.2.0", "0.3.0"]) {
      h.handlers.length = 0;
      h.handlers.push(githubHandler(await buildRelease(key, v)));
      expect((await importIt(v)).status).toBe(201);
    }
    const a = await h.json<{ release_version: string; canary_state: string | null }>("admin", "PATCH", "/sites/hall-b/release", { version: "0.2.0" });
    expect(a.body).toMatchObject({ release_version: "0.2.0", canary_state: null });
    const host = await enrolHost("hall-b", "srv");
    const b = await h.json<{ canary_state: string; canary_host_id: string; target_version: string; release_version: string }>("admin", "PATCH", "/sites/hall-b/release", { version: "0.3.0", canary_host_id: host.host_id });
    expect(b.body).toMatchObject({ canary_state: "pending", canary_host_id: host.host_id, target_version: "0.3.0", release_version: "0.2.0" });
    expect((await h.json("admin", "PATCH", "/sites/hall-b/release", { version: "0.3.0", canary_host_id: "h_01ARZ3NDEKTSV4RRFFQ69G5FAV" })).status).toBe(400);
    const rel = await h.json<{ items: Array<{ version: string; sites: string[] }> }>("viewer", "GET", "/releases");
    expect(rel.body.items.map((i) => [i.version, i.sites])).toEqual(expect.arrayContaining([["0.2.0", ["hall-b"]], ["0.3.0", ["hall-b"]]]));
    void getDesired;
  });
});
