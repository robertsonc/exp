// M6 compiler (CR-m6-manager): the all-in-one host validates against shared/schemas, tokens land only in the right
// documents, the zod settings mirror agrees with the JSON Schema fixtures, and the port check holds.
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { compile } from "../../src/compile/compile";
import { portConflicts } from "../../src/compile/speedtest";
import type { DesiredBody, WComponent, World } from "../../src/compile/types";
import { secretKey } from "../../src/compile/types";
import { checkSvg } from "../../src/speedtest/logo";
import { CorrelationConfigSchema, SettingsPutSchema, SpeedtestComponentConfigSchema } from "../../src/speedtest/schemas";
import { validateAgainst } from "./schemas";
import { H_COL, baseWorld, clone, fid, sha } from "./world";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = resolve(here, "../../../../test/fixtures");
const fx = (rel: string): Record<string, any> => JSON.parse(readFileSync(join(fixtures, rel), "utf8"));

const C_RUN = fid("cmp_", 7);
const C_SPD = fid("cmp_", 8);
const ART_LOGO = "art_01M7R3X9G0JPFS2FAGQ8ACHEYD";
const T = { exps: "exps_" + "S".repeat(43), expr: "expr_" + "R".repeat(43), expl: "expl_" + "L".repeat(43), expk: "expk_" + "K".repeat(43), expi: "expi_" + "I".repeat(43) };

/** the fixture's speedtest config as the manager's stored settings (everything the admin API owns) */
function settingsFromFixture(): Record<string, unknown> {
  const c = fx("configs/speedtest.json");
  const { schema: _s, speedtest_id: _i, site: _site, collector: _c, local_channel: _l, consent: _consent, ...rest } = c;
  const { logo_artifact: _logo, ...branding } = c.branding;
  return { ...rest, branding };
}

/** the admin-owned part of the fixture's correlation block (privacy, channel and network are compiled by the manager) */
function runnerOwn(): Record<string, unknown> {
  const { privacy: _p, speedtest_channel: _s, network: _n, ...own } = fx("configs/runner.correlation.json").correlation;
  return own;
}

function m6World(over: { settings?: Record<string, unknown> | null; tlsPair?: boolean } = {}): World {
  const w = baseWorld();
  for (const c of w.components) if (c.type !== "dashboard") c.host_id = H_COL;
  // the all-in-one box: collector + probe + runner + speedtest on H_COL; the dashboard stays on its own host
  w.hosts[H_COL]!.facts.interfaces!.push({ name: "eno2", state: "up", addrs: ["10.0.0.9/24"], default_route: false, in_use_by: "none" });
  const mk = (id: string, type: WComponent["type"], slug: string, config: Record<string, unknown>, n: number): WComponent => ({ component_id: id, host_id: H_COL, type, slug, config, enabled: true, facts: {}, created_at: `2026-11-18T10:00:0${n}.000Z` });
  w.components.push(
    mk(C_RUN, "runner", "run-core", { correlation: runnerOwn() }, 7),
    mk(C_SPD, "speedtest", "spd-core", {}, 8),
  );
  const sec = (owner: string, kind: string, plain: string, hashed: boolean) => {
    w.secrets[secretKey(owner, kind)] = { plaintext: plain, hash: hashed ? sha(plain) : null, previous_hash: null };
  };
  sec(C_RUN, "ingest_token", T.expi, true);
  sec(C_RUN, "runner_token", T.expr, true);
  sec(C_SPD, "speedtest_token", T.exps, true);
  sec(`${C_RUN}:${C_SPD}`, "channel_token", T.expl, true);
  sec("org", "device_key", T.expk, false);
  w.artifacts.push({ artifact_id: fid("art_", 300), version: "0.1.0", name: "exp-speedtest-0.1.0-noarch.tar.gz", component: "speedtest", arch: "noarch", sha256: sha("st"), size: 4321 });
  const c = fx("configs/speedtest.json");
  w.speedtest = {
    "hall-b":
      over.settings === null
        ? undefined!
        : {
            settings: over.settings ?? settingsFromFixture(),
            consent: { text: c.consent.text, version: c.consent.version },
            paused: false,
            logo: { artifact: { artifact_id: ART_LOGO, version: "0.0.0-logo.abcdef012345", name: "exp-speedtest-0.0.0-logo.abcdef012345-noarch.tar.gz", component: "speedtest-logo", arch: "noarch", sha256: sha("logo"), size: 321 }, content_type: "image/svg+xml" },
          },
  };
  if (over.tlsPair) w.secrets[secretKey("speedtest:hall-b", "speedtest_tls")] = { plaintext: JSON.stringify({ cert_pem: "CERT", key_pem: "KEY" }), hash: null, previous_hash: null };
  return w;
}

const build = (w: World, host = H_COL) => {
  const r = compile(w, host);
  expect(r.doc, r.warnings.join("; ")).not.toBeNull();
  return { ...(r.doc as DesiredBody), version: 1, generated_at: "2026-11-20T10:00:00.000Z" } as DesiredBody & { version: number; generated_at: string; components: Array<Record<string, any>> };
};
const comp = (d: { components: Array<Record<string, any>> }, type: string) => d.components.find((c) => c.type === type)!;

describe("the all-in-one host (collector + probe + runner + speedtest)", () => {
  it("validates against desired.schema.json (config schemas of every component included)", () => {
    const d = build(m6World());
    expect(d.components.map((c) => c.type)).toEqual(["collector", "probe", "runner", "speedtest"]);
    expect(validateAgainst("desired.schema.json", d)).toEqual([]);
    // the validator really checks the new configs: a bad listen_ip, an extra key and a bad creds name fail
    const bad = clone(d) as any;
    comp(bad, "speedtest").config.serve.listen_ip = "nope";
    expect(validateAgainst("desired.schema.json", bad).length).toBeGreaterThan(0);
    const bad2 = clone(d) as any;
    comp(bad2, "speedtest").config.surprise = 1;
    expect(validateAgainst("desired.schema.json", bad2).length).toBeGreaterThan(0);
    const bad3 = clone(d) as any;
    comp(bad3, "runner").config.correlation.sources.syslog.ring_minutes = 90;
    expect(validateAgainst("desired.schema.json", bad3).length).toBeGreaterThan(0);
  });

  it("the compiled speedtest config equals the contract fixture exp.speedtest.config/1", () => {
    const d = build(m6World());
    const want = fx("configs/speedtest.json");
    const got = comp(d, "speedtest").config;
    expect(got).toEqual({ ...want, collector: { ...want.collector, fallback: [] } });
    expect(validateAgainst("speedtest.config.schema.json", got)).toEqual([]);
  });

  it("the compiled runner config equals the contract fixture exp.runner.config/1 (correlation)", () => {
    const d = build(m6World());
    const want = fx("configs/runner.correlation.json");
    const got = comp(d, "runner").config;
    expect(got.correlation).toEqual(want.correlation);
    expect(validateAgainst("runner.config.schema.json", got)).toEqual([]);
  });

  it("the runner's correlation.network mirrors the box's NAT-guard inputs, also when they default to the zone labels", () => {
    const d = build(m6World());
    const net = comp(d, "runner").config.correlation.network;
    const serve = comp(d, "speedtest").config.serve;
    expect(net).toEqual({ require_real_client_ip: true, client_subnets: serve.client_subnets, translated_addresses: serve.translated_addresses,
      zone_subnets: comp(d, "speedtest").config.zone_labels.subnets });
    // no explicit attendee subnets: both configs fall back to the zone-label subnets
    const w = m6World();
    const st = w.speedtest!["hall-b"]!;
    const { client_subnets: _c, ...serveNoSubnets } = st.settings.serve as Record<string, unknown>;
    st.settings = { ...st.settings, serve: serveNoSubnets };
    const d2 = build(w);
    const zoneCidrs = (comp(d2, "speedtest").config.zone_labels.subnets as Array<{ cidr: string }>).map((z) => z.cidr);
    expect(comp(d2, "speedtest").config.serve.client_subnets).toEqual(zoneCidrs);
    expect(comp(d2, "runner").config.correlation.network.client_subnets).toEqual(zoneCidrs);
    expect(validateAgainst("runner.config.schema.json", comp(d2, "runner").config)).toEqual([]);
  });

  it("the collector config gains the speedtests block and accepts the two new tokens (hashes) + the device key", () => {
    const d = build(m6World());
    const col = comp(d, "collector");
    expect(col.config.speedtests).toEqual({ enabled: true, speedtests: ["spd-core"], runners: ["run-core"], retention_days: 30, scrub_after_diagnosis: false, targets: { down_mbps: 25, up_mbps: 10 } });
    expect(validateAgainst("collector.config.schema.json", col.config)).toEqual([]);
    expect(JSON.parse(col.creds["speedtest_tokens.json"])).toEqual({ "spd-core": sha(T.exps) });
    expect(JSON.parse(col.creds["runner_tokens.json"])).toEqual({ "run-core": sha(T.expr) });
    expect(col.creds.device_key_secret).toBe(T.expk);
  });

  it("each plaintext secret appears only in the documents/creds that need it", () => {
    const d = build(m6World());
    const where = (secret: string): string[] =>
      d.components.flatMap((c) => Object.entries(c.creds as Record<string, string>).filter(([, v]) => v.includes(secret)).map(([k]) => `${c.type}:${k}`)).sort();
    expect(where(T.exps)).toEqual(["speedtest:collector_token"]);
    expect(where(T.expr)).toEqual(["runner:collector_token"]);
    expect(where(T.expl)).toEqual(["runner:speedtest_channel_token"]);
    expect(where(T.expi)).toEqual(["runner:ingest_token"]);
    // the device_key secret goes to the runner and (optionally) the collector, never the speedtest
    expect(where(T.expk)).toEqual(["collector:device_key_secret", "runner:device_key_secret"]);
    // and never into a config document
    for (const c of d.components) expect(JSON.stringify(c.config)).not.toMatch(/exp[sirlk]_[A-Za-z0-9_-]{43}/);
    // the channel hash on the speedtest side is the sha256 of the runner's expl_
    expect(comp(d, "speedtest").creds.runner_channel_token_sha256).toBe(sha(T.expl));
    // the dashboard host (a different box) gets none of them
    const dash = build(m6World(), baseWorld().components.find((c) => c.type === "dashboard")!.host_id);
    expect(JSON.stringify(dash)).not.toMatch(/exp[sirlk]_[A-Za-z0-9_-]{43}/);
  });

  it("the logo is delivered as an asset (name logo, its content type, an artifact reference)", () => {
    const d = build(m6World());
    expect(comp(d, "speedtest").assets).toEqual([{ name: "logo", content_type: "image/svg+xml", artifact: expect.objectContaining({ id: ART_LOGO, sha256: sha("logo"), url: `/api/agent/v1/artifacts/${ART_LOGO}` }) }]);
    expect(comp(d, "speedtest").config.branding.logo_artifact).toBe(ART_LOGO);
    expect(validateAgainst("desired.schema.json", d)).toEqual([]);
  });

  it("the admin pause switch lands in internet_leg.paused", () => {
    const w = m6World();
    w.speedtest!["hall-b"]!.paused = true;
    expect(comp(build(w), "speedtest").config.internet_leg.paused).toBe(true);
  });

  it("client_subnets default to the zone-label subnets when serve names none", () => {
    const s = settingsFromFixture();
    (s.serve as Record<string, unknown>).client_subnets = undefined;
    const d = build(m6World({ settings: s }));
    expect(comp(d, "speedtest").config.serve.client_subnets).toEqual(["10.60.0.0/16", "10.61.0.0/16"]);
  });

  it("provided TLS: tls.mode provided + tls.crt/tls.key on the speedtest only; no pair = not compiled (fail closed)", () => {
    const s = { ...settingsFromFixture(), tls: { mode: "provided" } };
    const ok = build(m6World({ settings: s, tlsPair: true }));
    expect(comp(ok, "speedtest").config.tls).toEqual({ mode: "provided" });
    expect(comp(ok, "speedtest").creds["tls.crt"]).toBe("CERT");
    expect(JSON.stringify(comp(ok, "collector"))).not.toContain("KEY");
    expect(validateAgainst("desired.schema.json", ok)).toEqual([]);
    const r = compile(m6World({ settings: s }), H_COL);
    expect(r.doc!.components.map((c) => c.type)).not.toContain("speedtest");
    expect(r.warnings.join(" ")).toContain("no certificate pair was uploaded");
  });

  it("listen_ip is required; so are the collector's reported listen + pin and the tokens", () => {
    const s = settingsFromFixture();
    s.serve = { hostname: "speed.summit.example" };
    let r = compile(m6World({ settings: s }), H_COL);
    expect(r.doc!.components.map((c) => c.type)).not.toContain("speedtest");
    expect(r.warnings.join(" ")).toContain("serve.listen_ip is required");
    const w = m6World();
    delete w.secrets[secretKey(C_SPD, "speedtest_token")];
    r = compile(w, H_COL);
    expect(r.doc!.components.map((c) => c.type)).not.toContain("speedtest");
    const w2 = m6World();
    w2.components.find((c) => c.type === "collector")!.facts = {};
    r = compile(w2, H_COL);
    expect(r.doc!.components.map((c) => c.type)).toEqual(["collector", "probe"]);
  });

  it("a runner whose correlation credentials are not provisioned yet is not compiled (never half-configured)", () => {
    const w = m6World();
    delete w.secrets[secretKey("org", "device_key")];
    const r = compile(w, H_COL);
    expect(r.doc!.components.map((c) => c.type)).not.toContain("runner");
  });

  it("without saved settings the defaults apply (consent version 1), and the document still validates", () => {
    const w = m6World({ settings: null });
    w.components.find((c) => c.type === "speedtest")!.config = { serve: { hostname: "speed.summit.example", listen_ip: "10.0.0.9" } };
    const d = build(w);
    expect(comp(d, "speedtest").config.consent.version).toBe(1);
    expect(validateAgainst("desired.schema.json", d)).toEqual([]);
  });

  it("unknown keys of the stored settings are never echoed into the compiled config", () => {
    const s = { ...settingsFromFixture(), mystery: { a: 1 } };
    expect(comp(build(m6World({ settings: s })), "speedtest").config.mystery).toBeUndefined();
  });

  it("recompiling is deterministic", () => {
    const a = JSON.stringify(build(m6World()));
    const b = JSON.stringify(build(m6World()));
    expect(a).toBe(b);
  });
});

describe("port collisions on the all-in-one box", () => {
  it("the defaults do not collide (speedtest 80, DNS 53 on listen_ip; collector 8443; syslog 5514/6514; channel 8480)", () => {
    expect(portConflicts(m6World(), H_COL)).toEqual([]);
  });

  it("a dashboard on 0.0.0.0:80/443 collides with the speedtest; the speedtest is then left out", () => {
    const w = m6World();
    w.components.push({ component_id: fid("cmp_", 9), host_id: H_COL, type: "dashboard", slug: "dash-two", config: {}, enabled: true, facts: {}, created_at: "2026-11-18T10:00:09.000Z" });
    const c = portConflicts(w, H_COL);
    expect(c.join("\n")).toContain("tcp/80");
    const r = compile(w, H_COL);
    expect(r.doc!.components.map((x) => x.type)).not.toContain("speedtest");
    expect(r.warnings.join(" ")).toContain("port collision");
  });

  it("a runner syslog port equal to the speedtest's DNS port collides; provided TLS adds 443 and the redirect on 80", () => {
    const w = m6World();
    w.components.find((c) => c.type === "runner")!.config = { correlation: { sources: { syslog: { listen: ["udp:53"], bind: "10.0.0.9" } } } };
    expect(portConflicts(w, H_COL).join("\n")).toContain("udp/53");
    const w2 = m6World({ settings: { ...settingsFromFixture(), tls: { mode: "provided" } } });
    w2.components.push({ component_id: fid("cmp_", 10), host_id: H_COL, type: "dashboard", slug: "d", config: { listen: { https: "0.0.0.0:443", http_redirect: "0.0.0.0:8081" } }, enabled: true, facts: {}, created_at: "2026-11-18T10:00:10.000Z" });
    expect(portConflicts(w2, H_COL).join("\n")).toContain("tcp/443");
  });

  it("different listen addresses of the same port do not collide", () => {
    const w = m6World();
    w.components.find((c) => c.type === "collector")!.config = { listen: "10.32.98.25:80" };
    expect(portConflicts(w, H_COL)).toEqual([]);
  });
});

describe("zod mirrors agree with the JSON Schema fixtures", () => {
  it("every speedtest fixture's admin-owned part passes SettingsPutSchema", () => {
    for (const f of ["configs/speedtest.json", "configs/speedtest.tls-provided.json", "configs/speedtest.minimal.json"]) {
      const c = fx(f);
      const { schema: _a, speedtest_id: _b, site: _c, collector: _d, local_channel: _e, ...rest } = c;
      const body = { consent: { text: "x" }, ...rest };
      const p = SettingsPutSchema.safeParse(body);
      expect(p.success, `${f}: ${p.success ? "" : JSON.stringify(p.error.issues)}`).toBe(true);
    }
  });

  it("the runner correlation sources of the fixture pass CorrelationConfigSchema, SSE on does not", () => {
    const corr = fx("configs/runner.correlation.json").correlation;
    const { privacy: _p, speedtest_channel: _s, network: _n, ...own } = corr;
    expect(CorrelationConfigSchema.safeParse(own).success).toBe(true);
    expect(CorrelationConfigSchema.safeParse({ ...own, network: corr.network }).success).toBe(false); // compiled, not admin-set
    expect(CorrelationConfigSchema.safeParse({ sources: { sse: { enabled: true } } }).success).toBe(false);
    expect(CorrelationConfigSchema.safeParse(corr).success).toBe(false); // privacy, channel and network are the manager's, not the admin's
  });

  it("the speedtest component config accepts only host-level overrides", () => {
    expect(SpeedtestComponentConfigSchema.safeParse({ collector_id: "col-a", serve: { listen_ip: "10.0.0.9" }, tls: { mode: "none" } }).success).toBe(true);
    expect(SpeedtestComponentConfigSchema.safeParse({ branding: {} }).success).toBe(false);
  });
});

describe("SVG logo scan", () => {
  const svg = (inner: string) => new TextEncoder().encode(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">${inner}</svg>`);
  it("accepts plain vector art and local references", () => {
    expect(checkSvg(svg('<defs><linearGradient id="g"/></defs><rect fill="url(#g)"/><use href="#g"/>'))).toBeNull();
    expect(checkSvg(new TextEncoder().encode('<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"><metadata>d</metadata></svg>'))).toBeNull();
  });
  it("refuses active or foreign content", () => {
    for (const x of ["<script/>", "<rect onclick='a'/>", '<image href="http://x/y.png"/>', "<animate/>", "<iframe/>", '<rect style="background:url(http://x/)"/>', "<use xlink:href='//evil/x#a'/>"]) expect(checkSvg(svg(x)), x).not.toBeNull();
    expect(checkSvg(new Uint8Array([0xff, 0xfe, 0x00]))).not.toBeNull();
    expect(checkSvg(new TextEncoder().encode("<svg/>"))).toBeNull();
  });
});
