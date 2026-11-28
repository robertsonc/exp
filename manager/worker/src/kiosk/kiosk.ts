// Read-only kiosk: the ops board (Mist / Central device counts) for a wall screen on the management network, WITHOUT
// Cloudflare Access sign-in. Routes: GET /kiosk (the page) and GET /kiosk/api/devices (counts). Nothing else.
//
// Why a separate surface instead of an Access bypass on the admin app: every /api/admin/v1 request must carry a verified
// Access JWT (05-manager.md section 5) and a "viewer" there can read admin emails, host IPs and launch the dashboard SSO
// handoff. The kiosk exposes ONLY device counts (no names, serials, IPs, errors or connector details) and is gated twice:
//   1. Cloudflare Access: the "<worker> bypass /kiosk" application lets in only the source CIDRs (deploy.sh --kiosk-allow-ip);
//      any other address hits an Access app with no matching policy and is refused at the edge.
//   2. This Worker: the request's CF-Connecting-IP (set by Cloudflare's edge, not by the client; workers.dev is disabled)
//      must fall in KIOSK_ALLOW_CIDRS. Empty or unparsable -> the kiosk does not exist (404). Fail closed.
import { Hono } from "hono";
import type { AppBindings, Env } from "../env";
import { ApiError, notFound } from "../errors";
import { opsDevices } from "../ops/devices";
import { enforce } from "../ratelimit";
import { bytesToB64 } from "../util/encoding";

// ---- source address allowlist ---------------------------------------------------------------------------

interface Cidr { v: 4 | 6; net: bigint; bits: number }

function v4(s: string): bigint | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  let n = 0n;
  for (const o of m.slice(1)) {
    const x = Number(o);
    if (x > 255 || (o.length > 1 && o.startsWith("0"))) return null;
    n = (n << 8n) | BigInt(x);
  }
  return n;
}

function v6(s: string): bigint | null {
  if (!/^[0-9a-fA-F:]{2,39}$/.test(s) || s.split("::").length > 2) return null;
  const [head, tail] = s.includes("::") ? s.split("::") : [s, undefined];
  const h = head ? head.split(":") : [];
  const t = tail !== undefined && tail !== "" ? tail.split(":") : [];
  const fill = tail === undefined ? 0 : 8 - h.length - t.length;
  if (fill < (tail === undefined ? 0 : 1) || h.length + t.length + fill !== 8) return null;
  let n = 0n;
  for (const g of [...h, ...Array<string>(fill).fill("0"), ...t]) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

/** "37.34.66.15/32, 2001:db8::/48" -> CIDRs. A bare address is a host route. Invalid entries are reported, never guessed. */
export function parseCidrs(raw: string | undefined): { cidrs: Cidr[]; invalid: string[] } {
  const cidrs: Cidr[] = [];
  const invalid: string[] = [];
  for (const e of (raw ?? "").split(/[\s,]+/).filter(Boolean).slice(0, 32)) {
    const [addr = "", len, extra] = e.split("/");
    const a4 = v4(addr);
    const a6 = a4 === null ? v6(addr) : null;
    const max = a4 !== null ? 32 : 128;
    const bits = len === undefined ? max : /^\d{1,3}$/.test(len) ? Number(len) : -1;
    if (extra !== undefined || (a4 === null && a6 === null) || bits < 0 || bits > max) {
      invalid.push(e);
      continue;
    }
    const n = (a4 ?? a6) as bigint;
    const shift = BigInt(max - bits);
    cidrs.push({ v: a4 !== null ? 4 : 6, net: (n >> shift) << shift, bits });
  }
  return { cidrs, invalid };
}

export function ipAllowed(ip: string, cidrs: Cidr[]): boolean {
  const a4 = v4(ip);
  const a6 = a4 === null ? v6(ip) : null;
  if (a4 === null && a6 === null) return false;
  for (const c of cidrs) {
    const n = c.v === 4 ? a4 : a6;
    if (n === null) continue;
    const shift = BigInt((c.v === 4 ? 32 : 128) - c.bits);
    if ((n >> shift) << shift === c.net) return true;
  }
  return false;
}

// ---- the page (static: CSP pins the script and the style by hash) ------------------------------------------

const STYLE = `:root{--bg:#f6f7f9;--card:#fff;--text:#111827;--dim:#5b6472;--stroke:#d9dde3;--ok:#0d7a4e;--fail:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c23;--text:#e8ebef;--dim:#9aa3ae;--stroke:#2a313b;--ok:#3ccf8e;--fail:#ff6b5e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.4 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px}h1{font-size:1.5rem;margin:0 0 4px}.dim{color:var(--dim)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,360px),1fr));gap:16px;margin-top:20px}
section{background:var(--card);border:1px solid var(--stroke);border-radius:12px;padding:20px;min-width:0;container-type:inline-size}
section.stale{border-color:var(--fail)}h2{font-size:1.25rem;margin:0 0 12px}
dl{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:0}dt{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--dim)}
dd{margin:0;font-size:clamp(1.5rem,8cqi,4.5rem);line-height:1.05;font-weight:700;font-variant-numeric:tabular-nums;white-space:nowrap}
.on dd{color:var(--ok)}.bad dd{color:var(--fail)}.types,.note{margin:12px 0 0;color:var(--dim);font-variant-numeric:tabular-nums}.note.warn{color:var(--fail)}
footer{margin-top:16px;font-size:.85rem}`;

const SCRIPT = `(function(){
var grid=document.getElementById("grid"),foot=document.getElementById("foot");
var T={ap:"APs",switch:"Switches",gateway:"Gateways",other:"Other"};
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e;}
function n(v){return v==null?"\\u2013":Number(v).toLocaleString();}
function ago(ts){if(!ts)return "";var s=Math.max(0,Math.round((Date.now()-Date.parse(ts))/1000));return s<90?s+" s ago":Math.round(s/60)+" min ago";}
function num(dl,label,v,cls){var d=el("div",cls);d.appendChild(el("dt",null,label));d.appendChild(el("dd",null,n(v)));dl.appendChild(d);}
function card(s){var c=el("section",s.state==="stale"?"stale":"");c.appendChild(el("h2",null,s.label));
if(s.state==="unconfigured"){c.appendChild(el("p","dim","Not connected."));return c;}
var dl=el("dl");num(dl,"Total",s.total);num(dl,"Online",s.online,"on");num(dl,"Offline",s.offline,s.offline>0?"bad":"");c.appendChild(dl);
var t=Object.keys(s.by_type||{}).filter(function(k){return s.by_type[k]&&s.by_type[k].total>0;}).map(function(k){return (T[k]||k)+" "+s.by_type[k].online+"/"+s.by_type[k].total;});
if(t.length)c.appendChild(el("p","types",t.join(" \\u00b7 ")));
c.appendChild(el("p",s.state==="stale"?"note warn":"note",s.state==="pending"?"Waiting for the first poll":s.state==="stale"?"Platform not answering; counts from "+ago(s.counts_at):"Counted "+ago(s.counts_at)));
return c;}
function load(){fetch("/kiosk/api/devices",{cache:"no-store",credentials:"same-origin"}).then(function(r){if(!r.ok)throw new Error("HTTP "+r.status);return r.json();}).then(function(b){
grid.replaceChildren.apply(grid,(b.sources||[]).map(card));foot.textContent="Updated "+new Date(b.as_of).toLocaleTimeString()+" \\u00b7 refreshes every 30 s";foot.className="dim";
}).catch(function(e){foot.textContent="Could not refresh ("+e.message+"); retrying in 30 s";foot.className="note warn";});}
load();setInterval(load,30000);})();`;

const HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Device Status</title><style>${STYLE}</style></head>
<body><main><h1>Device status</h1><p class="dim">Juniper Mist and HPE Aruba Networking Central. Read-only.</p>
<div id="grid" class="grid" aria-live="polite"></div><footer id="foot" class="dim">Loading…</footer></main><script>${SCRIPT}</script></body></html>`;

const sha256B64 = async (s: string): Promise<string> => bytesToB64(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));
let cspCache: string | null = null;
async function csp(): Promise<string> {
  cspCache ??= `default-src 'none'; script-src 'sha256-${await sha256B64(SCRIPT)}'; style-src 'sha256-${await sha256B64(STYLE)}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
  return cspCache;
}

// ---- routes ---------------------------------------------------------------------------------------------

export const kioskRoutes = new Hono<AppBindings>();

let warned = "";
kioskRoutes.use("*", async (c, next) => {
  const { cidrs, invalid } = parseCidrs(c.env.KIOSK_ALLOW_CIDRS);
  if (invalid.length && warned !== c.env.KIOSK_ALLOW_CIDRS) {
    warned = c.env.KIOSK_ALLOW_CIDRS ?? "";
    console.error("KIOSK_ALLOW_CIDRS has invalid entries, ignored", invalid.length);
  }
  if (cidrs.length === 0) throw notFound("no such path");
  const ip = c.get("ip");
  if (!ipAllowed(ip, cidrs)) throw new ApiError(403, "forbidden", "the kiosk is only available from the management network");
  await enforce(c.env.RL_ADMIN, `kiosk:${ip}`);
  await next();
  c.res.headers.set("cache-control", "no-store");
});

kioskRoutes.get("/", async () => new Response(HTML, { status: 200, headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": await csp() } }));

/** Counts only: no connector state (`missing`), no vendor error text, no check time beyond the counts' own age. */
kioskRoutes.get("/api/devices", async (c) => {
  const b = await opsDevices(c.env);
  return c.json({
    as_of: b.as_of,
    sources: b.sources.map((s) => ({
      kind: s.kind,
      label: s.label,
      state: s.state === "error" ? "stale" : s.state,
      total: s.total,
      online: s.online,
      offline: s.offline,
      by_type: s.by_type,
      counts_at: s.counts_at,
    })),
  });
});

kioskRoutes.all("*", () => {
  throw notFound("no such path");
});

export type KioskEnv = Pick<Env, "KIOSK_ALLOW_CIDRS">;
