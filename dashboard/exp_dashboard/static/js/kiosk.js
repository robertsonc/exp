// Kiosk / NOC wall mode: ?kiosk=1[&rotate=30][&site=hall-b]. No interactive chrome; rotates the all-probes
// overview and then each probe's board every N seconds (worst probes first).
import { api, qs } from "./api.js";
import { h, clear, isSlug } from "./dom.js";
import { mountBoard } from "./board.js";
import { mountOverview } from "./overview.js";
import { SEV_RANK } from "./util.js";

export function clampRotate(v) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(600, Math.max(2, n)) : 30;
}

export function mountKiosk(root, opts) {
  const every = clampRotate(opts.rotate);
  const st = { slides: [{ type: "overview" }], i: -1, cur: null, timer: null, dead: false };
  const stage = h("div", { class: "kiosk-stage" });
  const dots = h("div", { class: "kiosk-dots", "aria-hidden": "true" });
  root.append(stage, dots);

  async function slides() {
    const site = opts.site && isSlug(opts.site) ? opts.site : "";
    try {
      const [p, s] = await Promise.all([api("/api/v1/probes" + qs({ site })), api("/api/v1/states" + qs({ site }))]);
      const sev = new Map((s.items || []).map((x) => [x.probe, SEV_RANK[x.severity] === undefined ? 2 : SEV_RANK[x.severity]]));
      const ids = (p.items || []).map((x) => x.probe).filter(isSlug);
      ids.sort((a, b) => (sev.has(a) ? sev.get(a) : 2) - (sev.has(b) ? sev.get(b) : 2) || a.localeCompare(b));
      st.slides = [{ type: "overview" }, ...ids.map((id) => ({ type: "probe", id }))];
    } catch (e) {
      st.slides = [{ type: "overview" }];
    }
  }

  function show(i) {
    if (st.cur) st.cur.destroy();
    clear(stage);
    const slide = st.slides[i];
    const box = h("div", { class: "kiosk-slide" });
    stage.appendChild(box);
    root.dataset.slide = slide.type === "overview" ? "overview" : slide.id;
    root.dataset.index = String(i);
    st.cur = slide.type === "overview"
      ? mountOverview(box, { kiosk: true, static: opts.static, site: opts.site })
      : mountBoard(box, { probe: slide.id, kiosk: true, static: opts.static, voice: opts.voice, defaultVoice: opts.defaultVoice, navigate: () => {} });
    clear(dots);
    st.slides.forEach((_, k) => dots.appendChild(h("span", { class: "dot" + (k === i ? " on" : "") })));
  }

  async function next() {
    if (st.dead) return;
    if (st.i + 1 >= st.slides.length) await slides();     // refresh the probe list once per cycle
    st.i = (st.i + 1) % st.slides.length;
    show(st.i);
    st.timer = setTimeout(next, every * 1000);
  }

  slides().then(next);
  return {
    destroy() {
      st.dead = true;
      if (st.timer) clearTimeout(st.timer);
      if (st.cur) st.cur.destroy();
      clear(root);
    },
  };
}
