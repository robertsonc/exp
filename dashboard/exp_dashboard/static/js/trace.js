// Beat strips: one column per beat, value 0/1/2/3 = ok/warn/fail/unknown.
// Redundant encoding (never colour alone): column height (low / mid / full), fill (solid / hollow dashed for 3)
// and the state icon next to the line name. Ported in spirit from the "heartbeat trace" lanes of
// reference/exm/lib/exm/static/pulse.html (drawTrace); the rule logic is not ported (state comes from the collector).
import { s } from "./dom.js";

const W = 900;
const H = 44;
const HEIGHT = [14, 28, 44, 44];
const NAME = ["ok", "warn", "fail", "unknown"];
export const BEAT_MS = 10000;   // default only: callers pass the probe's measured cadence (beatMs in util.js)

export function tally(points, win) {
  const n = [0, 0, 0, 0];
  for (const p of points) if (p[0] >= win.start && p[0] <= win.end && p[1] >= 0 && p[1] <= 3) n[p[1]]++;
  return n;
}

export function describe(label, points, win) {
  const n = tally(points, win);
  const total = n[0] + n[1] + n[2] + n[3];
  if (!total) return label + ": no results in this window";
  return label + ": " + total + " results, " + n[0] + " ok, " + n[1] + " warning, " + n[2] + " failing, " + n[3] + " no data";
}

export function xOf(t, win) {
  return ((t - win.start) / (win.end - win.start)) * W;
}

export function drawStrip(svg, points, win, playheadMs, beat = BEAT_MS) {
  svg.replaceChildren();
  svg.setAttribute("viewBox", "0 0 " + W + " " + H);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.appendChild(s("line", { class: "base", x1: 0, y1: H - 0.5, x2: W, y2: H - 0.5 }));
  const bw = Math.max(2, (W * beat) / (win.end - win.start) * 0.7);
  let any = false;
  for (const p of points) {
    const t = p[0];
    const v = p[1];
    if (!(t >= win.start && t <= win.end) || !(v >= 0 && v <= 3)) continue;
    any = true;
    const h = HEIGHT[v];
    svg.appendChild(s("rect", { class: "beat b" + v + " " + NAME[v], x: Math.max(0, xOf(t, win) - bw / 2).toFixed(1), y: H - h, width: bw.toFixed(1), height: h }));
  }
  if (!any) svg.appendChild(s("line", { class: "nodata", x1: 0, y1: H / 2, x2: W, y2: H / 2 }));
  if (Number.isFinite(playheadMs) && playheadMs >= win.start && playheadMs <= win.end) {
    const x = xOf(playheadMs, win).toFixed(1);
    svg.appendChild(s("line", { class: "playhead", x1: x, y1: 0, x2: x, y2: H }));
  }
}
