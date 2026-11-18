// DOM helpers. Every string that reaches the page goes through createTextNode / textContent:
// probe labels, headlines, incident facts and error texts come from remote parties (SR-13).
const SVG_NS = "http://www.w3.org/2000/svg";

function apply(node, props) {
  for (const key of Object.keys(props || {})) {
    const v = props[key];
    if (v === undefined || v === null || v === false) continue;
    if (key === "class") node.setAttribute("class", v);
    else if (key === "text") node.textContent = String(v);
    else if (key === "on") {
      for (const ev of Object.keys(v)) node.addEventListener(ev, v[ev]);
    } else if (key === "vars") {
      for (const name of Object.keys(v)) node.style.setProperty(name, String(v[name]));
    } else if (key === "data") {
      for (const name of Object.keys(v)) node.setAttribute("data-" + name, String(v[name]));
    } else if (/^on/i.test(key) || key === "style") {
      throw new Error("attribute not allowed: " + key);
    } else node.setAttribute(key, v === true ? "" : String(v));
  }
}

function append(node, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export function h(tag, props, ...children) {
  const node = document.createElement(tag);
  apply(node, props);
  append(node, children);
  return node;
}

export function s(tag, props, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  apply(node, props);
  append(node, children);
  return node;
}

export function clear(node) {
  node.replaceChildren();
  return node;
}

// Icon = a CSS mask of shared/ui/icons/<name>.svg painted with currentColor (see css/app.css).
export function icon(name, extra) {
  return h("span", { class: "ico ico-" + name + (extra ? " " + extra : ""), "aria-hidden": "true" });
}

export const STATE_ICON = { ok: "check", warn: "alert", fail: "x", unknown: "clock" };
export const STATE_WORD = { ok: "OK", warn: "Warning", fail: "Failing", unknown: "No data" };

export function normState(v) {
  return v === "ok" || v === "warn" || v === "fail" ? v : "unknown";
}

// A state is always shown as icon + text (never colour alone).
export function stateBadge(state, label) {
  const st = normState(state);
  return h("span", { class: "badge st-" + st, data: { state: st } }, icon(STATE_ICON[st]),
    h("span", { class: "badge-text", text: label || STATE_WORD[st] }));
}

// ids that go into URLs: only the slug alphabet the API accepts.
export const SLUG = /^[a-z0-9][a-z0-9-]{0,63}$/;
export const isSlug = (v) => typeof v === "string" && SLUG.test(v);
