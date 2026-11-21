// Support view (/speedtests/support): an operator pastes the share link a user read out or sent
// (".../st/r/<id>#k=...") or just a test id and lands on the detail page with the full evidence.
// The "#k=" key authorizes the user's own view on the box; it is not needed here and is dropped in the browser:
// it is never sent to the dashboard, never stored, never put in a URL we navigate to.
// Admins can additionally look a test up by device key / MAC / IP (audited) and file a purge.
import { api, qs, subNav, h, clear, icon, field, errorBanner, errText, ST_ID_FIND, testLink, scoreBadge, isAdmin, collectorBanner } from "./common.js";
import { purgeForm } from "./purge.js";
import { fmtDateTime, parseTs } from "../js/util.js";

export function extractTestId(text) {
  if (typeof text !== "string" || text.length > 4096) return null;
  const m = ST_ID_FIND.exec(text);
  return m ? m[0] : null;
}

export function mountSupport(root, opts) {
  const input = h("input", { id: "support-input", type: "text", inputmode: "url", autocomplete: "off", spellcheck: "false", maxlength: "2048", placeholder: "https://.../st/r/st_...#k=...   or   st_...", "aria-describedby": "support-help" });
  const err = h("p", { class: "inline-error", id: "support-error", role: "alert" });
  const results = h("div", { class: "support-results" });
  const form = h("form", { class: "support-form", novalidate: "" }, field("Result link or test id", input, "support-input"), h("button", { class: "btn btn-primary", type: "submit" }, icon("link"), "Open test"), err);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const id = extractTestId(input.value);
    if (!id) { err.textContent = "That does not contain a test id (it looks like st_ followed by 26 letters and digits)."; return; }
    err.textContent = "";
    input.value = "";                       // the fragment key leaves the page with the paste
    opts.go(testLink(id));
  });

  const sec = h("section", { class: "st st-support", "aria-label": "Support lookup" },
    h("h1", { class: "st-title", text: "Support lookup" }),
    h("p", { class: "sub", id: "support-help", text: "Paste the link from the user's result page, or the test id they read out. You get the full evidence the user does not see." }),
    form, results);
  root.append(subNav("support"), sec);

  // Admin: search by anything the collector can match (raw values only for admins; each use is audited).
  let dead = false;
  if (isAdmin()) {
    const q = h("input", { id: "support-q", type: "text", maxlength: "128", autocomplete: "off", spellcheck: "false", placeholder: "device IP, MAC, hostname, AP, SSID, comment text" });
    const out = h("div", { class: "support-found" });
    const f = h("form", { class: "support-form" }, field("Search tests (admin)", q, "support-q"), h("button", { class: "btn", type: "submit" }, "Search"));
    f.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      clear(out);
      const term = q.value.trim();
      if (!term) return;
      try {
        const doc = await api("/api/v1/speedtests" + qs({ q: term, identifiers: "1", limit: 25 }));
        if (dead) return;
        out.append(collectorBanner(doc.collectors));
        const items = Array.isArray(doc.items) ? doc.items : [];
        if (!items.length) { out.append(h("p", { class: "empty", text: "No test matches." })); return; }
        out.append(h("div", { class: "scroll" }, h("table", { class: "tests-table" }, h("thead", {}, h("tr", {}, ["When", "Score", "Zone", "AP", "Device", ""].map((t) => h("th", { scope: "col", text: t })))),
          h("tbody", {}, items.map((r) => h("tr", { data: { test: r.id } }, h("td", { text: fmtDateTime(parseTs(r.ended)) }), h("td", {}, scoreBadge(r.score)), h("td", { text: r.zone || "-" }), h("td", { text: r.ap_name || "-" }),
            h("td", { text: [r.client_ip, r.mac, r.hostname].filter(Boolean).join(" ") || (r.device_key ? "key " + String(r.device_key).slice(0, 12) : "-") }),
            h("td", {}, h("a", { href: testLink(r.id), "data-spa": "", text: "Open", "aria-label": "Open test " + r.id }))))))));
      } catch (e) {
        out.append(errorBanner(errText(e, "The search failed.")));
      }
    });
    sec.append(h("div", { class: "panel st-panel" }, h("h2", { text: "Find a test" }), f, out));
    const pf = purgeForm();
    if (pf) sec.append(pf);
  } else {
    sec.append(h("p", { class: "sub", id: "support-admin-note", text: "Searching by device address and data-subject purges are available to admins." }));
  }
  input.focus();
  return { destroy() { dead = true; clear(root); } };
}
