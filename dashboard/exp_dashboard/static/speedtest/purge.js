// Admin purge (SR-25 data-subject request): by device key, MAC, IP or test id. Two steps, always: a dry run that says
// exactly what would go, then an explicit "Delete permanently". The collector audits the actor; nothing here ever
// shows or stores the identifier beyond the form field. Viewers and operators never get this panel.
import { api, h, clear, icon, isAdmin, errText } from "./common.js";

const LABEL = { test: "this test", device_key: "every test of this device", mac: "every test of this MAC", ip: "every test from this IP" };

export function purgePanel(subjects, opts) {
  const o = opts || {};
  if (!isAdmin()) return null;
  const msg = h("div", { class: "purge-msg", role: "status", "aria-live": "polite" });
  const box = h("section", { class: "panel st-panel purge", id: "st-purge", "aria-label": "Purge data" },
    h("h2", {}, icon("alert"), " Purge data"),
    h("p", { class: "sub", text: "Permanently deletes the stored tests, device metadata and evidence. Aggregates carry no device labels and are not rewritten. The action is audited with your account." }));
  const row = h("div", { class: "purge-actions" });
  box.append(row, msg);

  function show(...nodes) { clear(msg); msg.append(...nodes); }

  async function run(by, value, dry) {
    return api("/api/v1/speedtests/purge", { method: "POST", json: { by, value, dry_run: dry, confirm: !dry } });
  }

  async function ask(by, value) {
    show(h("p", { class: "sub", text: "Checking what would be deleted..." }));
    try {
      const r = await run(by, value, true);
      const n = r.matched_tests || 0;
      const partial = r.partial ? " Some collectors did not answer, so the real total may be higher." : "";
      if (!n) {
        show(h("p", {}, "Nothing matches" + (by === "mac" && r.device_key_matched === false ? " (this collector can match a MAC only while the raw MAC is still stored)" : "") + "." + partial));
        return;
      }
      const go = h("button", { class: "btn btn-danger", type: "button", id: "purge-confirm" }, "Delete permanently");
      const cancel = h("button", { class: "btn", type: "button", on: { click: () => show() } }, "Cancel");
      go.addEventListener("click", async () => {
        go.disabled = true;
        try {
          const done = await run(by, value, false);
          const d = done.deleted || {};
          show(h("p", { class: "purge-done", text: "Deleted " + (d.tests || 0) + " test(s), " + (d.evidence || 0) + " evidence document(s) and " + (d.diagnoses || 0) + " diagnosis record(s)." + (done.partial ? " Some collectors did not answer: run the purge again when they are back." : "") }));
          if (o.onDone) o.onDone(by, done);
        } catch (e) {
          show(h("p", { class: "inline-error", text: errText(e, "The purge failed.") }));
        }
      });
      show(h("p", { class: "purge-warn" }, h("strong", { text: "Delete " + LABEL[by] + "? " }), n + " test(s) and their evidence will be removed." + partial), h("div", { class: "purge-actions" }, go, cancel));
      go.focus();
    } catch (e) {
      show(h("p", { class: "inline-error", text: errText(e, "Could not check the purge.") }));
    }
  }

  for (const sj of subjects) {
    if (!sj || typeof sj.value !== "string" || !sj.value) continue;
    row.append(h("button", { class: "btn", type: "button", data: { by: sj.by }, on: { click: () => ask(sj.by, sj.value) } }, "Purge " + LABEL[sj.by] + "..."));
  }
  if (!row.childNodes.length) return null;
  return box;
}

// Free-form purge for the support page: pick the kind, type the value.
export function purgeForm() {
  if (!isAdmin()) return null;
  const kind = h("select", { id: "purge-kind" }, [["test", "Test id"], ["device_key", "Device key"], ["mac", "MAC address"], ["ip", "IP address"]].map(([v, l]) => h("option", { value: v, text: l })));
  const val = h("input", { id: "purge-value", type: "text", maxlength: "128", autocomplete: "off", spellcheck: "false", placeholder: "st_..." });
  const slot = h("div", { class: "purge-slot" });
  const draw = () => {
    clear(slot);
    const p = purgePanel([{ by: kind.value, value: val.value.trim() }]);
    if (!p) return;
    slot.append(p);
    const b = p.querySelector("button[data-by]");
    if (b) b.click();
  };
  const go = h("button", { class: "btn", type: "button", on: { click: draw } }, "Check what would be deleted");
  kind.addEventListener("change", () => { clear(slot); val.placeholder = kind.value === "test" ? "st_..." : kind.value === "mac" ? "aa:bb:cc:dd:ee:ff" : kind.value === "ip" ? "10.0.0.1" : "64 hex characters"; });
  return h("section", { class: "panel st-panel", id: "st-purge-form" }, h("h2", { text: "Purge by subject" }),
    h("p", { class: "sub", text: "Data-subject request: remove every stored test of a device or address. Admins only; audited." }),
    h("div", { class: "filters" }, h("div", { class: "field" }, h("label", { for: "purge-kind", text: "Find by" }), kind),
      h("div", { class: "field" }, h("label", { for: "purge-value", text: "Value" }), val)), go, slot);
}
