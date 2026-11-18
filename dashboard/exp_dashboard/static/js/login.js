// Login page (/login) for local users. Works offline: the form posts to the dashboard itself.
import { api, ApiError } from "./api.js";
import { h, clear } from "./dom.js";
import { safeNext } from "./util.js";

export function mountLogin(root) {
  const next = safeNext(new URLSearchParams(location.search).get("next") || "/");
  const err = h("p", { class: "form-error", role: "alert", id: "login-error" });
  const user = h("input", { id: "username", name: "username", type: "text", autocomplete: "username", required: true, maxlength: "128", autocapitalize: "none", spellcheck: "false" });
  const pass = h("input", { id: "password", name: "password", type: "password", autocomplete: "current-password", required: true, maxlength: "1024" });
  const btn = h("button", { class: "btn btn-primary", type: "submit", text: "Sign in" });
  const form = h("form", { class: "login-form", method: "post", action: "/auth/login", "aria-describedby": "login-error", on: { submit: submit } },
    h("div", { class: "field" }, h("label", { for: "username", text: "Username" }), user),
    h("div", { class: "field" }, h("label", { for: "password", text: "Password" }), pass),
    err, btn);
  root.append(h("section", { class: "card login-card", "aria-labelledby": "login-h" },
    h("h1", { id: "login-h", text: "Sign in" }),
    h("p", { class: "sub", text: "Local account. This works without internet access." }), form));
  user.focus();

  async function submit(ev) {
    ev.preventDefault();
    err.textContent = "";
    btn.disabled = true;
    try {
      await api("/auth/login", { method: "POST", json: { username: user.value, password: pass.value }, noRedirect: true });
      location.replace(next);
    } catch (e) {
      pass.value = "";
      err.textContent = e instanceof ApiError && e.status === 429 ? "Too many attempts. Try again later."
        : e instanceof ApiError && e.status === 401 ? "Username or password is wrong." : "Could not sign in. The dashboard may be unreachable.";
      pass.focus();
    }
    btn.disabled = false;
  }
  return { destroy() { clear(root); } };
}
