// exp dashboard SPA: router, chrome (nav, theme, user), role-aware UI. No build step, no external resources.
import { api, loadSession, session, toLogin, ApiError } from "./api.js";
import { h, clear, icon, isSlug } from "./dom.js";
import { setTimezone, pref } from "./util.js";
import { mountBoard } from "./board.js";
import { mountOverview } from "./overview.js";
import { mountIncidents } from "./incidents.js";
import { mountLogin } from "./login.js";
import { mountKiosk } from "./kiosk.js";

const app = document.getElementById("app");
const chrome = document.getElementById("chrome");
let view = null;

const THEMES = ["dark", "light", "auto"];

function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", mode);
}

function cycleTheme(btn) {
  const cur = pref("theme") || "dark";
  const next = THEMES[(THEMES.indexOf(cur) + 1 + THEMES.length) % THEMES.length] || "light";
  pref("theme", next);
  applyTheme(next);
  btn.querySelector(".theme-text").textContent = "Theme: " + next;
}

async function logout() {
  try {
    await api("/auth/logout", { method: "POST", noRedirect: true });
  } catch (e) {
    // the cookie may already be gone; fall through to the login page either way
  }
  location.replace("/login");
}

function renderChrome(params, path) {
  clear(chrome);
  const kiosk = params.get("kiosk") === "1" && (path === "/" || path.startsWith("/probe/"));
  document.body.classList.toggle("kiosk", kiosk);
  chrome.hidden = kiosk || path === "/login";
  if (chrome.hidden) return;
  const nav = [["/", "Overview", "dashboard"], ["/incidents", "Incidents", "alert"]];
  const theme = pref("theme") || "dark";
  const themeBtn = h("button", { class: "btn btn-quiet", type: "button", title: "Change colour theme" }, icon("settings"), h("span", { class: "theme-text", text: "Theme: " + theme }));
  themeBtn.addEventListener("click", () => cycleTheme(themeBtn));
  chrome.append(
    h("a", { class: "brand", href: "/", "data-spa": "" }, icon("probe"), h("span", { text: session ? String(session.title || "exp") : "exp" })),
    h("nav", { "aria-label": "Main" }, nav.map(([href, label, ic]) => h("a", { class: "nav-link", href, "data-spa": "", "aria-current": href === path ? "page" : null }, icon(ic), label))),
    h("div", { class: "chrome-tools" }, themeBtn,
      session ? h("span", { class: "who", title: "Signed in" }, icon("user"), h("span", { class: "who-name", text: String(session.user) }),
        h("span", { class: "role role-" + String(session.role), text: String(session.role) })) : null,
      h("button", { class: "btn btn-quiet", type: "button", on: { click: logout } }, "Sign out")));
}

function go(url, replace) {
  if (replace) history.replaceState(null, "", url); else history.pushState(null, "", url);
  route();
}

// board-internal URL changes (rewind) update the address bar without remounting
function soft(url, replace) {
  if (replace) history.replaceState(null, "", url); else history.pushState(null, "", url);
}

function mount(fn) {
  if (view) view.destroy();
  clear(app);
  view = fn();
}

function notFound() {
  app.append(h("section", { class: "card" }, h("h1", { text: "Not found" }),
    h("p", { class: "sub" }, "This page does not exist. ", h("a", { href: "/", "data-spa": "", text: "Go to the overview" }))));
  return { destroy() { clear(app); } };
}

function drills() {
  app.append(h("section", { class: "card" }, h("h1", { text: "Drills" }), h("p", { class: "sub", text: "Drill runs appear here once the runner is installed." })));
  return { destroy() { clear(app); } };
}

async function route() {
  const url = new URL(location.href);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const params = url.searchParams;
  if (path === "/login") {
    renderChrome(params, path);
    document.title = "Sign in";
    mount(() => mountLogin(app));
    return;
  }
  if (!session) {
    try {
      if (!(await loadSession())) { toLogin(); return; }
    } catch (e) {
      app.append(h("section", { class: "card" }, h("h1", { text: "Dashboard unreachable" }), h("p", { class: "sub", text: e instanceof ApiError ? e.message : "Could not load the session." })));
      return;
    }
    setTimezone(session.timezone);
  }
  renderChrome(params, path);
  const staticMode = params.get("static") === "1";
  const kiosk = document.body.classList.contains("kiosk");
  const probe = /^\/probe\/([a-z0-9][a-z0-9-]{0,63})$/.exec(path);
  const common = { static: staticMode, voice: params.get("voice"), defaultVoice: session.voice, navigate: soft };
  if (path === "/") {
    document.title = "Overview";
    mount(() => kiosk ? mountKiosk(app, { ...common, rotate: params.get("rotate"), site: params.get("site") })
      : mountOverview(app, { ...common, site: params.get("site") }));
  } else if (probe && isSlug(probe[1])) {
    mount(() => mountBoard(app, { ...common, probe: probe[1], at: params.get("at"), kiosk }));
  } else if (path === "/incidents") {
    document.title = "Incidents";
    mount(() => mountIncidents(app, common));
  } else if (path === "/drills") {
    document.title = "Drills";
    mount(drills);
  } else {
    document.title = "Not found";
    mount(notFound);
  }
}

document.addEventListener("click", (ev) => {
  if (ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
  const a = ev.target instanceof Element ? ev.target.closest("a[data-spa]") : null;
  if (!a || a.origin !== location.origin) return;
  ev.preventDefault();
  go(a.pathname + a.search);
});
window.addEventListener("popstate", () => route());
route();
