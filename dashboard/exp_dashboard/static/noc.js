// NOC link: https://<dashboard>/noc#t=expn_...  The fragment is never sent to a server. It is read here,
// removed from the address bar, and POSTed in the request body (never in a URL) to /auth/noc.
(async () => {
  const msg = document.getElementById("msg");
  const m = /(?:^#|&)t=([A-Za-z0-9_-]+)/.exec(location.hash);
  history.replaceState(null, "", location.pathname);
  if (!m) { msg.textContent = "This link is incomplete."; return; }
  try {
    const r = await fetch("/auth/noc", {
      method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({token: m[1]}),
    });
    if (r.ok) { location.replace("/?kiosk=1"); return; }
    msg.textContent = r.status === 429 ? "Too many attempts. Try again later." : "This link is invalid or has expired.";
  } catch (e) {
    msg.textContent = "The dashboard could not be reached.";
  }
})();
