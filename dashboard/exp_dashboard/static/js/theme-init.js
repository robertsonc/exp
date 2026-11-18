// Runs before first paint (loaded synchronously from <head>): wall-screen default is dark; "auto" follows the OS.
(function () {
  var mode = "dark";
  try {
    var v = window.localStorage.getItem("exp.theme");
    if (v === "light" || v === "auto" || v === "dark") mode = v;
  } catch (e) {
    mode = "dark";
  }
  var root = document.documentElement;
  if (mode === "auto") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", mode);
})();
