/* Apply the saved colour theme before first paint: loaded without defer or
   async, ahead of the stylesheet, so there is no flash of the wrong theme.
   Light unless the reader chose Dark, or chose System on a dark OS. Theme in
   dashboard.js keeps the page and the picker in step afterwards. */
(function () {
  var t = "light";
  try { t = localStorage.getItem("cipherguard.theme") || "light"; } catch (e) {}
  if (t === "system") {
    t = window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", t === "dark" ? "dark" : "light");
})();
