/* CipherGuard dashboard. Talking to the server: access token, requests, toasts, dialogs, the Server dialog. */
"use strict";

/* ------------------------------------------------------------------- api */

/* The API gained optional bearer auth, so every call has to carry the token and
   handle 401 by asking for one — otherwise an authenticated deployment renders
   an empty dashboard with no indication why. */
function authHeaders(extra){
  const headers = Object.assign({}, extra || {});
  if (state.token) headers["Authorization"] = "Bearer " + state.token;
  return headers;
}

/* ------------------------------------------------ production utilities */

let activeApiRequests = 0;
function setProgressBar(active){
  const bar = $("global-progress-bar");
  if (!bar) return;
  if (active) {
    activeApiRequests++;
    bar.classList.add("active");
  } else {
    activeApiRequests = Math.max(0, activeApiRequests - 1);
    if (activeApiRequests === 0) {
      bar.classList.remove("active");
    }
  }
}

function showToast(message, type = "info", duration = 4000){
  const container = $("toast-container");
  if (!container) return;
  const item = document.createElement("div");
  item.className = `toast-item ${type}`;
  const icon = type === "error" ? "" : type === "success" ? "✔" : "ℹ";
  item.innerHTML = `
    <div class="toast-msg">
      <span>${icon}</span>
      <span>${esc(message)}</span>
    </div>
    <button type="button" class="toast-close" aria-label="Close notification">&times;</button>
  `;
  const closeBtn = item.querySelector(".toast-close");
  if (closeBtn) {
    closeBtn.onclick = () => dismissToast(item);
  }
  container.appendChild(item);
  setTimeout(() => {
    if (item.parentElement) dismissToast(item);
  }, duration);
}

function dismissToast(item){
  item.classList.add("is-leaving");
  setTimeout(() => item.remove(), 250);
}

function setButtonLoading(btn, isLoading, loadingText = "Processing..."){
  if (!btn) return;
  if (!btn.dataset) btn.dataset = {};
  if (isLoading) {
    if (!btn.dataset.originalText) {
      btn.dataset.originalText = btn.innerHTML;
    }
    btn.classList.add("btn-loading");
    btn.disabled = true;
    btn.innerHTML = `<span class="btn-spinner" aria-hidden="true"></span> ${esc(loadingText)}`;
  } else {
    btn.classList.remove("btn-loading");
    btn.disabled = false;
    if (btn.dataset.originalText) {
      btn.innerHTML = btn.dataset.originalText;
    }
  }
}

function showFieldError(inputEl, message){
  if (!inputEl) return;
  inputEl.classList.add("has-error");
  inputEl.setAttribute("aria-invalid", "true");
  let err = inputEl.parentElement.querySelector(".field-error-msg");
  if (!err) {
    err = document.createElement("div");
    err.className = "field-error-msg";
    err.setAttribute("role", "alert");
    inputEl.parentElement.appendChild(err);
  }
  err.textContent = message;
}

function clearFieldError(inputEl){
  if (!inputEl) return;
  inputEl.classList.remove("has-error");
  inputEl.removeAttribute("aria-invalid");
  const err = inputEl.parentElement.querySelector(".field-error-msg");
  if (err) err.remove();
}

const BACKEND_URL_KEY = "cipherguard_backend_url";
// Each refresh makes the server run the operating system's Wi-Fi tools.
const WIFI_REFRESH_MS = 15000;
const DEFAULT_LOCAL_BACKEND = "http://127.0.0.1:8000";

function storedBackendUrl(){
  try {
    const custom = localStorage.getItem(BACKEND_URL_KEY);
    return custom && custom.trim() ? custom.trim().replace(/\/+$/, "") : "";
  } catch (e) {
    return "";  // storage blocked: behave as if nothing was saved
  }
}

/* Where the API is. Empty means this page's own origin, which is right
 * whenever the server itself served the page, on whatever host and port. A
 * different backend is used only when someone saved one in the Local server
 * dialog: the page never goes looking for a server on the viewer's machine. */
function getBackendUrl(){
  return storedBackendUrl();
}

function resolveApiPath(path){
  if (path.startsWith("http://") || path.startsWith("https://")) return path;
  return getBackendUrl() + (path.startsWith("/") ? path : "/" + path);
}

async function testBackendConnection(targetUrl){
  const base = (targetUrl !== undefined ? targetUrl : getBackendUrl()).replace(/\/+$/, "");
  const probe = base ? `${base}/api/health` : "/api/health";
  const start = performance.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(probe, { cache: "no-store", signal: controller.signal });
    clearTimeout(timer);
    const latency = Math.round(performance.now() - start);
    if (res.ok) {
      const data = await res.json();
      return { ok: true, latency, data, url: base || window.location.origin };
    }
    return { ok: false, error: `HTTP ${res.status}: ${res.statusText}`, latency };
  } catch (err) {
    return { ok: false, error: err.message || "Could not connect", latency: Math.round(performance.now() - start) };
  }
}

function updateBackendModalContent(isLive, details = {}){
  const card = $("modal-status-card");
  const badge = $("modal-status-badge");
  const desc = $("modal-status-details");
  const ep = $("modal-metric-endpoint");
  const lat = $("modal-metric-latency");
  const adp = $("modal-metric-adapter");
  const ssid = $("modal-metric-ssid");
  const activeUrl = details.url || getBackendUrl() || window.location.origin;

  if (ep) ep.textContent = activeUrl;
  // only a latency that was measured; never a stand-in figure
  if (lat) lat.textContent = !isLive ? "Not connected"
    : Number.isFinite(details.latency) ? `${details.latency} ms` : "\u2014";

  // the adapter and network are shown only when they came from a live scan
  const wifiIface = (isLive && state.wifiIsLive && state.wifiAssessment
                     && state.wifiAssessment.interface) || {};
  if (adp) adp.textContent = wifiIface.description || "\u2014";
  if (ssid) ssid.textContent = wifiIface.ssid
    ? wifiIface.ssid + (wifiIface.channel ? ` (channel ${wifiIface.channel})` : "") : "\u2014";

  if (isLive) {
    if (card) { card.className = "modal-status-card online"; }
    if (badge) badge.textContent = "Connected";
    if (desc) desc.innerHTML = `Using the CipherGuard server at <code>${esc(activeUrl)}</code>. Captures are assessed there, and the Wi-Fi view shows that machine's adapter.`;
  } else {
    if (card) { card.className = "modal-status-card offline"; }
    if (badge) badge.textContent = "No server connected";
    if (desc) desc.textContent = "This page is showing assessments that were computed when it was built. To assess your own captures or scan Wi-Fi, start the server and connect to it below.";
  }
}

function openBackendModal(){
  const modal = $("backend-modal");
  if (!modal) return;
  modal.hidden = false;
  ModalFocus.trap(modal);
  const input = $("backend-url-input");
  if (input) input.value = storedBackendUrl();
  const cmd = $("backend-start-cmd");
  if (cmd) cmd.textContent = backendStartCommand();
  testBackendConnection().then(check => {
    updateBackendModalContent(check.ok, check);
  });
}

/* In-page replacement for window.prompt(): a native <dialog>, so focus is held
 * inside it, Escape cancels and the page behind is inert while it is open. */
const Dialogs = (() => {
  let seq = 0;

  function ask({ title, message, label, type = "text", confirmLabel = "Continue" }){
    return new Promise(resolve => {
      const dlg = document.createElement("dialog");
      if (typeof dlg.showModal !== "function"){ resolve(null); return; }
      const id = `cg-dialog-${++seq}`;
      dlg.className = "cg-dialog";
      dlg.setAttribute("aria-labelledby", `${id}-title`);
      dlg.innerHTML = `
        <form method="dialog" class="cg-dialog-form">
          <h2 class="cg-dialog-title" id="${id}-title">${esc(title)}</h2>
          <p class="cg-dialog-text">${esc(message)}</p>
          <label class="cg-dialog-label" for="${id}-input">${esc(label)}</label>
          <input class="cg-dialog-input" id="${id}-input" autocomplete="off" required
                 type="${type === "password" ? "password" : "text"}" maxlength="256">
          <div class="cg-dialog-actions">
            <button type="button" class="ghost" data-cancel>Cancel</button>
            <button type="submit">${esc(confirmLabel)}</button>
          </div>
        </form>`;
      const input = dlg.querySelector("input");
      let answer = null;
      dlg.querySelector("[data-cancel]").addEventListener("click", () => dlg.close());
      dlg.querySelector("form").addEventListener("submit", () => { answer = input.value.trim() || null; });
      dlg.addEventListener("close", () => { dlg.remove(); resolve(answer); });
      document.body.appendChild(dlg);
      dlg.showModal();
    });
  }

  return { ask };
})();

function closeBackendModal(){
  const modal = $("backend-modal");
  if (modal){ modal.hidden = true; ModalFocus.release(modal); }
}

function openShortcutsModal(){
  const modal = $("shortcuts-modal");
  if (!modal) return;
  modal.hidden = false;
  modal.removeAttribute("hidden");
  ModalFocus.trap(modal);
}

function closeShortcutsModal(){
  const modal = $("shortcuts-modal");
  if (!modal) return;
  modal.hidden = true;
  modal.setAttribute("hidden", "");
  ModalFocus.release(modal);
}

async function handleSaveBackendUrl(){
  const input = $("backend-url-input");
  const feedback = $("backend-url-feedback");
  const btn = $("btn-save-backend-url");
  if (!input) return;
  const rawUrl = input.value.trim().replace(/\/+$/, "");
  const say = (kind, text) => {
    if (!feedback) return;
    feedback.hidden = false;
    feedback.className = "backend-feedback" + (kind ? " " + kind : "");
    feedback.textContent = text;
  };
  if (!/^https?:\/\/[^\s/]+$/i.test(rawUrl)) {
    say("error", `Enter the server's address, for example ${DEFAULT_LOCAL_BACKEND}.`);
    return;
  }
  setButtonLoading(btn, true, "Testing…");
  const test = await testBackendConnection(rawUrl);
  setButtonLoading(btn, false);
  if (test.ok) {
    try { localStorage.setItem(BACKEND_URL_KEY, rawUrl); } catch (e) { /* works for this visit only */ }
    say("success", `Connected in ${test.latency} ms. Reloading to use this server.`);
    window.location.reload();
  } else {
    say("error", `Could not reach ${rawUrl}: ${test.error}. Check that the server is running and `
      + `was started with --cors-origin ${window.location.origin}`);
    updateBackendStatusPill(false);
  }
}

function handleResetBackendUrl(){
  let had = false;
  try {
    had = !!localStorage.getItem(BACKEND_URL_KEY);
    localStorage.removeItem(BACKEND_URL_KEY);
  } catch (e) { /* nothing was stored */ }
  if (had) { window.location.reload(); return; }
  const input = $("backend-url-input");
  if (input) input.value = "";
  const feedback = $("backend-url-feedback");
  if (feedback) {
    feedback.hidden = false;
    feedback.className = "backend-feedback";
    feedback.textContent = "No saved server address. This page uses the server that served it.";
  }
}

/* The command that starts a backend this page can reach. Served by the backend
 * itself, the page is same-origin and needs nothing extra. Served from anywhere
 * else (the hosted static build), the backend answers this origin only if it is
 * named with --cors-origin; cross-origin access is off by default. */
function backendStartCommand(){
  const base = "python -m cipherguard.cli serve";
  const origin = window.location.origin;
  const servedByBackend = !staticMode.active || !/^https?:/.test(origin);
  return servedByBackend ? base : `${base} --cors-origin ${origin}`;
}

function handleCopyBackendCmd(){
  const cmd = backendStartCommand();
  const done = ok => showToast(
    ok ? "Command copied" : "Could not copy. Select the command and copy it by hand.",
    ok ? "success" : "error");
  if (navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(cmd).then(() => done(true), () => done(false));
  } else {
    done(false);
  }
}

/* A failed request becomes an error carrying the status and the server's own
 * message (FastAPI's {"detail": "..."}), never the raw response body: a body
 * can be an HTML error page or a traceback, and neither belongs on screen.
 * The full body stays on the error object for the console. */
async function apiError(res){
  const body = await res.text().catch(() => "");
  let detail = null;
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed.detail === "string") detail = parsed.detail;
  } catch (e) { /* not JSON: keep no detail rather than show markup */ }
  const err = new Error(detail || `HTTP ${res.status}`);
  err.status = res.status;
  err.detail = detail;
  err.body = body;
  return err;
}

/* One calm sentence for a failed request, chosen by what failed. The server's
 * detail is only shown where it is written for the user (upload rules). */
function explainFailure(err){
  if (typeof staticMode !== "undefined" && staticMode.active){
    return "The saved assessment for this capture could not be loaded.";
  }
  if (!err || err.status === undefined){
    return "The server is not responding.";
  }
  if (err.status === 401 || err.status === 403) return "The server needs a valid access token.";
  if (err.status === 404) return "That capture is no longer available on the server.";
  if (err.status === 413) return "That capture is larger than the server accepts.";
  if (err.status === 422) return err.detail || "The server could not read that capture.";
  if (err.status === 429) return "Too many requests. Wait a minute, then try again.";
  if (err.status >= 500) return "The server could not complete the assessment.";
  return "The request could not be completed.";
}

/* Several requests can be refused at once on page load; they share one dialog. */
let pendingTokenRequest = null;
function requestToken(){
  if (!pendingTokenRequest){
    pendingTokenRequest = Dialogs.ask({
      title: "Access token required",
      message: "This CipherGuard server only answers requests that carry its access token. "
        + "The person who started the server has it.",
      label: "Access token",
      type: "password",
      confirmLabel: "Connect"
    }).finally(() => { pendingTokenRequest = null; });
  }
  return pendingTokenRequest;
}

async function api(path, options){
  const isSilent = !!(options && options.silent);
  if (!isSilent) setProgressBar(true);
  try {
    const opts = Object.assign({}, options || {});
    delete opts.silent;
    opts.headers = authHeaders(opts.headers);
    // One server only. A failed request used to be retried against
    // 127.0.0.1:8000, which sent the access token to whatever was listening
    // on that port of the viewer's own machine.
    const url = resolveApiPath(path);
    let res = await fetch(url, opts);

    if (res.status === 401){
      const supplied = await requestToken();
      if (!supplied){
        const cancelled = new Error("authentication required");
        cancelled.status = 401;
        throw cancelled;
      }
      state.token = supplied;
      try { sessionStorage.setItem("cipherguard.token", state.token); } catch (e) {}
      opts.headers = authHeaders(options && options.headers);
      res = await fetch(url, opts);
    }
    if (!res.ok) throw await apiError(res);
    return res;
  } finally {
    if (!isSilent) setProgressBar(false);
  }
}

function showBanner(message, kind, action){
  const el = $("banner");
  if (!message){ el.hidden = true; el.textContent = ""; return; }
  el.textContent = message;
  // an optional button, e.g. Retry; built as a node, never from markup
  if (action){
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ghost banner-retry";
    btn.textContent = action.label;
    btn.addEventListener("click", action.onClick);
    el.appendChild(btn);
  }
  // an informational banner must not look like the error banner, or a working
  // static demo reads as a broken deployment
  el.className = kind === "info" ? "banner info" : "banner";
  el.hidden = false;
}
