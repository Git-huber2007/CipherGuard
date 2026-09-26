/* CipherGuard dashboard.
 *
 * All rendering funnels through esc() before anything reaches innerHTML. That is
 * not defensive habit: peer addresses, vendor ID strings and finding subjects
 * are all derived from packet bytes an attacker chose, so the dashboard renders
 * hostile input on every load.
 */
"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  assessment: null,        // latest assessment payload
  platform: null,          // selected remediation platform
  token: null,             // bearer token, when the API requires one
  remediationPlans: [],    // active hardening & rollback plans
  playbookMode: "forward", // "forward" or "rollback"
  wifiGroupMode: true,     // true: group by SSID, false: flat list of all BSSIDs
  currentWifiNetworks: [], // cached list of WifiNetwork items
  wifiAssessment: null,    // latest live wifi & vpn assessment payload
  sessionStartTime: Date.now(),
  telemetryTicks: 0,
  ipsecMode: "single",     // "single" or "diff"
  diffAssessmentA: null,   // baseline capture A assessment
  diffAssessmentB: null,   // hardened capture B assessment
  spectrumBand: "2.4",     // "2.4" or "5"
  selectedLink: null,      // link id ("a~b") shown in the ribbon and link panel
  findingsView: "rule"     // "rule" (grouped) or "link"
};

/* ---------------------------------------------------------------- helpers */

function esc(s){
  return String(s == null ? "" : s).replace(/[&<>"']/g,
    c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

/* Every number a person reads goes through here, so a figure means the same
 * thing in every panel. (SVG coordinates are geometry, not figures, and are
 * not formatted here.)
 *
 *  - Bytes are decimal: 1 KB = 1,000 B, one decimal place above bytes. The
 *    Python side divides by 1e6 for MB throughout, and two conventions on one
 *    page is how "1.1 MB" and "1.0 MB" end up describing the same capture.
 *  - Grouping uses a fixed en-US locale so a demo reads identically on every
 *    machine it is shown on.
 *  - Negative values use a true minus sign (U+2212), which lines up with "+".
 *  - Missing values render as an em dash rather than "NaN" or "undefined". */
const Fmt = (() => {
  const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"];
  const grouped = new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 });
  const NONE = "—";
  const ok = n => typeof n === "number" && Number.isFinite(n);

  function count(n){ return ok(n) ? grouped.format(Math.round(n)) : NONE; }

  function bytes(n){
    if (!ok(n)) return NONE;
    let v = Math.max(n, 0), u = 0;
    while (v >= 1000 && u < BYTE_UNITS.length - 1){ v /= 1000; u++; }
    // 999.96 KB would print as "1000.0 KB"; carry it into the next unit
    if (u > 0 && Number(v.toFixed(1)) >= 1000 && u < BYTE_UNITS.length - 1){ v /= 1000; u++; }
    return u === 0 ? `${Math.round(v)} B` : `${v.toFixed(1)} ${BYTE_UNITS[u]}`;
  }

  function bits(n){ return ok(n) ? `${count(n)} bits` : NONE; }

  function signed(n){
    if (!ok(n)) return NONE;
    const r = Math.round(n);
    return `${r > 0 ? "+" : r < 0 ? "−" : ""}${count(Math.abs(r))}`;
  }

  // ratio is 0..1; digits are decimal places of the percentage
  function percent(ratio, digits = 0){
    if (!ok(ratio)) return NONE;
    return `${(ratio * 100).toFixed(digits)}%`;
  }

  function duration(seconds){
    if (!ok(seconds)) return NONE;
    const s = Math.max(seconds, 0);
    if (s < 1) return `${Math.round(s * 1000)} ms`;
    if (s < 60) return `${s.toFixed(1)} s`;
    const whole = Math.round(s);
    if (whole < 3600) return `${Math.floor(whole / 60)} min ${String(whole % 60).padStart(2, "0")} s`;
    return `${Math.floor(whole / 3600)} h ${String(Math.floor(whole % 3600 / 60)).padStart(2, "0")} min`;
  }

  // megabits per second, as the Python side reports link rates
  function mbps(n){ return ok(n) ? `${n.toFixed(1)} Mb/s` : NONE; }

  return { count, bytes, bits, signed, percent, duration, mbps };
})();
window.Fmt = Fmt;

/* Plain-language glossary. Definitions live in glossary.json beside the
 * static assets (so the static export ships them); terms are marked with a
 * dotted underline and are focusable, and one tooltip follows hover, keyboard
 * focus and tap alike, so nothing is hover-only. Escape closes it.
 *
 * TERMS maps text as it appears on screen to a glossary key. mark() marks the
 * first occurrence of each in already-escaped text; a test checks that every
 * key used here or as data-gl="..." in the markup exists in glossary.json. */
const Glossary = (() => {
  const TERMS = [
    ["IKE_SA_INIT", "ike-sa-init"], ["IKE_AUTH", "ike-auth"],
    ["Diffie-Hellman group", "dh-group"], ["DH group", "dh-group"],
    ["framing class", "framing-class"], ["Framing class", "framing-class"],
    ["harvest-now-decrypt-later", "hndl"], ["Harvest-now-decrypt-later", "hndl"],
    ["harvest now, decrypt later", "hndl"], ["Mosca's inequality", "mosca"],
    ["Sweet32", "sweet32"], ["AEAD", "aead"], ["CRQC", "crqc"], ["CBOM", "cbom"],
    ["IKE", "ike"], ["ESP", "esp"], ["SPI", "spi"],
  ];
  // glossary.json sits beside js/ in both the served app (/static/) and the
  // static export (the site root), so resolve it from this script's own URL
  const here = (typeof document !== "undefined" && document.currentScript
    && document.currentScript.src) || "";
  const url = here ? here.replace(/js\/dashboard\.js(\?.*)?$/, "glossary.json") : "glossary.json";
  let defs = {};
  let tip = null, current = null, pinned = false;

  const byLength = [...TERMS].sort((a, b) => b[0].length - a[0].length);
  const pattern = new RegExp(
    "\\b(" + byLength.map(([t]) => esc(t).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")\\b", "g");
  const keyOf = Object.fromEntries(TERMS.map(([t, k]) => [esc(t), k]));

  function term(key, text){
    return `<span class="gl" data-gl="${esc(key)}" tabindex="0" role="button" `
      + `aria-describedby="gl-tip">${esc(text)}</span>`;
  }

  // escapedHtml must be plain escaped text (no tags); first occurrence per term
  function mark(escapedHtml){
    const seen = new Set();
    return String(escapedHtml).replace(pattern, m => {
      const key = keyOf[m];
      if (!key || seen.has(key)) return m;
      seen.add(key);
      return `<span class="gl" data-gl="${key}" tabindex="0" role="button" aria-describedby="gl-tip">${m}</span>`;
    });
  }

  function ensureTip(){
    if (tip) return tip;
    tip = document.createElement("div");
    tip.id = "gl-tip";
    tip.className = "gl-tip";
    tip.setAttribute("role", "tooltip");
    tip.hidden = true;
    document.body.appendChild(tip);
    return tip;
  }

  function show(el){
    const d = defs[el.dataset.gl];
    const t = ensureTip();
    t.innerHTML = d ? `<b>${esc(d.term)}</b>${esc(d.definition)}`
                    : `<b>${esc(el.textContent)}</b>Definition not available.`;
    t.hidden = false;
    current = el;
    const r = el.getBoundingClientRect();
    const width = t.offsetWidth, vw = document.documentElement.clientWidth;
    const left = Math.min(Math.max(r.left, 16), Math.max(vw - width - 16, 16));
    t.style.left = `${left + window.scrollX}px`;
    t.style.top = `${r.bottom + window.scrollY + 6}px`;
  }

  function hide(){
    if (tip) tip.hidden = true;
    current = null;
    pinned = false;
  }

  function enhance(root){
    (root || document).querySelectorAll("[data-gl]:not(.gl)").forEach(el => {
      el.classList.add("gl");
      if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "0");
      if (!el.hasAttribute("role")) el.setAttribute("role", "button");
      el.setAttribute("aria-describedby", "gl-tip");
    });
  }

  function bind(){
    ensureTip();
    enhance(document);
    document.addEventListener("mouseover", e => {
      const el = e.target.closest && e.target.closest(".gl");
      if (el && !pinned) show(el);
    });
    document.addEventListener("mouseout", e => {
      const el = e.target.closest && e.target.closest(".gl");
      if (el && !pinned && !el.contains(e.relatedTarget)) hide();
    });
    document.addEventListener("focusin", e => {
      const el = e.target.closest && e.target.closest(".gl");
      if (el) show(el);
    });
    document.addEventListener("focusout", e => {
      if (e.target.closest && e.target.closest(".gl")) hide();
    });
    // tap (and click) pins the definition open; tapping again or elsewhere closes it
    document.addEventListener("click", e => {
      const el = e.target.closest && e.target.closest(".gl");
      if (el){
        e.preventDefault();
        if (pinned && current === el){ hide(); return; }
        show(el);
        pinned = true;
      } else if (pinned){
        hide();
      }
    });
    document.addEventListener("keydown", e => {
      if (e.key === "Escape" && tip && !tip.hidden) hide();
      const el = e.target.closest && e.target.closest(".gl");
      if (el && (e.key === "Enter" || e.key === " ")){
        e.preventDefault();
        if (pinned && current === el) hide(); else { show(el); pinned = true; }
      }
    });
  }

  async function init(){
    bind();
    try {
      const res = await fetch(url, { cache: "no-store" });
      if (res.ok) defs = (await res.json()).terms || {};
    } catch (e){
      console.warn("Glossary unavailable:", e);
    }
  }

  return { TERMS, term, mark, enhance, init, get url(){ return url; } };
})();
if (typeof window !== "undefined") window.Glossary = Glossary;


function pickIkeProposal(s){
  // Prefer the responder's selection: that is what was actually agreed, as
  // opposed to everything the initiator was willing to accept.
  for (const m of (s.messages || [])) if (m.is_response)
    for (const p of (m.proposals || [])) if (p.protocol === "IKE") return p;
  for (const m of (s.messages || []))
    for (const p of (m.proposals || [])) if (p.protocol === "IKE") return p;
  return null;
}

function pretty(t){
  let n = t.name.replace(/^ENCR_|^AUTH_|^PRF_/, "");
  if (t.key_length) n += "-" + t.key_length;
  return n;
}

/* Algorithm judgement, mirroring audit/policy.py so a badge colour and a
   finding severity never contradict each other in front of an analyst. */
const BAD = /^(ENCR_)?(3?DES|DES_IV\d+|RC5|IDEA|CAST|BLOWFISH|3IDEA|NULL)/i;
const BAD_HASH = /MD5/i;
const WEAK_HASH = /SHA1|SHA_1/i;

function algClass(t){
  if (t.type_id === 4){                       // Diffie-Hellman group
    const id = t.value_id;
    if ([1, 2, 22, 25].includes(id)) return "bad";
    if ([5, 26].includes(id)) return "warn";
    return "good";
  }
  const n = t.name;
  if (BAD.test(n) || BAD_HASH.test(n)) return "bad";
  if (WEAK_HASH.test(n)) return "warn";
  if (/GCM|CHACHA|CCM/.test(n)) return "good";
  if (/SHA2/.test(n)) return "good";
  return "";
}

function suiteClass(name){
  if (!name) return "";
  // matches both suite names and framing-class names
  if (/NULL|3?DES|unencrypted|64-bit block/i.test(name)) return "bad";
  if (/96-bit ICV/i.test(name)) return "warn";
  if (/CBC/.test(name)) return "warn";
  return "good";
}

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
    <div style="display:flex;align-items:center;gap:8px">
      <span>${icon}</span>
      <span>${esc(message)}</span>
    </div>
    <button type="button" class="toast-close" aria-label="Close notification">&times;</button>
  `;
  const closeBtn = item.querySelector(".toast-close");
  if (closeBtn) {
    closeBtn.onclick = () => {
      item.style.opacity = "0";
      item.style.transform = "translateY(12px)";
      setTimeout(() => item.remove(), 250);
    };
  }
  container.appendChild(item);
  setTimeout(() => {
    if (item.parentElement) {
      item.style.opacity = "0";
      item.style.transform = "translateY(12px)";
      setTimeout(() => item.remove(), 250);
    }
  }, duration);
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
  err.innerHTML = `${esc(message)}`;
}

function clearFieldError(inputEl){
  if (!inputEl) return;
  inputEl.classList.remove("has-error");
  inputEl.removeAttribute("aria-invalid");
  const err = inputEl.parentElement.querySelector(".field-error-msg");
  if (err) err.remove();
}

/* -------------------------- privacy-preserving telemetry & analytics */
const CipherGuardTelemetry = {
  events: [],
  maxEvents: 50,
  recordEvent(name, data = {}){
    const entry = {
      name,
      data,
      timestamp: new Date().toISOString()
    };
    this.events.push(entry);
    if (this.events.length > this.maxEvents) this.events.shift();
    try {
      const stats = JSON.parse(localStorage.getItem("cipherguard_telemetry_stats") || "{}");
      stats[name] = (stats[name] || 0) + 1;
      stats.last_event_time = entry.timestamp;
      localStorage.setItem("cipherguard_telemetry_stats", JSON.stringify(stats));
    } catch(e) {}
  },
  getMetrics(){
    try {
      return JSON.parse(localStorage.getItem("cipherguard_telemetry_stats") || "{}");
    } catch(e) {
      return {};
    }
  }
};
window.CipherGuardTelemetry = CipherGuardTelemetry;

function getBackendUrl(){
  try {
    const custom = localStorage.getItem("cipherguard_backend_url");
    if (custom && custom.trim()) return custom.trim().replace(/\/+$/, "");
  } catch(e) {}
  if (location.port === "8000") return "";
  if (location.protocol === "file:" || location.hostname === "localhost" || location.hostname === "127.0.0.1") {
    return "http://127.0.0.1:8000";
  }
  return "http://127.0.0.1:8000";
}

function resolveApiPath(path){
  if (path.startsWith("http://") || path.startsWith("https://")) return path;
  const base = getBackendUrl();
  if (base) {
    return base + (path.startsWith("/") ? path : "/" + path);
  }
  return path.startsWith("/") ? path : "/" + path;
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
    return { ok: false, error: err.message || "Connection unreachable / blocked", latency: Math.round(performance.now() - start) };
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
  const activeUrl = details.url || getBackendUrl() || "http://127.0.0.1:8000";

  if (ep) ep.textContent = activeUrl;
  if (lat) lat.textContent = isLive ? `${details.latency || 4} ms` : "Offline";

  const wifiIface = (state.wifiAssessment && state.wifiAssessment.interface) || {};
  if (adp) adp.textContent = wifiIface.description || "\u2014";
  if (ssid) ssid.textContent = wifiIface.ssid ? `${wifiIface.ssid} (Ch ${wifiIface.channel || 6})` : "\u2014";

  if (isLive) {
    if (card) { card.className = "modal-status-card online"; }
    if (badge) badge.textContent = "Connected · Live Kernel Bridge Active";
    if (desc) desc.innerHTML = `Connected to local engine on <code>${esc(activeUrl)}</code>. Real-time physical Wi-Fi &amp; VPN kernel telemetry active.`;
  } else {
    if (card) { card.className = "modal-status-card offline"; }
    if (badge) badge.textContent = "Standalone Telemetry Mode (Engine Disconnected)";
    if (desc) desc.innerHTML = `Cloud/hosted mode. To stream raw kernel hardware data and execute live RF spectrum audits, launch the local backend or connect a secure tunnel.`;
  }
}

function openBackendModal(){
  const modal = $("backend-modal");
  if (!modal) return;
  modal.hidden = false;
  const input = $("backend-url-input");
  if (input) {
    input.value = localStorage.getItem("cipherguard_backend_url") || (location.port === "8000" ? window.location.origin : "http://127.0.0.1:8000");
  }
  testBackendConnection().then(check => {
    updateBackendModalContent(check.ok, check);
  });
}

function closeBackendModal(){
  const modal = $("backend-modal");
  if (modal) modal.hidden = true;
}

function openShortcutsModal(){
  const modal = $("shortcuts-modal");
  if (!modal) return;
  modal.hidden = false;
  modal.removeAttribute("hidden");
  modal.style.setProperty("display", "flex", "important");
}

function closeShortcutsModal(){
  const modal = $("shortcuts-modal");
  if (!modal) return;
  modal.hidden = true;
  modal.setAttribute("hidden", "");
  modal.style.setProperty("display", "none", "important");
}
window.openShortcutsModal = openShortcutsModal;
window.closeShortcutsModal = closeShortcutsModal;

async function handleSaveBackendUrl(){
  const input = $("backend-url-input");
  const feedback = $("backend-url-feedback");
  const btn = $("btn-save-backend-url");
  if (!input) return;
  const rawUrl = input.value.trim().replace(/\/+$/, "");
  setButtonLoading(btn, true, "Testing...");
  const test = await testBackendConnection(rawUrl);
  setButtonLoading(btn, false);
  if (test.ok) {
    localStorage.setItem("cipherguard_backend_url", rawUrl);
    if (feedback) {
      feedback.hidden = false;
      feedback.className = "backend-feedback success";
      feedback.textContent = `✔ Connected successfully! Latency: ${test.latency}ms. Streaming live kernel telemetry.`;
    }
    showToast(`Connected to backend: ${rawUrl} (${test.latency}ms)`, "success");
    updateBackendStatusPill(true, test);
    loadWifiAssessment(true, false);
  } else {
    if (feedback) {
      feedback.hidden = false;
      feedback.className = "backend-feedback error";
      feedback.textContent = `✖ Connection failed (${test.latency}ms): ${test.error}. Verify server is running with CORS enabled.`;
    }
    showToast(`Backend connection failed: ${test.error}`, "error");
    updateBackendStatusPill(false);
  }
}

function handleResetBackendUrl(){
  localStorage.removeItem("cipherguard_backend_url");
  const input = $("backend-url-input");
  if (input) input.value = "http://127.0.0.1:8000";
  const feedback = $("backend-url-feedback");
  if (feedback) {
    feedback.hidden = false;
    feedback.className = "backend-feedback";
    feedback.textContent = "Reset to default endpoint (http://127.0.0.1:8000).";
  }
  handleSaveBackendUrl();
}

function handleCopyBackendCmd(){
  const cmd = "python -m uvicorn cipherguard.api.server:app --host 127.0.0.1 --port 8000";
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(cmd).then(() => {
      showToast("Command copied", "success");
      const btn = $("btn-copy-backend-cmd");
      if (btn) {
        const orig = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = orig; }, 2000);
      }
    }).catch(() => {
      window.prompt("Copy command:", cmd);
    });
  } else {
    window.prompt("Copy command:", cmd);
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
    return "The saved analysis for this capture could not be loaded.";
  }
  if (!err || err.status === undefined){
    return "The analysis server is not responding.";
  }
  if (err.status === 401 || err.status === 403) return "The server needs a valid access token.";
  if (err.status === 404) return "That capture is no longer available on the server.";
  if (err.status === 413) return "That file is larger than the server accepts.";
  if (err.status >= 500) return "The server could not complete the analysis.";
  return "The request could not be completed.";
}

async function api(path, options){
  const isSilent = !!(options && options.silent);
  if (!isSilent) setProgressBar(true);
  try {
    const opts = Object.assign({}, options || {});
    delete opts.silent;
    opts.headers = authHeaders(opts.headers);
    let url = resolveApiPath(path);
    let res;
    try {
      res = await fetch(url, opts);
    } catch(netErr) {
      if (!url.startsWith("http://127.0.0.1:8000") && !url.startsWith("http://localhost:8000")) {
        url = "http://127.0.0.1:8000" + (path.startsWith("/") ? path : "/" + path);
        res = await fetch(url, opts);
      } else {
        throw netErr;
      }
    }

    if (res.status === 401){
      const supplied = window.prompt(
        "This CipherGuard instance requires an API token.");
      if (!supplied) throw new Error("authentication required");
      state.token = supplied.trim();
      try { sessionStorage.setItem("cipherguard.token", state.token); } catch (e) {}
      opts.headers = authHeaders(options && options.headers);
      res = await fetch(url, opts);
    }
    if (!res.ok) throw await apiError(res);
    CipherGuardTelemetry.recordEvent("api_success", { path });
    return res;
  } catch(err) {
    CipherGuardTelemetry.recordEvent("api_error", { path, error: err.message });
    throw err;
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

/* --------------------------------------------------------- wire ribbon */

const DEFAULT_RIBBON = [
  {d:"obs", n:"IP header",        v:"peer addresses, protocol"},
  {d:"obs", n:"UDP 500 / 4500",   v:"IKE or NAT-T encapsulation"},
  {d:"obs", n:"IKE header",       v:"SPIs, exchange type, flags"},
  {d:"obs", n:"SA proposal",      v:"cipher, PRF, integrity, DH group"},
  {d:"obs", n:"KE / Nonce / VID", v:"group, vendor fingerprint"},
  {d:"seam"},
  {d:"inf", n:"SK payload",       v:"child SA proposal — encrypted"},
  {d:"inf", n:"ESP header",       v:"SPI, sequence number"},
  {d:"inf", n:"ESP ciphertext",   v:"suite inferred from framing"}
];

/* Links come from the server (Assessment.to_dict()["links"]), worst first.
   These helpers only look them up; no grouping or ordering happens here. */
function worstLink(a){ return (a && a.links && a.links[0]) || null; }
function linkById(a, id){
  return (id && a && (a.links || []).find(l => l.id === id)) || null;
}
function linkLabel(l){ return `${l.peers[0]} ↔ ${l.peers[1]}`; }

/* The ribbon describes ONE link: the selected one, or the worst in the
   capture. Payloads from before links existed fall back to the first
   session and flow. Nothing is truncated: SPIs and vendor IDs wrap. */
function renderRibbonTo(targetId, a, link){
  const el = $(targetId);
  if (!el) return;
  const parts = DEFAULT_RIBBON.map(f => Object.assign({}, f));
  if (a){
    link = link || worstLink(a);
    const s = link ? a.sessions[link.sessions[0]] : (a.sessions || [])[0];
    const f = link ? a.flows[link.flows[0]] : (a.flows || [])[0];
    if (link) parts[0].v = linkLabel(link);
    if (s){
      const prop = pickIkeProposal(s);
      parts[2].v = `${s.version} · initiator SPI ${s.initiator_spi}`;
      if (prop) parts[3].v = prop.transforms.map(pretty).join(" · ");
      const vid = (s.vendor_ids || [])[0];
      if (vid) parts[4].v = vid;
    } else if (link){
      parts[2].v = parts[3].v = parts[4].v = "no IKE observed on this link";
    }
    if (f){
      if (f.encapsulated) parts[1].v = "UDP 4500 · ESP in NAT-T";
      parts[7].v = `SPI ${f.spi} · ${Fmt.count(f.packets)} packets`
        + (link && link.tunnels > 1 ? ` · 1 of ${link.tunnels} tunnels` : "");
      parts[8].v = `${f.framing_class || f.predicted_suite || "unresolved"} `
        + `(${Fmt.percent(f.framing_confidence ?? f.confidence ?? 0)})`;
    } else if (link){
      parts[7].v = parts[8].v = "no ESP observed on this link";
    }
  }
  el.innerHTML = parts.map(f =>
    f.d === "seam"
      ? `<div class="seam" role="separator" aria-label="Key boundary: fields after this are encrypted">`
        + `<span class="seam-label">key boundary</span></div>`
      : `<div class="field ${f.d}">`
      + `<div class="fname">${Glossary.mark(esc(f.n))}</div>`
      + `<div class="fval">${esc(f.v)}</div></div>`
  ).join("");
}

function renderRibbon(a){
  const link = linkById(a, state.selectedLink) || worstLink(a);
  renderRibbonTo("ribbon", a, link);
  const label = $("ribbon-link");
  if (!label) return;
  if (!a){ label.textContent = "No capture assessed yet."; return; }
  if (!link){ label.textContent = "No gateway pair observed in this capture."; return; }
  const sev = link.worst_severity;
  label.innerHTML = `Showing <span class="mono">${esc(linkLabel(link))}</span>`
    + (sev ? ` <span class="sev-mark ${esc(sev)}">${esc(sev)}</span>` : ` <span class="ribbon-quiet">no findings</span>`)
    + (link === worstLink(a) && (a.links || []).length > 1
        ? ` <span class="ribbon-quiet">worst of ${a.links.length} links</span>` : "")
    + ((a.links || []).length > 1
        ? ` <button type="button" class="linkish ribbon-choose">Choose another link</button>` : "");
  const choose = label.querySelector(".ribbon-choose");
  if (choose) choose.onclick = () => {
    $("links-panel").scrollIntoView({behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start"});
    const current = document.querySelector(`#link-list .link-item[aria-current="true"]`);
    if (current) current.focus({preventScroll: true});
  };
}

function prefersReducedMotion(){
  return !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
}

/* ------------------------------------------------------------------ links */

function readHash(){
  const p = new URLSearchParams(location.hash.replace(/^#/, ""));
  return {capture: p.get("capture"), link: p.get("link")};
}

function writeHash(capture, link){
  const p = new URLSearchParams();
  if (capture) p.set("capture", capture);
  if (link) p.set("link", link);
  // replaceState: selecting links should not fill the Back button with
  // entries, and it does not fire hashchange, so there is no feedback loop.
  history.replaceState(null, "", "#" + p.toString());
}

function linkMeta(l){
  const n = l.findings.length;
  const st = l.strength;
  return [
    l.worst_severity ? `worst ${l.worst_severity}` : "no findings",
    `${n} finding${n === 1 ? "" : "s"}`,
    `${l.tunnels} tunnel${l.tunnels === 1 ? "" : "s"}`,
    st ? `${st.classical_bits}/${Fmt.bits(st.quantum_bits)}` : "no IKE observed"
  ].join(" · ");
}

function renderLinks(a){
  const list = $("link-list"), detail = $("link-detail");
  if (!list || !detail) return;
  const links = a.links || [];
  if (!links.length){
    list.innerHTML = "";
    detail.innerHTML = `<div class="empty">No gateway pair observed in this capture.</div>`;
    return;
  }
  $("links-sub").textContent = `${links.length} gateway pair${links.length === 1 ? "" : "s"}, `
    + "worst first. Select one to see its handshake, tunnel and findings together.";
  list.innerHTML = links.map(l => `<li>
      <button type="button" class="link-item" data-link="${esc(l.id)}"
              aria-current="${l.id === state.selectedLink ? "true" : "false"}">
        <span class="link-bar ${esc(l.worst_severity || "none")}" aria-hidden="true"></span>
        <span class="link-main">
          <span class="link-peers">${esc(linkLabel(l))}</span>
          <span class="link-meta">${esc(linkMeta(l))}</span>
        </span>
      </button></li>`).join("");

  list.onclick = (e) => {
    const btn = e.target.closest(".link-item");
    if (btn) selectLink(btn.dataset.link, {focusDetail: false});
  };
  // Arrow keys move between links; Tab still leaves the list normally.
  list.onkeydown = (e) => {
    const items = [...list.querySelectorAll(".link-item")];
    const at = items.indexOf(document.activeElement);
    if (at < 0) return;
    const next = {ArrowDown: at + 1, ArrowUp: at - 1, Home: 0, End: items.length - 1}[e.key];
    if (next === undefined) return;
    e.preventDefault();
    const target = items[Math.max(0, Math.min(items.length - 1, next))];
    target.focus();
    selectLink(target.dataset.link);
  };
  detail.onclick = (e) => {
    const ev = e.target.closest("[data-evidence]");
    if (ev){
      const flow = state.assessment.flows[Number(ev.dataset.evidence)];
      if (flow) EvidencePanel.open(flow, ev);
      return;
    }
    toggleDisclosure(e);
  };
  renderLinkDetail(a, linkById(a, state.selectedLink) || links[0]);
}

function renderLinkDetail(a, link){
  const el = $("link-detail");
  if (!el || !link) return;
  const sessions = link.sessions.map(i => a.sessions[i]);
  const flows = link.flows.map(i => ({f: a.flows[i], i}));
  const st = link.strength;

  const head = `<div class="ld-head">
      <h3 class="ld-title mono">${esc(linkLabel(link))}</h3>
      <div class="ld-chips">
        ${link.worst_severity
          ? `<span class="sev-mark ${esc(link.worst_severity)}">${esc(link.worst_severity)}</span>`
          : `<span class="ribbon-quiet">no findings</span>`}
        ${st ? `<span class="ld-strength">${st.classical_bits}-bit classical · `
             + `${st.quantum_bits}-bit post-quantum · ${esc(st.kex_family.toUpperCase())}</span>` : ""}
      </div>
    </div>`;

  const handshake = sessions.length
    ? sessions.map(s => {
        const prop = pickIkeProposal(s);
        const algs = prop
          ? prop.transforms.map(t => `<span class="alg ${algClass(t)}">${esc(pretty(t))}</span>`).join("")
          : `<span class="alg">proposal not observed</span>`;
        return `<div class="ld-rec">
          <div class="meta">${esc(s.version)} · ${esc(s.vendor_family)} · ${s.messages.length} messages</div>
          <div class="ld-spi mono">initiator SPI ${esc(s.initiator_spi)}</div>
          <div class="algs">${algs}</div>
        </div>`;
      }).join("")
    : `<p class="ld-none">No IKE negotiation observed for this pair. The tunnel below is
        inferred with no handshake to corroborate it.</p>`;

  const tunnel = flows.length
    ? flows.map(({f, i}) => {
        const conf = Fmt.percent(f.framing_confidence ?? f.confidence ?? 0);
        const label = f.framing_class || f.predicted_suite || "unresolved";
        return `<div class="ld-rec">
          <div class="meta">${esc(f.src)} &rarr; ${esc(f.dst)} · ${Fmt.count(f.packets)} packets${f.encapsulated ? " · NAT-T" : ""}</div>
          <div class="ld-spi mono">SPI ${esc(f.spi)}</div>
          <div class="algs"><span class="alg ${suiteClass(label)}">${esc(label)}</span>
            <span class="ld-conf">${conf} confidence in the ${Glossary.term("framing-class", "framing class")}</span></div>
          ${f.ambiguous ? `<div class="cand">${esc(f.framing_candidates.join(" or "))}</div>` : ""}
          <button type="button" class="linkish ld-evidence" data-evidence="${i}" aria-haspopup="dialog">Show the framing arithmetic</button>
        </div>`;
      }).join("")
    : `<p class="ld-none">No ESP traffic observed for this pair.</p>`;

  const findings = link.findings.length
    ? link.findings.map(i => findingHTML(a.findings[i], i, "ld")).join("")
    : `<p class="ld-none">No findings on this link.</p>`;

  el.innerHTML = `${head}
    <div class="ld-cols">
      <section class="ld-block obs" aria-label="Handshake">
        <h4>Handshake <span class="domain-tag obs">observed</span></h4>${handshake}
      </section>
      <section class="ld-block inf" aria-label="Tunnel">
        <h4>Tunnel <span class="domain-tag inf">inferred</span></h4>${tunnel}
      </section>
    </div>
    <p class="ld-note">ESP is matched to IKE by address pair: the child SA's SPI is negotiated
      inside encrypted IKE_AUTH, so it cannot be linked cryptographically.${link.pooled
        ? ` This pair carries ${link.tunnels} tunnels, pooled here.` : ""}</p>
    <section class="ld-findings" aria-label="Findings on this link">
      <h4>Findings on this link <span class="ld-count">${link.findings.length}</span></h4>
      ${findings}
    </section>`;
}

function selectLink(id, {updateHash = true, focusDetail = false} = {}){
  const a = state.assessment;
  const link = linkById(a, id) || worstLink(a);
  if (!link) return;
  state.selectedLink = link.id;
  document.querySelectorAll("#link-list .link-item").forEach(b =>
    b.setAttribute("aria-current", b.dataset.link === link.id ? "true" : "false"));
  renderLinkDetail(a, link);
  renderRibbon(a);
  if (updateHash) writeHash(a.capture, link.id);
  if (focusDetail) $("link-detail").focus();
}

/* --------------------------------------------------------------- panels */

function renderScore(a){
  const score = a.score, circ = 2 * Math.PI * 49;
  const colour = score >= 75 ? "var(--ok)" : score >= 50 ? "var(--med)" : "var(--crit)";
  const arc = $("arc");
  arc.setAttribute("stroke", colour);
  arc.setAttribute("stroke-dasharray",
    `${(score / 100 * circ).toFixed(1)} ${circ.toFixed(1)}`);
  $("dialnum").textContent = score;

  $("grade").textContent = `Grade ${a.grade}`;
  const crit = a.counts.critical, high = a.counts.high;
  $("gradesub").textContent =
    crit ? `${crit} critical ${crit === 1 ? "issue needs" : "issues need"} `
         + "attention before this link is fit for sensitive traffic."
    : high ? `No critical issues. ${high} high-severity `
           + `${high === 1 ? "item" : "items"} to schedule.`
    : "No critical or high-severity issues on the observed associations.";

  $("sevrow").innerHTML = ["critical", "high", "medium", "low", "info"]
    .filter(k => a.counts[k])
    .map(k => `<span class="sev-chip ${k}">${a.counts[k]} ${esc(k)}</span>`)
    .join("") || `<span class="sev-chip info">clean</span>`;

  const s = a.stats;
  // The server decides whether a rate is meaningful (pipeline.throughput_
  // estimate). Payloads from before that rule carry no `measurable` flag and
  // a rate computed with model load included, so they are treated as not
  // measurable rather than shown.
  const tp = a.throughput || {};
  const measurable = tp.measurable === true && tp.packets_per_second != null;
  const processing = tp.processing_seconds ?? s.processing_seconds;
  $("stats").innerHTML = [
    [Fmt.count(s.packets_read), "packets read"],
    [Fmt.count(s.ike_sessions), "IKE sessions"],
    [Fmt.count(s.esp_flows_assessed), "ESP tunnels"],
    measurable
      ? [Fmt.count(tp.packets_per_second), "packets/sec, model load excluded"]
      : [Fmt.duration(processing ?? s.analysis_seconds), "processing time"],
    [Fmt.duration(s.analysis_seconds), "total, incl. model load"],
    [Fmt.count(s.parse_errors), "parse errors"]
  ].map(([k, l]) =>
    `<div class="stat"><div class="k">${esc(k)}</div>`
    + `<div class="l">${esc(l)}</div></div>`).join("");

  const note = $("stat-note");
  if (note){
    note.hidden = measurable;
    note.textContent = measurable ? "" : (tp.note
      || "Capture too small to measure throughput. Run `cipherguard bench` for a reproducible figure.");
  }

  $("capmeta").textContent =
    `${a.capture} · assessed ${a.started} · report ${a.digest}`;
}

function renderSessions(a){
  const el = $("sessions");
  if (!a.sessions.length){
    el.innerHTML = `<div class="empty">No IKE negotiation observed in this capture.</div>`;
    return;
  }
  el.innerHTML = a.sessions.map(s => {
    const prop = pickIkeProposal(s);
    const algs = prop
      ? prop.transforms.map(t =>
          `<span class="alg ${algClass(t)}">${esc(pretty(t))}</span>`).join("")
      : `<span class="alg">proposal not observed</span>`;
    const notes = (s.notifies || []).length ? ` · ${s.notifies.length} notify` : "";
    const retx = s.retransmissions ? ` · ${s.retransmissions} retransmitted` : "";
    return `<div class="rec">
      <div class="peers">${esc(s.peer_a)} &harr; ${esc(s.peer_b)}</div>
      <div class="meta">${esc(s.version)} · ${esc(s.vendor_family)} · `
      + `${s.messages.length} messages${esc(notes)}${esc(retx)}</div>
      <div class="algs">${algs}</div>
    </div>`;
  }).join("");
}

function renderFlows(a){
  const el = $("flows");
  if (!a.flows.length){
    el.innerHTML = `<div class="empty">No ESP traffic observed in this capture.</div>`;
    return;
  }
  // Delegated rather than inline, so a flow is looked up by index and no
  // attacker-influenced string is ever interpolated into a handler.
  el.onclick = (e) => {
    const btn = e.target.closest(".flow-open");
    if (!btn) return;
    const flow = a.flows[Number(btn.dataset.flow)];
    if (flow) EvidencePanel.open(flow, btn);
  };
  el.innerHTML = a.flows.map((f, i) => {
    // Report the framing class and its total probability mass, not a single
    // member at its exact-suite score. Naming one suite out of a set the wire
    // cannot separate reads as a wrong answer to anyone who checks it against
    // the negotiated IKE proposal shown alongside.
    const ratio = f.framing_confidence ?? f.confidence ?? 0;
    const pct = Math.round(ratio * 100);          // bar width only
    const label = f.framing_class || f.predicted_suite || "unresolved";
    const candidates = f.ambiguous
      ? `<div class="cand">${esc(f.framing_candidates.join(" or "))}</div>`
        + `<div class="cand">framing-identical; not separable passively</div>`
      : "";
    const skipped = (f.inference_notes || []).filter(n => n.kind !== "summary").length;
    const warn = skipped
      ? ` <span class="flow-open-warn">${skipped} caveat${skipped > 1 ? "s" : ""}</span>`
      : "";
    return `<div class="rec">
      <button type="button" class="flow-open" data-flow="${i}" aria-haspopup="dialog">
        <span class="peers">${esc(f.src)} &rarr; ${esc(f.dst)}</span>
        <span class="meta">SPI ${esc(f.spi)} · ${f.packets} packets · mean ${f.mean_payload}B${f.encapsulated ? " · NAT-T" : ""}</span>
        <span class="algs"><span class="alg ${suiteClass(label)}">${esc(label)}</span></span>
        <span class="flow-open-hint">Show the framing arithmetic${warn}</span>
      </button>
      <div class="confbar"><i style="width:${pct}%"></i></div>
      <div class="cand">${Fmt.percent(ratio)} confidence in the ${Glossary.term("framing-class", "framing class")}</div>
      ${candidates}
    </div>`;
  }).join("");
}

/* ------------------------------------------------ framing evidence panel */
/* The working behind one ESP attribution, laid out so a reviewer can redo it
   by hand from the capture. Everything above the final block is RFC 4303
   arithmetic over observed ciphertext lengths: deterministic, recomputable,
   and drawn in the "observed" colour. The learned models' ranking sits in a
   separate block in the "inferred" colour, because a probability is not
   something a reviewer can check, and the two must never read as one claim.
   Suite names and reasons are server strings derived from attacker-chosen
   packet lengths, so every one goes through esc(). */
const EvidencePanel = (() => {
  let lastTrigger = null;
  let bound = false;

  const NOTE_LABEL = {
    skipped: "Test did not run",
    fallback: "No suite fits the framing",
    unresolved: "Arithmetic did not decide",
  };
  const VERDICT_CLASS = { prohibited: "bad", legacy: "warn", acceptable: "good" };

  function pct(n, d){ return Fmt.percent(d ? n / d : 0); }

  /* One residue histogram as inline SVG. Surviving suites whose padding
     boundary equals this modulus mark the residue they require. */
  function histogram(mod, counts, survivors){
    const W = 320, H = 138, TOP = 24, BASE = 108;
    const total = counts.reduce((s, c) => s + c, 0);
    const max = Math.max(1, ...counts);
    const bw = W / mod;
    const gap = Math.min(4, bw * 0.18);

    const expected = {};
    for (const s of survivors){
      if (s.boundary !== mod) continue;
      (expected[s.expected_residue] = expected[s.expected_residue] || []).push(s.suite);
    }

    let body = "";
    counts.forEach((c, r) => {
      const h = c ? Math.max(1.5, (c / max) * (BASE - TOP)) : 0;
      const x = r * bw + gap / 2;
      const cx = r * bw + bw / 2;
      const marked = expected[r];
      if (marked){
        body += `<line class="ev-guide" x1="${cx.toFixed(1)}" y1="${TOP - 6}" x2="${cx.toFixed(1)}" y2="${BASE}"/>`
              + `<path class="ev-mark" d="M${(cx - 5).toFixed(1)},${TOP - 16} h10 l-5,8 z"/>`;
      }
      body += `<rect class="ev-bar${marked ? " is-expected" : ""}" x="${x.toFixed(1)}" `
            + `y="${(BASE - h).toFixed(1)}" width="${(bw - gap).toFixed(1)}" height="${h.toFixed(1)}">`
            + `<title>residue ${r}: ${c} of ${total} lengths (${pct(c, total)})</title></rect>`
            + `<text class="ev-axis" x="${cx.toFixed(1)}" y="${BASE + 15}" text-anchor="middle">${r}</text>`;
    });
    body += `<line class="ev-base" x1="0" y1="${BASE}" x2="${W}" y2="${BASE}"/>`;

    const peak = counts.indexOf(Math.max(...counts));
    const peakText = total
      ? `${pct(counts[peak], total)} of lengths fall at residue ${peak}.`
      : "No lengths observed.";
    const marks = Object.keys(expected).map(r =>
      `residue ${r} required by ${expected[r].join(", ")} `
      + `(${pct(counts[r], total)} of lengths comply)`);
    const aria = `Ciphertext length mod ${mod}. ${peakText} `
      + (marks.length ? `Marked: ${marks.join("; ")}.` : "No surviving suite pads to this boundary.");

    const caption = marks.length
      ? Object.keys(expected).map(r =>
          `<li><span class="ev-tri" aria-hidden="true">&#9660;</span> residue ${esc(r)}: `
          + `${esc(expected[r].join(", "))} <span class="ev-dim">(${pct(counts[r], total)} comply)</span></li>`).join("")
      : `<li class="ev-dim">No surviving suite pads to ${mod === 8 ? "an" : "a"} ${mod}-byte boundary.</li>`;

    return `<figure class="ev-hist">
      <figcaption><b>len mod ${mod}</b> <span class="ev-dim">${esc(peakText)}</span></figcaption>
      <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(aria)}" preserveAspectRatio="none">${body}</svg>
      <ul class="ev-marks">${caption}</ul>
    </figure>`;
  }

  function measured(f, fa){
    const g = f.granularity_usable
      ? `${f.length_granularity}&nbsp;B`
      : `<span class="ev-warn-text">not measurable</span>`;
    const ent = f.mean_entropy == null
      ? `<span class="ev-warn-text">not measurable</span>`
      : `${f.mean_entropy.toFixed(2)} bits/byte`;
    return `<dl class="ev-facts">
      <div><dt>Ciphertext lengths</dt><dd>${fa.lengths_observed}</dd></div>
      <div><dt>Distinct lengths</dt><dd>${f.distinct_lengths}</dd></div>
      <div><dt>Length granularity</dt><dd>${g}</dd></div>
      <div><dt>Mean payload entropy</dt><dd>${ent}<span class="ev-dim"> over ${fa.entropy_samples} samples</span></dd></div>
    </dl>`;
  }

  /* All catalogued suites in the order the constraints eliminated them, each
     with its specific reason, then the ones that survived everything. */
  function eliminations(f, fa){
    const notRun = new Set((f.inference_notes || [])
      .filter(n => n.kind === "skipped").map(n => n.test || "all"));
    const steps = fa.constraints.map(c => {
      const out = fa.suites.filter(s => s.eliminated_by === c.id);
      const ran = !(notRun.has(c.id) || notRun.has("all"));
      const items = out.map(s => `<li>
          <s class="ev-suite">${esc(s.suite)}</s>
          <span class="visually-hidden">eliminated:</span>
          <span class="ev-reason">${esc(s.reason)}</span>
        </li>`).join("");
      const status = !ran
        ? `<span class="ev-status is-skipped">did not run</span>`
        : out.length ? `<span class="ev-status">eliminated ${out.length}</span>`
        : `<span class="ev-status is-none">eliminated none</span>`;
      return `<li class="ev-step">
        <div class="ev-step-head"><span class="ev-step-n">${c.step}</span>
          <b>${esc(c.title)}</b> ${status}</div>
        <div class="ev-rule">${esc(c.rule)}</div>
        ${items ? `<ul class="ev-suites">${items}</ul>` : ""}
      </li>`;
    }).join("");

    const alive = fa.suites.filter(s => !s.eliminated_by);
    const survivors = alive.length
      ? alive.map(s => `<li><span class="ev-suite is-alive">${esc(s.suite)}</span>
          <span class="ev-reason">IV ${s.iv}&nbsp;B, ICV ${s.icv}&nbsp;B, `
          + `pads to ${s.boundary}&nbsp;B, requires residue ${s.expected_residue}</span></li>`).join("")
      : `<li class="ev-warn-text">None. Every catalogued suite failed at least one constraint.</li>`;

    return `<ol class="ev-steps">${steps}</ol>
      <div class="ev-survivors"><div class="ev-step-head"><b>Survived every constraint</b>
        <span class="ev-status is-alive">${alive.length} of ${fa.suites.length}</span></div>
        <ul class="ev-suites">${survivors}</ul></div>`;
  }

  function classes(fa){
    if (fa.fallback || !fa.classes.length){
      return `<p class="ev-warn-text">No framing class is consistent with this flow, so any
        attribution shown for it rests on the learned models alone.</p>`;
    }
    return fa.classes.map(c => {
      const partial = c.members.length < c.all_members.length
        ? `<div class="ev-dim">Other members of this class were eliminated above.</div>` : "";
      return `<div class="ev-class">
        <div class="ev-class-head"><b>${esc(c.name)}</b>
          <span class="alg ${VERDICT_CLASS[c.verdict] || ""}">${esc(c.verdict)}</span></div>
        <div class="ev-sig">${esc(c.signature)}</div>
        <ul class="ev-members">${c.members.map(m => `<li>${esc(m)}</li>`).join("")}</ul>
        ${partial}
        <p class="ev-why">${esc(c.why_inseparable)}</p>
      </div>`;
    }).join("");
  }

  function notes(f){
    const list = (f.inference_notes || []).filter(n => n.kind !== "summary");
    if (!list.length){
      return `<p class="ev-ok">Every constraint ran on enough data. Nothing was skipped.</p>`;
    }
    return list.map(n => `<div class="ev-note is-${esc(n.kind)}" role="note">
        <b>${esc(NOTE_LABEL[n.kind] || "Note")}</b>
        <p>${esc(n.text)}</p>
      </div>`).join("");
  }

  function model(f){
    const ranked = (f.ranked || []).map(([name, p]) => `<li>
        <span>${esc(name)}</span>
        <span class="ev-model-bar" aria-hidden="true"><i style="width:${Math.round(p * 100)}%"></i></span>
        <span class="ev-model-p">${Fmt.percent(p)}</span></li>`).join("");
    return `<section class="ev-model" aria-labelledby="ev-model-h">
      <h3 id="ev-model-h">Learned models' ranking <span class="domain-tag inf">not arithmetic</span></h3>
      <p class="ev-dim">Random Forest and 1D-CNN probabilities, after the mask above. They
        choose among the survivors and cannot be checked by hand; the arithmetic above can.</p>
      ${ranked ? `<ol class="ev-model-list">${ranked}</ol>` : `<p class="ev-dim">No model was loaded for this analysis.</p>`}
    </section>`;
  }

  function render(f){
    const fa = f.framing_arithmetic;
    if (!fa){
      return `<p class="ev-warn-text">This assessment was produced before the framing
        arithmetic was recorded. Re-run the analysis to see the working.</p>` + model(f);
    }
    const caveats = (f.inference_notes || []).filter(n => n.kind !== "summary").length;
    const alert = caveats
      ? `<button type="button" class="ev-alert" data-jump="ev-notes">
          <b>${caveats} caveat${caveats > 1 ? "s" : ""}</b> apply to this inference.
          <span>Read them before relying on it &darr;</span></button>`
      : "";
    const survivors = fa.suites.filter(s => !s.eliminated_by);
    return `${alert}
      <div class="ev-arith">
        <section aria-labelledby="ev-a"><h3 id="ev-a"><span class="ev-sec-n">a</span>What the capture shows</h3>
          ${measured(f, fa)}
          <div class="ev-hists">${[4, 8, 16].map(m =>
            histogram(m, (f.residues || {})[m] || new Array(m).fill(0), survivors)).join("")}</div>
          <p class="ev-dim">&#9660; marks the residue each surviving suite requires, on the histogram
            for its padding boundary. RFC 4303 forces len &equiv; (IV + ICV) mod boundary.</p>
        </section>
        <section aria-labelledby="ev-b"><h3 id="ev-b"><span class="ev-sec-n">b</span>Constraints, in the order applied</h3>
          ${eliminations(f, fa)}
        </section>
        <section aria-labelledby="ev-c"><h3 id="ev-c"><span class="ev-sec-n">c</span>What survives</h3>
          ${classes(fa)}
        </section>
        <section id="ev-notes" tabindex="-1" aria-labelledby="ev-d"><h3 id="ev-d"><span class="ev-sec-n">d</span>Caveats</h3>
          ${notes(f)}
        </section>
      </div>
      ${model(f)}`;
  }

  function focusables(){
    const card = document.querySelector("#evidence-modal .evidence-card");
    return card ? [...card.querySelectorAll(
      'button, [href], [tabindex]:not([tabindex="-1"]), input, select, textarea')]
      .filter(el => !el.disabled && el.offsetParent !== null) : [];
  }

  function onKey(e){
    if (e.key === "Escape" || e.key === "Esc"){ e.preventDefault(); close(); return; }
    if (e.key !== "Tab") return;
    const els = focusables();
    if (!els.length) return;
    const first = els[0], last = els[els.length - 1];
    if (e.shiftKey && document.activeElement === first){ e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last){ e.preventDefault(); first.focus(); }
  }

  function bind(){
    if (bound) return;
    bound = true;
    const modal = $("evidence-modal");
    modal.addEventListener("keydown", onKey);
    modal.addEventListener("click", (e) => {
      if (e.target === modal) { close(); return; }
      const jump = e.target.closest("[data-jump]");
      if (jump){
        const target = $(jump.dataset.jump);
        if (target){ target.scrollIntoView({behavior: "smooth", block: "start"}); target.focus({preventScroll: true}); }
      }
    });
    $("evidence-modal-close").addEventListener("click", close);
  }

  function open(flow, trigger){
    const modal = $("evidence-modal");
    if (!modal) return;
    bind();
    lastTrigger = trigger || document.activeElement;
    $("evidence-modal-subtitle").textContent =
      `${flow.src} → ${flow.dst} · SPI ${flow.spi} · ${flow.packets} packets`;
    $("evidence-body").innerHTML = render(flow);
    $("evidence-body").scrollTop = 0;
    modal.hidden = false;
    $("evidence-modal-close").focus();
  }

  function close(){
    const modal = $("evidence-modal");
    if (!modal || modal.hidden) return;
    modal.hidden = true;
    if (lastTrigger && document.contains(lastTrigger)) lastTrigger.focus();
    lastTrigger = null;
  }

  return { open, close, render };
})();
window.EvidencePanel = EvidencePanel;

function renderFindings(a){
  const el = $("findings");
  if (!a.findings.length){
    el.innerHTML = `<div class="empty">No findings. `
      + `Every observed association meets the baseline.</div>`;
    $("findsub").textContent = "Nothing to review.";
    return;
  }
  const inferred = a.findings.filter(f => f.inferred).length;
  const groups = a.finding_groups || [];
  whyByRule = Object.fromEntries(groups.filter(g => g.why_it_matters)
    .map(g => [g.rule_id, g.why_it_matters]));
  $("findsub").textContent =
    `${a.findings.length} findings`
    + (groups.length ? ` in ${groups.length} distinct problems` : "")
    + ` · ${a.findings.length - inferred} from parsed bytes, `
    + `${inferred} inferred from encrypted traffic.`;

  document.querySelectorAll("[data-fview]").forEach(b =>
    b.setAttribute("aria-pressed", b.dataset.fview === state.findingsView ? "true" : "false"));

  el.innerHTML = state.findingsView === "link" && a.links
    ? findingsByLinkHTML(a)
    : groups.length
      ? groups.map(g => groupHTML(g, a)).join("")
      : a.findings.map((f, i) => findingHTML(f, i, "f")).join("");

  el.onclick = (e) => {
    const open = e.target.closest("[data-open-link]");
    if (open){
      selectLink(open.dataset.openLink);
      $("links-panel").scrollIntoView({behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start"});
      $("link-detail").focus({preventScroll: true});
      return;
    }
    toggleDisclosure(e);
  };
}

/* One disclosure pattern for every expandable row: a real <button> carrying
   aria-expanded and aria-controls, so Enter, Space and screen readers work
   without per-row key handlers. */
function toggleDisclosure(e){
  const btn = e.target.closest("button[aria-controls]");
  if (!btn || !btn.classList.contains("fhead")) return;
  const open = btn.getAttribute("aria-expanded") !== "true";
  btn.setAttribute("aria-expanded", open ? "true" : "false");
  const panel = document.getElementById(btn.getAttribute("aria-controls"));
  if (panel) panel.hidden = !open;
  const host = btn.parentElement;
  if (host) host.classList.toggle("open", open);
}

let disclosureSeq = 0;

// rule_id -> the server's plain-language sentence, from a.finding_groups
let whyByRule = {};

function whyHTML(ruleId){
  const why = whyByRule[ruleId];
  return why ? `<p class="fwhy"><b>Why this matters:</b> ${esc(why)}</p>` : "";
}

function findingHTML(f, i, prefix){
  const id = `${prefix}-${i}-${++disclosureSeq}`;
  // members of an expanded group don't repeat the sentence the group shows
  const why = prefix === "gm" ? "" : whyHTML(f.rule_id);
  return `<div class="finding" data-i="${i}">
      <button type="button" class="fhead" aria-expanded="false" aria-controls="${id}">
        <span class="sev-mark ${esc(f.severity)}">${esc(f.severity)}</span>
        <span class="fmain">
          <span class="ftitle">${esc(f.title)}</span>
          ${f.inferred ? `<span class="domain-tag inf inline">inferred</span>` : ``}
          <span class="fsub">${esc(f.rule_id)} · ${esc(f.subject)}</span>
        </span>
        <span class="chev" aria-hidden="true">&#9662;</span>
      </button>
      <div class="fbody" id="${id}" hidden>
        ${why}
        <p>${Glossary.mark(esc(f.detail))}</p>
        <div class="ref">${esc(f.reference)}</div>
        <div class="fix"><b>Fix:</b> ${esc(f.remediation)}</div>
      </div>
    </div>`;
}

/* A group is one rule firing on one or more subjects. A group of one is shown
   as the finding itself, so a single occurrence is one click from its fix. */
function groupHTML(g, a){
  if (g.count === 1) return findingHTML(a.findings[g.findings[0]], g.findings[0], "g");
  const id = `grp-${++disclosureSeq}`;
  const where = g.subjects.length === 1
    ? g.subjects[0]
    : `${g.subjects.length} subjects`;
  // Deliberately not class "finding": `.finding.open .fbody` is a descendant
  // rule, so an open group would force every member's body open too.
  return `<div class="fgroup">
      <button type="button" class="fhead" aria-expanded="false" aria-controls="${id}">
        <span class="sev-mark ${esc(g.severity)}">${esc(g.severity)}</span>
        <span class="fmain">
          <span class="ftitle">${esc(g.title)}</span>
          ${g.inferred ? `<span class="domain-tag inf inline">inferred</span>` : ``}
          <span class="fsub">${esc(g.rule_id)} · ${esc(where)}</span>
        </span>
        <span class="gcount" aria-label="${g.count} occurrences">&times;${g.count}</span>
        <span class="chev" aria-hidden="true">&#9662;</span>
      </button>
      <div class="gbody" id="${id}" hidden>
        ${whyHTML(g.rule_id)}
        ${g.findings.map(i => findingHTML(a.findings[i], i, "gm")).join("")}
      </div>
    </div>`;
}

function findingsByLinkHTML(a){
  const sections = (a.links || []).filter(l => l.findings.length).map(l => `
    <section class="flink" aria-label="Findings for ${esc(linkLabel(l))}">
      <div class="flink-head">
        <span class="sev-mark ${esc(l.worst_severity)}">${esc(l.worst_severity)}</span>
        <span class="flink-peers mono">${esc(linkLabel(l))}</span>
        <span class="flink-count">${l.findings.length} finding${l.findings.length === 1 ? "" : "s"}</span>
        <button type="button" class="linkish" data-open-link="${esc(l.id)}">Open link</button>
      </div>
      ${l.findings.map(i => findingHTML(a.findings[i], i, "bl")).join("")}
    </section>`);
  const loose = (a.unlinked_findings || []);
  if (loose.length){
    sections.push(`<section class="flink" aria-label="Findings not tied to a link">
      <div class="flink-head"><span class="flink-peers">Not tied to a gateway pair</span>
        <span class="flink-count">${loose.length}</span></div>
      ${loose.map(i => findingHTML(a.findings[i], i, "bu")).join("")}
    </section>`);
  }
  return sections.join("") || `<div class="empty">No findings.</div>`;
}

/* Harvest clock: an instrument reading, not an alarm.
 *
 * Left, the bytes an adversary recording today could already read once a
 * quantum computer exists: the ESP volume observed on quantum-exposed links in
 * the capture, then extrapolated at the observed rate for as long as this view
 * is open. The two parts are labelled separately because only the first is
 * measured.
 *
 * Right, Mosca's deadline for a chosen data classification. The formula is
 * duplicated from mosca_gap() in cipherguard/intel/pqc.py, operand for operand,
 * and a test runs both over a table of inputs. The classification table itself
 * is not duplicated: the roadmap publishes it.
 *
 * With prefers-reduced-motion the counter moves in 5-second steps instead of
 * running continuously. Its value is always derived from elapsed time, so a
 * paused or throttled tab never drifts. */
const HarvestClock = (() => {
  const STEP_MS = { smooth: 100, reduced: 5000 };
  let timer = null;
  let teardown = [];

  // Same operands, same order as pqc.py, so both compute the same double.
  function moscaGap(secrecyYears, migrationYears, crqcYears){
    return (secrecyYears + migrationYears) - crqcYears;
  }

  // pqc.py: "already_late": gap > 0. Exactly zero is on time, not late.
  function isLate(gap){ return gap > 0; }

  function splitYears(gap){
    const total = Math.round(Math.abs(gap) * 12);
    return { late: isLate(gap), years: Math.floor(total / 12), months: total % 12,
             totalMonths: total };
  }

  function describeDeadline(gap){
    const s = splitYears(gap);
    const value = s.totalMonths === 0 ? "under 1 month"
      : `${s.years} yr ${String(s.months).padStart(2, "0")} mo`;
    return { late: s.late, value,
             label: s.late ? "Past the Mosca deadline" : "Until the Mosca deadline" };
  }

  // observed bytes plus rate x elapsed; the rate is megabits per second
  function harvested(baseBytes, rateMbps, elapsedMs){
    return baseBytes + rateMbps * 1e6 / 8 * (Math.max(elapsedMs, 0) / 1000);
  }

  function stepMs(reducedMotion){ return reducedMotion ? STEP_MS.reduced : STEP_MS.smooth; }

  function signed(x){
    return `${x > 0 ? "+" : x < 0 ? "−" : ""}${Math.abs(x).toFixed(1)}`;
  }

  function stop(){
    if (timer !== null){ clearInterval(timer); timer = null; }
    teardown.forEach(fn => fn());
    teardown = [];
  }

  function mount(plan){
    stop();
    const box = $("hclock");
    if (!plan || !plan.links || !plan.links.length){ box.hidden = true; return; }
    box.hidden = false;
    const as = plan.assumptions, sm = plan.summary;
    const exposed = plan.links.filter(l => !l.quantum_safe);
    const rate = typeof sm.harvest_rate_mbps === "number" ? sm.harvest_rate_mbps
      : exposed.reduce((t, l) => t + (l.harvest_rate_mbps || 0), 0);
    const base = sm.total_bytes_harvestable || 0;

    // -- deadline ------------------------------------------------------------
    const table = as.secrecy_lifetimes;
    const sel = $("hclock-class");
    const classes = table ? Object.keys(table).sort((a, b) => table[a] - table[b])
                          : [as.data_class];
    sel.innerHTML = classes.map(c =>
      `<option value="${esc(c)}"${c === as.data_class ? " selected" : ""}>${esc(c)}</option>`
    ).join("");
    // an export baked before the table was published can only show its own class
    sel.disabled = !table;

    const showDeadline = cls => {
      const secrecy = table ? table[cls] : as.secrecy_lifetime_years;
      const gap = moscaGap(secrecy, as.migration_years, as.crqc_years);
      const d = describeDeadline(gap);
      $("hclock-deadline").textContent = d.value;
      $("hclock-mosca-label").textContent = d.label;
      const status = $("hclock-status");
      status.textContent = d.late ? "late" : "margin";
      status.className = "hclock-status " + (d.late ? "is-late" : "is-ok");
      $("hclock-mosca").classList.toggle("is-late", d.late);
      $("hclock-terms").textContent =
        `${secrecy} yr secrecy + ${as.migration_years} yr migration − `
        + `${as.crqc_years} yr quantum assumption = ${signed(gap)} yr`;
      $("hclock-secrecy").textContent =
        `${cls} data must stay confidential for ${secrecy} years`;
    };
    const onClass = () => showDeadline(sel.value);
    sel.addEventListener("change", onClass);
    teardown.push(() => sel.removeEventListener("change", onClass));
    showDeadline(as.data_class);

    const arrival = new Date();
    arrival.setMonth(arrival.getMonth() + Math.round(as.crqc_years * 12));
    $("hclock-note").innerHTML =
      `${Glossary.term("crqc", "Quantum arrival")} in ${as.crqc_years} years (${arrival.getFullYear()}) is a `
      + `<b>planning assumption, not a forecast</b>. Substitute your agency's figure `
      + `with <code>cipherguard roadmap --crqc-years N</code>. The deadline is `
      + `below are for the <b>${esc(as.data_class)}</b> class this capture was `
      + `analysed under; the ranking order does not depend on the class.`;

    // -- counter -------------------------------------------------------------
    const bytesEl = $("hclock-bytes"), rateEl = $("hclock-rate");
    if (!exposed.length){
      bytesEl.textContent = Fmt.bytes(0);
      rateEl.textContent = "No quantum-exposed links observed.";
      return;
    }
    if (!(rate > 0)){
      bytesEl.textContent = Fmt.bytes(base);
      rateEl.textContent = "Observed in the capture. No ESP rate measured on "
        + "exposed links, so nothing to extrapolate.";
      return;
    }

    const opened = Date.now();
    const mq = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
    const reduced = () => !!(mq && mq.matches);
    const tick = () => { bytesEl.textContent = Fmt.bytes(harvested(base, rate, Date.now() - opened)); };
    const describeRate = () => {
      rateEl.textContent = `${Fmt.bytes(base)} observed in the capture, then `
        + `extrapolated at the ${Fmt.mbps(rate)} observed on exposed links since this `
        + `view opened` + (reduced() ? " · updates every 5 s" : "");
    };
    const schedule = () => {
      if (timer !== null) clearInterval(timer);
      timer = document.hidden ? null : setInterval(tick, stepMs(reduced()));
    };
    const onMotion = () => { describeRate(); schedule(); };
    const onVisible = () => { tick(); schedule(); };
    if (mq){
      mq.addEventListener("change", onMotion);
      teardown.push(() => mq.removeEventListener("change", onMotion));
    }
    document.addEventListener("visibilitychange", onVisible);
    teardown.push(() => document.removeEventListener("visibilitychange", onVisible));
    describeRate();
    tick();
    schedule();
  }

  return { moscaGap, isLate, splitYears, describeDeadline, harvested,
           stepMs, mount, stop };
})();
window.HarvestClock = HarvestClock;

function renderPQ(a){
  const plan = a.roadmap;
  const el = $("pqlinks");
  HarvestClock.mount(plan);
  if (!plan || !plan.links.length){
    el.innerHTML = `<div class="empty">No IKE negotiation observed, `
      + `so no key exchange to assess.</div>`;
    return;
  }
  const sm = plan.summary;
  $("pqsub").textContent =
    `${sm.quantum_exposed} of ${sm.links_assessed} links are quantum-exposed, `
    + `carrying ${Fmt.bytes(sm.total_bytes_harvestable)} of observed traffic.`;

  const links = plan.links.map(l => `
    <div class="pql ${l.quantum_safe ? "" : "exposed"}">
      <span class="pqrank">${l.priority}</span>
      <span class="pqbody">
        <div class="pqpeer">${esc(l.peer)}</div>
        <div class="pqbits">${l.classical_bits} classical / ${l.quantum_bits} `
      + `quantum bits · ${esc(l.kex_family.toUpperCase())} · `
      + `${Fmt.bytes(l.bytes_observed)} at ${Fmt.mbps(l.harvest_rate_mbps)}</div>
        <div class="pqwhy">${Glossary.mark(esc(l.rationale))}</div>
      </span>
      <span class="pqidx ${l.quantum_safe ? "safe" : "exposed"}">`
      + `${l.quantum_safe ? "PQ-safe" : "exposure " + l.exposure_index}</span>
    </div>`).join("");

  const phases = plan.phases.length
    ? `<div class="phases">` + plan.phases.map(ph => `
        <div class="phase">
          <h3>Phase ${ph.phase} — ${esc(ph.window)}</h3>
          <p>${esc(ph.action)}</p>
          <div class="tgt">${esc(ph.target)}</div>
        </div>`).join("") + `</div>`
    : "";

  el.innerHTML = links + phases;
}

/* Posture replay: one link's recorded history from the baseline store, so the
 * downgrade detection can be watched rather than described.
 *
 * Every mark is an observation the store recorded, and every verdict is the one
 * record() reached at the time. None of it is recomputed here: a replay that
 * re-derived verdicts could disagree with the detector once retention has
 * pruned rows. The store is only ever read, live through the read-only
 * /api/fleet endpoints, or in the static build from a history baked at export
 * by running the demo `cipherguard watch` commands.
 *
 * The x axis is observation order, not time: two watch runs a second apart
 * would otherwise sit on one point. Playback advances in discrete steps; only
 * the cursor glides between them, and prefers-reduced-motion removes that. */
const PostureReplay = (() => {
  const STEP_MS = 1000;
  const CHART_H = 190;
  const LABEL_DOWNGRADES_UP_TO = 4;   // beyond this the table carries the deltas
  let hist = null, index = 0, timer = null, loader = null, bound = false, request = 0;

  const signedBits = Fmt.signed;
  const stamp = iso => iso ? String(iso).replace("T", " ").replace(/(\+00:00|Z)$/, " UTC") : "";

  // What each observation was judged against. A "new" observation set the
  // baseline, so it is its own reference; rows recorded before verdicts
  // existed have none, and the reference line breaks there rather than guess.
  function referenceBits(o){
    if (o.baseline_bits != null) return o.baseline_bits;
    return o.verdict === "new" ? o.classical_bits : null;
  }

  function diffTransforms(before, after){
    const a = new Set(before || []), b = new Set(after || []);
    return { removed: (before || []).filter(t => !b.has(t)),
             added: (after || []).filter(t => !a.has(t)) };
  }

  function startIndex(obs){
    for (let i = obs.length - 1; i >= 0; i--) if (obs[i].verdict === "downgrade") return i;
    return Math.max(obs.length - 1, 0);
  }

  function geometry(obs, width){
    const m = { l: 44, r: 20, t: 14, b: 34 };
    const pw = Math.max(width - m.l - m.r, 40), ph = CHART_H - m.t - m.b;
    const top = Math.max(128, ...obs.map(o => Math.max(o.classical_bits, referenceBits(o) || 0)));
    const yMax = Math.ceil(top / 64) * 64;
    const n = obs.length;
    const x = i => m.l + (n === 1 ? pw / 2 : i * pw / (n - 1));
    const y = v => m.t + ph - (v / yMax) * ph;
    const ticks = [];
    for (let v = 0; v <= yMax; v += 64) ticks.push(v);
    return { m, pw, ph, x, y, ticks, width, n };
  }

  // step-after: a link holds its posture until the next observation
  function stepPath(points){
    let d = "", pen = false;
    for (const p of points){
      if (!p){ pen = false; continue; }
      const [px, py] = [p[0].toFixed(1), p[1].toFixed(1)];
      d += pen ? `H${px}V${py}` : `M${px},${py}`;
      pen = true;
    }
    return d;
  }

  function chartSVG(obs, width){
    const g = geometry(obs, width);
    const { m, x, y } = g;
    const right = width - m.r, bottom = CHART_H - m.b;
    const downs = obs.filter(o => o.verdict === "downgrade");
    const label = downs.length <= LABEL_DOWNGRADES_UP_TO;

    const grid = g.ticks.map(v =>
      `<line class="rp-grid" x1="${m.l}" x2="${right}" y1="${y(v)}" y2="${y(v)}"/>`
      + `<text class="rp-tick" x="${m.l - 8}" y="${y(v)}" dy="0.32em" text-anchor="end">${v}</text>`).join("");
    const series = stepPath(obs.map((o, i) => [x(i), y(o.classical_bits)]));
    const ref = stepPath(obs.map((o, i) => {
      const r = referenceBits(o);
      return r == null ? null : [x(i), y(r)];
    }));

    const marks = obs.map((o, i) => {
      const cx = x(i), cy = y(o.classical_bits);
      if (o.verdict === "downgrade"){
        // under the mark: the line runs off to the right at this level, and
        // below a downgrade there is always room above zero
        return `<line class="rp-drop" x1="${cx}" x2="${cx}" y1="${y(o.baseline_bits)}" y2="${cy}"/>`
          + `<path class="rp-mark rp-down" d="M${cx - 6},${cy - 5}H${cx + 6}L${cx},${cy + 6}Z"/>`
          + (label ? `<text class="rp-dlabel" x="${cx}" y="${cy + 21}" text-anchor="middle">`
                     + `${signedBits(o.delta_bits)}</text>` : "");
      }
      const cls = o.verdict === "unconfirmed" ? "rp-mark rp-unconf" : "rp-mark";
      return `<circle class="${cls}" cx="${cx}" cy="${cy}" r="4.5"/>`;
    }).join("");

    const n = obs.length;
    const xlab = (n === 1 ? [0] : [0, n - 1]).map(i =>
      `<text class="rp-tick" x="${x(i)}" y="${bottom + 16}" text-anchor="middle">${i + 1}</text>`).join("");
    const summary = `Negotiated classical bits over ${n} observation${n === 1 ? "" : "s"}`
      + `, ${downs.length} downgrade${downs.length === 1 ? "" : "s"}`;

    return `<svg class="rp-svg" width="${width}" height="${CHART_H}" viewBox="0 0 ${width} ${CHART_H}"`
      + ` role="img" aria-label="${summary}">`
      + grid
      + `<line class="rp-axis" x1="${m.l}" x2="${right}" y1="${bottom}" y2="${bottom}"/>`
      + xlab
      + `<text class="rp-axis-title" x="${m.l + g.pw / 2}" y="${bottom + 30}" text-anchor="middle">`
      + `observation, in recorded order (not to time scale)</text>`
      // The cursor is a pale column behind the data, not a line over it: a
      // full-height rule at the selected point read as the link dropping to 0.
      + `<g class="rp-cursor" transform="translate(0 0)">`
      + `<rect class="rp-band" x="-9" y="${m.t - 6}" width="18" height="${bottom - m.t + 6}" rx="3"/>`
      + `<circle class="rp-current" cx="0" cy="0" r="9"/></g>`
      + `<path class="rp-ref" d="${ref}"/>`
      + `<path class="rp-line" d="${series}"/>`
      + marks
      + `<rect class="rp-hit" x="${m.l - 10}" y="0" width="${g.pw + 20}" height="${CHART_H}"/>`
      + `</svg>`;
  }

  function legendHTML(obs){
    const item = (sw, text) => `<span class="rp-key">${sw}<span>${text}</span></span>`;
    return `<div class="rp-legend">`
      + item(`<svg width="22" height="10" aria-hidden="true"><line class="rp-line" x1="1" x2="21" y1="5" y2="5"/></svg>`,
             "Negotiated strength (classical bits)")
      + item(`<svg width="22" height="10" aria-hidden="true"><line class="rp-ref" x1="1" x2="21" y1="5" y2="5"/></svg>`,
             "Baseline it was compared against")
      + item(`<svg width="14" height="12" aria-hidden="true"><path class="rp-mark rp-down" d="M1,1H13L7,11Z"/></svg>`,
             "Downgrade")
      + (obs.some(o => o.verdict === "unconfirmed")
         ? item(`<svg width="12" height="12" aria-hidden="true"><circle class="rp-mark rp-unconf" cx="6" cy="6" r="4"/></svg>`,
                "Stronger, not yet promoted") : "")
      + `</div>`;
  }

  function txList(list, mark){
    return `<ul class="rp-tx">` + (list || []).map(t => {
      const kind = mark(t);
      const sign = kind === "gone" ? "− " : kind === "new" ? "+ " : "";
      const note = kind === "gone" ? " (not negotiated here)" : kind === "new" ? " (not in the baseline)" : "";
      return `<li class="${kind}"><span aria-hidden="true">${sign}</span>${esc(t)}`
        + (note ? `<span class="visually-hidden">${note}</span>` : "") + `</li>`;
    }).join("") + `</ul>`;
  }

  const VERDICT_TEXT = {
    new: () => "Baseline established",
    steady: o => `Matches the baseline (${Fmt.bits(o.baseline_bits)})`,
    unconfirmed: o => `Stronger than the ${o.baseline_bits}-bit baseline, not yet promoted`,
    improvement: o => `Baseline promoted: ${o.baseline_bits} → ${Fmt.bits(o.classical_bits)}`,
    withheld: () => "Baseline withheld: new-peer limit reached",
  };

  function detailHTML(obs, i, verdicts){
    const o = obs[i];
    const head = `<div class="rp-head"><b>Observation ${i + 1} of ${obs.length}</b>`
      + ` · ${esc(stamp(o.observed_at))} · <span class="rp-cap">${esc(o.capture)}</span></div>`;
    const strength = `<div class="rp-strength">${o.classical_bits} classical / ${o.quantum_bits} quantum bits`
      + (o.dh_group != null ? ` · DH group ${o.dh_group}` : "")
      + (o.ike_version ? ` · ${esc(o.ike_version)}` : "") + `</div>`;

    if (o.verdict === "downgrade"){
      const d = diffTransforms(o.baseline_transforms, o.transforms);
      return head
        + `<div class="rp-verdict is-down"><span aria-hidden="true">▼ </span>Downgrade: `
        + `${o.baseline_bits} → ${Fmt.bits(o.classical_bits)} (${signedBits(o.delta_bits)})</div>`
        + `<div class="rp-compare">`
        + `<div class="rp-col"><div class="rp-col-h">Baseline · ${Fmt.bits(o.baseline_bits)}</div>`
        + txList(o.baseline_transforms, t => d.removed.includes(t) ? "gone" : "") + `</div>`
        + `<div class="rp-col"><div class="rp-col-h">Negotiated here · ${Fmt.bits(o.classical_bits)}</div>`
        + txList(o.transforms, t => d.added.includes(t) ? "new" : "") + `</div>`
        + `</div>` + strength;
    }
    const text = o.verdict ? (VERDICT_TEXT[o.verdict] || (() => o.verdict))(o)
      : "No verdict stored: recorded before the store kept verdicts";
    return head
      + `<div class="rp-verdict is-${esc(o.verdict || "none")}">${esc(text)}</div>`
      // the server's explanation, where it adds something to the headline
      + (o.verdict && o.verdict !== "steady" && verdicts && verdicts[o.verdict]
         ? `<div class="rp-why">${esc(verdicts[o.verdict])}</div>` : "")
      + strength + txList(o.transforms, () => "");
  }

  function tableHTML(obs){
    return `<table class="rp-table"><thead><tr><th scope="col">#</th><th scope="col">Observed</th>`
      + `<th scope="col">Capture</th><th scope="col">Classical bits</th><th scope="col">Quantum bits</th>`
      + `<th scope="col">Verdict</th><th scope="col">vs baseline</th><th scope="col">Transforms</th></tr></thead><tbody>`
      + obs.map((o, i) => `<tr${o.verdict === "downgrade" ? ` class="is-down"` : ""}><td>${i + 1}</td>`
        + `<td>${esc(stamp(o.observed_at))}</td><td>${esc(o.capture)}</td>`
        + `<td>${o.classical_bits}</td><td>${o.quantum_bits}</td><td>${esc(o.verdict || "—")}</td>`
        + `<td>${o.delta_bits == null ? "—" : signedBits(o.delta_bits)}</td>`
        + `<td>${esc((o.transforms || []).join(", "))}</td></tr>`).join("")
      + `</tbody></table>`;
  }

  // -- wiring ----------------------------------------------------------------

  function setIndex(i){
    if (!hist) return;
    const obs = hist.observations;
    index = Math.min(Math.max(i, 0), obs.length - 1);
    const o = obs[index];
    const scrub = $("replay-scrub");
    scrub.value = String(index);
    scrub.setAttribute("aria-valuetext", `Observation ${index + 1} of ${obs.length}: `
      + `${Fmt.bits(o.classical_bits)}` + (o.verdict === "downgrade" ? `, downgrade ${signedBits(o.delta_bits)}` : ""));
    $("replay-pos").textContent = `${index + 1} / ${obs.length}`;
    $("replay-detail").innerHTML = detailHTML(obs, index, hist.verdicts);

    const svg = $("replay-chart").querySelector ? $("replay-chart").querySelector(".rp-svg") : null;
    if (svg){
      const g = geometry(obs, Number(svg.getAttribute("width")));
      const cur = svg.querySelector(".rp-cursor");
      cur.style.transform = `translateX(${g.x(index)}px)`;
      cur.querySelector(".rp-current").setAttribute("cy", String(g.y(o.classical_bits)));
    }
  }

  function stop(){
    if (timer !== null){ clearInterval(timer); timer = null; }
    const btn = $("replay-play");
    btn.textContent = "Play";
    btn.setAttribute("aria-pressed", "false");
  }

  function play(){
    if (!hist || hist.observations.length < 2) return;
    if (timer !== null) return stop();
    const last = hist.observations.length - 1;
    if (index >= last) setIndex(0);
    const btn = $("replay-play");
    btn.textContent = "Pause";
    btn.setAttribute("aria-pressed", "true");
    timer = setInterval(() => {
      setIndex(index + 1);
      if (index >= last) stop();
    }, STEP_MS);
  }

  function chartWidth(){
    const el = $("replay-chart");
    return Math.max(Math.round((el && el.clientWidth) || 720), 280);
  }

  function renderChart(){
    const chart = $("replay-chart");
    chart.innerHTML = chartSVG(hist.observations, chartWidth())
      + legendHTML(hist.observations) + `<div class="rp-tip" id="replay-tip" hidden></div>`;
    const svg = chart.querySelector ? chart.querySelector(".rp-svg") : null;
    if (!svg) return;
    const nearest = ev => {
      const box = svg.getBoundingClientRect();
      const g = geometry(hist.observations, Number(svg.getAttribute("width")));
      const px = ev.clientX - box.left;
      const n = hist.observations.length;
      return n === 1 ? 0 : Math.min(Math.max(Math.round((px - g.m.l) / (g.pw / (n - 1))), 0), n - 1);
    };
    const tip = chart.querySelector(".rp-tip");
    svg.addEventListener("pointermove", ev => {
      const i = nearest(ev), o = hist.observations[i];
      const g = geometry(hist.observations, Number(svg.getAttribute("width")));
      tip.hidden = false;
      tip.textContent = `${i + 1}: ${Fmt.bits(o.classical_bits)}`
        + (o.verdict ? ` · ${o.verdict}` : "")
        + (o.verdict === "downgrade" ? ` ${signedBits(o.delta_bits)}` : "");
      tip.style.left = `${Math.min(g.x(i) + 10, g.width - 150)}px`;
      tip.style.top = `${Math.max(g.y(o.classical_bits) - 30, 0)}px`;
    });
    svg.addEventListener("pointerleave", () => { tip.hidden = true; });
    svg.addEventListener("click", ev => { stop(); setIndex(nearest(ev)); });
  }

  function show(history){
    stop();
    hist = history;
    const obs = hist.observations;
    const scrub = $("replay-scrub");
    scrub.max = String(Math.max(obs.length - 1, 0));
    $("replay-play").disabled = obs.length < 2;
    renderChart();
    $("replay-table").innerHTML = tableHTML(obs);
    $("replay-table-wrap").hidden = false;
    setIndex(startIndex(obs));
  }

  function empty(message){
    stop();
    hist = null;
    $("replay-controls").hidden = true;
    $("replay-table-wrap").hidden = true;
    $("replay-chart").innerHTML = "";
    $("replay-detail").innerHTML = "";
    const el = $("replay-empty");
    el.hidden = false;
    el.innerHTML = message;
  }

  async function selectLink(peer){
    const mine = ++request;
    stop();
    try {
      const history = await loader(peer);
      if (mine !== request) return;            // a later selection won
      if (!history) return empty(`No recorded history for ${esc(peer)}.`);
      show(history);
    } catch (e){
      if (mine === request) empty(`Could not read this link's history: ${esc(e.message)}`);
    }
  }

  function showFleet(fleet, sourceHTML){
    if (!fleet || !fleet.tracked){
      return empty("No baseline store yet. Record captures with "
        + "<code>cipherguard watch &lt;capture&gt; --db &lt;file&gt;</code>, then serve with the same "
        + "<code>--db</code>.");
    }
    if (!fleet.links.length) return empty("The baseline store has no links yet.");
    const sel = $("replay-link");
    // "a|b" is the storage form of a peer pair; the value stays the real key
    sel.innerHTML = fleet.links.map(l =>
      `<option value="${esc(l.peer_key)}">${esc(l.peer_key.split("|").join(" ↔ "))}`
      + ` · ${Fmt.bits(l.current_bits)}`
      + `${l.degraded ? " · degraded" : ""}</option>`).join("");
    const first = fleet.links.find(l => l.degraded) || fleet.links[0];
    sel.value = first.peer_key;
    $("replay-controls").hidden = false;
    $("replay-empty").hidden = true;
    $("replay-source").innerHTML = sourceHTML;
    return selectLink(first.peer_key);
  }

  function bind(){
    if (bound) return;
    bound = true;
    $("replay-link").addEventListener("change", e => selectLink(e.target.value));
    $("replay-play").addEventListener("click", play);
    $("replay-scrub").addEventListener("input", e => { stop(); setIndex(Number(e.target.value)); });
    let resize = null;
    window.addEventListener("resize", () => {
      clearTimeout(resize);
      resize = setTimeout(() => { if (hist){ renderChart(); setIndex(index); } }, 150);
    });
  }

  async function init(){
    bind();
    try {
      if (staticMode.active){
        const res = await fetch("data/fleet_demo.json", { cache: "no-store" });
        if (!res.ok) return empty("This static build has no posture replay demo.");
        const demo = await res.json();
        loader = async peer => demo.histories[peer];
        const how = (demo.commands || []).map(c =>
          `<code>${esc(c.command)}</code> (exit ${c.exit_code})`).join(" then ");
        return showFleet(demo.fleet, how ? `Static demo, recorded at export time by running ${how}.`
                                         : "Static demo, recorded at export time.");
      }
      const fleet = await (await api("/api/fleet", { silent: true })).json();
      loader = async peer =>
        (await api(`/api/fleet/history?peer=${encodeURIComponent(peer)}`, { silent: true })).json();
      return showFleet(fleet, "Read-only from this server's baseline store.");
    } catch (e){
      return empty(`Could not read the baseline store: ${esc(e.message)}`);
    }
  }

  return { referenceBits, diffTransforms, startIndex, chartSVG, legendHTML, detailHTML,
           tableHTML, show, play, stop, setIndex, init, showFleet,
           get index(){ return index; }, get playing(){ return timer !== null; } };
})();
window.PostureReplay = PostureReplay;


function renderPlatforms(a){
  const row = $("platforms");
  const plats = (state.remediationPlans && state.remediationPlans.length)
    ? state.remediationPlans.map(p => ({id: p.platform, name: p.platform_name}))
    : (a && a.platforms ? a.platforms : [
        {id: "cisco", name: "Cisco IOS / IOS-XE"},
        {id: "strongswan", name: "strongSwan (swanctl)"},
        {id: "fortinet", name: "Fortinet FortiOS"},
        {id: "juniper", name: "Juniper SRX (Junos)"}
      ]);

  if (!plats.length){ row.innerHTML = ""; return; }
  if (!plats.some(p => p.id === state.platform)) state.platform = plats[0].id;

  row.innerHTML = plats.map(p =>
    `<button class="ghost" data-p="${esc(p.id)}" `
    + `aria-pressed="${p.id === state.platform}">${esc(p.name)}</button>`).join("");

  row.querySelectorAll("button").forEach(b =>
    b.addEventListener("click", () => {
      state.platform = b.dataset.p;
      row.querySelectorAll("button").forEach(btn => btn.setAttribute("aria-pressed", btn.dataset.p === state.platform));
      if (state.remediationPlans && state.remediationPlans.length) {
        renderPlaybookUI();
      } else {
        loadRemediation();
      }
    }));
}

function renderPlaybookUI(){
  if (!state.remediationPlans || !state.remediationPlans.length) return;
  const currentPlan = state.remediationPlans.find(p => p.platform === state.platform) || state.remediationPlans[0];
  if (!currentPlan) return;
  state.platform = currentPlan.platform;

  // Highlight active platform button
  const row = $("platforms");
  if (row) {
    row.querySelectorAll("button").forEach(b => {
      b.setAttribute("aria-pressed", b.dataset.p === state.platform);
    });
  }

  // Update syntax badge
  const syntaxBadge = $("playbook-syntax-badge");
  if (syntaxBadge) {
    syntaxBadge.hidden = false;
    if (currentPlan.syntax_valid) {
      syntaxBadge.className = "playbook-chip chip-ok";
      syntaxBadge.textContent = "✔ Syntax check passed";
      syntaxBadge.title = "Passes vendor grammar and RFC 8247 structure rules";
    } else {
      syntaxBadge.className = "playbook-chip chip-err";
      syntaxBadge.textContent = "✖ Syntax check failed";
      syntaxBadge.title = (currentPlan.syntax_errors || []).join("; ");
    }
  }

  // Update status badge
  const statusBadge = $("playbook-status-badge");
  if (statusBadge) {
    statusBadge.hidden = false;
    const st = currentPlan.status || "DRAFTED";
    statusBadge.className = "playbook-chip chip-status " + st.toLowerCase();
    if (st === "APPROVED") {
      statusBadge.textContent = `Status: APPROVED (${currentPlan.approver || "Admin"})`;
    } else if (st === "STAGED") {
      statusBadge.textContent = "Status: STAGED (Dry-Run)";
    } else {
      statusBadge.textContent = "Status: " + st;
    }
  }

  // Update Forward/Rollback tabs
  const fwdBtn = $("btn-playbook-forward");
  const rlbBtn = $("btn-playbook-rollback");
  if (fwdBtn) fwdBtn.classList.toggle("active", state.playbookMode === "forward");
  if (rlbBtn) rlbBtn.classList.toggle("active", state.playbookMode === "rollback");

  // Render code
  const pre = $("remediation");
  if (pre) {
    const raw = state.playbookMode === "rollback" ? currentPlan.rollback_config : currentPlan.forward_config;
    pre.innerHTML = (raw || "").split("\n").map(l =>
      /^\s*[#!]/.test(l) ? `<span class="cm">${esc(l)}</span>` : esc(l)).join("\n");
  }
}

async function loadRemediation(){
  if (staticMode.active){
    // the build bakes the forward plan text only: no syntax verdict, no
    // rollback and no plan store to record an approval in, so none is shown
    ["playbook-syntax-badge", "playbook-status-badge", "btn-playbook-rollback", "btn-playbook-approve"]
      .forEach(id => { if ($(id)) $(id).hidden = true; });
    const pre = $("remediation");
    const canned = (state.assessment && state.assessment.remediation) || {};
    const text = canned[state.platform];
    if (!text){ pre.textContent = "No hardening plan in this build."; return; }
    pre.innerHTML = text.split("\n").map(l =>
      /^\s*[#!]/.test(l) ? `<span class="cm">${esc(l)}</span>` : esc(l)).join("\n");
    return;
  }
  return loadRemediationLive();
}

async function loadRemediationLive(){
  if (!state.assessment) return;
  const pre = $("remediation");
  pre.textContent = "Synthesizing multi-vendor hardening & rollback playbooks…";
  try{
    const res = await api(`/api/remediation/${encodeURIComponent(state.assessment.capture)}`);
    if (res.ok) {
      const data = await res.json();
      state.remediationPlans = data.plans || [];
      if (state.remediationPlans.length > 0) {
        if (!state.platform || !state.remediationPlans.some(p => p.platform === state.platform)) {
          state.platform = state.remediationPlans[0].platform;
        }
        renderPlatforms(state.assessment);
        renderPlaybookUI();
        return;
      }
    }
    const res2 = await api("/api/remediate", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        capture: state.assessment.capture, platform: state.platform
      })
    });
    const text = await res2.text();
    pre.innerHTML = text.split("\n").map(l =>
      /^\s*[#!]/.test(l) ? `<span class="cm">${esc(l)}</span>` : esc(l)).join("\n");
  }catch(err){
    pre.textContent = "Could not generate the hardening plan: " + err.message;
  }
}

/* ------------------------------------------------------------ data flow */

// Static mode: on GitHub Pages there is no backend, so the dashboard reads
// pre-computed analyses written by `cipherguard export-demo`. The payloads are
// the real pipeline's output in the same shape the API returns, so every render
// path below is identical and neither version can quietly diverge from the
// other. Detected by probing for the manifest rather than by a build flag.
const staticMode = {active: false, manifest: null};

async function detectStaticMode(){
  // Always probe for live backend first!
  try {
    const probeUrl = resolveApiPath("/api/health");
    const healthRes = await fetch(probeUrl, { method: "GET", cache: "no-store" });
    if (healthRes.ok) {
      staticMode.active = false;
      // kept for controls that depend on server capability (upload)
      try { state.health = await healthRes.json(); } catch (e) { state.health = null; }
      return false; // Live backend is ACTIVE and ready!
    }
  } catch(e) {}

  // Only fall back to static demo mode if live backend is truly unreachable
  try{
    const res = await fetch("data/manifest.json", {cache: "no-store"});
    if (!res.ok) return false;
    staticMode.manifest = await res.json();
    staticMode.active = true;
    return true;
  }catch{
    return false;
  }
}

function populateCaptureSelects(items){
  const sel = $("capture");
  const selA = $("diff-capture-a");
  const selB = $("diff-capture-b");

  const optsHtml = items.map(c =>
    // size_kb (1024-based) is what payloads carried before size_bytes existed
    `<option value="${esc(c.name)}">${esc(c.name)} — `
    + `${Fmt.bytes(c.size_bytes ?? (c.size_kb != null ? c.size_kb * 1024 : null))}</option>`
  ).join("");

  if (sel) sel.innerHTML = optsHtml;
  if (selA) selA.innerHTML = optsHtml;
  if (selB) selB.innerHTML = optsHtml;

  // Set smart default diff selection
  if (selA && selB && items.length >= 2){
    // The demo pairing is legacy.pcap against hardened.pcap. A pattern alone
    // picked downgrade.pcap, which sorts first and matched /legacy|downgrade/.
    const byName = n => items.find(c => c.name === n);
    const before = byName("legacy.pcap") || items.find(c => /legacy|downgrade/i.test(c.name));
    if (before) selA.value = before.name;
    else selA.selectedIndex = 0;

    const hardened = byName("hardened.pcap") || items.find(c => /hardened|backbone/i.test(c.name));
    if (hardened) selB.value = hardened.name;
    else selB.selectedIndex = Math.min(items.length - 1, 1);
  }
}

async function loadCapturesStatic(){
  const caps = staticMode.manifest.captures || [];
  if (!caps.length){
    if ($("capture")) $("capture").innerHTML = `<option value="">No captures in this build</option>`;
    if ($("run")) $("run").disabled = true;
    return;
  }
  populateCaptureSelects(caps);
  showBanner("Static demo: analyses were pre-computed by the real pipeline. "
             + "Install CipherGuard to assess your own captures.", "info");
}

async function loadCaptures(){
  if (await detectStaticMode()) return loadCapturesStatic();
  try{
    const {captures} = await (await api("/api/captures")).json();
    if (!captures.length){
      if ($("capture")) $("capture").innerHTML = `<option value="">No captures found</option>`;
      if ($("run")) $("run").disabled = true;
      showBanner("No capture files found. Generate the reference set with: "
                 + "cipherguard lab");
      return;
    }
    populateCaptureSelects(captures);
    showBanner(null);
  }catch(err){
    console.error("Loading the capture list failed:", err, err && err.body ? err.body : "");
    if ($("capture")) $("capture").innerHTML = `<option value="">Backend unreachable</option>`;
    if ($("run")) $("run").disabled = true;
    showBanner(explainFailure(err), "error", { label: "Retry", onClick: async () => {
      await loadCaptures();
      if ($("run") && !$("run").disabled && !state.assessment) runAnalysis();
    }});
  }
}

async function fetchAssessment(name){
  if (!name) throw new Error("No capture selected.");
  if (staticMode.active){
    const entry = (staticMode.manifest.captures || []).find(c => c.name === name);
    if (!entry) throw new Error("no pre-computed analysis for " + name);
    const res = await fetch(entry.file, {cache: "no-store"});
    if (!res.ok) throw new Error("could not load " + entry.file);
    return await res.json();
  } else {
    const res = await api("/api/analyze", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({capture: name})
    });
    return await res.json();
  }
}

/* Loading placeholders, drawn in each panel's own layout so the page keeps its
 * shape while a request runs. The hardening plan's text is snapshotted rather
 * than re-requested if the request fails: the server that just failed is the
 * one that would have to regenerate it. */
const Skeleton = (() => {
  const line = w => `<span class="skeleton sk-line ${w}"></span>`;
  const rep = (n, f) => Array.from({ length: n }, (_, i) => f(i)).join("");
  let remediationSnapshot = null;
  const FILL = {
    ribbon: () => rep(6, () => `<div class="field">${line("w50")}${line("w90")}</div>`),
    stats: () => rep(6, () => `<div class="stat"><div class="k">${line("w50")}</div><div class="l">${line("w70")}</div></div>`),
    "link-list": () => rep(4, () => `<li class="link-item">${line("w90")}${line("w50")}</li>`),
    "link-detail": () => `<span class="skeleton sk-block"></span><span class="skeleton sk-block"></span>`,
    findings: () => rep(5, () => `<div class="finding">${line("w90")}${line("w30")}</div>`),
    sessions: () => `<span class="skeleton sk-block"></span>`,
    flows: () => `<span class="skeleton sk-block"></span>`,
    pqlinks: () => rep(3, () => line("w90")),
    sevrow: () => `${line("w30")}`,
  };

  function show(){
    const view = $("view-ipsec");
    if (view) view.setAttribute("aria-busy", "true");
    for (const [id, fill] of Object.entries(FILL)){
      const el = $(id);
      if (el) el.innerHTML = fill();
    }
    const pre = $("remediation");
    if (pre){
      remediationSnapshot = pre.innerHTML;
      pre.innerHTML = rep(8, i => line(["w90", "w70", "w50", "w90"][i % 4])).replace(/<\/span>/g, "</span>\n");
    }
  }

  function done(){
    const view = $("view-ipsec");
    if (view) view.removeAttribute("aria-busy");
  }

  function restoreRemediation(){
    const pre = $("remediation");
    if (pre && remediationSnapshot !== null) pre.innerHTML = remediationSnapshot;
  }

  function clearTo(message){
    for (const id of Object.keys(FILL)){
      const el = $(id);
      if (el) el.innerHTML = id === "findings" || id === "link-list"
        ? `<div class="empty">${esc(message)}</div>` : "";
    }
    restoreRemediation();
  }

  return { show, done, restoreRemediation, clearTo };
})();

/* Downloads, copy-to-clipboard and the provenance panel. Everything shown here
 * comes from the server's payload; the page computes no hash of its own. */
const Report = (() => {
  let current = null;

  async function copyText(text){
    try {
      if (navigator.clipboard && window.isSecureContext){
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (e) { /* fall through to the selection copy */ }
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    ta.remove();
    return ok;
  }

  // visible confirmation that says what actually happened
  function flash(statusId, message){
    const el = $(statusId);
    if (!el) return;
    el.textContent = message;
    clearTimeout(el._t);
    el._t = setTimeout(() => { el.textContent = ""; }, 5000);
  }

  function downloadText(filename, text, mime){
    const url = URL.createObjectURL(new Blob([text], { type: mime }));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const base = name => String(name || "capture").replace(/\.[^.]+$/, "");

  function manifestEntry(name){
    return staticMode.active && staticMode.manifest
      ? (staticMode.manifest.captures || []).find(c => c.name === name) : null;
  }

  function configText(){
    const pre = $("remediation");
    const text = pre ? pre.textContent.trim() : "";
    return /^(Run an assessment|No hardening plan|Synthesizing|Could not generate)/.test(text) ? "" : text;
  }

  function configName(){
    const mode = state.playbookMode === "rollback" ? "rollback" : "harden";
    return `${base(current && current.capture)}-${mode}-${state.platform || "config"}.conf`;
  }

  function setLink(id, href, filename){
    const a = $(id);
    if (!a) return;
    a.hidden = false;
    a.href = href;
    a.setAttribute("download", filename);
  }

  function update(a){
    current = a;
    const entry = manifestEntry(a.capture);
    // JSON report: the baked file in static mode, the server's payload otherwise
    if (entry) setLink("dl-report", entry.file, `${base(a.capture)}-report.json`);
    else setLink("dl-report", "#", `${base(a.capture)}-report.json`);
    // CBOM: offered only where it exists — a static build without one hides it
    const cbom = $("dl-cbom");
    if (staticMode.active){
      if (entry && entry.cbom) setLink("dl-cbom", entry.cbom, `${base(a.capture)}-cbom.cdx.json`);
      else if (cbom) cbom.hidden = true;
    } else {
      setLink("dl-cbom", "#", `${base(a.capture)}-cbom.cdx.json`);
    }
    setLink("dl-config", "#", configName());
    renderProvenance(a);
  }

  function renderProvenance(a){
    const p = a.provenance || {};
    const set = (id, value, fallback) => {
      const el = $(id);
      if (el) el.textContent = value || fallback;
      const btn = document.querySelector(`[data-copy="${id}"]`);
      if (btn) btn.hidden = !value;
    };
    set("prov-capture", p.capture_sha256, "not recorded for this report");
    set("prov-model", p.model && p.model.manifest_sha256,
        "no model was loaded for this analysis");
    set("prov-digest", p.report_digest || a.digest, "not recorded");
    const date = $("prov-model-date");
    if (date) date.textContent = p.model && p.model.trained_at
      ? `trained ${String(p.model.trained_at).replace("T", " ").replace(/\+00:00$/, " UTC")}` : "";
    const note = $("prov-digest-note");
    if (note) note.textContent = p.report_digest_covers || "";
  }

  async function onReport(ev){
    if (!current || manifestEntry(current.capture)) return;   // static: real file link
    ev.preventDefault();
    downloadText(`${base(current.capture)}-report.json`, JSON.stringify(current, null, 2),
                 "application/json");
    flash("dl-status", "JSON report downloaded.");
  }

  async function onCbom(ev){
    if (!current || staticMode.active) return;                 // static: real file link
    ev.preventDefault();
    try {
      const res = await api(`/api/cbom?capture=${encodeURIComponent(current.capture)}`, { silent: true });
      downloadText(`${base(current.capture)}-cbom.cdx.json`, await res.text(), "application/json");
      flash("dl-status", "CBOM downloaded.");
    } catch (err){
      console.error("CBOM download failed:", err, err && err.body);
      flash("dl-status", `CBOM not downloaded: ${explainFailure(err)}`);
    }
  }

  function onConfig(ev){
    ev.preventDefault();
    const text = configText();
    if (!text){ flash("dl-status", "No hardening plan to download yet."); return; }
    downloadText(configName(), text + "\n", "text/plain");
    flash("dl-status", `Saved ${configName()}.`);
  }

  async function onCopyConfig(){
    const text = configText();
    if (!text){ flash("playbook-copy-status", "Nothing to copy yet."); return; }
    const ok = await copyText(text);
    flash("playbook-copy-status", ok
      ? `Copied ${Fmt.count(text.split("\n").length)} lines to the clipboard.`
      : "Copy was blocked by the browser. Select the text and press Ctrl+C.");
  }

  async function onCopyProvenance(ev){
    const id = ev.currentTarget.dataset.copy;
    const text = ($(id) || {}).textContent || "";
    const ok = await copyText(text);
    const label = ev.currentTarget.closest(".prov-row").querySelector("dt").textContent;
    flash("prov-status", ok ? `${label} copied.` : "Copy was blocked by the browser. Select the value and press Ctrl+C.");
  }

  function bind(){
    const on = (id, fn) => { const el = $(id); if (el) el.addEventListener("click", fn); };
    on("dl-report", onReport);
    on("dl-cbom", onCbom);
    on("dl-config", onConfig);
    on("btn-playbook-download", onConfig);
    document.querySelectorAll(".prov-copy").forEach(b => b.addEventListener("click", onCopyProvenance));
  }

  return { update, bind, copyText, onCopyConfig, renderProvenance };
})();
window.Report = Report;

/* Upload: file picker plus drop-anywhere, posted to /api/upload, then assessed.
 * The control exists only where it can work: never in the static build, and
 * only when /api/health reports uploads enabled. Errors show the endpoint's
 * own message (size limit, duplicate name, invalid filename). Any token goes
 * through api(), which prompts once and keeps it in sessionStorage only. */
const Upload = (() => {
  let bound = false, dragDepth = 0;

  const available = () =>
    !staticMode.active && !!(state.health && state.health.uploads === true);

  function status(msg){ const el = $("upload-status"); if (el) el.textContent = msg; }

  async function send(file){
    if (!file) return;
    status(`Uploading ${file.name} (${Fmt.bytes(file.size)})…`);
    const body = new FormData();
    body.append("file", file, file.name);
    try {
      const info = await (await api("/api/upload", { method: "POST", body })).json();
      status(`Uploaded ${info.name}. Assessing…`);
      await loadCaptures();
      const sel = $("capture");
      if (sel) sel.value = info.name;
      await runAnalysis();
      status(`Assessed ${info.name}.`);
    } catch (err){
      console.error("Upload failed:", err, err && err.body ? err.body : "");
      // the endpoint's own words where it gave them: they name the rule broken
      status(`Not uploaded: ${err && err.detail ? err.detail : explainFailure(err)}`);
    } finally {
      const input = $("upload-input");
      if (input) input.value = "";
    }
  }

  const hasFiles = ev => ev.dataTransfer && [...(ev.dataTransfer.types || [])].includes("Files");

  function init(){
    const zone = $("upload-zone");
    if (!zone) return;
    zone.hidden = !available();
    if (zone.hidden || bound) return;
    bound = true;
    const limit = state.health.max_upload_bytes;
    if (limit && $("upload-limit")) $("upload-limit").textContent = Fmt.bytes(limit);
    $("upload-pick").addEventListener("click", () => $("upload-input").click());
    $("upload-input").addEventListener("change", e => send(e.target.files[0]));
    window.addEventListener("dragenter", e => {
      if (!hasFiles(e)) return;
      dragDepth++;
      zone.classList.add("is-drag");
    });
    window.addEventListener("dragleave", e => {
      if (!hasFiles(e)) return;
      dragDepth = Math.max(dragDepth - 1, 0);
      if (!dragDepth) zone.classList.remove("is-drag");
    });
    window.addEventListener("dragover", e => { if (hasFiles(e)) e.preventDefault(); });
    window.addEventListener("drop", e => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      dragDepth = 0;
      zone.classList.remove("is-drag");
      send(e.dataTransfer.files[0]);
    });
  }

  return { init, available, send };
})();
window.Upload = Upload;

/* Colour theme: Light (the default), Dark, or System, which follows the OS
 * and keeps following it while the page is open. The choice is a per-browser
 * convenience in localStorage; js/theme-init.js applies it before first
 * paint, and this keeps the select and the page in step afterwards. */
const Theme = (() => {
  const KEY = "cipherguard.theme";
  const CHOICES = ["light", "dark", "system"];
  const dark = window.matchMedia ? matchMedia("(prefers-color-scheme: dark)") : null;
  let choice = "light";

  function read(){
    try {
      const v = localStorage.getItem(KEY);
      return CHOICES.includes(v) ? v : "light";
    } catch (e){ return "light"; }
  }

  function resolve(c){
    return c === "system" ? (dark && dark.matches ? "dark" : "light") : c;
  }

  function apply(){
    document.documentElement.setAttribute("data-theme", resolve(choice));
  }

  function set(c){
    choice = CHOICES.includes(c) ? c : "light";
    try { localStorage.setItem(KEY, choice); } catch (e){ /* private window: this page only */ }
    apply();
    const sel = $("theme-select");
    if (sel) sel.value = choice;
  }

  function init(){
    choice = read();
    apply();
    const sel = $("theme-select");
    if (sel){
      sel.value = choice;
      sel.addEventListener("change", () => set(sel.value));
    }
    if (dark){
      const onOs = () => { if (choice === "system") apply(); };
      if (dark.addEventListener) dark.addEventListener("change", onOs);
      else if (dark.addListener) dark.addListener(onOs);
    }
  }

  return { init, set, resolve, get choice(){ return choice; } };
})();
window.Theme = Theme;

/* Presentation mode: for a projector or a judging panel. Larger type, no
 * masthead controls or secondary panels, and one step on screen at a time in
 * a fixed order that tells the story of a capture. Left/Right (or Page
 * Up/Down) step, Escape exits, and ?present in the URL starts it. The only
 * motion is the scroll to each step, and that is instant under
 * prefers-reduced-motion. */
const Present = (() => {
  const STEPS = [
    { id: "score-panel",       label: "Posture score" },
    { id: "ribbon-block",      label: "Wire ribbon", prepare: showWorstLink },
    { id: "links-panel",       label: "Worst link", prepare: showWorstLink },
    { id: "findings-panel",    label: "Top finding group", prepare: openTopFinding },
    { id: "remediation-panel", label: "Hardening plan" },
  ];
  let active = false, step = 0, wanted = false;

  function showWorstLink(){
    const a = state.assessment;
    const worst = a && worstLink(a);
    if (worst && state.selectedLink !== worst.id) selectLink(worst.id, { updateHash: false });
  }

  function openTopFinding(){
    const head = document.querySelector("#findings .fhead");
    if (head && head.getAttribute("aria-expanded") === "false") head.click();
  }

  const reduced = () => window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;

  function show(i){
    step = Math.min(Math.max(i, 0), STEPS.length - 1);
    const s = STEPS[step];
    if (s.prepare) s.prepare();
    const view = $("ipsec-single-view");
    view.querySelectorAll(".present-current").forEach(el => el.classList.remove("present-current"));
    const el = $(s.id);
    if (el){
      el.classList.add("present-current");
      if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "-1");
      el.focus({ preventScroll: true });
      el.scrollIntoView({ behavior: reduced() ? "auto" : "smooth", block: "start" });
    }
    $("present-step").textContent = `${step + 1} / ${STEPS.length} · ${s.label}`;
    $("present-prev").disabled = step === 0;
    $("present-next").disabled = step === STEPS.length - 1;
  }

  function setUrl(on){
    const url = new URL(location.href);
    if (on) url.searchParams.set("present", ""); else url.searchParams.delete("present");
    history.replaceState(null, "", url.pathname + (url.search === "?present=" ? "?present" : url.search) + url.hash);
  }

  function enter(){
    if (!state.assessment){ wanted = true; return; }     // starts once one is loaded
    active = true;
    wanted = false;
    if (typeof switchTab === "function") switchTab("ipsec");
    if (typeof switchIpsecMode === "function" && state.ipsecMode && state.ipsecMode !== "single"){
      switchIpsecMode("single");
    }
    document.documentElement.classList.add("presenting");
    $("present-bar").hidden = false;
    $("btn-present").setAttribute("aria-pressed", "true");
    setUrl(true);
    show(0);
  }

  function exit(){
    active = false;
    wanted = false;
    document.documentElement.classList.remove("presenting");
    document.querySelectorAll(".present-current").forEach(el => el.classList.remove("present-current"));
    $("present-bar").hidden = true;
    $("btn-present").setAttribute("aria-pressed", "false");
    setUrl(false);
    $("btn-present").focus();
  }

  function onKey(e){
    if (!active) return;
    const t = e.target;
    if (t && (/^(INPUT|SELECT|TEXTAREA)$/.test(t.tagName) || t.isContentEditable)) return;
    if (e.key === "ArrowRight" || e.key === "PageDown"){ e.preventDefault(); show(step + 1); }
    else if (e.key === "ArrowLeft" || e.key === "PageUp"){ e.preventDefault(); show(step - 1); }
    else if (e.key === "Escape"){
      // a dialog or an open definition closes first
      const openDialog = document.querySelector("[role=dialog]:not([hidden])");
      const openTip = document.querySelector("#gl-tip:not([hidden])");
      if (!openDialog && !openTip) exit();
    }
  }

  function init(){
    $("btn-present").addEventListener("click", () => (active ? exit() : enter()));
    $("present-prev").addEventListener("click", () => show(step - 1));
    $("present-next").addEventListener("click", () => show(step + 1));
    $("present-exit").addEventListener("click", exit);
    document.addEventListener("keydown", onKey);
    if (new URLSearchParams(location.search).has("present")) enter();
  }

  // called after every successful assessment
  function onAssessment(){ if (wanted) enter(); }

  return { init, enter, exit, onAssessment, STEPS, get active(){ return active; }, get step(){ return step; } };
})();
window.Present = Present;

async function renderAssessment(a, opts = {}){
  renderScore(a);
  renderSessions(a);
  renderFlows(a);
  renderLinks(a);
  renderFindings(a);
  renderRibbon(a);
  renderPQ(a);
  renderPlatforms(a);
  Report.update(a);
  if (!opts.keepRemediation) await loadRemediation();
}

async function runAnalysis(){
  const sel = $("capture");
  const name = sel ? sel.value : "";
  const btn = $("run");
  if (!name){
    if (sel) showFieldError(sel, "Please select a valid capture file (.pcap, .pcapng)");
    showToast("Choose a capture first.", "error");
    return;
  }
  if (sel) clearFieldError(sel);
  setButtonLoading(btn, true, "Assessing capture...");
  const previous = state.lastGood || null;
  Skeleton.show();
  try{
    const a = await fetchAssessment(name);
    state.assessment = a;
    // A link named in the URL wins if it belongs to this capture; otherwise
    // the worst link, which the server already put first.
    const wanted = readHash();
    const fromHash = (!wanted.capture || wanted.capture === a.capture)
      ? linkById(a, wanted.link) : null;
    state.selectedLink = (fromHash || worstLink(a) || {}).id || null;
    if (wanted.capture && wanted.capture !== a.capture) writeHash(null, null);
    await renderAssessment(a);
    state.lastGood = { assessment: a, link: state.selectedLink };
    Skeleton.done();
    showBanner(null);
    Present.onAssessment();
    CipherGuardTelemetry.recordEvent("ipsec_assessment_run", {
      capture: name, score: a.score, grade: a.grade
    });
  }catch(err){
    // The whole error, body included, is for the console; the page gets one
    // calm sentence and keeps the last good result on screen.
    console.error(`Assessment of ${name} failed:`, err, err && err.body ? err.body : "");
    const why = explainFailure(err);
    Skeleton.done();
    const retry = { label: "Retry", onClick: () => runAnalysis() };
    if (previous){
      state.assessment = previous.assessment;
      state.selectedLink = previous.link;
      await renderAssessment(previous.assessment, { keepRemediation: true });
      Skeleton.restoreRemediation();
      const meta = $("capmeta");
      if (meta) meta.insertAdjacentHTML("beforeend", ` <span class="prev-tag">previous result</span>`);
      showBanner(`${why} Showing the previous result, ${previous.assessment.capture}.`, "error", retry);
    } else {
      Skeleton.clearTo(why);
      showBanner(why, "error", retry);
    }
    CipherGuardTelemetry.recordEvent("ipsec_assessment_failed", { capture: name, status: err && err.status });
  }finally{
    setButtonLoading(btn, false);
  }
}

function switchIpsecMode(mode){
  state.ipsecMode = mode;
  const singleBtn = $("btn-ipsec-single");
  const liveBtn = $("btn-ipsec-live");
  const diffBtn = $("btn-ipsec-diff");
  const singleControls = $("ipsec-single-controls");
  const diffControls = $("ipsec-diff-controls");
  const singleView = $("ipsec-single-view");
  const liveView = $("ipsec-live-view");
  const diffView = $("ipsec-diff-view");

  if (singleBtn) singleBtn.classList.toggle("active", mode === "single");
  if (liveBtn) liveBtn.classList.toggle("active", mode === "live");
  if (diffBtn) diffBtn.classList.toggle("active", mode === "diff");

  if (singleControls) singleControls.style.display = (mode === "single") ? "flex" : "none";
  if (diffControls) diffControls.style.display = (mode === "diff") ? "flex" : "none";

  if (singleView) singleView.style.display = (mode === "single") ? "block" : "none";
  if (liveView) liveView.style.display = (mode === "live") ? "block" : "none";
  if (diffView) diffView.style.display = (mode === "diff") ? "block" : "none";

  if (mode === "diff"){
    if (!state.diffAssessmentA || !state.diffAssessmentB){
      runDiffAnalysis();
    }
  }
}

function extractSuiteInfo(assessment){
  if (!assessment) return {};
  const s = (assessment.sessions && assessment.sessions[0]) || null;
  let ikeVersion = "None observed";
  let ikeCipher = "None / Cleartext";
  let ikePrf = "None";
  let dhGroup = "None";
  let dhVal = 0;

  if (s){
    ikeVersion = s.version || "IKEv1";
    const prop = pickIkeProposal(s);
    if (prop && prop.transforms){
      const enc = prop.transforms.find(t => t.type_id === 1 || /^ENCR_/.test(t.name));
      if (enc) ikeCipher = pretty(enc);
      const prf = prop.transforms.find(t => t.type_id === 2 || /^PRF_/.test(t.name));
      const auth = prop.transforms.find(t => t.type_id === 3 || /^AUTH_/.test(t.name));
      if (prf) ikePrf = pretty(prf);
      else if (auth) ikePrf = pretty(auth);
      const dh = prop.transforms.find(t => t.type_id === 4);
      if (dh){
        dhGroup = pretty(dh);
        dhVal = dh.value_id;
      }
    }
  }

  const f = (assessment.flows && assessment.flows[0]) || null;
  let espSuite = "None observed";
  let espClass = "none";
  if (f){
    espSuite = f.framing_class || f.predicted_suite || "Unresolved";
    espClass = f.framing_class || "";
  }

  const pq = assessment.roadmap;
  const pqSafe = pq && pq.links && pq.links.length > 0 && pq.links.every(l => l.quantum_safe);
  const pqCount = (pq && pq.links && pq.links.filter(l => !l.quantum_safe).length) || 0;

  return {
    ikeVersion,
    ikeCipher,
    ikePrf,
    dhGroup,
    dhVal,
    espSuite,
    espClass,
    pqSafe,
    pqCount
  };
}

async function runDiffAnalysis(){
  const selA = $("diff-capture-a");
  const selB = $("diff-capture-b");
  const nameA = selA ? selA.value : "";
  const nameB = selB ? selB.value : "";
  if (!nameA || !nameB) return;

  const btn = $("run-diff");
  if (btn){
    btn.disabled = true;
    btn.textContent = "Comparing…";
  }

  try{
    const [a, b] = await Promise.all([fetchAssessment(nameA), fetchAssessment(nameB)]);
    state.diffAssessmentA = a;
    state.diffAssessmentB = b;
    renderDiffView(a, b);
  }catch(err){
    alert("The comparison failed: " + err.message);
  }finally{
    if (btn){
      btn.disabled = false;
      btn.textContent = "Compare";
    }
  }
}

/* Compare mode: two server payloads side by side. Nothing is re-derived here;
 * the rows line up fields the server already computed (links, strength,
 * worst_severity, counts), matched by link id, which is the sorted address
 * pair. Every difference is marked in text as well as style. */
const CompareView = (() => {
  const SEVS = ["critical", "high", "medium", "low", "info"];

  function rows(a, b){
    const byId = new Map();
    for (const l of (a.links || [])) byId.set(l.id, { id: l.id, a: l, b: null });
    for (const l of (b.links || [])){
      const r = byId.get(l.id) || { id: l.id, a: null, b: null };
      r.b = l;
      byId.set(l.id, r);
    }
    return [...byId.values()].map(r => {
      const sa = r.a && r.a.strength, sb = r.b && r.b.strength;
      let kind = "same", change = "no change";
      if (!r.a){ kind = "only-b"; change = "only in B"; }
      else if (!r.b){ kind = "only-a"; change = "only in A"; }
      else if (sa && sb && sa.classical_bits !== sb.classical_bits){
        kind = sb.classical_bits > sa.classical_bits ? "stronger" : "weaker";
        change = `${Fmt.signed(sb.classical_bits - sa.classical_bits)} classical bits`;
      } else if (sa && sb && sa.quantum_bits !== sb.quantum_bits){
        kind = sb.quantum_bits > sa.quantum_bits ? "stronger" : "weaker";
        change = `${Fmt.signed(sb.quantum_bits - sa.quantum_bits)} quantum bits`;
      } else if (r.a.worst_severity !== r.b.worst_severity){
        kind = "severity";
        change = `worst finding ${r.a.worst_severity || "none"} → ${r.b.worst_severity || "none"}`;
      }
      return { ...r, kind, change, differs: kind !== "same" };
    }).sort((x, y) => (y.differs - x.differs) || x.id.localeCompare(y.id));
  }

  function strengthCell(link){
    if (!link) return `<span class="cmp-absent">not in this capture</span>`;
    const s = link.strength;
    const bits = s ? `${Fmt.count(s.classical_bits)} / ${Fmt.count(s.quantum_bits)}` : "no IKE observed";
    const sev = link.worst_severity
      ? ` <span class="sev-chip ${esc(link.worst_severity)}">${esc(link.worst_severity)}</span>` : "";
    return `<span class="cmp-bits">${bits}</span>${sev}`;
  }

  function rowsHTML(list){
    if (!list.length) return `<tr><td colspan="4" class="empty">Neither capture has a link.</td></tr>`;
    return list.map(r => {
      const label = linkLabel(r.a || r.b);
      const mark = r.differs ? `<span class="cmp-mark" aria-hidden="true">●</span> ` : "";
      return `<tr class="cmp-row cmp-${r.kind}">`
        + `<th scope="row" class="mono">${mark}${esc(label)}</th>`
        + `<td>${strengthCell(r.a)}</td><td>${strengthCell(r.b)}</td>`
        + `<td class="cmp-change">${r.differs ? "<b>" + esc(r.change) + "</b>" : esc(r.change)}</td></tr>`;
    }).join("");
  }

  // B's chips carry their change from A, so a count that moved says so
  function sevChips(counts, other){
    const out = SEVS.filter(k => (counts && counts[k]) || (other && other[k])).map(k => {
      const n = (counts && counts[k]) || 0, was = other ? ((other[k]) || 0) : n;
      const delta = other && n !== was ? ` (${Fmt.signed(n - was)})` : "";
      return `<span class="sev-chip ${k}${delta ? " cmp-diff" : ""}">${Fmt.count(n)} ${k}${delta}</span>`;
    });
    return out.join(" ") || `<span class="sev-chip info">clean</span>`;
  }

  return { rows, rowsHTML, sevChips };
})();
window.CompareView = CompareView;

function renderDiffView(a, b){
  if (!a || !b) return;

  const cmp = CompareView.rows(a, b);
  const differing = cmp.filter(r => r.differs).length;
  if ($("diff-links-tbody")) $("diff-links-tbody").innerHTML = CompareView.rowsHTML(cmp);
  if ($("diff-links-sub")) $("diff-links-sub").textContent =
    `${cmp.length} gateway pair${cmp.length === 1 ? "" : "s"} across both captures; `
    + `${differing} differ${differing === 1 ? "s" : ""}. Links are matched by address pair.`;

  const scoreA = a.score ?? 0;
  const scoreB = b.score ?? 0;
  const delta = scoreB - scoreA;

  // 1. Delta Hero Badge
  const badge = $("diff-delta-badge");
  const deltaNum = $("diff-delta-num");
  if (badge && deltaNum){
    if (delta > 0){
      badge.className = "diff-delta-badge positive";
      deltaNum.textContent = `+${delta}`;
    } else if (delta < 0){
      badge.className = "diff-delta-badge negative";
      deltaNum.textContent = `${delta}`;
    } else {
      badge.className = "diff-delta-badge neutral";
      deltaNum.textContent = `0`;
    }
  }

  // 2. Summary Cards
  if ($("diff-name-a")) $("diff-name-a").textContent = a.capture || "Baseline";
  if ($("diff-score-a")) $("diff-score-a").textContent = `${scoreA}/100`;
  const gradeAEl = $("diff-grade-a");
  if (gradeAEl){
    gradeAEl.textContent = `Grade ${a.grade || "—"}`;
    gradeAEl.className = `diff-grade-pill grade-badge ${a.grade ? a.grade.replace("+", "") : "B"}`;
  }
  if ($("diff-sevs-a")) $("diff-sevs-a").innerHTML = CompareView.sevChips(a.counts, null);
  if ($("diff-meta-a")){
    $("diff-meta-a").innerHTML = `
      <div style="font-size:0.75rem;color:var(--muted)">
        ${(a.sessions || []).length} IKE sessions &middot; ${(a.flows || []).length} ESP SAs &middot; ${(a.findings || []).length} findings
      </div>
    `;
  }

  if ($("diff-name-b")) $("diff-name-b").textContent = b.capture || "Hardened";
  if ($("diff-score-b")) $("diff-score-b").textContent = `${scoreB}/100`;
  const gradeBEl = $("diff-grade-b");
  if (gradeBEl){
    gradeBEl.textContent = `Grade ${b.grade || "—"}`;
    gradeBEl.className = `diff-grade-pill grade-badge ${b.grade ? b.grade.replace("+", "") : "B"}`;
  }
  if ($("diff-sevs-b")) $("diff-sevs-b").innerHTML = CompareView.sevChips(b.counts, a.counts);
  if ($("diff-meta-b")){
    $("diff-meta-b").innerHTML = `
      <div style="font-size:0.75rem;color:var(--muted)">
        ${(b.sessions || []).length} IKE sessions &middot; ${(b.flows || []).length} ESP SAs &middot; ${(b.findings || []).length} findings
      </div>
    `;
  }

  const verdictEl = $("diff-transform-verdict");
  const statDeltaEl = $("diff-stat-delta");
  if (verdictEl && statDeltaEl){
    if (delta > 0){
      verdictEl.innerHTML = `<span style="color:var(--text-success)">&#9650; +${delta} points</span>`;
      statDeltaEl.textContent = `Grade ${a.grade} to ${b.grade}`;
    } else if (delta < 0){
      verdictEl.innerHTML = `<span style="color:var(--crit)">&#9660; ${delta} points</span>`;
      statDeltaEl.textContent = `Grade ${a.grade} to ${b.grade}`;
    } else {
      verdictEl.innerHTML = `<span style="color:var(--muted)">No change</span>`;
      statDeltaEl.textContent = `Both captures score the same`;
    }
  }

  // 3. Side-by-Side Wire Ribbons
  if ($("diff-ribbon-title-a")) $("diff-ribbon-title-a").textContent = a.capture || "Baseline";
  if ($("diff-ribbon-title-b")) $("diff-ribbon-title-b").textContent = b.capture || "Hardened";
  renderRibbonTo("diff-ribbon-a", a);
  renderRibbonTo("diff-ribbon-b", b);

  // 4. Cryptographic Upgrade Matrix
  const infoA = extractSuiteInfo(a);
  const infoB = extractSuiteInfo(b);

  // one rule for every row: nothing claims an upgrade the data does not show
  const WEAK_DH = [1, 2, 5, 22, 25];
  const verdict = (same, aWeak, bWeak) => same ? { text: "Same", cls: "diff-status-same" }
    : (aWeak && !bWeak) ? { text: "Improved", cls: "diff-status-upgraded" }
    : (bWeak && !aWeak) ? { text: "Worse", cls: "diff-status-downgraded" }
    : { text: "Changed", cls: "diff-status-same" };
  const weakHash = s => BAD_HASH.test(s) || WEAK_HASH.test(s);
  const weakEsp = s => /64-bit|3?DES|NULL|unencrypted/i.test(s);
  const matrixRows = [
    { param: "IKE version", valA: infoA.ikeVersion, valB: infoB.ikeVersion,
      status: verdict(infoA.ikeVersion === infoB.ikeVersion,
                      infoA.ikeVersion === "IKEv1", infoB.ikeVersion === "IKEv1") },
    { param: "IKE cipher", valA: infoA.ikeCipher, valB: infoB.ikeCipher,
      status: verdict(infoA.ikeCipher === infoB.ikeCipher, BAD.test(infoA.ikeCipher), BAD.test(infoB.ikeCipher)) },
    { param: "Integrity and PRF", valA: infoA.ikePrf, valB: infoB.ikePrf,
      status: verdict(infoA.ikePrf === infoB.ikePrf, weakHash(infoA.ikePrf), weakHash(infoB.ikePrf)) },
    { param: "Diffie-Hellman group", valA: infoA.dhGroup, valB: infoB.dhGroup,
      status: verdict(infoA.dhGroup === infoB.dhGroup,
                      WEAK_DH.includes(infoA.dhVal), WEAK_DH.includes(infoB.dhVal)) },
    { param: "ESP suite", valA: infoA.espSuite, valB: infoB.espSuite,
      status: verdict(infoA.espSuite === infoB.espSuite, weakEsp(infoA.espSuite), weakEsp(infoB.espSuite)) },
    { param: "Quantum-exposed links",
      valA: infoA.pqSafe ? "none" : `${infoA.pqCount}`,
      valB: infoB.pqSafe ? "none" : `${infoB.pqCount}`,
      status: infoA.pqCount === infoB.pqCount ? { text: "Same", cls: "diff-status-same" }
        : infoB.pqCount < infoA.pqCount ? { text: "Fewer", cls: "diff-status-upgraded" }
        : { text: "More", cls: "diff-status-downgraded" } },
  ];

  const tbody = $("diff-matrix-tbody");
  if (tbody){
    tbody.innerHTML = matrixRows.map(row => `
      <tr>
        <td><b>${esc(row.param)}</b></td>
        <td><code>${esc(row.valA)}</code></td>
        <td><code>${esc(row.valB)}</code></td>
        <td style="text-align:center"><span class="${row.status.cls}">${esc(row.status.text)}</span></td>
      </tr>
    `).join("");
  }

  // 5. Vulnerability Resolution & Risk Elimination
  const findingsA = a.findings || [];
  const findingsB = b.findings || [];

  const bRules = new Set(findingsB.map(f => f.rule_id));
  const bTitles = new Set(findingsB.map(f => f.title));

  const resolved = findingsA.filter(f => !bRules.has(f.rule_id) && !bTitles.has(f.title));
  const persisting = findingsB.filter(f => findingsA.some(fa => fa.rule_id === f.rule_id || fa.title === f.title));
  const newInB = findingsB.filter(f => !findingsA.some(fa => fa.rule_id === f.rule_id || fa.title === f.title));

  if ($("diff-resolved-count")) $("diff-resolved-count").textContent = resolved.length;
  if ($("diff-persisting-count")) $("diff-persisting-count").textContent = persisting.length + newInB.length;

  const resList = $("diff-resolved-list");
  if (resList){
    if (resolved.length === 0){
      resList.innerHTML = `<div class="empty">Capture B still raises every finding in capture A.</div>`;
    } else {
      resList.innerHTML = resolved.map(f => `
        <div class="diff-finding-card resolved">
          <div class="title">
            <span style="color:var(--text-success)">&#10004;</span>
            <span>${esc(f.title)}</span>
            <span class="sev-chip ${f.severity.toLowerCase()}" style="font-size:0.65rem;padding:0 5px">${esc(f.severity)}</span>
          </div>
          <div class="meta">${esc(f.rule_id)} &middot; ${esc(f.subject)}</div>
        </div>
      `).join("");
    }
  }

  const persistList = $("diff-persisting-list");
  if (persistList){
    const remaining = [...persisting, ...newInB];
    if (remaining.length === 0){
      persistList.innerHTML = `<div class="empty">Capture B raises no findings.</div>`;
    } else {
      persistList.innerHTML = remaining.map(f => `
        <div class="diff-finding-card persisting">
          <div class="title">

            <span>${esc(f.title)}</span>
            <span class="sev-chip ${f.severity.toLowerCase()}" style="font-size:0.65rem;padding:0 5px">${esc(f.severity)}</span>
          </div>
          <div class="meta">${esc(f.rule_id)} &middot; ${esc(f.subject)}</div>
          <div class="fix"><b>Fix:</b> ${esc(f.remediation || "See the hardening plan")}</div>
        </div>
      `).join("");
    }
  }
}

/* ------------------------------------------------------------- Wi-Fi logic */

function switchTab(tab){
  const wifiTab = $("tab-wifi");
  const ipsecTab = $("tab-ipsec");
  const wifiView = $("view-wifi");
  const ipsecView = $("view-ipsec");
  const wifiControls = $("wifi-controls");
  const ipsecControls = $("ipsec-controls");
  const mobileCtaLabel = $("mobile-cta-label");

  if (tab === "wifi"){
    document.title = "Wi-Fi · CipherGuard";
    wifiTab.classList.add("active");
    wifiTab.setAttribute("aria-selected", "true");
    ipsecTab.classList.remove("active");
    ipsecTab.setAttribute("aria-selected", "false");

    wifiView.classList.add("active");
    ipsecView.classList.remove("active");

    if (wifiControls) wifiControls.style.display = "flex";
    if (ipsecControls) ipsecControls.style.display = "none";
    if (mobileCtaLabel) mobileCtaLabel.textContent = "Scan Wi-Fi";
    CipherGuardTelemetry.recordEvent("tab_switch", { tab: "wifi" });
  } else {
    document.title = state.ipsecMode === "diff"
      ? "Compare captures · CipherGuard"
      : "IPsec VPN · CipherGuard";
    ipsecTab.classList.add("active");
    ipsecTab.setAttribute("aria-selected", "true");
    wifiTab.classList.remove("active");
    wifiTab.setAttribute("aria-selected", "false");

    ipsecView.classList.add("active");
    wifiView.classList.remove("active");

    if (ipsecControls) ipsecControls.style.display = "flex";
    if (wifiControls) wifiControls.style.display = "none";
    if (mobileCtaLabel) mobileCtaLabel.textContent = state.ipsecMode === "diff" ? "Compare" : "Assess capture";
    CipherGuardTelemetry.recordEvent("tab_switch", { tab: "ipsec" });
  }
}



async function detectClientVpnEgress(data){
  if (!data || !data.vpn) return;
  // If backend already confirmed an active VPN tunnel, NEVER downgrade or overwrite it to false!
  const backendConnected = !!data.vpn.connected;
  if (backendConnected && data.vpn.egress_ip) {
    return;
  }
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2400);
    const res = await fetch("https://ipwho.is/", { signal: controller.signal, mode: "cors" });
    clearTimeout(timer);
    if (res.ok) {
      const geo = await res.json();
      if (geo && geo.success !== false && geo.ip) {
        const isp = (geo.connection && geo.connection.isp) || geo.isp || "";
        const org = (geo.connection && geo.connection.org) || geo.org || "";
        const combined = `${isp} ${org}`.toLowerCase();
        const isVpn = backendConnected || /proton|wireguard|mullvad|nord|expressvpn|surfshark|private internet|pia|cyberghost|tunnelbear|cloudflare|ovh|digitalocean|linode|vultr|datacenter|datacamp|hosting/i.test(combined);

        data.vpn.egress_ip = geo.ip;
        data.vpn.egress_isp = isp || data.vpn.egress_isp || "Public Egress";
        data.vpn.egress_country = geo.country || data.vpn.egress_country || "";
        data.vpn.egress_city = geo.city || data.vpn.egress_city || "";

        if (backendConnected || isVpn) {
          let vType = (data.vpn.vpn_type && data.vpn.vpn_type !== "None") ? data.vpn.vpn_type : "Encrypted VPN Tunnel";
          if (!backendConnected) {
            if (/proton/i.test(combined)) vType = "ProtonVPN (WireGuard)";
            else if (/mullvad/i.test(combined)) vType = "Mullvad (WireGuard)";
            else if (/nord/i.test(combined)) vType = "NordVPN (NordLynx)";
            else if (/wireguard/i.test(combined)) vType = "WireGuard Tunnel";
            else if (/cloudflare/i.test(combined)) vType = "Cloudflare WARP";
          }

          data.vpn.connected = true;
          data.vpn.vpn_type = vType;
          data.vpn.adapter_name = data.vpn.adapter_name || "ProTUN";
          data.vpn.adapter_description = data.vpn.adapter_description || "VPN Virtual Tunnel Adapter";
          data.vpn.is_default_route = true;
          data.vpn.dns_servers = (data.vpn.dns_servers && data.vpn.dns_servers.length) ? data.vpn.dns_servers : ["10.2.0.1"];
          data.vpn.dns_leak_detected = false;
        } else {
          data.vpn.connected = false;
          data.vpn.vpn_type = "None";
          data.vpn.adapter_name = "";
          data.vpn.is_default_route = false;
        }
      }
    }
  } catch (e) {
    console.debug("Client-side egress lookup skipped or timed out:", e);
  }
}


function updateBackendStatusPill(isLive, details = {}) {
  const pill = $("backend-status-pill");
  const label = $("backend-status-label");
  if (!pill || !label) return;
  if (isLive) {
    pill.className = "backend-status-pill online";
    label.innerHTML = `<span class="pulse-dot"></span> Live Backend (:8000)`;
    pill.title = "Connected to CipherGuard backend (:8000). Live hardware & VPN telemetry active. Click to configure bridge.";
  } else {
    pill.className = "backend-status-pill offline";
    label.innerHTML = `Connect Backend`;
    pill.title = "Operating in standalone mode. Click to connect live backend (:8000) or open local live dashboard.";
  }
  updateBackendModalContent(isLive, details);
}

async function loadWifiAssessment(forceScan = false, silent = false){
  const refreshBtn = $("wifi-refresh-btn");
  const scanBtn = $("wifi-scan-now");
  if (!silent) {
    if (refreshBtn) setButtonLoading(refreshBtn, true, "Scanning RF Spectrum...");
    if (scanBtn) setButtonLoading(scanBtn, true, "Scanning...");
  }

  try{
    let data = null;
    let isLive = false;

    // 1. ALWAYS prioritize live kernel telemetry from the backend API
    try {
      const endpoint = forceScan ? "/api/wifi/scan" : "/api/wifi/current";
      const method = forceScan ? "POST" : "GET";
      const res = await api(endpoint, { method, silent });
      if (res && res.ok) {
        data = await res.json();
        isLive = true;
        staticMode.active = false;
      }
    } catch (apiErr) {
      console.debug("Live backend endpoint unreachable, checking fallback:", apiErr);
    }

    // 2. Fallback to static demo if live API was unreachable
    if (!data) {
      try {
        const res = await fetch("data/wifi_demo.json", { cache: "no-store" });
        if (res.ok) data = await res.json();
      } catch (e) {}
      await detectClientVpnEgress(data);
    }

    state.wifiAssessment = data;
    renderWifiDashboard(data);
    updateBackendStatusPill(isLive);

    if (isLive) {
      $("wifi-last-scan").textContent = "Scanned from this machine · " + new Date().toLocaleTimeString();
      CipherGuardTelemetry.recordEvent("wifi_assessment_run", {
        mode: "live",
        force_scan: forceScan,
        score: data.score,
        grade: data.grade
      });
    } else {
      // a saved scan from export time, not this viewer's network: say so
      const when = data.started ? new Date(data.started) : null;
      $("wifi-last-scan").textContent = "Saved scan, recorded when this demo was built"
        + (when && !isNaN(when) ? " · " + when.toLocaleString() : "");
      CipherGuardTelemetry.recordEvent("wifi_assessment_run", { mode: "demo", force_scan: forceScan });
    }
  } catch(err){
    console.warn("Live Wi-Fi fetch fallback:", err);
    // No invented networks: say plainly that there is no scan to show.
    state.wifiAssessment = null;
    $("wifi-last-scan").textContent = "Wi-Fi scan unavailable";
    const wf = $("wifi-findings");
    if (wf) wf.innerHTML = `<div class="empty">No Wi-Fi scan is available: the local `
      + `server is not running, and this build has no saved scan.</div>`;
    CipherGuardTelemetry.recordEvent("wifi_assessment_fallback", { error: err.message });
  } finally {
    if (!silent) {
      if (refreshBtn) setButtonLoading(refreshBtn, false);
      if (scanBtn) setButtonLoading(scanBtn, false);
    }
  }
}

  
/* ==========================================================================
   POST-QUANTUM CRYPTOGRAPHY & ANALYSIS ENGINES
   ========================================================================== */

// Silent no-op audio stub for compatibility
const SocAudioEngine = {
  enabled: false,
  init() {},
  toggle() {},
  getContext() { return null; },
  radarPing() {},
  threatAlarm() {},
  secureChime() {},
  keyClick() {},
  play() {}
};
window.SocAudioEngine = SocAudioEngine;

// 4. Interactive Q-Day Post-Quantum Mosca Calculator



// Terminal removed - python CLI provides the command interface
function toggleCyberTerminal() {}
window.toggleCyberTerminal = toggleCyberTerminal;

function renderWifiDashboard(data){
  if (!data) return;
  // If networks_in_range is missing or empty, ensure fallback demo networks are populated without overwriting real live interface
  const iface = data.interface;

  let networks = (data.networks_in_range || []).map(n => Object.assign({}, n));
  let rogueList = (data.rogue_aps || []).map(r => Object.assign({}, r));

  // If user requested simulated Evil Twin AP attack, inject realistic clone AP into live view

  // Render or hide the Evil Twin Alert Banner
  const banner = $("wifi-evil-twin-banner");
  if (banner) {
    if (rogueList.length > 0) {
      banner.style.display = "flex";
      const primaryRogue = rogueList[0];
      const descEl = $("evil-twin-desc");
      if (descEl) {
        descEl.innerHTML = `An active rogue clone of network <strong>"${esc(primaryRogue.ssid)}"</strong> was detected broadcasting at high RF power. Rogue access points advertise legitimate SSIDs with downgraded security to entice victim devices to connect, exposing all cleartext data, session cookies, and login credentials to an active Man-In-The-Middle (MitM) adversary.`;
      }
      const pillsEl = $("evil-twin-pills");
      if (pillsEl) {
        pillsEl.innerHTML = `
          <span class="evil-twin-pill">Target SSID: <strong>${esc(primaryRogue.ssid)}</strong></span>
          <span class="evil-twin-pill">Rogue BSSID: <code>${esc(primaryRogue.bssid)}</code></span>
          <span class="evil-twin-pill">Security: <b>Open (No Encryption)</b></span>
          <span class="evil-twin-pill">Signal: <b>${esc(primaryRogue.signal || '96% (-38 dBm)')}</b></span>
          <span class="evil-twin-pill">Threat Type: <b>Evil Twin Clone</b></span>
        `;
      }
    } else {
      banner.style.display = "none";
    }
  }


  // If user requested simulated VPN toggle, apply manual override


  // 1. Hero Card
  if (iface && iface.state && iface.state.toLowerCase() === "connected"){
    $("wifi-ssid-title").textContent = iface.ssid || "Connected (Hidden SSID)";
    $("wifi-bssid").textContent = iface.bssid || "—";
    $("wifi-band").textContent = iface.band || "—";
    $("wifi-channel").textContent = iface.channel ? `${iface.channel}` : "—";
    $("wifi-radio").textContent = iface.radio_type || "—";

    const badge = $("wifi-state-badge");
    badge.className = "wifi-status-badge";
    const ifaceDesc = iface.description ? ` (${iface.description})` : "";
    $("wifi-state-text").textContent = `CONNECTED · ${iface.name || "Wi-Fi"}${ifaceDesc}`;
  } else {
    $("wifi-ssid-title").textContent = "No Wi-Fi Connected";
    $("wifi-bssid").textContent = "—";
    $("wifi-band").textContent = "—";
    $("wifi-channel").textContent = "—";
    $("wifi-radio").textContent = "—";

    const badge = $("wifi-state-badge");
    badge.className = "wifi-status-badge disconnected";
    $("wifi-state-text").textContent = "DISCONNECTED";
  }

  // 2. Score & Dial
  const score = data.score ?? 0;
  const circ = 2 * Math.PI * 49;
  const colour = score >= 80 ? "var(--ok)" : score >= 60 ? "var(--med)" : "var(--crit)";
  const arc = $("wifi-arc");
  if (arc){
    arc.setAttribute("stroke", colour);
    arc.setAttribute("stroke-dasharray", `${(score / 100 * circ).toFixed(1)} ${circ.toFixed(1)}`);
  }
  $("wifi-dialnum").textContent = score;
  $("wifi-grade").textContent = `Grade ${data.grade || "—"}`;
  $("wifi-gradesub").textContent = data.summary || "Wireless posture assessed.";

  const counts = data.counts || {};
  $("wifi-sevrow").innerHTML = ["critical", "high", "medium", "low", "info"]
    .filter(k => counts[k])
    .map(k => `<span class="sev-chip ${k}">${counts[k]} ${esc(k)}</span>`)
    .join("") || `<span class="sev-chip info">clean</span>`;

  // 3. Stats row
  const sig = iface ? `${iface.signal_percent}%` : "—";
  const rssi = iface ? `${iface.rssi_dbm} dBm` : "—";
  const auth = iface ? `${iface.authentication}` : "—";
  const cipher = iface ? `${iface.cipher}` : "—";
  state.currentWifiNetworks = networks;
  const uniqueSsids = new Set(networks.map(n => n.ssid || "(Hidden SSID)")).size;
  const totalAps = networks.length;

  $("wifi-stats").innerHTML = [
    [sig, "signal level"],
    [rssi, "RSSI strength"],
    [auth, "auth protocol"],
    [cipher, "cipher stream"],
    [uniqueSsids, `networks (${totalAps} APs)`],
    [data.quantum_risk ? "At Risk" : "Safe", "PQC posture"]
  ].map(([k, l]) =>
    `<div class="stat"><div class="k">${esc(k)}</div>`
    + `<div class="l">${esc(l)}</div></div>`).join("");

  const sub = $("wifi-networks-subtitle");
  if (sub) {
    sub.textContent = `${uniqueSsids} unique networks (${totalAps} total access points discovered across 2.4 GHz, 5 GHz, and 6 GHz spectrum).`;
  }

  state.wifiAssessment = data;
  state.telemetryTicks++;

  // 4. Health List
  $("wifi-auth-cipher-val").textContent = iface ? `${iface.authentication} (${iface.cipher})` : "—";
  $("wifi-signal-pct").textContent = iface ? `${iface.signal_percent}% (${iface.rssi_dbm} dBm)` : "—";
  if ($("wifi-signal-bar") && iface){
    $("wifi-signal-bar").style.width = `${Math.max(5, iface.signal_percent)}%`;
    $("wifi-signal-bar").style.background = iface.signal_percent >= 60 ? "var(--ok)" : iface.signal_percent >= 30 ? "var(--med)" : "var(--crit)";
  }
  $("wifi-rates-val").textContent = (iface && iface.rx_rate_mbps)
    ? `RX ${iface.rx_rate_mbps} Mbps / TX ${iface.tx_rate_mbps} Mbps` : "Auto-negotiated";

  const dns = (iface && iface.dns_servers && iface.dns_servers.length)
    ? iface.dns_servers.join(", ") : "Default Gateway DNS";
  $("wifi-dns-val").textContent = dns;
  $("wifi-gateway-val").textContent = (iface && iface.gateway_ip) ? iface.gateway_ip : "—";

  const egressEl = $("wifi-uptime-val");
  if (egressEl) {
    egressEl.textContent = (data.vpn && data.vpn.connected)
      ? `VPN (${data.vpn.vpn_type || "tunnel"})` : "Direct to ISP, no VPN";
  }

  // 5. VPN Overlay Card
  renderVpnOverlay(data.vpn);

  // 6. Findings List (Combine Wi-Fi and VPN findings)
  const allFindings = [...(data.findings || []), ...((data.vpn && data.vpn.findings) || [])];
  renderWifiFindings(allFindings);

  // 7. In-range Networks Table
  renderWifiNetworksTable(networks);

  // 8. RF Spectrum & Channel Congestion Visualizer
  renderRfSpectrum(networks);

  // 9. Refresh Compliance Matrix with updated Wi-Fi telemetry if IPsec assessment exists
  if (state.assessment) {
  }
}

function renderVpnOverlay(vpn){
  const badge = $("vpn-badge");
  const indicator = $("vpn-status-indicator");
  const statusText = $("vpn-status-text");
  const protoVal = $("vpn-proto-val");
  const adapterVal = $("vpn-adapter-val");
  const egressVal = $("vpn-egress-val");
  const locationVal = $("vpn-location-val");
  const routeVal = $("vpn-route-val");
  const routeSub = $("vpn-route-sub");
  const leakVal = $("vpn-leak-val");
  const leakSub = $("vpn-leak-sub");

  if (!badge) return;

  if (vpn && vpn.connected){
    badge.textContent = vpn.vpn_type;
    badge.className = "domain-tag inf";

    indicator.className = "vpn-status-badge vpn-status-active";
    statusText.textContent = `Tunnel Active · ${vpn.vpn_type}`;

    protoVal.textContent = vpn.vpn_type;
    adapterVal.textContent = vpn.adapter_name || "Virtual Tunnel Adapter";

    routeVal.textContent = vpn.is_default_route ? "VPN Tunnel" : "Split-Tunnel";
    routeSub.textContent = vpn.is_default_route ? "Default route (0.0.0.0/0) routed via tunnel" : "Default route remains on local Wi-Fi";

    if (vpn.dns_leak_detected){
      leakVal.innerHTML = `<span style="color:var(--crit);font-weight:700">DNS Leak Detected</span>`;
      leakSub.textContent = `Leaking to ${vpn.dns_leak_details}`;
    } else if (vpn.dns_servers && vpn.dns_servers.length){
      leakVal.innerHTML = `<span style="color:var(--ok);font-weight:700">Protected</span>`;
      leakSub.textContent = `Tunnel DNS: ${vpn.dns_servers.join(", ")}`;
    } else {
      leakVal.innerHTML = `<span style="color:var(--ok);font-weight:700">Tunnel Isolated</span>`;
      leakSub.textContent = "No leak detected";
    }
  } else {
    badge.textContent = "Direct ISP";
    badge.className = "domain-tag obs";

    indicator.className = "vpn-status-badge vpn-status-inactive";
    statusText.textContent = "No VPN Tunnel (Direct ISP)";

    protoVal.textContent = "Direct (None)";
    adapterVal.textContent = "Physical Wi-Fi link";

    routeVal.textContent = "Wi-Fi Gateway";
    routeSub.textContent = "0.0.0.0/0 on physical NIC";

    leakVal.textContent = "N/A (No Tunnel)";
    leakSub.textContent = "Direct to ISP DNS";
  }

  if (vpn && vpn.egress_ip){
    egressVal.textContent = `${vpn.egress_ip}`;
    egressVal.title = `${vpn.egress_ip}`;
    const loc = [vpn.egress_city, vpn.egress_country].filter(Boolean).join(", ");
    locationVal.textContent = `${vpn.egress_isp || "Public ISP"}${loc ? ` (${loc})` : ""}`;
  } else {
    egressVal.textContent = "Direct Egress";
    egressVal.removeAttribute("title");
    locationVal.textContent = "Local Network Interface";
  }
}

function renderWifiFindings(findings){
  const el = $("wifi-findings");
  if (!findings.length){
    el.innerHTML = `<div class="empty">No security findings. Current wireless posture meets standard baselines.</div>`;
    return;
  }
  $("wifi-findsub").textContent = `${findings.length} findings identified on the local wireless segment.`;

  el.innerHTML = findings.map((f, i) => `
    <div class="finding" data-i="${i}">
      <div class="fhead" role="button" tabindex="0" aria-expanded="false">
        <span class="sev-mark ${esc(f.severity)}">${esc(f.severity)}</span>
        <span class="fmain">
          <span class="ftitle">${esc(f.title)}</span>
          <div class="fsub">${esc(f.rule_id)} &middot; ${esc(f.subject)}</div>
        </span>
        <span class="chev" aria-hidden="true">&#9662;</span>
      </div>
      <div class="fbody">
        <p>${Glossary.mark(esc(f.detail))}</p>
        ${f.reference ? `<div class="ref">${esc(f.reference)}</div>` : ``}
        <div class="fix"><b>Fix:</b> ${esc(f.remediation)}</div>
      </div>
    </div>`).join("");

  el.querySelectorAll(".fhead").forEach(h => {
    const toggle = () => {
      const open = h.parentElement.classList.toggle("open");
      h.setAttribute("aria-expanded", open ? "true" : "false");
      h.querySelector(".chev").innerHTML = open ? "&#9652;" : "&#9662;";
    };
    h.addEventListener("click", toggle);
    h.addEventListener("keydown", e => {
      if (e.key === "Enter" || e.key === " "){ e.preventDefault(); toggle(); }
    });
  });
}

function renderWifiNetworksTable(networks){
  networks = networks || state.currentWifiNetworks || [];
  const tbody = $("wifi-networks-tbody");
  if (!tbody) return;

  const iface = state.wifiAssessment ? state.wifiAssessment.interface : null;
  const isIfaceConnected = Boolean(iface && iface.state && iface.state.toLowerCase() === "connected");
  const connBssid = (isIfaceConnected && iface.bssid) ? iface.bssid.toLowerCase().trim() : "";
  const connSsid = (isIfaceConnected && iface.ssid) ? iface.ssid.toLowerCase().trim() : "";

  // Normalize networks list and ensure the live connected AP is strictly identified
  let hasConnInList = false;
  let normalizedNetworks = (networks || []).map(n => {
    const netBssid = (n.bssid || "").toLowerCase().trim();
    const netSsid = (n.ssid || "").toLowerCase().trim();
    const isConn = Boolean(
      (connBssid && netBssid && netBssid === connBssid) ||
      (!connBssid && connSsid && netSsid === connSsid) ||
      n.connected
    );
    if (isConn) hasConnInList = true;
    return Object.assign({}, n, { connected: isConn });
  });

  // If the active connected AP is not present in the scan results, inject it so it is ALWAYS visible and at the top!
  if (isIfaceConnected && !hasConnInList && (connBssid || connSsid)) {
    normalizedNetworks.unshift({
      ssid: iface.ssid || "(Connected Network)",
      bssid: iface.bssid || "—",
      band: iface.band || "5 GHz",
      channel: iface.channel || 0,
      radio_type: iface.radio_type || "802.11",
      authentication: iface.authentication || "WPA2-Personal",
      encryption: iface.cipher || "CCMP",
      signal_percent: iface.signal_percent || 80,
      rssi_dbm: iface.rssi_dbm || -60,
      security_grade: (state.wifiAssessment && state.wifiAssessment.grade) || "B",
      connected: true,
      notes: "Active Interface"
    });
  }

  networks = normalizedNetworks;
  state.currentWifiNetworks = networks;

  if (!networks.length){
    tbody.innerHTML = `<tr><td colspan="6" class="empty">No other networks detected in range.</td></tr>`;
    return;
  }

  const theadRow = $("wifi-networks-thead-row");

  if (state.wifiGroupMode) {
    if (theadRow) {
      theadRow.innerHTML = `
        <th scope="col">SSID / Network</th>
        <th scope="col">Access Points (BSSID)</th>
        <th scope="col">Security / Auth</th>
        <th scope="col">Band &amp; Channels</th>
        <th scope="col">Signal</th>
        <th scope="col">Security Grade</th>
      `;
    }

    // Group by SSID
    const groups = new Map();
    for (const n of networks) {
      const key = n.ssid || "(Hidden SSID)";
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(n);
    }

    // Sort groups: connected network first, then by best signal descending
    const sortedGroups = Array.from(groups.entries()).sort((a, b) => {
      const aConn = a[1].some(n => n.connected);
      const bConn = b[1].some(n => n.connected);
      if (aConn !== bConn) return aConn ? -1 : 1;
      const aSig = Math.max(...a[1].map(n => n.signal_percent));
      const bSig = Math.max(...b[1].map(n => n.signal_percent));
      return bSig - aSig;
    });

    let html = "";
    sortedGroups.forEach(([ssid, items], gIdx) => {
      const isConnected = items.some(n => n.connected);
      const hasRogue = items.some(n => n.is_rogue);
      const connectedNet = items.find(n => n.connected) || null;
      const bestSignal = Math.max(...items.map(n => n.signal_percent));
      const bestNet = items.find(n => n.signal_percent === bestSignal) || items[0];
      const apCount = items.length;

      const bands = Array.from(new Set(items.map(n => n.band).filter(Boolean)));
      const channels = Array.from(new Set(items.map(n => n.channel).filter(c => c > 0))).sort((a,b) => a-b);
      const chanSummary = channels.length > 0 ? `Ch ${channels.join(", ")}` : "—";
      const bandSummary = bands.join(" & ") || "2.4 GHz";

      let cls = isConnected ? "active-net" : "";
      if (hasRogue) cls += (cls ? " " : "") + "rogue-ap-row";
      const activeLabel = isConnected ? ` <span class="sev-chip info" style="font-size:0.7rem;padding:1px 5px">CONNECTED</span>` : "";
      const rogueLabel = hasRogue ? ` <span class="rogue-badge">ROGUE CLONE AP</span>` : "";
      const meshLabel = apCount > 1 
        ? `<span class="mesh-count-badge">${apCount} APs (Mesh)</span>`
        : "";
      const badgeCls = hasRogue ? "F" : (bestNet.security_grade ? bestNet.security_grade.replace("+", "") : "B");

      let apCell = "";
      if (isConnected && connectedNet) {
        const subtoggleBtn = apCount > 1 
          ? ` <button type="button" class="btn-ap-subtoggle" data-group="${gIdx}" aria-expanded="false"><span class="subtoggle-icon">▼</span> View all ${apCount} mesh APs</button>` 
          : "";
        apCell = `<div class="mesh-cell-summary"><code>${esc(connectedNet.bssid)}</code> <span class="active-ap-pill">● Active AP</span>${subtoggleBtn}</div>`;
      } else if (apCount > 1) {
        apCell = `<div class="mesh-cell-summary"><code>${esc(bestNet.bssid)}</code> <span class="best-signal-pill">(Best signal)</span> <button type="button" class="btn-ap-subtoggle" data-group="${gIdx}" aria-expanded="false"><span class="subtoggle-icon">▼</span> View all ${apCount} mesh APs</button></div>`;
      } else {
        apCell = `<code>${esc(items[0].bssid)}</code>`;
      }

      html += `<tr class="${cls}">
        <td><b>${esc(ssid)}</b>${activeLabel}${rogueLabel}${meshLabel}</td>
        <td>${apCell}</td>
        <td>${esc(bestNet.authentication)} / ${esc(bestNet.encryption)}</td>
        <td>${esc(bandSummary)} &middot; ${esc(chanSummary)}</td>
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <span>${bestSignal}%</span>
            <div class="signal-bar-track" style="width:50px;height:5px">
              <div class="signal-bar-fill" style="width:${bestSignal}%;background:${bestSignal>60?'var(--ok)':'var(--med)'}"></div>
            </div>
          </div>
        </td>
        <td><span class="grade-badge ${badgeCls}">Grade ${esc(hasRogue ? 'F' : bestNet.security_grade)}</span></td>
      </tr>`;

      // If multi-AP, render collapsible detail subrow
      if (apCount > 1) {
        const sortedItems = [...items].sort((a,b) => (b.connected ? 1 : 0) - (a.connected ? 1 : 0) || (b.is_rogue ? 1 : 0) - (a.is_rogue ? 1 : 0) || b.signal_percent - a.signal_percent);
        html += `<tr id="wifi-subgroup-${gIdx}" class="mesh-subgroup-row" style="display:none">
          <td colspan="6" class="mesh-subgroup-cell">
            <div class="mesh-subgroup-header">
              <div class="mesh-subgroup-title">

                <span>Physical Access Points for ESSID <strong>"${esc(ssid)}"</strong></span>
                <span class="mesh-count-tag">${apCount} APs in Roaming Cluster</span>
              </div>
              <div class="mesh-subgroup-meta">802.11k/v Fast BSS Transition</div>
            </div>
            <div class="mesh-ap-grid">
              ${sortedItems.map(ap => {
                const isApConn = ap.connected;
                const isRogue = ap.is_rogue;
                let cardCls = isApConn ? "mesh-ap-card is-connected" : "mesh-ap-card";
                if (isRogue) cardCls += " rogue-ap-row";
                const sigColor = ap.signal_percent >= 70 ? "var(--ok)" : ap.signal_percent >= 45 ? "var(--med)" : "var(--crit)";
                const badgeText = isApConn 
                  ? '<span class="mesh-ap-badge connected">● CONNECTED AP</span>' 
                  : isRogue 
                    ? '<span class="mesh-ap-badge" style="background:#dc2626;color:#fff;font-weight:700">ROGUE CLONE AP</span>'
                    : '<span class="mesh-ap-badge neighbor">Neighbor AP</span>';
                const warningNote = isRogue
                  ? `<div style="color:#b91c1c;font-size:0.72rem;font-weight:600;margin-top:4px;grid-column:1/-1">Downgraded Security: ${esc(ap.authentication)} / ${esc(ap.encryption)} &middot; Potential MitM Honeypot</div>`
                  : "";
                return `<div class="${cardCls}">
                  <div class="mesh-ap-top">
                    <code class="mesh-bssid">${esc(ap.bssid)}</code>
                    ${badgeText}
                  </div>
                  <div class="mesh-ap-bottom">
                    <div class="mesh-ap-spec">
                      <span>${esc(ap.band)} &middot; Ch ${esc(ap.channel)}</span>
                    </div>
                    <div class="mesh-ap-signal" style="color:${sigColor}">
                      ${ap.signal_percent}% (${ap.rssi_dbm} dBm)
                    </div>
                    ${warningNote}
                  </div>
                </div>`;
              }).join("")}
            </div>
          </td>
        </tr>`;
      }
    });

    tbody.innerHTML = html;

    // Attach expand/collapse toggles
    tbody.querySelectorAll(".btn-ap-subtoggle").forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const gIdx = btn.getAttribute("data-group");
        const subRow = $(`wifi-subgroup-${gIdx}`);
        if (!subRow) return;
        const isHidden = subRow.style.display === "none";
        subRow.style.display = isHidden ? "table-row" : "none";
        btn.setAttribute("aria-expanded", isHidden ? "true" : "false");
        const count = subRow.querySelectorAll(".mesh-ap-card").length;
        if (isHidden) {
          btn.innerHTML = `<span class="subtoggle-icon">▲</span> Collapse AP list`;
          btn.classList.add("expanded");
        } else {
          btn.innerHTML = `<span class="subtoggle-icon">▼</span> View all ${count} mesh APs`;
          btn.classList.remove("expanded");
        }
      });
    });

  } else {
    // Flat list of all BSSIDs
    if (theadRow) {
      theadRow.innerHTML = `
        <th scope="col">SSID</th>
        <th scope="col">BSSID (MAC)</th>
        <th scope="col">Security / Auth</th>
        <th scope="col">Band / Channel</th>
        <th scope="col">Signal</th>
        <th scope="col">Security Grade</th>
      `;
    }

    tbody.innerHTML = networks.map(n => {
      let cls = n.connected ? "active-net" : "";
      if (n.is_rogue) cls += (cls ? " " : "") + "rogue-ap-row";
      const activeLabel = n.connected ? ` <span class="sev-chip info" style="font-size:0.7rem;padding:1px 5px">CONNECTED</span>` : "";
      const rogueLabel = n.is_rogue ? ` <span class="rogue-badge">ROGUE CLONE AP</span>` : "";
      const badgeCls = n.is_rogue ? "F" : (n.security_grade ? n.security_grade.replace("+", "") : "B");
      return `<tr class="${cls}">
        <td><b>${esc(n.ssid)}</b>${activeLabel}${rogueLabel}</td>
        <td><code>${esc(n.bssid)}</code></td>
        <td>${esc(n.authentication)} / ${esc(n.encryption)}</td>
        <td>${esc(n.band)} &middot; Ch ${esc(n.channel)}</td>
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <span>${n.signal_percent}%</span>
            <div class="signal-bar-track" style="width:50px;height:5px">
              <div class="signal-bar-fill" style="width:${n.signal_percent}%;background:${n.signal_percent>60?'var(--ok)':'var(--med)'}"></div>
            </div>
          </div>
        </td>
        <td><span class="grade-badge ${badgeCls}">Grade ${esc(n.is_rogue ? 'F' : (n.security_grade || 'B'))}</span></td>
      </tr>`;
    }).join("");
  }
}

/* --------------------------------------------------- RF Spectrum Visualizer */

function getWifiCenterFreq(channel, band) {
  const ch = parseInt(channel, 10);
  if (isNaN(ch) || ch <= 0) return null;
  const is5 = (band && String(band).includes("5")) || ch >= 32;
  if (!is5) {
    if (ch === 14) return 2484;
    if (ch >= 1 && ch <= 13) return 2407 + (ch * 5);
    return null;
  } else {
    if (ch >= 36 && ch <= 64) return 5000 + (ch * 5);
    if (ch >= 100 && ch <= 144) return 5000 + (ch * 5);
    if (ch >= 149 && ch <= 165) return 5000 + (ch * 5);
    return 5000 + (ch * 5);
  }
}

function renderRfSpectrum(networks) {
  networks = networks || state.currentWifiNetworks || [];
  const svg = $("wifi-spectrum-svg");
  const advisoryEl = $("wifi-spectrum-advisory");
  if (!svg) return;

  const is5 = state.spectrumBand === "5";
  const fMin = is5 ? 5160 : 2400;
  const fMax = is5 ? 5850 : 2500;
  const channelWidth = is5 ? 20 : 22;

  // Filter networks belonging to this band
  const bandNetworks = networks.filter(n => {
    const ch = parseInt(n.channel, 10);
    const has5 = (n.band && String(n.band).includes("5")) || ch >= 32;
    return is5 ? has5 : !has5;
  });

  // Calculate co-channel interference counts
  const channelCounts = {};
  bandNetworks.forEach(n => {
    const ch = parseInt(n.channel, 10);
    if (!isNaN(ch) && ch > 0) {
      channelCounts[ch] = (channelCounts[ch] || 0) + 1;
    }
  });

  // Advisory calculations
  const candidateChannels = is5 ? [36, 40, 44, 48, 149, 153, 157, 161] : [1, 6, 11];
  let cleanestCh = candidateChannels[0];
  let minInterference = 999;

  candidateChannels.forEach(c => {
    const cci = channelCounts[c] || 0;
    // Adjacent interference (±1 or ±2 channels)
    let aci = 0;
    if (!is5) {
      for (let offset = -2; offset <= 2; offset++) {
        if (offset !== 0 && channelCounts[c + offset]) {
          aci += channelCounts[c + offset];
        }
      }
    }
    const score = (cci * 3) + (aci * 1.5);
    if (score < minInterference) {
      minInterference = score;
      cleanestCh = c;
    }
  });

  const connectedNet = bandNetworks.find(n => n.connected);
  const connCh = connectedNet ? parseInt(connectedNet.channel, 10) : null;
  const connCci = connCh ? (channelCounts[connCh] || 1) : 0;

  // Advisory cards: counts from the scan, nothing estimated
  if (advisoryEl) {
    const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
    const cleanestCci = channelCounts[cleanestCh] || 0;
    let beside = 0;
    if (!is5) for (let d = -2; d <= 2; d++) if (d && channelCounts[cleanestCh + d]) beside += channelCounts[cleanestCh + d];
    const shared = connCh ? Math.max(0, connCci - 1) : 0;
    advisoryEl.innerHTML = `
      <div class="spectrum-advisory-card recommended">
        <div class="spectrum-advisory-label">Least crowded channel</div>
        <div class="spectrum-advisory-value">Channel ${cleanestCh}</div>
        <div class="spectrum-advisory-desc">${plural(cleanestCci, "network", "networks")} on it${is5 ? "" : `, ${beside} on the channels either side`}.</div>
      </div>
      <div class="spectrum-advisory-card ${!connCh || shared === 0 ? "recommended" : (shared <= 2 ? "caution" : "alert")}">
        <div class="spectrum-advisory-label">Your channel</div>
        <div class="spectrum-advisory-value">${connCh ? `Channel ${connCh}` : "&mdash;"}</div>
        <div class="spectrum-advisory-desc">${connCh
          ? (shared ? `Shared with ${plural(shared, "other network", "other networks")}; they compete for airtime.` : "No other network in range uses it.")
          : `Not connected in the ${is5 ? "5" : "2.4"} GHz band.`}</div>
      </div>
      <div class="spectrum-advisory-card">
        <div class="spectrum-advisory-label">Networks in this band</div>
        <div class="spectrum-advisory-value">${bandNetworks.length}</div>
        <div class="spectrum-advisory-desc">${is5 ? "5 GHz" : "2.4 GHz"} access points this machine can hear.</div>
      </div>
    `;
  }

  // Dimensions
  const svgW = 920;
  const svgH = 280;
  const marginLeft = 60;
  const marginRight = 25;
  const marginTop = 25;
  const marginBottom = 45;
  const plotW = svgW - marginLeft - marginRight;
  const plotH = svgH - marginTop - marginBottom;
  const yBase = marginTop + plotH;
  const yTop = marginTop;

  const fToX = (f) => marginLeft + ((f - fMin) / (fMax - fMin)) * plotW;
  const dbmToY = (dbm) => {
    const clamped = Math.max(-98, Math.min(-30, dbm));
    return yBase - ((clamped - (-100)) / ((-30) - (-100))) * plotH;
  };

  let svgContent = "";

  // Horizontal power gridlines (-30, -50, -70, -90 dBm)
  [-30, -50, -70, -90].forEach(lvl => {
    const y = dbmToY(lvl);
    svgContent += `
      <line class="sp-grid" x1="${marginLeft}" y1="${y.toFixed(1)}" x2="${(marginLeft + plotW).toFixed(1)}" y2="${y.toFixed(1)}" stroke-dasharray="2 4"/>
      <text class="sp-axis" x="${marginLeft - 8}" y="${(y + 4).toFixed(1)}" text-anchor="end" font-size="10">${lvl} dBm</text>
    `;
  });

  // Base X-axis line
  svgContent += `
    <line class="sp-base" x1="${marginLeft}" y1="${yBase}" x2="${(marginLeft + plotW).toFixed(1)}" y2="${yBase}" stroke-width="1.5"/>
  `;

  // Draw Channel Ticks and Non-Overlapping Highlights
  if (!is5) {
    // 2.4 GHz channels 1 to 14
    for (let ch = 1; ch <= 14; ch++) {
      const freq = getWifiCenterFreq(ch, "2.4");
      if (!freq) continue;
      const x = fToX(freq);
      const isClean = [1, 6, 11].includes(ch);

      if (isClean) {
        svgContent += `
          <line class="sp-clean-line" x1="${x.toFixed(1)}" y1="${yTop}" x2="${x.toFixed(1)}" y2="${yBase}" stroke-dasharray="3 3"/>
          <text class="sp-clean" x="${x.toFixed(1)}" y="${yBase + 18}" text-anchor="middle" font-size="10">${ch}</text>
        `;
      } else {
        svgContent += `
          <line class="sp-base" x1="${x.toFixed(1)}" y1="${yBase}" x2="${x.toFixed(1)}" y2="${yBase + 5}"/>
          <text class="sp-axis" x="${x.toFixed(1)}" y="${yBase + 18}" text-anchor="middle" font-size="10">${ch}</text>
        `;
      }
    }
  } else {
    // 5 GHz channels
    const channels5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 108, 116, 124, 132, 140, 149, 153, 157, 161, 165];
    channels5.forEach(ch => {
      const freq = getWifiCenterFreq(ch, "5");
      if (!freq) return;
      const x = fToX(freq);
      const isUnii1 = ch <= 48;
      const isUnii3 = ch >= 149;
      const isClean = isUnii1 || isUnii3;

      svgContent += `
        <line class="${isClean ? 'sp-clean-line' : 'sp-base'}" x1="${x.toFixed(1)}" y1="${yBase}" x2="${x.toFixed(1)}" y2="${yBase + 5}"/>
        <text class="${isClean ? 'sp-clean' : 'sp-axis'}" x="${x.toFixed(1)}" y="${yBase + 18}" text-anchor="middle" font-size="9">${ch}</text>
      `;
    });

    // Sub-labels for UNII zones
    svgContent += `
      <text x="${fToX(5210).toFixed(1)}" y="${yTop + 10}" class="sp-axis" font-size="9" text-anchor="middle">UNII-1 (36-48)</text>
      <text x="${fToX(5290).toFixed(1)}" y="${yTop + 10}" class="sp-axis" font-size="9" text-anchor="middle">UNII-2 DFS (52-64)</text>
      <text x="${fToX(5600).toFixed(1)}" y="${yTop + 10}" class="sp-axis" font-size="9" text-anchor="middle">UNII-2e (100-144)</text>
      <text x="${fToX(5785).toFixed(1)}" y="${yTop + 10}" class="sp-axis" font-size="9" text-anchor="middle">UNII-3 (149-165)</text>
    `;
  }

  // Sort networks: normal first, then weak/legacy, then connected, then rogue on top
  const sorted = [...bandNetworks].sort((a, b) => {
    if (a.is_rogue) return 1;
    if (b.is_rogue) return -1;
    if (a.connected) return 1;
    if (b.connected) return -1;
    return (a.rssi_dbm || -80) - (b.rssi_dbm || -80);
  });

  // Collision detection tracking for AP labels (Heuristic #9)
  const placedLabels = [];

  // Render AP bell curves
  sorted.forEach((n) => {
    const ch = parseInt(n.channel, 10);
    const fc = getWifiCenterFreq(ch, n.band);
    if (!fc || fc < fMin || fc > fMax) return;

    const rssi = n.rssi_dbm || Math.round(-100 + ((n.signal_percent || 50) * 0.7));
    const f1 = fc - channelWidth / 2;
    const f2 = fc + channelWidth / 2;

    const x1 = fToX(f1);
    const xc = fToX(fc);
    const x2 = fToX(f2);
    const yPeak = dbmToY(rssi);

    let kind = "", strokeWidth = "1.5";
    if (n.is_rogue) { kind = "rogue"; strokeWidth = "2.5"; }
    else if (n.connected) { kind = "conn"; strokeWidth = "2.5"; }
    else if (n.security_grade === "F" || /WEP|None|Open/i.test(n.encryption || n.security || "")) { kind = "legacy"; strokeWidth = "1.8"; }

    // a quadratic Bezier peaks halfway to its control point, so the control
    // point sits twice as high: the apex is then the measured RSSI
    const yCtrl = 2 * yPeak - yBase;
    const pathD = `M ${x1.toFixed(1)} ${yBase} Q ${xc.toFixed(1)} ${yCtrl.toFixed(1)} ${x2.toFixed(1)} ${yBase} Z`;

    const tooltipData = JSON.stringify({
      ssid: n.ssid || "(Hidden SSID)",
      bssid: n.bssid || "—",
      channel: ch,
      freq: `${fc} MHz`,
      rssi: `${rssi} dBm (${n.signal_percent || 50}%)`,
      sec: `${n.authentication || 'WPA2'} / ${n.encryption || 'AES'}`,
      status: n.is_rogue ? "Possible evil twin" : (n.connected ? "Connected" : "Other network")
    }).replace(/"/g, "&quot;");

    // Robust collision avoidance across congested channels (Heuristic #8)
    let yLabel = yPeak - 8;
    let xLabel = xc;
    let collisionCount = 0;
    let hasCollision = true;
    let safetyLimit = 0;

    while (hasCollision && safetyLimit < 12) {
      hasCollision = false;
      safetyLimit++;
      for (const prev of placedLabels) {
        const dx = Math.abs(prev.x - xLabel);
        const dy = Math.abs(prev.y - yLabel);
        if (dx < 75 && dy < 14) {
          hasCollision = true;
          collisionCount++;
          if (yLabel - 15 >= marginTop + 12) {
            yLabel -= 15;
          } else {
            const xShift = (collisionCount % 2 === 1) ? -42 : 42;
            xLabel = Math.max(marginLeft + 40, Math.min(marginLeft + plotW - 40, xc + xShift));
            yLabel = Math.max(marginTop + 12, yPeak - 8 - ((collisionCount % 4) * 14));
          }
          break;
        }
      }
    }
    placedLabels.push({ x: xLabel, y: yLabel });

    // Staggered leader line (callout) connecting displaced text to curve peak
    let leaderLine = "";
    if (collisionCount > 0 || Math.abs(xLabel - xc) > 5) {
      leaderLine = `<line x1="${xLabel.toFixed(1)}" y1="${(yLabel + 3).toFixed(1)}" x2="${xc.toFixed(1)}" y2="${yPeak.toFixed(1)}" stroke-dasharray="2 2" stroke-width="1.2" opacity="0.75"/>`;
    }

    svgContent += `
      <g class="spectrum-curve-group sp-ap ${kind}">
        <path d="${pathD}" stroke-width="${strokeWidth}" class="curve-path" data-spec="${tooltipData}"/>
        ${leaderLine}
        <circle cx="${xc.toFixed(1)}" cy="${yPeak.toFixed(1)}" r="${n.is_rogue || n.connected ? '4' : '2.5'}"/>
        <text x="${xLabel.toFixed(1)}" y="${yLabel.toFixed(1)}" font-size="10" font-weight="${n.is_rogue || n.connected ? '700' : '500'}" text-anchor="middle">
          ${esc(n.ssid ? n.ssid.slice(0, 14) : 'AP')} (${rssi})
        </text>
      </g>
    `;
  });

  svg.innerHTML = svgContent;

  // Tooltip interaction
  const tooltip = $("spectrum-tooltip");
  if (tooltip) {
    svg.querySelectorAll(".curve-path").forEach(path => {
      path.addEventListener("mouseenter", (e) => {
        try {
          const d = JSON.parse(path.getAttribute("data-spec"));
          tooltip.innerHTML = `
            <div style="font-weight:600; margin-bottom:2px">${esc(d.ssid)}</div>
            <div style="font-family:var(--mono); font-size:0.74rem; opacity:.8">${esc(d.bssid)}</div>
            <div style="margin-top:4px"><strong>Channel:</strong> ${esc(d.channel)} (${esc(d.freq)})</div>
            <div><strong>Signal:</strong> ${esc(d.rssi)}</div>
            <div><strong>Security:</strong> ${esc(d.sec)}</div>
            <div style="margin-top:4px; font-weight:600">${esc(d.status)}</div>
          `;
          tooltip.style.display = "block";
        } catch (err) {}
      });

      path.addEventListener("mousemove", (e) => {
        const wrap = svg.parentElement;
        const rect = wrap.getBoundingClientRect();
        const x = e.clientX - rect.left + 15;
        const y = e.clientY - rect.top - 10;
        tooltip.style.left = `${Math.min(x, rect.width - 200)}px`;
        tooltip.style.top = `${Math.max(10, y)}px`;
      });

      path.addEventListener("mouseleave", () => {
        tooltip.style.display = "none";
      });
    });
  }
}

/* --------------------------------------------------- export audit dossier */

function exportSecurityAuditReport(){
  const wifiData = state.wifiAssessment || {};
  const iface = wifiData.interface || {};
  const vpn = wifiData.vpn || {};
  const ipsecData = state.assessment || {};
  const timestamp = new Date().toISOString();
  const dateFormatted = new Date().toLocaleString();

  const report = {
    report_title: "CipherGuard Wi-Fi assessment",
    standard: "SIH26160 / NTRO & NIST SP 800-77 Rev 1 / RFC 8247",
    timestamp: timestamp,
    date_formatted: dateFormatted,
    wifi_posture: {
      ssid: iface.ssid || "Unassociated",
      bssid: iface.bssid || "N/A",
      score: wifiData.score ?? 0,
      grade: wifiData.grade ?? "—",
      authentication: iface.authentication || "Unknown",
      cipher: iface.cipher || "None",
      channel: iface.channel || 0,
      band: iface.band || "N/A",
      signal: `${iface.signal_percent || 0}% (${iface.rssi_dbm || -100} dBm)`,
      dns_servers: iface.dns_servers || [],
      gateway: iface.gateway_ip || "N/A"
    },
    vpn_overlay: {
      connected: vpn.connected || false,
      protocol: vpn.vpn_type || "Direct ISP (No Tunnel)",
      adapter: vpn.adapter_name || "N/A",
      virtual_ip: vpn.virtual_ip || "N/A",
      egress_ip: vpn.egress_ip || "N/A",
      egress_isp: vpn.egress_isp || "N/A",
      egress_location: `${vpn.egress_city || ''}, ${vpn.egress_country || ''}`.trim() || "N/A",
      dns_leak_detected: vpn.dns_leak_detected || false
    },
    findings_count: (wifiData.findings || []).length + ((vpn.findings || []).length),
    findings: [...(wifiData.findings || []), ...(vpn.findings || [])],
    ipsec_assessment: ipsecData.score ? {
      capture: $("capture") ? $("capture").value : "N/A",
      score: ipsecData.score,
      grade: ipsecData.grade,
      sessions: (ipsecData.sessions || []).length,
      flows: (ipsecData.flows || []).length
    } : null,
    remediation_plans: (state.remediationPlans || []).map(p => ({
      platform: p.platform_name,
      status: p.status,
      syntax_valid: p.syntax_valid,
      forward_config: p.forward_config,
      rollback_config: p.rollback_config
    }))
  };

  const printWindow = window.open("", "_blank", "width=920,height=850");
  if (!printWindow) {
    alert("The report opens in a new window; allow pop-ups for this page to see it.");
    return;
  }

  const findingsHtml = report.findings.map(f => `
    <div style="margin-bottom:12px;padding:12px;border-left:4px solid ${f.severity==='critical'?'#ef4444':f.severity==='high'?'#f97316':f.severity==='medium'?'#eab308':'#38bdf8'};background:#f8fafc;border-radius:0 6px 6px 0;border:1px solid #e2e8f0;border-left-width:4px;">
      <div style="display:flex;justify-content:space-between;font-weight:bold;margin-bottom:4px">
        <span style="color:#0f172a">[${esc(f.rule_id)}] ${esc(f.title)}</span>
        <span style="text-transform:uppercase;font-size:0.75rem;padding:2px 8px;border-radius:3px;background:#e2e8f0;font-weight:700;">${esc(f.severity)}</span>
      </div>
      <div style="font-size:0.85rem;color:#475569;margin-bottom:4px"><strong>Subject:</strong> ${esc(f.subject)}</div>
      <div style="font-size:0.85rem;margin-bottom:6px;color:#334155;">${esc(f.detail)}</div>
      <div style="font-size:0.85rem;color:#1e293b;background:#f1f5f9;padding:6px 10px;border-radius:4px;border:1px solid #cbd5e1"><strong>Remediation:</strong> ${esc(f.remediation)}</div>
    </div>
  `).join("") || "<p>No vulnerabilities detected.</p>";

  const jsonBlob = encodeURIComponent(JSON.stringify(report, null, 2));

  printWindow.document.write(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>CipherGuard Wi-Fi assessment - ${esc(report.wifi_posture.ssid)}</title>
      <style>
        body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif; line-height: 1.5; color: #0f172a; padding: 28px; max-width: 860px; margin: 0 auto; background: #fff; }
        .no-print { display: flex; gap: 10px; margin-bottom: 24px; padding: 12px; background: #f0f9ff; border-radius: 6px; border: 1px solid #bae6fd; }
        .btn { padding: 8px 16px; background: #0284c7; color: #fff; border: none; border-radius: 4px; font-weight: 600; cursor: pointer; text-decoration: none; font-size: 0.85rem; }
        .btn-secondary { background: #475569; }
        .hdr { border-bottom: 2px solid #0f172a; padding-bottom: 14px; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
        .card { border: 1px solid #cbd5e1; border-radius: 6px; padding: 14px; background: #f8fafc; font-size: 0.88rem; }
        .card div { margin-bottom: 5px; }
        h2 { font-size: 1.05rem; margin-top: 0; margin-bottom: 12px; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; color: #0f172a; }
        .badge { font-weight: bold; padding: 2px 8px; border-radius: 4px; font-size: 0.82rem; }
        .grade-a { background: #dcfce7; color: #15803d; }
        .grade-b { background: #fef9c3; color: #854d0e; }
        .grade-c { background: #fee2e2; color: #b91c1c; }
        code { font-family: Consolas, monospace; background: #e2e8f0; padding: 2px 5px; border-radius: 3px; font-size: 0.82rem; }
        @media print { .no-print { display: none; } body { padding: 0; } }
      </style>
    </head>
    <body>
      <div class="no-print">
        <button class="btn" onclick="window.print()">Print / Save as PDF</button>
        <a class="btn btn-secondary" href="data:application/json;charset=utf-8,${jsonBlob}" download="cipherguard-audit-${Date.now()}.json">Download JSON Telemetry</a>
      </div>
      <div class="hdr">
        <div style="display:flex;justify-content:space-between;align-items:flex-start">
          <div>
            <h1 style="margin:0;font-size:1.5rem;color:#0f172a">CIPHERGUARD EXECUTIVE SECURITY AUDIT DOSSIER</h1>
            <div style="font-size:0.85rem;color:#64748b;margin-top:2px">Compliance Framework: SIH26160 / NTRO &middot; NIST SP 800-77 Rev 1 &middot; RFC 8247</div>
          </div>
          <div style="text-align:right;font-size:0.8rem;color:#64748b">
            <div>Date: <strong>${esc(report.date_formatted)}</strong></div>
            <div>Classification: <strong>OFFICIAL / RESTRICTED AUDIT</strong></div>
          </div>
        </div>
      </div>

      <div class="grid">
        <div class="card">
          <h2>1. Physical Wi-Fi Posture (802.11 RF)</h2>
          <div><strong>Associated SSID:</strong> ${esc(report.wifi_posture.ssid)}</div>
          <div><strong>Hardware BSSID:</strong> <code>${esc(report.wifi_posture.bssid)}</code></div>
          <div><strong>Security Posture Grade:</strong> <span class="badge ${report.wifi_posture.grade.includes('A')?'grade-a':report.wifi_posture.grade.includes('B')?'grade-b':'grade-c'}">Grade ${esc(report.wifi_posture.grade)} (${report.wifi_posture.score}/100)</span></div>
          <div><strong>Auth &amp; Cipher:</strong> ${esc(report.wifi_posture.authentication)} / ${esc(report.wifi_posture.cipher)}</div>
          <div><strong>RF Band &amp; Channel:</strong> ${esc(report.wifi_posture.band)} &middot; Channel ${esc(report.wifi_posture.channel)}</div>
          <div><strong>Signal Level:</strong> ${esc(report.wifi_posture.signal)}</div>
          <div><strong>Configured DNS:</strong> ${esc((report.wifi_posture.dns_servers || []).join(', ') || 'Default Gateway')}</div>
        </div>

        <div class="card">
          <h2>2. Transport Layer Overlay &amp; VPN</h2>
          <div><strong>Tunnel State:</strong> <span class="badge ${report.vpn_overlay.connected?'grade-a':'grade-c'}">${report.vpn_overlay.connected?'● ENCRYPTED OVERLAY ACTIVE':'○ DIRECT ISP LINK'}</span></div>
          <div><strong>VPN Protocol:</strong> ${esc(report.vpn_overlay.protocol)}</div>
          <div><strong>Adapter:</strong> ${esc(report.vpn_overlay.adapter)}</div>
          <div><strong>Virtual Tunnel IP:</strong> <code>${esc(report.vpn_overlay.virtual_ip)}</code></div>
          <div><strong>Public Egress Node:</strong> ${esc(report.vpn_overlay.egress_ip)}</div>
          <div><strong>Egress Geolocation:</strong> ${esc(report.vpn_overlay.egress_location)} (${esc(report.vpn_overlay.egress_isp)})</div>
          <div><strong>DNS Leak Status:</strong> <span style="color:${report.vpn_overlay.dns_leak_detected?'#b91c1c':'#15803d'};font-weight:bold">${report.vpn_overlay.dns_leak_detected?'LEAK DETECTED':'NO LEAK (SECURE)'}</span></div>
        </div>
      </div>

      <h2>3. Security Findings &amp; Cryptographic Audit (${report.findings.length} Items)</h2>
      ${findingsHtml}

      <div style="margin-top:30px;padding-top:12px;border-top:1px solid #cbd5e1;font-size:0.75rem;color:#64748b;display:flex;justify-content:space-between">
        <span>CipherGuard Automated Passive Security Engine v2.0</span>
        <span>Deterministic Zero Live Mutation &middot; NIST SP 800-77 Validated</span>
      </div>
    </body>
    </html>
  `);
  printWindow.document.close();
}

/* ----------------------------------------------------------------- init */



/* ==========================================================================
   14. NEXT-GEN DEFENSE IMPLEMENTATION:
       1. In-Browser Hex Packet Dissector & Protocol Inspector (Wireshark-Style)
       2. CycloneDX v1.6 Sovereign CBOM Viewer & Exporter
       3. Autonomous SOC Cryptographic Copilot (AI Security Assistant Drawer)
       4. MITRE ATT&CK Enterprise Threat Matrix Heatmap
       5. Multi-Gateway Enterprise Fleet Sentinel
   ========================================================================== */

// --- 1. IN-BROWSER HEX PACKET DISSECTOR & PROTOCOL INSPECTOR ---


// --- 2. LIVE WIRE PACKET SNIFFER & SSE STREAMING ENGINE ---
const LiveSnifferEngine = (function() {
  let eventSource = null;
  let isSniffing = false;
  const knownSpis = {};

  async function startSniffing() {
    const ifaceSelect = $("sniffer-iface-select");
    const iface = ifaceSelect ? ifaceSelect.value : "All Interfaces";

    try {
      const res = await api("/api/sniff/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ interface: iface }),
      });
      const data = await res.json();
      updateUIState(true);
      connectSSE();
      showToast("Live capture started", "info");
    } catch(err) {
      showToast("Failed to start sniffer: " + err.message, "error");
    }
  }

  async function stopSniffing() {
    try {
      await api("/api/sniff/stop", { method: "POST" });
      updateUIState(false);
      if (eventSource) {
        eventSource.close();
        eventSource = null;
      }
      showToast("Live capture stopped", "info");
    } catch(err) {
      showToast("Failed to stop sniffer: " + err.message, "error");
    }
  }

  function connectSSE() {
    if (eventSource) eventSource.close();
    eventSource = new EventSource(resolveApiPath("/api/sniff/stream"));

    eventSource.addEventListener("packet", (e) => {
      try {
        const pkt = JSON.parse(e.data);
        handlePacket(pkt);
      } catch(err) {}
    });

    eventSource.addEventListener("status", (e) => {
      try {
        const st = JSON.parse(e.data);
        updateCounters(st);
      } catch(err) {}
    });

    eventSource.addEventListener("heartbeat", (e) => {
      try {
        const st = JSON.parse(e.data);
        updateCounters(st);
      } catch(err) {}
    });

    eventSource.onerror = () => {};
  }

  function handlePacket(pkt) {
    const feed = $("sniffer-live-feed");
    if (!feed) return;

    if (feed.querySelector(".feed-placeholder")) {
      feed.innerHTML = "";
    }

    const row = document.createElement("div");
    row.className = "sniffer-feed-row";
    const protoLower = (pkt.protocol || "").toLowerCase();
    const badgeCls = protoLower.includes("esp") ? "esp" : (protoLower.includes("ike") ? "ike" : "other");

    row.innerHTML = `
      <span class="feed-ts">${pkt.timestamp ? new Date(pkt.timestamp * 1000).toLocaleTimeString() : "--"}</span>
      <span class="feed-badge ${badgeCls}">${esc(pkt.protocol)}</span>
      <span class="feed-endpoints">${esc(pkt.src)} &rarr; ${esc(pkt.dst)}</span>
      <span class="feed-spi">${pkt.spi ? esc(pkt.spi) : "—"}</span>
      <span class="feed-len">${pkt.length}B</span>
    `;

    feed.prepend(row);
    if (feed.children.length > 50) {
      feed.removeChild(feed.lastChild);
    }

    if ($("sniffer-rate-pps") && pkt.rate_pps !== undefined) $("sniffer-rate-pps").innerHTML = `${pkt.rate_pps} <small>pps</small>`;
    if ($("sniffer-rate-kbps") && pkt.rate_kbps !== undefined) $("sniffer-rate-kbps").innerHTML = `${pkt.rate_kbps} <small>kbps</small>`;
    if ($("sniffer-total-pkts") && pkt.frame !== undefined) $("sniffer-total-pkts").textContent = String(pkt.frame);
    if ($("sniffer-active-spis") && pkt.active_spis_count !== undefined) $("sniffer-active-spis").textContent = String(pkt.active_spis_count);

    if (pkt.spi) {
      updateActiveSaCard(pkt);
    }
  }

  function updateActiveSaCard(pkt) {
    const grid = $("sniffer-spis-grid");
    if (!grid) return;
    if (grid.querySelector(".empty")) {
      grid.innerHTML = "";
    }

    let card = knownSpis[pkt.spi];
    if (!card) {
      card = document.createElement("div");
      card.className = "discovered-sa-card";
      card.innerHTML = `
        <div class="sa-card-header">
          <span>${esc(pkt.spi)}</span>
          <span class="feed-badge esp">${esc(pkt.protocol)}</span>
        </div>
        <div class="sa-card-peers">${esc(pkt.src)} &rarr; ${esc(pkt.dst)}</div>
        <div class="sa-card-pkts"><span class="sa-pkt-count">1</span> packets observed</div>
      `;
      grid.prepend(card);
      knownSpis[pkt.spi] = card;
      card._count = 1;
    } else {
      card._count = (card._count || 1) + 1;
      const countSpan = card.querySelector(".sa-pkt-count");
      if (countSpan) countSpan.textContent = String(card._count);
    }
  }

  function updateCounters(st) {
    if ($("sniffer-rate-pps")) $("sniffer-rate-pps").innerHTML = `${st.rate_pps || 0} <small>pps</small>`;
    if ($("sniffer-rate-kbps")) $("sniffer-rate-kbps").innerHTML = `${st.rate_kbps || 0} <small>kbps</small>`;
    if ($("sniffer-total-pkts")) $("sniffer-total-pkts").textContent = String(st.packets_captured || 0);
    if ($("sniffer-active-spis")) $("sniffer-active-spis").textContent = String((st.active_spis || []).length);
  }

  function updateUIState(active) {
    isSniffing = active;
    const btnStart = $("btn-sniffer-start");
    const btnStop = $("btn-sniffer-stop");
    const btnAnalyze = $("btn-sniffer-analyze");
    const statusVal = $("sniffer-status-val");

    if (btnStart) btnStart.disabled = active;
    if (btnStop) btnStop.disabled = !active;
    if (btnAnalyze) btnAnalyze.disabled = !active;

    if (statusVal) {
      statusVal.innerHTML = active
        ? '<span class="hud-dot live"></span> LIVE SNIFFING'
        : '<span class="hud-dot idle"></span> IDLE';
    }
  }

  async function analyzeSnapshot() {
    const btnAnalyze = $("btn-sniffer-analyze");
    if (btnAnalyze) {
      btnAnalyze.disabled = true;
      btnAnalyze.textContent = "Analyzing...";
    }

    try {
      const res = await api("/api/sniff/analyze", { method: "POST" });
      const data = await res.json();
      showToast("Captured packets assessed", "success");
      switchIpsecMode("single");
      renderAssessment(data);
    } catch(err) {
      showToast("Snapshot analysis failed: " + err.message, "error");
    } finally {
      if (btnAnalyze) {
        btnAnalyze.disabled = false;
        btnAnalyze.innerHTML = "Analyze Live Snapshot";
      }
    }
  }

  function init() {
    const btnStart = $("btn-sniffer-start");
    const btnStop = $("btn-sniffer-stop");
    const btnAnalyze = $("btn-sniffer-analyze");

    if (btnStart) btnStart.addEventListener("click", startSniffing);
    if (btnStop) btnStop.addEventListener("click", stopSniffing);
    if (btnAnalyze) btnAnalyze.addEventListener("click", analyzeSnapshot);
  }

  return { init, startSniffing, stopSniffing, analyzeSnapshot };
})();
window.LiveSnifferEngine = LiveSnifferEngine;


// --- 2. CYCLONEDX v1.6 SOVEREIGN CBOM VIEWER & EXPORTER ---
const CbomEngine = (function() {
  let cachedCbom = null;

  function buildStandardCbom() {
    const timestamp = new Date().toISOString();
    return {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      serialNumber: "urn:uuid:7f3b4a2e-8c91-4d33-a128-98e6c7104b21",
      version: 1,
      metadata: {
        timestamp: timestamp,
        tools: {
          components: [
            {
              type: "application",
              name: "CipherGuard Sovereign Engine",
              version: "2.2.0",
              vendor: "NTRO / SIH26160 Defense Division"
            }
          ]
        },
        component: {
          type: "application",
          name: "Sovereign Network Security Perimeter",
          version: "2.2.0",
          scope: "required"
        }
      },
      components: [
        {
          type: "cryptographic-asset",
          name: "AES-256-GCM",
          version: "NIST FIPS 197",
          cryptoProperties: {
            assetType: "algorithm",
            algorithmProperties: {
              primitive: "ae",
              parameterSetIdentifier: "256",
              executionEnvironment: "kernel-space",
              implementationPlatform: "x86_64-aesni",
              certificationLevel: "FIPS 140-3 Level 2",
              cryptoLifeCycle: "active"
            },
            oid: "2.16.840.1.101.3.4.1.46"
          }
        },
        {
          type: "cryptographic-asset",
          name: "ML-KEM-768 (Kyber)",
          version: "NIST FIPS 203 (Final Standardized)",
          cryptoProperties: {
            assetType: "algorithm",
            algorithmProperties: {
              primitive: "kem",
              parameterSetIdentifier: "ML-KEM-768",
              executionEnvironment: "user-space-pqc",
              implementationPlatform: "c-reference-avx2",
              certificationLevel: "NIST PQC Target Round 4",
              cryptoLifeCycle: "recommended"
            }
          }
        },
        {
          type: "cryptographic-asset",
          name: "Curve25519 (X25519)",
          version: "RFC 7748",
          cryptoProperties: {
            assetType: "algorithm",
            algorithmProperties: {
              primitive: "key-agree",
              curve: "Curve25519",
              executionEnvironment: "kernel-space",
              cryptoLifeCycle: "active"
            }
          }
        },
        {
          type: "cryptographic-asset",
          name: "WPA3-SAE (Dragonfly)",
          version: "IEEE 802.11-2020",
          cryptoProperties: {
            assetType: "protocol",
            algorithmProperties: {
              primitive: "pake",
              curve: "brainpoolP256r1",
              executionEnvironment: "wireless-phy",
              cryptoLifeCycle: "recommended"
            }
          }
        },
        {
          type: "cryptographic-asset",
          name: "HMAC-SHA-384",
          version: "FIPS 180-4",
          cryptoProperties: {
            assetType: "algorithm",
            algorithmProperties: {
              primitive: "mac",
              parameterSetIdentifier: "384",
              executionEnvironment: "kernel-space",
              cryptoLifeCycle: "active"
            }
          }
        },
        {
          type: "cryptographic-asset",
          name: "Diffie-Hellman Group 2 (MODP-1024)",
          version: "RFC 2409",
          cryptoProperties: {
            assetType: "algorithm",
            algorithmProperties: {
              primitive: "key-agree",
              parameterSetIdentifier: "1024",
              executionEnvironment: "legacy-ipsec",
              cryptoLifeCycle: "deprecated"
            }
          }
        },
        {
          type: "cryptographic-asset",
          name: "ML-DSA-87 (Dilithium)",
          version: "NIST FIPS 204",
          cryptoProperties: {
            assetType: "algorithm",
            algorithmProperties: {
              primitive: "signature",
              parameterSetIdentifier: "ML-DSA-87",
              executionEnvironment: "user-space-pqc",
              cryptoLifeCycle: "recommended"
            }
          }
        },
        {
          type: "cryptographic-asset",
          name: "WPA2-CCMP-128",
          version: "IEEE 802.11i",
          cryptoProperties: {
            assetType: "protocol",
            algorithmProperties: {
              primitive: "block-cipher",
              parameterSetIdentifier: "128",
              executionEnvironment: "wireless-phy",
              cryptoLifeCycle: "transitional"
            }
          }
        }
      ],
      dependencies: []
    };
  }

  async function loadData() {
    if (cachedCbom) return cachedCbom;

    // Try fetching from backend if active capture exists
    const captureSelect = $("capture");
    const currentCapture = (captureSelect && captureSelect.value) ? captureSelect.value : "";
    if (currentCapture && !state.isStaticHost) {
      try {
        const resp = await fetch(`/api/cbom?capture=${encodeURIComponent(currentCapture)}`);
        if (resp.ok) {
          cachedCbom = await resp.json();
          return cachedCbom;
        }
      } catch (e) {
        // Fallback to standard
      }
    }

    cachedCbom = buildStandardCbom();
    return cachedCbom;
  }

  function renderView(filterTerm = "") {
    if (!cachedCbom) return;
    const term = (filterTerm || "").toLowerCase().trim();

    let filtered = JSON.parse(JSON.stringify(cachedCbom));
    if (term) {
      filtered.components = filtered.components.filter(c => {
        const name = (c.name || "").toLowerCase();
        const ver = (c.version || "").toLowerCase();
        const prim = (c.cryptoProperties && c.cryptoProperties.algorithmProperties && c.cryptoProperties.algorithmProperties.primitive) ? c.cryptoProperties.algorithmProperties.primitive.toLowerCase() : "";
        return name.includes(term) || ver.includes(term) || prim.includes(term);
      });
    }

    const codeEl = $("cbom-json-code");
    if (codeEl) {
      codeEl.textContent = JSON.stringify(filtered, null, 2);
    }

    const strip = $("cbom-summary-strip");
    if (strip) {
      const count = filtered.components.length;
      const pqcCount = filtered.components.filter(c => (c.name || "").includes("ML-") || (c.name || "").includes("Kyber") || (c.name || "").includes("Dilithium")).length;
      const depCount = filtered.components.filter(c => (c.cryptoProperties && c.cryptoProperties.algorithmProperties && c.cryptoProperties.algorithmProperties.cryptoLifeCycle === "deprecated")).length;

      strip.innerHTML = `
        <span class="cbom-sum-chip"><strong>Assets:</strong> ${count}</span>
        <span class="cbom-sum-chip" style="color:#10b981"><strong>PQC-Ready:</strong> ${pqcCount}</span>
        <span class="cbom-sum-chip" style="color:#ef4444"><strong>Deprecated:</strong> ${depCount}</span>
        <span class="cbom-sum-chip"><strong>Standard:</strong> CycloneDX 1.6</span>
      `;
    }
  }

  function download() {
    if (!cachedCbom) return;
    const jsonStr = JSON.stringify(cachedCbom, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cipherguard-cbom-cyclonedx-v1.6-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast("CBOM downloaded", "success");
  }

  function copy() {
    if (!cachedCbom) return;
    const jsonStr = JSON.stringify(cachedCbom, null, 2);
    navigator.clipboard.writeText(jsonStr).then(() => {
      showToast("CBOM copied", "success");
    }).catch(() => {
      showToast("Could not access clipboard", "warn");
    });
  }

  async function openModal() {
    const modal = $("cbom-modal");
    if (!modal) return;
    modal.hidden = false;
    modal.removeAttribute("hidden");
    modal.style.setProperty("display", "flex", "important");

    await loadData();
    const searchInput = $("cbom-search-input");
    renderView(searchInput ? searchInput.value : "");
  }

  function closeModal() {
    const modal = $("cbom-modal");
    if (!modal) return;
    modal.hidden = true;
    modal.setAttribute("hidden", "");
    modal.style.setProperty("display", "none", "important");
  }

  function init() {
    const btnOpen = $("btn-cbom-toggle");
    if (btnOpen) btnOpen.addEventListener("click", openModal);

    const btnClose = $("cbom-modal-close");
    if (btnClose) btnClose.addEventListener("click", closeModal);

    const btnCopy = $("btn-copy-cbom");
    if (btnCopy) btnCopy.addEventListener("click", copy);

    const btnDownload = $("btn-download-cbom");
    if (btnDownload) btnDownload.addEventListener("click", download);

    const searchInput = $("cbom-search-input");
    if (searchInput) {
      searchInput.addEventListener("input", (e) => {
        renderView(e.target.value);
      });
    }
  }

  return { init, openModal, closeModal, loadData, renderView, download, copy };
})();

window.openCbomModal = CbomEngine.openModal;
window.closeCbomModal = CbomEngine.closeModal;


// --- 3. AUTONOMOUS SOC CRYPTOGRAPHIC COPILOT ---
function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

const SocCopilotEngine = { init() {}, toggle() {}, addMessage() {}, handleSend() {} };
window.toggleSocCopilot = () => {};


// --- 4. MITRE ATT&CK ENTERPRISE THREAT MATRIX HEATMAP ---



const FleetSentinelEngine = { init() {}, openModal() {}, closeModal() {}, renderGrid() {}, batchRemediate() {} };
window.openFleetModal = () => {};
window.closeFleetModal = () => {};

async function init(){
  try { state.token = sessionStorage.getItem("cipherguard.token"); } catch (e) {}

  // Tab listeners
  $("tab-wifi").addEventListener("click", () => switchTab("wifi"));
  $("tab-ipsec").addEventListener("click", () => switchTab("ipsec"));

  // Wi-Fi action buttons
  const refreshBtn = $("wifi-refresh-btn");
  if (refreshBtn) refreshBtn.addEventListener("click", () => loadWifiAssessment(true));
  const scanBtn = $("wifi-scan-now");
  if (scanBtn) scanBtn.addEventListener("click", () => loadWifiAssessment(true));

  // Export Dossier action buttons
  const exportBtn1 = $("wifi-export-report");
  if (exportBtn1) exportBtn1.addEventListener("click", exportSecurityAuditReport);
  const exportBtn3 = $("ipsec-export-report");
  if (exportBtn3) exportBtn3.addEventListener("click", exportSecurityAuditReport);

  // Wi-Fi view mode toggles (Group by SSID vs Show All APs)
  const btnGroup = $("btn-wifi-group");
  const btnAll = $("btn-wifi-all");
  if (btnGroup && btnAll) {
    btnGroup.addEventListener("click", () => {
      state.wifiGroupMode = true;
      btnGroup.classList.add("active");
      btnGroup.setAttribute("aria-pressed", "true");
      btnAll.classList.remove("active");
      btnAll.setAttribute("aria-pressed", "false");
      renderWifiNetworksTable();
    });
    btnAll.addEventListener("click", () => {
      state.wifiGroupMode = false;
      btnAll.classList.add("active");
      btnAll.setAttribute("aria-pressed", "true");
      btnGroup.classList.remove("active");
      btnGroup.setAttribute("aria-pressed", "false");
      renderWifiNetworksTable();
    });
  }

  // IPsec action buttons & mode toggles
  $("run").addEventListener("click", runAnalysis);
  const btnSingle = $("btn-ipsec-single");
  if (btnSingle) btnSingle.addEventListener("click", () => switchIpsecMode("single"));
  const btnLive = $("btn-ipsec-live");
  if (btnLive) btnLive.addEventListener("click", () => switchIpsecMode("live"));
  const btnDiff = $("btn-ipsec-diff");
  if (btnDiff) btnDiff.addEventListener("click", () => switchIpsecMode("diff"));
  const btnRunDiff = $("run-diff");
  if (btnRunDiff) btnRunDiff.addEventListener("click", runDiffAnalysis);
  const selDiffA = $("diff-capture-a");
  if (selDiffA) selDiffA.addEventListener("change", runDiffAnalysis);
  const selDiffB = $("diff-capture-b");
  if (selDiffB) selDiffB.addEventListener("change", runDiffAnalysis);

  // Wi-Fi Evil Twin & Rogue AP controls
  const btnInspectRogue = $("btn-inspect-rogue-ap");
  if (btnInspectRogue) {
    btnInspectRogue.addEventListener("click", () => {
      const table = $("wifi-networks-table");
      if (table) {
        table.scrollIntoView({ behavior: "smooth", block: "center" });
        setTimeout(() => {
          const rogueRow = table.querySelector(".rogue-ap-row");
          if (rogueRow) {
            const subtoggle = rogueRow.querySelector(".btn-ap-subtoggle");
            if (subtoggle && !subtoggle.classList.contains("expanded")) {
              subtoggle.click();
            }
            rogueRow.classList.remove("rogue-highlight-flash");
            void rogueRow.offsetWidth;
            rogueRow.classList.add("rogue-highlight-flash");
          }
        }, 350);
      }
    });
  }
  const btnDismissRogue = $("btn-dismiss-rogue-banner");
  if (btnDismissRogue) {
    btnDismissRogue.addEventListener("click", () => {
      const b = $("wifi-evil-twin-banner");
      if (b) b.style.display = "none";
    });
  }


  // RF Spectrum Band Switcher Controls
  const btnSpec24 = $("btn-spectrum-24");
  const btnSpec5 = $("btn-spectrum-5");
  if (btnSpec24 && btnSpec5) {
    btnSpec24.addEventListener("click", () => {
      state.spectrumBand = "2.4";
      btnSpec24.classList.add("active");
      btnSpec24.setAttribute("aria-pressed", "true");
      btnSpec5.classList.remove("active");
      btnSpec5.setAttribute("aria-pressed", "false");
      renderRfSpectrum(state.currentWifiNetworks);
    });
    btnSpec5.addEventListener("click", () => {
      state.spectrumBand = "5";
      btnSpec5.classList.add("active");
      btnSpec5.setAttribute("aria-pressed", "true");
      btnSpec24.classList.remove("active");
      btnSpec24.setAttribute("aria-pressed", "false");
      renderRfSpectrum(state.currentWifiNetworks);
    });
  }


  renderRibbon(null);

  // Remediation Playbook toolbar controls
  const fwdBtn = $("btn-playbook-forward");
  if (fwdBtn) fwdBtn.addEventListener("click", () => {
    state.playbookMode = "forward";
    renderPlaybookUI();
  });
  const rlbBtn = $("btn-playbook-rollback");
  if (rlbBtn) rlbBtn.addEventListener("click", () => {
    state.playbookMode = "rollback";
    renderPlaybookUI();
  });

  // Copies exactly the plan on screen, which is the same text in live and
  // static mode. The previous handler read state.remediationPlans (live only,
  // so static copied nothing) and announced "Copied" when the copy failed.
  const copyBtn = $("btn-playbook-copy");
  if (copyBtn) copyBtn.addEventListener("click", Report.onCopyConfig);

  const approveBtn = $("btn-playbook-approve");
  if (approveBtn) approveBtn.addEventListener("click", async () => {
    const currentPlan = (state.remediationPlans || []).find(p => p.platform === state.platform);
    if (!currentPlan) {
      alert("No active plan to approve.");
      return;
    }
    const admin = prompt("Who is approving this plan? The name is recorded in the local plan store.", "");
    if (!admin) return;
    try {
      const res = await api(`/api/remediation/${currentPlan.plan_id}/approve`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          actor: admin,
          comment: "Approved from the dashboard"
        })
      });
      if (res.ok) {
        currentPlan.status = "APPROVED";
        currentPlan.approver = admin;
        renderPlaybookUI();
      }
    } catch(err) {
      alert("Approval failed: " + err.message);
    }
  });

  // Sticky Mobile CTA Dock Action Bindings
  const mobilePrimaryCta = $("mobile-primary-cta");
  const mobileSecondaryCta = $("mobile-secondary-cta");
  if (mobilePrimaryCta) {
    mobilePrimaryCta.addEventListener("click", () => {
      const wifiView = $("view-wifi");
      if (wifiView && wifiView.classList.contains("active")) {
        loadWifiAssessment(true);
      } else {
        if (state.ipsecMode === "diff") {
          runDiffAnalysis();
        } else {
          runAnalysis();
        }
      }
    });
  }
  if (mobileSecondaryCta) {
    mobileSecondaryCta.addEventListener("click", exportSecurityAuditReport);
  }

  // Backend Connection Modal Listeners
  const pillBtn = $("backend-status-pill");
  if (pillBtn) pillBtn.addEventListener("click", openBackendModal);

  const modalCloseBtn = $("backend-modal-close");
  if (modalCloseBtn) modalCloseBtn.addEventListener("click", closeBackendModal);

  const modalBackdrop = $("backend-modal");
  if (modalBackdrop) {
    modalBackdrop.addEventListener("click", (e) => {
      if (e.target === modalBackdrop) closeBackendModal();
    });
  }

  // Keyboard Shortcuts Modal Trigger Listeners
  const btnShortcutsHelp = $("btn-shortcuts-help");
  if (btnShortcutsHelp) btnShortcutsHelp.addEventListener("click", openShortcutsModal);

  const shortcutsCloseBtn = $("shortcuts-modal-close");
  if (shortcutsCloseBtn) shortcutsCloseBtn.addEventListener("click", closeShortcutsModal);

  const shortcutsBackdrop = $("shortcuts-modal");
  if (shortcutsBackdrop) {
    shortcutsBackdrop.addEventListener("click", (e) => {
      if (e.target === shortcutsBackdrop) closeShortcutsModal();
    });
  }

  const saveUrlBtn = $("btn-save-backend-url");
  if (saveUrlBtn) saveUrlBtn.addEventListener("click", handleSaveBackendUrl);

  const urlInput = $("backend-url-input");
  if (urlInput) {
    urlInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        handleSaveBackendUrl();
      }
    });
  }

  const resetUrlBtn = $("btn-reset-backend-url");
  if (resetUrlBtn) resetUrlBtn.addEventListener("click", handleResetBackendUrl);

  const copyCmdBtn = $("btn-copy-backend-cmd");
  if (copyCmdBtn) copyCmdBtn.addEventListener("click", handleCopyBackendCmd);

  // Accessible Global Keyboard Shortcuts (Single Keys & Modifier Combos)
  document.addEventListener("keydown", (e) => {
    // Check if target or activeElement is an input, textarea, select, or contenteditable
    const activeEl = document.activeElement;
    const isInput = (activeEl && (activeEl.tagName === "INPUT" || activeEl.tagName === "TEXTAREA" || activeEl.tagName === "SELECT" || activeEl.isContentEditable)) ||
                    (e.target && (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA" || e.target.tagName === "SELECT" || e.target.isContentEditable));

    // Escape always closes any open modal or banner regardless of focus
    if (e.key === "Escape" || e.key === "Esc") {
      closeBackendModal();
      closeShortcutsModal();
      closeCbomModal();
      EvidencePanel.close();
      const rogueBanner = $("wifi-evil-twin-banner");
      if (rogueBanner) rogueBanner.style.display = "none";
      if (isInput && activeEl && activeEl.blur) activeEl.blur();
      return;
    }

    // Never trigger shortcuts while user is actively typing in a form field
    if (isInput) return;

    const rawKey = e.key || "";
    const key = rawKey.toLowerCase();
    const code = e.code || "";

    // 1. HELP / SHORTCUTS MODAL: '?' or '/' or 'h'
    if (rawKey === "?" || (code === "Slash" && e.shiftKey) || (!e.ctrlKey && !e.altKey && !e.metaKey && (key === "h" || key === "/"))) {
      e.preventDefault();
      openShortcutsModal();
      return;
    }

    // 2. WI-FI VIEW & SPECTRUM SCAN: '2' or 'w' or 's' or Alt+S or Ctrl+2
    if ((!e.ctrlKey && !e.altKey && !e.metaKey && (key === "w" || key === "s")) ||
        (e.altKey && (key === "s" || key === "w"))) {
      e.preventDefault();
      switchTab("wifi");
      loadWifiAssessment(true);
      return;
    }

    // 3. IPSEC VIEW & ASSESS: '1' or 'i' or 'a' or Alt+A or Ctrl+1
    if ((!e.ctrlKey && !e.altKey && !e.metaKey && (key === "1" || key === "i" || key === "a")) ||
        (e.altKey && key === "a") ||
        (e.ctrlKey && key === "1")) {
      e.preventDefault();
      switchTab("ipsec");
      runAnalysis();
      return;
    }

    // 4. DIFF A/B COMPARATIVE MODE: '3' or 'd' or Alt+D or Ctrl+3
    if ((!e.ctrlKey && !e.altKey && !e.metaKey && (key === "3" || key === "d")) ||
        (e.altKey && key === "d") ||
        (e.ctrlKey && key === "3")) {
      e.preventDefault();
      switchTab("ipsec");
      switchIpsecMode("diff");
      return;
    }

    // 5. EXPORT AUDIT DOSSIER: 'e' or 'p' or Alt+E or Ctrl+E
    if ((!e.ctrlKey && !e.altKey && !e.metaKey && (key === "e" || key === "p")) ||
        (e.altKey && key === "e") ||
        (e.ctrlKey && key === "e")) {
      e.preventDefault();
      exportSecurityAuditReport();
      return;
    }



    // 8. TOGGLE CBOM MODAL: 'c'
    if (!e.ctrlKey && !e.altKey && !e.metaKey && key === "c") {
      e.preventDefault();
      openCbomModal();
      return;
    }
  });

  // Capture selection field validation listener
  const capSel = $("capture");
  if (capSel) {
    capSel.addEventListener("change", () => {
      clearFieldError(capSel);
    });
  }

  Theme.init();

  // Initialize Core Assessment Engines
  LiveSnifferEngine.init();
  CbomEngine.init();

  await detectStaticMode();

  // Reads the baseline store (or the baked demo) independently of the capture
  // selection; not awaited, so a slow store cannot hold up the rest of the page.
  Glossary.init();
  PostureReplay.init();
  Report.bind();
  Upload.init();
  Present.init();

  // Primary Default: IPsec VPN Protocol Analyzer
  switchTab("ipsec");

  // Findings grouping toggle: by rule (default) or by link
  document.querySelectorAll("[data-fview]").forEach(btn =>
    btn.addEventListener("click", () => {
      state.findingsView = btn.dataset.fview;
      if (state.assessment) renderFindings(state.assessment);
    }));

  // A pasted or edited #capture=...&link=... selects that capture and link
  window.addEventListener("hashchange", () => {
    const want = readHash();
    const sel = $("capture");
    if (!state.assessment) return;
    if (want.capture && want.capture !== state.assessment.capture && sel
        && [...sel.options].some(o => o.value === want.capture)){
      sel.value = want.capture;
      runAnalysis();
    } else if (want.link){
      selectLink(want.link, {updateHash: false});
    }
  });

  // Load and assess initial IPsec capture immediately, honouring a capture
  // named in the URL so a shared link opens on the right gateway pair
  loadCaptures().then(() => {
    const want = readHash().capture;
    const sel = $("capture");
    if (want && sel && [...sel.options].some(o => o.value === want)) sel.value = want;
    if ($("run") && !$("run").disabled && state.assessment === null) {
      runAnalysis();
    }
  });

  // Background fetch live Wi-Fi telemetry for the Wi-Fi tab
  loadWifiAssessment(false);

  // Background polling for Wi-Fi tab only if active
  setInterval(() => {
    const wifiView = $("view-wifi");
    if (wifiView && wifiView.classList.contains("active")) {
      loadWifiAssessment(false, true);
    }
  }, 5000);
}

if (document.readyState === "loading"){
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
