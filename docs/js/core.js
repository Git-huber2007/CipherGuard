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
    ["IKE_INTERMEDIATE", "ike-intermediate"],
    ["hybrid key exchange", "hybrid-kex"], ["Hybrid key exchange", "hybrid-kex"],
    ["ML-KEM", "ml-kem"],
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

/* RFC 9370 additional key exchanges: transform types 6 to 12 (ADDKE1-ADDKE7).
   They take their IDs from the same registry as the key exchange (type 4). */
function isAddKe(t){ return t.type_id >= 6 && t.type_id <= 12; }
const PQ_GROUPS = [35, 36, 37];                 // ML-KEM-512 / 768 / 1024

function pretty(t){
  // an additional key exchange is shown with its slot, so "ML-KEM-768" as the
  // second exchange of a hybrid does not read as the only one
  if (isAddKe(t)) return `${t.type_name}: ${t.value_id === 0 ? "none" : t.name}`;
  let n = t.name.replace(/^ENCR_|^AUTH_|^PRF_/, "");
  if (t.key_length) n += "-" + t.key_length;
  return n;
}

/* The key exchange of a proposal as one label: the method, plus any additional
   exchange that is not NONE. "Curve25519 + ML-KEM-768" for a hybrid. */
function keyExchangeLabel(prop){
  const base = prop.transforms.find(t => t.type_id === 4);
  if (!base) return null;
  const extra = prop.transforms.filter(t => isAddKe(t) && t.value_id !== 0).map(t => t.name);
  return [base.name, ...extra].join(" + ");
}

/* A session's hybrid status, from the server's key_exchange block. Observed,
   not inferred: the selection is cleartext in IKE_SA_INIT. The additional
   exchange itself is encrypted, so this says how many IKE_INTERMEDIATE
   exchanges were seen and claims nothing about what they carried. */
function hybridNote(s){
  const kx = s.key_exchange;
  if (!kx || !kx.hybrid) return "";
  const n = kx.intermediate_exchanges;
  return ` · hybrid key exchange, ${n} IKE_INTERMEDIATE exchange${n === 1 ? "" : "s"} observed`;
}

/* Algorithm judgement, mirroring audit/policy.py so a badge colour and a
   finding severity never contradict each other in front of an analyst. */
const BAD = /^(ENCR_)?(3?DES|DES_IV\d+|RC5|IDEA|CAST|BLOWFISH|3IDEA|NULL)/i;
const BAD_HASH = /MD5/i;
const WEAK_HASH = /SHA1|SHA_1/i;

function algClass(t){
  if (t.type_id === 4 || isAddKe(t)){         // key exchange, first or additional
    const id = t.value_id;
    if (id === 0) return "";                  // an additional slot left unused
    if (PQ_GROUPS.includes(id)) return "good";
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
