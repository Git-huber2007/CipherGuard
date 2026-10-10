/* CipherGuard dashboard. Loading placeholders, downloads and provenance, and capture upload. */
"use strict";

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
        ? UIState.box(message, "Assess capture", "run-analysis", true) : "";
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
    ta.className = "clipboard-proxy";
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
        "no model was loaded for this assessment");
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
    const trigger = $("upload-picker-trigger");
    if (trigger) {
      trigger.hidden = !available();
      trigger.addEventListener("click", () => $("upload-input").click());
    }
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
