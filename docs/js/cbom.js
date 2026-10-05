/* CipherGuard dashboard. The CBOM dialog. */
"use strict";

/* -------------------------------------------------------------- CBOM viewer */

/* Shows the CBOM the server built for the capture on screen or, in the static
 * build, the one exported alongside it. There is no stand-in inventory: if the
 * CBOM cannot be loaded the dialog says so, because a bill of materials that
 * did not come from the capture is worse than none. */
const CbomEngine = (() => {
  let loaded = null;   // { capture, bom }

  const friendly = message => Object.assign(new Error(message), { friendly: true });
  const propertyOf = (c, name) => ((c.properties || []).find(p => p.name === name) || {}).value;

  function currentCapture(){
    const sel = $("capture");
    return (state.assessment && state.assessment.capture) || (sel && sel.value) || "";
  }

  async function fetchCbom(capture){
    if (staticMode.active){
      const entry = ((staticMode.manifest && staticMode.manifest.captures) || [])
        .find(c => c.name === capture);
      if (!entry || !entry.cbom) throw friendly(`This build has no CBOM for ${capture}.`);
      const res = await fetch(entry.cbom, { cache: "no-store" });
      if (!res.ok) throw friendly(`The saved CBOM for ${capture} could not be loaded.`);
      return res.json();
    }
    const res = await api(`/api/cbom?capture=${encodeURIComponent(capture)}`, { silent: true });
    return res.json();
  }

  async function loadData(){
    const capture = currentCapture();
    if (!capture) throw friendly("Assess a capture first; the CBOM is built from it.");
    if (loaded && loaded.capture === capture) return loaded.bom;
    loaded = null;
    loaded = { capture, bom: await fetchCbom(capture) };
    return loaded.bom;
  }

  function setActionsEnabled(enabled){
    ["btn-copy-cbom", "btn-download-cbom", "cbom-search-input"].forEach(id => {
      const el = $(id);
      if (el) el.disabled = !enabled;
    });
  }

  function showMessage(message){
    const code = $("cbom-json-code");
    const strip = $("cbom-summary-strip");
    if (code) code.textContent = message;
    if (strip) strip.textContent = "";
    setActionsEnabled(false);
  }

  function renderView(filterTerm = ""){
    if (!loaded) return;
    const bom = loaded.bom;
    const all = bom.components || [];
    const term = String(filterTerm || "").toLowerCase().trim();
    const shown = term
      ? all.filter(c => JSON.stringify([c.name, c.cryptoProperties]).toLowerCase().includes(term))
      : all;

    const code = $("cbom-json-code");
    if (code) code.textContent = JSON.stringify(
      term ? Object.assign({}, bom, { components: shown }) : bom, null, 2);

    const strip = $("cbom-summary-strip");
    if (strip){
      const count = kind => all.filter(c => propertyOf(c, "cipherguard:provenance") === kind).length;
      strip.innerHTML = [
        ["Capture", loaded.capture],
        ["Assets", term ? `${shown.length} of ${all.length}` : all.length],
        ["Observed", count("observed")],
        ["Inferred", count("inferred")],
        ["Vulnerabilities", (bom.vulnerabilities || []).length],
        ["Format", `CycloneDX ${bom.specVersion || ""}`.trim()]
      ].map(([k, value]) =>
        `<span class="cbom-sum-chip"><strong>${esc(k)}:</strong> ${esc(value)}</span>`).join("");
    }
    setActionsEnabled(true);
  }

  // always the whole CBOM, whatever the filter is showing
  function download(){
    if (!loaded) return;
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(loaded.bom, null, 2)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${loaded.capture.replace(/\.[^.]+$/, "")}-cbom.cdx.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast("CBOM downloaded", "success");
  }

  function copy(){
    if (!loaded || !navigator.clipboard) {
      showToast("Could not copy. Use Download instead.", "error");
      return;
    }
    navigator.clipboard.writeText(JSON.stringify(loaded.bom, null, 2)).then(
      () => showToast("CBOM copied", "success"),
      () => showToast("Could not copy. Use Download instead.", "error"));
  }

  async function openModal(){
    const modal = $("cbom-modal");
    if (!modal) return;
    modal.hidden = false;
    modal.style.setProperty("display", "flex", "important");
    showMessage("Loading the CBOM\u2026");
    try {
      await loadData();
      const search = $("cbom-search-input");
      renderView(search ? search.value : "");
    } catch (err) {
      console.error("Loading the CBOM failed:", err);
      showMessage(err.friendly ? err.message : explainFailure(err));
    }
  }

  function closeModal(){
    const modal = $("cbom-modal");
    if (!modal) return;
    modal.hidden = true;
    modal.style.setProperty("display", "none", "important");
  }

  function init(){
    const bind = (id, event, fn) => { const el = $(id); if (el) el.addEventListener(event, fn); };
    bind("btn-cbom-toggle", "click", openModal);
    bind("cbom-modal-close", "click", closeModal);
    bind("btn-copy-cbom", "click", copy);
    bind("btn-download-cbom", "click", download);
    bind("cbom-search-input", "input", e => renderView(e.target.value));
    const modal = $("cbom-modal");
    if (modal) modal.addEventListener("click", e => { if (e.target === modal) closeModal(); });
  }

  return { init, openModal, closeModal, loadData, renderView, download, copy };
})();
