/* CipherGuard dashboard. Where assessments come from: the server, or the analyses saved with a static build. */
"use strict";

/* ------------------------------------------------------------ data flow */

// Static mode: on GitHub Pages there is no backend, so the dashboard reads
// pre-computed analyses written by `cipherguard export-demo`. The payloads are
// the real pipeline's output in the same shape the API returns, so every render
// path below is identical and neither version can quietly diverge from the
// other. Detected by probing for the manifest rather than by a build flag.
const staticMode = {active: false, manifest: null};

/* Asked once per page load; every caller shares the answer. */
let staticModeDetection = null;
function detectStaticMode(){
  if (!staticModeDetection) staticModeDetection = probeForServer();
  return staticModeDetection;
}

async function probeForServer(){
  // A server, if there is one, always wins over the saved analyses.
  try {
    const probeUrl = resolveApiPath("/api/health");
    const healthRes = await fetch(probeUrl, { method: "GET", cache: "no-store" });
    // A static host that answers every path with its index page returns 200
    // here too, so the body has to be the server's own health document.
    const health = healthRes.ok ? await healthRes.json() : null;
    if (health && health.status === "ok") {
      staticMode.active = false;
      // kept for controls that depend on server capability (upload)
      state.health = health;
      return false;
    }
  } catch (e) { /* no server here: fall through to the static manifest */ }

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
      staticModeDetection = null;  // the server may have come up since
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
