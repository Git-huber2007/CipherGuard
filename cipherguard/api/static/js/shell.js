/* CipherGuard dashboard. Theme, presentation mode, and running an assessment. */
"use strict";

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
  document.body.classList.add("has-assessment");
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
    if (sel) showFieldError(sel, "That is not a capture file. Choose a .pcap, .pcapng or .cap file.");
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

  if (singleBtn) singleBtn.setAttribute("aria-pressed", String(mode === "single"));
  if (liveBtn) liveBtn.setAttribute("aria-pressed", String(mode === "live"));
  if (diffBtn) diffBtn.setAttribute("aria-pressed", String(mode === "diff"));

  if (singleControls) singleControls.hidden = mode !== "single";
  if (diffControls) diffControls.hidden = mode !== "diff";

  if (singleView) singleView.hidden = mode !== "single";
  if (liveView) liveView.hidden = mode !== "live";
  if (diffView) diffView.hidden = mode !== "diff";

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
  let ikeCipher = "None (cleartext)";
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
        // with any additional key exchange, so a hybrid compares as a hybrid
        dhGroup = keyExchangeLabel(prop);
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
showBanner(explainFailure(err), "error", { label: "Retry", onClick: () => runDiffAnalysis() });
  }finally{
    if (btn){
      btn.disabled = false;
      btn.textContent = "Compare";
    }
  }
}

/* Section links scroll in script instead of using fragment links: the fragment
 * already carries the selected link (#link=...), and a plain #id would replace it. */
document.addEventListener("click", e => {
  const btn = e.target.closest("[data-jump]");
  const el = btn && document.getElementById(btn.dataset.jump);
  if (!el) return;
  const nav = btn.closest(".section-nav");
  if (nav) {
    nav.querySelectorAll("[data-jump]").forEach(b => {
      b.classList.remove("active");
      b.removeAttribute("aria-current");
    });
    btn.classList.add("active");
    btn.setAttribute("aria-current", "true");
  }
  const reduced = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  el.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
  if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "-1");
  el.focus({ preventScroll: true });
});

/* Buttons that scripts or the page generate carry data-action="name". This one
 * listener runs the matching function, so no markup carries a handler and the
 * script policy needs no 'unsafe-inline'. */
const ACTIONS = {
  "run-analysis": () => runAnalysis(),
  "diff-run": () => runDiffAnalysis(),
  "wifi-scan": () => loadWifiAssessment(true),
  "replay-init": () => PostureReplay.init(),
  "export-report": () => exportSecurityAuditReport(),
  "sniffer-start": () => $("btn-sniffer-start").click(),
  "focus-capture": () => $("capture").focus(),
  "focus-capture-b": () => $("diff-capture-b").focus(),
  "focus-replay-link": () => $("replay-link").focus(),
  "clear-link-filter": () => { state.linkFilter = null; renderFindings(state.assessment); },
  "jump-remediation": () =>
    $("remediation").scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth" }),
};
document.addEventListener("click", e => {
  const btn = e.target.closest("[data-action]");
  if (btn && Object.hasOwn(ACTIONS, btn.dataset.action)) ACTIONS[btn.dataset.action]();
});

function initSectionObserver() {
  const nav = document.querySelector(".section-nav");
  if (!nav) return;
  const buttons = Array.from(nav.querySelectorAll("[data-jump]"));
  const sectionIds = buttons.map(b => b.dataset.jump);
  const sections = sectionIds.map(id => document.getElementById(id)).filter(Boolean);

  function setActive(activeId) {
    buttons.forEach(btn => {
      const isActive = btn.dataset.jump === activeId;
      btn.classList.toggle("active", isActive);
      if (isActive) {
        btn.setAttribute("aria-current", "true");
      } else {
        btn.removeAttribute("aria-current");
      }
    });
  }

  function updateActive() {
    if (!sections.length) return;

    // Start on Wire at the top of the document
    if (window.scrollY < 80) {
      setActive(sectionIds[0]);
      return;
    }

    // Activate the last section if scrolled to page bottom
    const scrollBottom = window.innerHeight + window.scrollY;
    const docHeight = document.documentElement.scrollHeight;
    if (scrollBottom >= docHeight - 50) {
      setActive(sectionIds[sectionIds.length - 1]);
      return;
    }

    // Reading line just below the sticky header / section-nav
    const navRect = nav.getBoundingClientRect();
    const refLine = navRect.bottom > 0 ? navRect.bottom + 16 : 140;

    let bestSection = null;
    let minDistance = Infinity;

    for (const s of sections) {
      const rect = s.getBoundingClientRect();
      if (rect.top <= refLine && rect.bottom >= refLine) {
        bestSection = s;
        break;
      }
      const dist = Math.abs(rect.top - refLine);
      if (dist < minDistance) {
        minDistance = dist;
        bestSection = s;
      }
    }

    if (bestSection) {
      setActive(bestSection.id);
    }
  }

  let ticking = false;
  function onScroll() {
    if (!ticking) {
      requestAnimationFrame(() => {
        updateActive();
        ticking = false;
      });
      ticking = true;
    }
  }

  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", onScroll, { passive: true });

  // Initial call ensures highlight starts on Wire
  updateActive();
  window.updateSectionNav = updateActive;
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initSectionObserver);
} else {
  initSectionObserver();
}
