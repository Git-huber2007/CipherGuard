/* CipherGuard dashboard. Hardening plans: platform picker, plan text, approval status. */
"use strict";

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

  const countTag = $("remediation-count-tag");
  if (countTag){
    countTag.hidden = !plats.length;
    countTag.textContent = plats.length === 1 ? "1 platform" : `${plats.length} platforms`;
  }
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
      // the name is whatever was typed; the API does not authenticate people
      statusBadge.textContent = `Status: APPROVED (self-declared: ${currentPlan.approver || "no name"})`;
      statusBadge.title = "The approver's name was typed in, not authenticated.";
    } else if (st === "STAGED") {
      statusBadge.textContent = "Status: STAGED (Dry-Run)";
    } else {
      statusBadge.textContent = "Status: " + st;
    }
  }

  // Update Forward/Rollback tabs
  const fwdBtn = $("btn-playbook-forward");
  const rlbBtn = $("btn-playbook-rollback");
  if (fwdBtn) fwdBtn.setAttribute("aria-pressed", String(state.playbookMode === "forward"));
  if (rlbBtn) rlbBtn.setAttribute("aria-pressed", String(state.playbookMode === "rollback"));

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
  pre.textContent = "Building the hardening plan…";
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
