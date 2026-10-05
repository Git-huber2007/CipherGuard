/* CipherGuard dashboard. Wiring: event listeners, keyboard shortcuts, first load. */
"use strict";

/* ----------------------------------------------------------------- init */

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
      showToast(staticMode.active
        ? "Approvals are recorded by the server. This saved build has none."
        : "There is no plan to approve yet. Assess a capture first.", "error");
      return;
    }
    const admin = await Dialogs.ask({
      title: "Record approval",
      message: "The name is recorded as self-declared in the plan store and the audit log. "
        + "This server does not authenticate individual people.",
      label: "Approver name",
      confirmLabel: "Record approval"
    });
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
      // show what the server stored, which is the cleaned name
      const saved = (await res.json()).plan || {};
      currentPlan.status = saved.status || "APPROVED";
      currentPlan.approver = saved.approver || admin;
      renderPlaybookUI();
    } catch(err) {
      console.error("Recording the approval failed:", err);
      showToast(explainFailure(err), "error");
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

  // Keyboard shortcuts. Every one needs Alt. A bare letter fires whenever
  // focus is outside a field, which trips speech-input users and anyone who
  // starts typing with focus on the page (WCAG 2.1.4). Matched on the
  // physical key, because Alt changes the character on some layouts.
  const SHORTCUTS = {
    KeyA: () => { switchTab("ipsec"); runAnalysis(); },
    KeyS: () => { switchTab("wifi"); loadWifiAssessment(true); },
    KeyD: () => { switchTab("ipsec"); switchIpsecMode("diff"); },
    KeyE: () => exportSecurityAuditReport(),
    KeyC: () => CbomEngine.openModal(),
    KeyH: () => openShortcutsModal()
  };
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" || e.key === "Esc") {
      closeBackendModal();
      closeShortcutsModal();
      CbomEngine.closeModal();
      EvidencePanel.close();
      const rogueBanner = $("wifi-evil-twin-banner");
      if (rogueBanner) rogueBanner.style.display = "none";
      return;
    }
    if (!e.altKey || e.ctrlKey || e.metaKey) return;
    const run = SHORTCUTS[e.code];
    if (!run) return;
    e.preventDefault();
    run();
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

  // Load the Wi-Fi view in the background so the tab opens with data
  loadWifiAssessment(false);

  // Keep the Wi-Fi view current while it is on screen and there is a server
  // to ask. Not in the static build, and not while the tab is in the background.
  setInterval(() => {
    if (staticMode.active || document.hidden) return;
    const wifiView = $("view-wifi");
    if (wifiView && wifiView.classList.contains("active")) {
      loadWifiAssessment(false, true);
    }
  }, WIFI_REFRESH_MS);
}

if (document.readyState === "loading"){
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
