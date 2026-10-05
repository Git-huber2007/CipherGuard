/* CipherGuard dashboard. Tabs, the server status pill, and the Wi-Fi view. */
"use strict";

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
  }
}



function updateBackendStatusPill(isLive, details = {}) {
  const pill = $("backend-status-pill");
  const label = $("backend-status-label");
  if (!pill || !label) return;
  if (isLive) {
    pill.className = "backend-status-pill online";
    label.textContent = "Server connected";
    pill.title = "Connected to a CipherGuard server. Select for details.";
  } else {
    pill.className = "backend-status-pill offline";
    label.textContent = "Saved analyses";
    pill.title = "Showing analyses saved with this page. Select to connect a CipherGuard server.";
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

    // The server's own scan when there is a server. The static build has none,
    // so it does not ask; a failed request there is noise in the console and a
    // request every few seconds for nothing.
    if (!staticMode.active) {
      try {
        const endpoint = forceScan ? "/api/wifi/scan" : "/api/wifi/current";
        const method = forceScan ? "POST" : "GET";
        const res = await api(endpoint, { method, silent });
        data = await res.json();
        isLive = true;
      } catch (apiErr) {
        console.warn("Wi-Fi scan request failed:", apiErr);
        if (!silent) showToast(explainFailure(apiErr), "error");
      }
    }

    // Otherwise the bundled example scan, shown as it was saved: the page
    // makes no lookup of its own, so it works with no internet connection.
    if (!data) {
      try {
        const res = await fetch("data/wifi_demo.json", { cache: "no-store" });
        if (res.ok) data = await res.json();
      } catch (e) { /* no example in this build: handled below */ }
    }
    if (!data) throw new Error("no Wi-Fi scan available");

    state.wifiAssessment = data;
    state.wifiIsLive = isLive;
    renderWifiDashboard(data);
    updateBackendStatusPill(!staticMode.active);

    // the bundled example has invented networks: not this viewer's network
    // and not anyone else's, so say so
    $("wifi-last-scan").textContent = isLive
      ? "Scanned from the server's adapter · " + new Date().toLocaleTimeString()
      : "Example scan · invented networks, not a real site";
  } catch(err){
    // No invented networks: say plainly that there is no scan to show.
    state.wifiAssessment = null;
    state.wifiIsLive = false;
    $("wifi-last-scan").textContent = "Wi-Fi scan unavailable";
    const wf = $("wifi-findings");
    if (wf) wf.innerHTML = `<div class="empty">No Wi-Fi scan is available: the `
      + `server did not return one, and this build has no saved example.</div>`;
  } finally {
    if (!silent) {
      if (refreshBtn) setButtonLoading(refreshBtn, false);
      if (scanBtn) setButtonLoading(scanBtn, false);
    }
  }
}

  

function renderWifiDashboard(data){
  if (!data) return;
  const iface = data.interface;

  let networks = (data.networks_in_range || []).map(n => Object.assign({}, n));
  let rogueList = (data.rogue_aps || []).map(r => Object.assign({}, r));

  // Render or hide the Evil Twin Alert Banner
  const banner = $("wifi-evil-twin-banner");
  if (banner) {
    if (rogueList.length > 0) {
      banner.style.display = "flex";
      const primaryRogue = rogueList[0];
      const descEl = $("evil-twin-desc");
      if (descEl) {
        descEl.innerHTML = `Another access point is advertising the name <strong>${esc(primaryRogue.ssid)}</strong> with weaker security than the rest of that network. A device that joins it sends its traffic through whoever runs it.`;
      }
      const pillsEl = $("evil-twin-pills");
      if (pillsEl) {
        pillsEl.innerHTML = `
          <span class="evil-twin-pill">Network name: <strong>${esc(primaryRogue.ssid)}</strong></span>
          <span class="evil-twin-pill">Access point: <code>${esc(primaryRogue.bssid || "\u2014")}</code></span>
          ${primaryRogue.authentication ? `<span class="evil-twin-pill">Advertises: <b>${esc(primaryRogue.authentication)}</b></span>` : ""}
          ${primaryRogue.signal ? `<span class="evil-twin-pill">Signal: <b>${esc(primaryRogue.signal)}</b></span>` : ""}
        `;
      }
    } else {
      banner.style.display = "none";
    }
  }


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

  if (!vpn){
    // detection did not run or failed on the server: that is not "no VPN"
    badge.textContent = "Not checked";
    badge.className = "domain-tag obs";
    indicator.className = "vpn-status-badge vpn-status-inactive";
    statusText.textContent = "VPN state not available";
    [protoVal, adapterVal, egressVal, locationVal, routeVal, routeSub, leakVal, leakSub]
      .forEach(el => { if (el) el.textContent = "\u2014"; });
    return;
  }

  if (vpn.connected){
    badge.textContent = vpn.vpn_type;
    badge.className = "domain-tag inf";

    indicator.className = "vpn-status-badge vpn-status-active";
    statusText.textContent = `Tunnel active · ${vpn.vpn_type}`;

    protoVal.textContent = vpn.vpn_type;
    adapterVal.textContent = vpn.adapter_name || "\u2014";

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
    badge.textContent = "No VPN";
    badge.className = "domain-tag obs";

    indicator.className = "vpn-status-badge vpn-status-inactive";
    statusText.textContent = "No VPN tunnel";

    protoVal.textContent = "None";
    adapterVal.textContent = "Traffic leaves on the physical adapter";

    routeVal.textContent = "Local gateway";
    routeSub.textContent = "Default route is not through a tunnel";

    leakVal.textContent = "Not applicable";
    leakSub.textContent = "No tunnel for DNS to leak from";
  }

  if (vpn && vpn.egress_ip){
    egressVal.textContent = `${vpn.egress_ip}`;
    egressVal.title = `${vpn.egress_ip}`;
    const loc = [vpn.egress_city, vpn.egress_country].filter(Boolean).join(", ");
    locationVal.textContent = [vpn.egress_isp, loc].filter(Boolean).join(" \u00b7 ") || "\u2014";
  } else if (vpn && vpn.egress_queried){
    egressVal.textContent = "No answer";
    egressVal.removeAttribute("title");
    locationVal.textContent = "The lookup service did not respond";
  } else {
    // Off by default: finding the public address means asking an outside
    // service, and the analyzer makes no outbound calls unless told to.
    egressVal.textContent = "Not queried";
    egressVal.title = "Set CIPHERGUARD_EGRESS_LOOKUP=1 on the server to look it up";
    locationVal.textContent = "Outbound lookup is off";
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
      // what the interface reported, and nothing where it reported nothing
      band: iface.band || "",
      channel: iface.channel || 0,
      radio_type: iface.radio_type || "",
      authentication: iface.authentication || "",
      encryption: iface.cipher || "",
      signal_percent: iface.signal_percent || 0,
      rssi_dbm: iface.rssi_dbm || 0,
      security_grade: (state.wifiAssessment && state.wifiAssessment.grade) || "",
      connected: true,
      notes: "Connected; not in the scan results"
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
