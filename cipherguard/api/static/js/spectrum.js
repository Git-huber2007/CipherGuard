/* CipherGuard dashboard. Channel-use chart for the Wi-Fi view. */
"use strict";

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
      <div class="spectrum-advisory-card stat">
        <div class="spectrum-advisory-value k">Channel ${cleanestCh}</div>
        <div class="spectrum-advisory-label l">Least crowded channel</div>
        <div class="spectrum-advisory-desc">${plural(cleanestCci, "network", "networks")} on it${is5 ? "" : `, ${beside} on the channels either side`}.</div>
      </div>
      <div class="spectrum-advisory-card stat">
        <div class="spectrum-advisory-value k">${connCh ? `Channel ${connCh}` : "&mdash;"}</div>
        <div class="spectrum-advisory-label l">Your channel</div>
        <div class="spectrum-advisory-desc">${connCh
          ? (shared ? `Shared with ${plural(shared, "other network", "other networks")}; they compete for airtime.` : "No other network in range uses it.")
          : `Not connected in the ${is5 ? "5" : "2.4"} GHz band.`}</div>
      </div>
      <div class="spectrum-advisory-card stat">
        <div class="spectrum-advisory-value k">${bandNetworks.length}</div>
        <div class="spectrum-advisory-label l">Networks in this band</div>
        <div class="spectrum-advisory-desc">${is5 ? "5 GHz" : "2.4 GHz"} access points this machine can hear.</div>
      </div>
    `;
  }

  // Dimensions
  const svgW = 920;
  const svgH = 295;
  const marginLeft = 60;
  const marginRight = 25;
  const marginTop = 28;
  const marginBottom = 50;
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

  // Accessible title & description for screen readers
  svgContent += `
    <title id="sp-chart-title">Wi-Fi channel use (${is5 ? "5 GHz" : "2.4 GHz"})</title>
    <desc id="sp-chart-desc">Spectrum graph showing ${bandNetworks.length} networks across channels. ${connectedNet ? "Connected to " + esc(connectedNet.ssid) + " on channel " + connCh + "." : "Not connected."} The least crowded channel is ${cleanestCh}.</desc>
  `;

  // Y-axis title
  svgContent += `
    <text class="sp-axis-title" x="${marginLeft}" y="${yTop - 10}" text-anchor="start">Signal (dBm)</text>
  `;

  // Horizontal power gridlines (-30, -50, -70, -90 dBm)
  [-30, -50, -70, -90].forEach(lvl => {
    const y = dbmToY(lvl);
    svgContent += `
      <line class="sp-grid" x1="${marginLeft}" y1="${y.toFixed(1)}" x2="${(marginLeft + plotW).toFixed(1)}" y2="${y.toFixed(1)}" stroke-dasharray="2 4"/>
      <text class="sp-axis" x="${marginLeft - 8}" y="${(y + 4).toFixed(1)}" text-anchor="end" font-size="12">${lvl} dBm</text>
    `;
  });

  // Base X-axis line & title
  svgContent += `
    <line class="sp-base" x1="${marginLeft}" y1="${yBase}" x2="${(marginLeft + plotW).toFixed(1)}" y2="${yBase}" stroke-width="1.5"/>
    <text class="sp-axis-title" x="${(marginLeft + plotW / 2).toFixed(1)}" y="${yBase + 38}" text-anchor="middle">Channel (${is5 ? "5 GHz" : "2.4 GHz"} band)</text>
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
          <text class="sp-clean" x="${x.toFixed(1)}" y="${yBase + 18}" text-anchor="middle" font-size="12">${ch}</text>
        `;
      } else {
        svgContent += `
          <line class="sp-base" x1="${x.toFixed(1)}" y1="${yBase}" x2="${x.toFixed(1)}" y2="${yBase + 5}"/>
          <text class="sp-axis" x="${x.toFixed(1)}" y="${yBase + 18}" text-anchor="middle" font-size="12">${ch}</text>
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
        <text class="${isClean ? 'sp-clean' : 'sp-axis'}" x="${x.toFixed(1)}" y="${yBase + 18}" text-anchor="middle" font-size="12">${ch}</text>
      `;
    });

    // Sub-labels for UNII zones
    svgContent += `
      <text x="${fToX(5210).toFixed(1)}" y="${yTop + 10}" class="sp-axis" font-size="12" text-anchor="middle">UNII-1 (36-48)</text>
      <text x="${fToX(5290).toFixed(1)}" y="${yTop + 10}" class="sp-axis" font-size="12" text-anchor="middle">UNII-2 DFS (52-64)</text>
      <text x="${fToX(5600).toFixed(1)}" y="${yTop + 10}" class="sp-axis" font-size="12" text-anchor="middle">UNII-2e (100-144)</text>
      <text x="${fToX(5785).toFixed(1)}" y="${yTop + 10}" class="sp-axis" font-size="12" text-anchor="middle">UNII-3 (149-165)</text>
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

  // Collision detection tracking for AP labels using bounding boxes.
  // Prevents collisions between any direct labels (e.g. Lab-Guest and Annex-Printer
  // sharing Channel 11) and curve peaks.
  const obstacles = [];
  sorted.forEach((n) => {
    const fc = getWifiCenterFreq(parseInt(n.channel, 10), n.band);
    if (!fc || fc < fMin || fc > fMax || (!n.rssi_dbm && !n.signal_percent)) return;
    const rssi = n.rssi_dbm || Math.round(-100 + (n.signal_percent * 0.7));
    const px = fToX(fc);
    const py = dbmToY(rssi);
    obstacles.push({
      left: px - 12,
      right: px + 12,
      top: py - 10,
      bottom: py + 10,
      peakFor: n
    });
  });

  function labelBox(x, y, text) {
    const w = Math.max(78, Math.min(140, (text || "").length * 7.5 + 14));
    return {
      left: x - w / 2,
      right: x + w / 2,
      top: y - 13,
      bottom: y + 4,
      width: w,
      height: 17
    };
  }

  function collides(b1, b2, padX = 8, padY = 5) {
    return !(
      b1.right + padX < b2.left ||
      b1.left - padX > b2.right ||
      b1.bottom + padY < b2.top ||
      b1.top - padY > b2.bottom
    );
  }

  // Render AP bell curves
  sorted.forEach((n) => {
    const ch = parseInt(n.channel, 10);
    const fc = getWifiCenterFreq(ch, n.band);
    if (!fc || fc < fMin || fc > fMax) return;

    // no reported signal, no curve: a guessed height would read as a measurement
    if (!n.rssi_dbm && !n.signal_percent) return;
    const rssi = n.rssi_dbm || Math.round(-100 + (n.signal_percent * 0.7));
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

    const tooltipData = esc(JSON.stringify({
      ssid: n.ssid || "(Hidden SSID)",
      bssid: n.bssid || "—",
      channel: ch,
      freq: `${fc} MHz`,
      rssi: `${rssi} dBm` + (n.signal_percent ? ` (${n.signal_percent}%)` : ""),
      sec: [n.authentication, n.encryption].filter(Boolean).join(" / ") || "not reported",
      status: n.is_rogue ? "Possible evil twin" : (n.connected ? "Connected" : "Other network")
    }));

    const labelText = `${n.ssid ? n.ssid.slice(0, 14) : 'AP'} (${rssi})`;
    const estBox = labelBox(xc, yPeak - 10, labelText);
    const halfW = estBox.width / 2;
    const clampX = (x) => Math.max(marginLeft + halfW + 6, Math.min(svgW - marginRight - halfW - 6, x));

    // Candidate positions: above peak, higher tiers, staggered offsets left/right, and below peak
    const candidateOffsets = [
      { dx: 0, dy: -10 },
      { dx: 0, dy: -28 },
      { dx: 0, dy: -46 },
      { dx: -70, dy: -12 },
      { dx: 70, dy: -12 },
      { dx: -70, dy: -30 },
      { dx: 70, dy: -30 },
      { dx: -100, dy: -14 },
      { dx: 100, dy: -14 },
      { dx: 0, dy: 22 },
      { dx: -70, dy: 22 },
      { dx: 70, dy: 22 },
      { dx: 0, dy: -64 },
      { dx: -120, dy: -28 },
      { dx: 120, dy: -28 },
      { dx: 0, dy: 40 }
    ];

    let chosenX = xc;
    let chosenY = yPeak - 10;
    let foundSlot = false;

    for (const offset of candidateOffsets) {
      const candX = clampX(xc + offset.dx);
      const candY = yPeak + offset.dy;
      const box = labelBox(candX, candY, labelText);

      // Must remain within chart vertical bounds
      if (box.top < marginTop + 8 || box.bottom > yBase - 6) continue;

      let hit = false;
      for (const obs of obstacles) {
        if (obs.peakFor === n) continue; // ignore network's own peak
        if (collides(box, obs)) {
          hit = true;
          break;
        }
      }
      if (!hit) {
        chosenX = candX;
        chosenY = candY;
        foundSlot = true;
        break;
      }
    }

    if (!foundSlot) {
      chosenX = clampX(xc);
      chosenY = Math.max(marginTop + 14, yPeak - 10 - ((obstacles.length % 5) * 16));
    }

    // Register chosen label box as an obstacle for subsequent networks
    obstacles.push(labelBox(chosenX, chosenY, labelText));

    // Staggered leader line connecting displaced label to curve peak
    let leaderLine = "";
    if (Math.hypot(chosenX - xc, chosenY - yPeak) > 16) {
      const lineY = chosenY < yPeak ? chosenY + 3 : chosenY - 13;
      leaderLine = `<line class="sp-leader" x1="${chosenX.toFixed(1)}" y1="${lineY.toFixed(1)}" x2="${xc.toFixed(1)}" y2="${yPeak.toFixed(1)}" stroke-dasharray="2 2" stroke-width="1.2" opacity="0.65"/>`;
    }

    svgContent += `
      <g class="spectrum-curve-group sp-ap ${kind}">
        <path d="${pathD}" stroke-width="${strokeWidth}" class="curve-path" data-spec="${tooltipData}"/>
        ${leaderLine}
        <circle cx="${xc.toFixed(1)}" cy="${yPeak.toFixed(1)}" r="${n.is_rogue || n.connected ? '4' : '2.5'}"/>
        <text x="${chosenX.toFixed(1)}" y="${chosenY.toFixed(1)}" font-size="12" font-weight="${n.is_rogue || n.connected ? '700' : '500'}" text-anchor="middle">
          ${esc(labelText)}
        </text>
      </g>
    `;
  });

  svg.setAttribute("role", "img");
  svg.setAttribute("aria-labelledby", "sp-chart-title sp-chart-desc");
  svg.innerHTML = svgContent;

  // Tooltip interaction
  const tooltip = $("spectrum-tooltip");
  if (tooltip) {
    svg.querySelectorAll(".curve-path").forEach(path => {
      path.addEventListener("mouseenter", (e) => {
        try {
          const d = JSON.parse(path.getAttribute("data-spec"));
          tooltip.innerHTML = `
            <div class="tt-title">${esc(d.ssid)}</div>
            <div class="tt-bssid">${esc(d.bssid)}</div>
            <div class="tt-gap"><strong>Channel:</strong> ${esc(d.channel)} (${esc(d.freq)})</div>
            <div><strong>Signal:</strong> ${esc(d.rssi)}</div>
            <div><strong>Security:</strong> ${esc(d.sec)}</div>
            <div class="tt-status">${esc(d.status)}</div>
          `;
          tooltip.hidden = false;
        } catch (err) {}
      });

      path.addEventListener("mousemove", (e) => {
        const wrap = svg.parentElement;
        const rect = wrap.getBoundingClientRect();
        const x = e.clientX - rect.left + 15;
        const y = e.clientY - rect.top - 10;
        tooltip.style.setProperty("--x", `${Math.min(x, rect.width - 200)}px`);
        tooltip.style.setProperty("--y", `${Math.max(10, y)}px`);
      });

      path.addEventListener("mouseleave", () => {
        tooltip.hidden = true;
      });
    });
  }
}
