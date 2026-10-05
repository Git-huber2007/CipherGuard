/* CipherGuard dashboard. Live capture: start, stop, the packet stream and the SA grid. */
"use strict";

/* ---------------------------------------------- live capture stream */
const LiveSnifferEngine = (function() {
  let streamAbort = null;
  let isSniffing = false;
  let currentMode = "idle";   // the server's word for it: live_socket | replay | idle
  const knownSpis = {};

  /* `replay` is only ever true from the Replay button. A live capture that
   * cannot start shows the server's reason and stays stopped; it is never
   * swapped for sample traffic. */
  async function startSniffing(replay) {
    replay = replay === true;
    const ifaceSelect = $("sniffer-iface-select");
    const iface = ifaceSelect ? ifaceSelect.value : "All Interfaces";

    try {
      const res = await api("/api/sniff/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ interface: iface, replay }),
      });
      const st = await res.json();
      resetFeed();
      updateUIState(true, st.mode);
      connectStream();
      showToast(st.mode === "replay"
        ? "Replaying the sample captures. This is not live traffic."
        : "Live capture started", "info");
    } catch(err) {
      updateUIState(false, "failed", err.message);
      showToast((replay ? "Replay could not start: " : "Live capture could not start: ") + err.message, "error");
    }
  }

  async function stopSniffing() {
    try {
      await api("/api/sniff/stop", { method: "POST" });
      disconnectStream();
      updateUIState(false, "idle");
      showToast("Capture stopped", "info");
    } catch(err) {
      showToast("Failed to stop sniffer: " + err.message, "error");
    }
  }

  function disconnectStream() {
    if (streamAbort) streamAbort.abort();
    streamAbort = null;
  }

  /* One server-sent event: "event: <name>" and "data: <json>" lines. */
  function dispatchEvent(block) {
    let name = "message", data = "";
    for (const line of block.split("\n")) {
      if (line.startsWith("event:")) name = line.slice(6).trim();
      else if (line.startsWith("data:")) data += line.slice(5).trim();
    }
    if (!data) return;
    let parsed;
    try { parsed = JSON.parse(data); } catch (e) { return; }
    if (name === "packet") handlePacket(parsed);
    else if (name === "status" || name === "heartbeat") updateCounters(parsed);
  }

  /* The stream is read with fetch(), not EventSource: EventSource cannot send
   * an Authorization header, and the endpoint requires the token like every
   * other data route. The token never goes in the URL. */
  async function connectStream() {
    disconnectStream();
    const controller = new AbortController();
    streamAbort = controller;
    try {
      const res = await fetch(resolveApiPath("/api/sniff/stream"), {
        headers: authHeaders({ "Accept": "text/event-stream" }),
        cache: "no-store",
        signal: controller.signal,
      });
      if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let cut;
        while ((cut = buffer.indexOf("\n\n")) !== -1) {
          dispatchEvent(buffer.slice(0, cut));
          buffer = buffer.slice(cut + 2);
        }
      }
    } catch (err) {
      if (controller.signal.aborted) return;
      console.warn("Capture stream ended:", err);
    }
    // dropped while a capture is still running: try again, as EventSource did
    if (streamAbort === controller && isSniffing) setTimeout(() => {
      if (streamAbort === controller && isSniffing) connectStream();
    }, 2000);
  }

  function resetFeed() {
    const feed = $("sniffer-live-feed");
    if (feed) feed.innerHTML = "";
    const grid = $("sniffer-spis-grid");
    if (grid) grid.innerHTML = `<div class="empty">None seen yet.</div>`;
    for (const k of Object.keys(knownSpis)) delete knownSpis[k];
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
    // The label follows what the server says is running, so a capture that
    // stopped on its own (the socket failed) does not stay marked as live.
    if (isSniffing && st.running === false) {
      disconnectStream();
      updateUIState(false, st.error ? "failed" : "idle", st.error);
    } else if (st.running && st.mode !== currentMode) {
      updateUIState(true, st.mode);
    }
  }

  /* What the status card says. Replay is spelled out as replay everywhere it
   * appears, so sample traffic is never read as traffic from this machine. */
  function statusLabel(active, mode) {
    if (!active) {
      return mode === "failed"
        ? '<span class="hud-dot idle"></span> COULD NOT START'
        : '<span class="hud-dot idle"></span> IDLE';
    }
    return mode === "replay"
      ? '<span class="hud-dot replay"></span> REPLAY · SAMPLES, NOT LIVE'
      : '<span class="hud-dot live"></span> LIVE CAPTURE';
  }

  function updateUIState(active, mode, reason) {
    isSniffing = active;
    currentMode = active ? (mode || "live_socket") : "idle";
    const btnStart = $("btn-sniffer-start");
    const btnReplay = $("btn-sniffer-replay");
    const btnStop = $("btn-sniffer-stop");
    const btnAnalyze = $("btn-sniffer-analyze");
    const statusVal = $("sniffer-status-val");
    const notice = $("sniffer-source-notice");

    if (btnStart) btnStart.disabled = active;
    if (btnReplay) btnReplay.disabled = active;
    if (btnStop) btnStop.disabled = !active;
    if (btnAnalyze) btnAnalyze.disabled = !active;

    if (statusVal) statusVal.innerHTML = statusLabel(active, mode);

    if (notice) {
      if (active && mode === "replay") {
        notice.hidden = false;
        notice.className = "banner sniffer-source-notice";
        notice.textContent = "Replaying the bundled sample captures. These packets are not " +
          "live traffic from this machine, and anything assessed from them is labelled as a replay.";
      } else if (!active && mode === "failed") {
        notice.hidden = false;
        notice.className = "banner sniffer-source-notice";
        notice.textContent = (reason || "Live capture could not start.") +
          " Nothing is being captured. To see the panel working without live traffic, choose Replay samples.";
      } else {
        notice.hidden = true;
        notice.textContent = "";
      }
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
      const fromReplay = data.capture_source === "replay";
      showToast(fromReplay ? "Replayed sample packets assessed" : "Captured packets assessed", "success");
      switchIpsecMode("single");
      await renderAssessment(data);
      // after the render, which resets the banner for a fresh assessment
      if (fromReplay) showBanner(
        "This assessment is of replayed sample captures, not of live traffic from this machine.");
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
    const btnReplay = $("btn-sniffer-replay");
    const btnStop = $("btn-sniffer-stop");
    const btnAnalyze = $("btn-sniffer-analyze");

    if (btnStart) btnStart.addEventListener("click", () => startSniffing(false));
    if (btnReplay) btnReplay.addEventListener("click", () => startSniffing(true));
    if (btnStop) btnStop.addEventListener("click", stopSniffing);
    if (btnAnalyze) btnAnalyze.addEventListener("click", analyzeSnapshot);
  }

  return { init, startSniffing, stopSniffing, analyzeSnapshot };
})();
window.LiveSnifferEngine = LiveSnifferEngine;
