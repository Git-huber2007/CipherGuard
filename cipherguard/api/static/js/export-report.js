/* CipherGuard dashboard. The printable executive & engineering report. */
"use strict";

/* ------------------------------------------------------- printable report */

const REPORT_SEVERITIES = ["critical", "high", "medium", "low", "info"];

/**
 * Extract wire ribbon fields for the specified or worst link in the assessment.
 */
function collectReportRibbon(a) {
  if (!a) return null;
  const link = (state.selectedLink && (a.links || []).find(l => l.id === state.selectedLink))
    || (a.links && a.links[0])
    || null;

  const parts = [
    { d: "obs", n: "IP header",        v: link ? `${link.peers[0]} ↔ ${link.peers[1]}` : "peer addresses, protocol" },
    { d: "obs", n: "UDP 500 / 4500",   v: "IKE or NAT-T encapsulation" },
    { d: "obs", n: "IKE header",       v: "SPIs, exchange type, flags" },
    { d: "obs", n: "SA proposal",      v: "cipher, PRF, integrity, DH group" },
    { d: "obs", n: "KE / Nonce / VID", v: "group, vendor fingerprint" },
    { d: "seam", n: "Key boundary",    v: "fields after this are encrypted" },
    { d: "inf", n: "SK payload",       v: "child SA proposal — encrypted" },
    { d: "inf", n: "ESP header",       v: "SPI, sequence number" },
    { d: "inf", n: "ESP ciphertext",   v: "suite inferred from framing" }
  ];

  const s = link ? a.sessions[link.sessions[0]] : (a.sessions || [])[0];
  const f = link ? a.flows[link.flows[0]] : (a.flows || [])[0];

  if (s) {
    const prop = typeof pickIkeProposal === "function" ? pickIkeProposal(s) : null;
    parts[2].v = `${s.version || "IKE"} · initiator SPI ${s.initiator_spi || "—"}`;
    if (prop && prop.transforms) {
      parts[3].v = prop.transforms.map(t => typeof pretty === "function" ? pretty(t) : t).join(" · ");
    }
    const vid = (s.vendor_ids || [])[0];
    if (vid) parts[4].v = vid;
  } else if (link) {
    parts[2].v = parts[3].v = parts[4].v = "no IKE observed on this link";
  }

  if (f) {
    if (f.encapsulated) parts[1].v = "UDP 4500 · ESP in NAT-T";
    const pktCount = (typeof Fmt !== "undefined" && Fmt.count) ? Fmt.count(f.packets) : f.packets;
    parts[7].v = `SPI ${f.spi} · ${pktCount} packets` + (link && link.tunnels > 1 ? ` · 1 of ${link.tunnels} tunnels` : "");
    const conf = f.framing_confidence ?? f.confidence ?? 0;
    const confStr = Fmt.percent(conf);
    parts[8].v = `${f.framing_class || f.predicted_suite || "unresolved"} (${confStr})`;
  } else if (link) {
    parts[7].v = parts[8].v = "no ESP observed on this link";
  }

  return {
    link_label: link ? `${link.peers[0]} ↔ ${link.peers[1]}` : "Primary link",
    parts
  };
}

/**
 * Gather hardening playbooks from live state or cached assessment remediation.
 */
function collectReportRemediation(a) {
  if (state.remediationPlans && state.remediationPlans.length) {
    return state.remediationPlans.map(p => ({
      platform: p.platform_name || p.platform,
      status: p.status || "DRAFTED",
      approver: p.approver || null,
      syntax_valid: p.syntax_valid != null ? p.syntax_valid : true,
      forward_config: p.forward_config || "",
      rollback_config: p.rollback_config || ""
    }));
  }
  if (a && a.remediation && typeof a.remediation === "object") {
    const platformNames = {
      strongswan: "strongSwan (swanctl)",
      cisco: "Cisco IOS / IOS-XE",
      fortinet: "Fortinet FortiOS",
      juniper: "Juniper SRX (Junos)"
    };
    return Object.entries(a.remediation).map(([plat, txt]) => ({
      platform: platformNames[plat] || plat,
      status: "DRAFTED",
      approver: null,
      syntax_valid: true,
      forward_config: typeof txt === "string" ? txt : JSON.stringify(txt, null, 2),
      rollback_config: ""
    }));
  }
  return [];
}

/**
 * Build the complete report document object.
 */
function collectReport(){
  const a = state.assessment;
  const wifi = state.wifiAssessment;
  const vpn = (wifi && wifi.vpn) || null;
  return {
    generated: new Date().toISOString(),
    tool: "CipherGuard" + (state.health && state.health.version ? " " + state.health.version : ""),
    ipsec: a ? {
      capture: a.capture,
      assessed: a.started,
      score: a.score,
      grade: a.grade,
      counts: a.counts || {},
      sessions: (a.sessions || []).length,
      flows: (a.flows || []).length,
      links_count: (a.links || []).length,
      capture_sha256: (a.provenance && a.provenance.capture_sha256) || null,
      report_digest: (a.provenance && a.provenance.report_digest) || a.digest || null,
      disabled_rules: (a.stats && a.stats.disabled_rules) || [],
      findings: a.findings || [],
      ribbon: collectReportRibbon(a)
    } : null,
    wifi: wifi ? {
      source: state.wifiIsLive ? "scan" : "example",
      score: wifi.score,
      grade: wifi.grade,
      interface: wifi.interface || null,
      vpn,
      findings: [...(wifi.findings || []), ...((vpn && vpn.findings) || [])]
    } : null,
    remediation_plans: collectReportRemediation(a)
  };
}

/**
 * Generate high-density printable HTML matching DESIGN.md and UX-copy rules.
 */
function reportHtml(r){
  const v = x => (x === null || x === undefined || x === "") ? "\u2014" : esc(x);
  const row = (k, value) => `<tr><th scope="row">${esc(k)}</th><td>${value}</td></tr>`;

  // UX-copy helper: format number words for plain sentence headings
  const numWord = n => {
    const words = ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten"];
    return n <= 10 ? words[n] : String(n);
  };

  // UX-copy helper: plain sentence headings for severity groups
  const sevGroupSentence = (sev, count) => {
    const nw = numWord(count);
    switch (sev) {
      case "critical":
        return `${nw} critical ${count === 1 ? "finding requires" : "findings require"} immediate mitigation.`;
      case "high":
        return `${nw} high-severity ${count === 1 ? "finding indicates" : "findings indicate"} vulnerable cryptographic algorithms.`;
      case "medium":
        return `${nw} medium-severity ${count === 1 ? "finding indicates" : "findings indicate"} legacy cryptographic choices.`;
      case "low":
        return `${nw} low-severity ${count === 1 ? "finding represents" : "findings represent"} configuration hygiene improvements.`;
      case "info":
      default:
        return `${nw} informational ${count === 1 ? "finding documents" : "findings document"} observed operational parameters.`;
    }
  };

  // Grade narrative matching DESIGN.md epistemic posture thresholds
  const gradeSummary = (score, grade) => {
    if (score >= 90) return "Post-quantum hybrid security or robust modern algorithms protect all monitored links.";
    if (score >= 75) return "Modern cryptographic standards are enforced with minor legacy parameters observed.";
    if (score >= 50) return "Deprecated algorithms or key exchange modes introduce operational security risks.";
    if (score >= 25) return "Severe protocol vulnerabilities and weak ciphers were detected on the wire.";
    return "Critical vulnerabilities and unauthenticated key exchanges compromise confidentiality.";
  };

  let body = "";

  if (r.ipsec){
    const i = r.ipsec;
    const counts = i.counts || {};
    const ribbon = i.ribbon || { parts: [] };

    // Group findings strictly by severity
    const groupedFindings = {};
    for (const s of REPORT_SEVERITIES) groupedFindings[s] = [];
    for (const f of (i.findings || [])) {
      const s = (f.severity || "info").toLowerCase();
      if (groupedFindings[s]) groupedFindings[s].push(f);
      else groupedFindings.info.push(f);
    }

    // 1. Posture Hero Block
    body += `
      <section class="report-section posture-section">
        <h2 class="section-title">The overall cryptographic posture scored ${v(i.score)} out of 100 with grade ${v(i.grade)}.</h2>
        <div class="posture-hero-card">
          <div class="score-dial grade-${esc(String(i.grade).toLowerCase())}">
            <div class="score-val">${v(i.score)}</div>
            <div class="score-max">/ 100</div>
            <div class="score-grade">Grade ${v(i.grade)}</div>
          </div>
          <div class="posture-meta">
            <p class="posture-narrative">${esc(gradeSummary(i.score, i.grade))}</p>
            <div class="posture-metrics-strip">
              <div class="p-metric"><span class="pm-val crit">${counts.critical || 0}</span><span class="pm-lbl">Critical</span></div>
              <div class="p-metric"><span class="pm-val high">${counts.high || 0}</span><span class="pm-lbl">High</span></div>
              <div class="p-metric"><span class="pm-val med">${counts.medium || 0}</span><span class="pm-lbl">Medium</span></div>
              <div class="p-metric"><span class="pm-val low">${counts.low || 0}</span><span class="pm-lbl">Low</span></div>
              <div class="p-metric"><span class="pm-val info">${counts.info || 0}</span><span class="pm-lbl">Info</span></div>
              <div class="p-divider"></div>
              <div class="p-metric"><span class="pm-val">${v(i.sessions)}</span><span class="pm-lbl">IKE sessions</span></div>
              <div class="p-metric"><span class="pm-val">${v(i.flows)}</span><span class="pm-lbl">ESP tunnels</span></div>
            </div>
          </div>
        </div>
      </section>`;

    // 2. Wire Ribbon Block
    if (ribbon && ribbon.parts && ribbon.parts.length){
      const ribbonFields = ribbon.parts.map(p => {
        if (p.d === "seam") {
          return `
            <div class="report-ribbon-seam" role="separator" title="Key boundary">
              <div class="r-seam-bar"></div>
              <div class="r-seam-label">key boundary</div>
              <div class="r-seam-bar"></div>
            </div>`;
        }
        return `
          <div class="report-ribbon-field ${p.d}">
            <div class="r-field-name">${typeof formatRibbonHex === "function" ? formatRibbonHex(esc(p.n)) : esc(p.n)}</div>
            <div class="r-field-val">${typeof formatRibbonHex === "function" ? formatRibbonHex(esc(p.v)) : esc(p.v)}</div>
          </div>`;
      }).join("");

      body += `
        <section class="report-section wire-section">
          <h2 class="section-title">The wire ribbon displays packet framing across the cryptographic key boundary.</h2>
          <p class="section-lede">Cleartext fields on the left were parsed from wire headers, while encrypted fields on the right were inferred from packet framing without decryption.</p>
          <div class="wire-ribbon-wrap">
            <div class="wire-ribbon-header">
              <span class="w-link-tag">Link</span>
              <span class="w-link-peers">${esc(ribbon.link_label || "Monitored Link")}</span>
            </div>
            <div class="wire-ribbon-body">
              ${ribbonFields}
            </div>
          </div>
          <div class="wire-legend">
            <span class="legend-chip"><span class="swatch obs"></span> Observed cleartext wire parameters</span>
            <span class="legend-chip"><span class="swatch seam"></span> Cryptographic key boundary seam</span>
            <span class="legend-chip"><span class="swatch inf"></span> Inferred ciphertext framing parameters</span>
          </div>
        </section>`;
    }

    // 3. Findings Grouped by Severity
    body += `
      <section class="report-section findings-section">
        <h2 class="section-title">Identified security findings are grouped by severity level.</h2>`;

    let totalFindings = 0;
    for (const sev of REPORT_SEVERITIES){
      const list = groupedFindings[sev];
      if (!list || !list.length) continue;
      totalFindings += list.length;

      body += `
        <div class="findings-group group-${sev}">
          <h3 class="group-title"><span class="sev-sq ${sev}"></span> ${esc(sevGroupSentence(sev, list.length))}</h3>
          <div class="group-items">
            ${list.map(f => `
              <article class="report-finding ${sev}">
                <div class="f-head">
                  <span class="f-rule">${v(f.rule_id)}</span>
                  <h4 class="f-title">${esc(f.title.trim().endsWith(".") ? f.title : f.title + ".")}</h4>
                </div>
                <div class="f-target"><b>Observed target:</b> <code>${v(f.subject)}</code></div>
                <p class="f-detail">${v(f.detail)}</p>
                ${f.remediation ? `<div class="f-fix"><b>Remediation guidance:</b> ${esc(f.remediation)}</div>` : ""}
              </article>
            `).join("")}
          </div>
        </div>`;
    }

    if (totalFindings === 0) {
      body += `<p class="empty-state">No cryptographic findings were detected in this assessment.</p>`;
    }

    body += `</section>`;
  }

  // 4. Hardening Plan Block
  if (r.remediation_plans && r.remediation_plans.length){
    body += `
      <section class="report-section hardening-section">
        <h2 class="section-title">The hardening plan provides verified configuration commands for gateway remediation.</h2>`;

    for (const p of r.remediation_plans){
      body += `
        <div class="plan-card">
          <div class="plan-header">
            <h3 class="plan-title">Remediation commands for ${esc(p.platform)} are structured below.</h3>
            <div class="plan-badges">
              <span class="plan-badge ${p.syntax_valid ? 'badge-ok' : 'badge-err'}">
                ${p.syntax_valid ? 'Syntax validation passed.' : 'Syntax validation failed.'}
              </span>
              <span class="plan-badge badge-status">Status: ${esc(p.status || 'DRAFTED')}.</span>
            </div>
          </div>
          ${p.forward_config ? `
            <div class="code-block">
              <div class="code-label">Forward remediation configuration</div>
              <pre><code>${esc(p.forward_config)}</code></pre>
            </div>` : ""}
          ${p.rollback_config ? `
            <div class="code-block rollback">
              <div class="code-label">Rollback configuration</div>
              <pre><code>${esc(p.rollback_config)}</code></pre>
            </div>` : ""}
        </div>`;
    }

    body += `</section>`;
  } else if (r.ipsec) {
    body += `
      <section class="report-section hardening-section">
        <h2 class="section-title">The hardening plan provides verified configuration commands for gateway remediation.</h2>
        <p class="empty-state">No hardening plan was generated for this session.</p>
      </section>`;
  }

  // 5. Wi-Fi Assessment Block (if present)
  if (r.wifi){
    const w = r.wifi;
    const iface = w.interface || {};
    const vpn = w.vpn;
    body += `
      <section class="report-section wifi-section">
        <h2 class="section-title">The Wi-Fi assessment evaluated wireless authentication and link parameters.</h2>
        ${w.source === "example" ? `<p class="note warn">This section describes the bundled synthetic capture and does not reflect a live site survey.</p>` : ""}
        <table class="report-table">
          ${row("Network SSID", v(iface.ssid))}
          ${row("Access point BSSID", `<code>${v(iface.bssid)}</code>`)}
          ${row("Cryptographic posture", `${v(w.score)}/100, Grade ${v(w.grade)}`)}
          ${row("Authentication & cipher", `${v(iface.authentication)} / ${v(iface.cipher)}`)}
          ${row("Band & channel", `${v(iface.band)}, channel ${v(iface.channel)}`)}
          ${row("DNS resolvers", v((iface.dns_servers || []).join(", ")))}
          ${vpn ? row("VPN tunnel", vpn.connected ? `connected (${v(vpn.vpn_type)})` : "not connected") : ""}
          ${vpn && vpn.connected ? row("DNS leak status", vpn.dns_leak_detected ? "leak detected" : "clean (no leaks)") : ""}
        </table>
        ${(w.findings && w.findings.length) ? `
          <div class="wifi-findings-wrap">
            <h3 class="group-title">${numWord(w.findings.length)} wireless ${w.findings.length === 1 ? "finding requires" : "findings require"} review.</h3>
            ${w.findings.map(f => `
              <article class="report-finding ${esc(f.severity || 'info')}">
                <div class="f-head">
                  <span class="f-rule">${v(f.rule_id)}</span>
                  <h4 class="f-title">${esc(f.title.trim().endsWith(".") ? f.title : f.title + ".")}</h4>
                </div>
                <p class="f-detail">${v(f.detail)}</p>
                ${f.remediation ? `<div class="f-fix"><b>Remediation guidance:</b> ${esc(f.remediation)}</div>` : ""}
              </article>
            `).join("")}
          </div>
        ` : `<p class="empty-state">No wireless security findings were detected in this assessment.</p>`}
      </section>`;
  }

  // 6. Cryptographic Provenance Block
  if (r.ipsec){
    const i = r.ipsec;
    body += `
      <section class="report-section provenance-section">
        <h2 class="section-title">Cryptographic provenance verifies report integrity and capture checksums.</h2>
        <table class="report-table">
          ${row("Capture SHA-256", `<code>${v(i.capture_sha256)}</code>`)}
          ${row("Audit report digest", `<code>${v(i.report_digest)}</code>`)}
          ${row("Assessment engine", v(r.tool))}
          ${row("Timestamp", v(r.generated))}
          ${i.disabled_rules && i.disabled_rules.length ? row("Rules switched off", esc(i.disabled_rules.join(", "))) : row("Active rules", "All cryptographic rules remained active.")}
        </table>
        <p class="epistemic-disclaimer">Zero-payload wire assurance: Cleartext IKE parameters are parsed directly. ESP suites are inferred from packet framing and block alignment. Nothing is decrypted.</p>
      </section>`;
  }

  const captureName = (r.ipsec && r.ipsec.capture) || (r.wifi && r.wifi.interface && r.wifi.interface.ssid) || "Capture";
  const reportDigest = (r.ipsec && r.ipsec.report_digest) || "VERIFIED-RECORD";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CipherGuard assessment report \u00b7 ${esc(captureName)}</title>
<style>
  :root {
    --ink: #14212b;
    --muted: #4b5a66;
    --faint: #596975;
    --surface: #ffffff;
    --sunk: #f4f6f8;
    --rule: #c3cfd8;
    --rule-light: #e4ebf0;
    --observed: #1b6e8c;
    --observed-bg: #e2eff4;
    --inferred: #6d4e9c;
    --inferred-bg: #ece5f5;
    --crit: #a81e13;
    --high: #a84b1d;
    --med: #7d630e;
    --low: #3a6b8a;
    --info: #5b6872;
    --ok: #1f6b4a;
    --sans: "IBM Plex Sans", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    --mono: "IBM Plex Mono", ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  }

  @page {
    size: A4 portrait;
    margin: 16mm 14mm 18mm 14mm;
    @bottom-right {
      content: "Page " counter(page) " of " counter(pages);
      font-family: var(--mono);
      font-size: 8pt;
      color: var(--muted);
    }
    @bottom-left {
      content: "CipherGuard \u00b7 Cryptographic assessment report";
      font-family: var(--sans);
      font-size: 8pt;
      color: var(--muted);
    }
  }

  * { box-sizing: border-box; }
  body {
    font-family: var(--sans);
    line-height: 1.5;
    color: var(--ink);
    background: #e9edf0;
    margin: 0;
    padding: 24px 12px;
    font-size: 13px;
    font-variant-numeric: tabular-nums;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }

  .report-page-container {
    max-width: 860px;
    margin: 0 auto;
    background: var(--surface);
    border: 1px solid var(--rule);
    border-radius: 8px;
    box-shadow: 0 4px 24px rgba(20, 33, 43, 0.08);
    padding: 36px 40px;
  }

  /* Screen toolbar (Hidden in print) */
  .toolbar {
    max-width: 860px;
    margin: 0 auto 16px;
    display: flex;
    justify-content: flex-end;
    gap: 12px;
  }
  .toolbar button {
    font-family: var(--sans);
    font-size: 13px;
    font-weight: 600;
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    border: 1px solid var(--ink);
    background: var(--ink);
    color: #ffffff;
    transition: background 0.15s ease, transform 0.1s ease;
  }
  .toolbar button:hover { background: #243442; }
  .toolbar button.secondary {
    background: var(--surface);
    color: var(--ink);
    border-color: var(--rule);
  }
  .toolbar button.secondary:hover { background: var(--sunk); border-color: var(--ink); }

  /* Title Block */
  .report-header {
    border-bottom: 2px solid var(--ink);
    padding-bottom: 20px;
    margin-bottom: 24px;
  }
  .report-badge-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
  }
  .report-brand-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--observed);
    background: var(--observed-bg);
    padding: 3px 10px;
    border-radius: 4px;
  }
  .report-id-chip {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
  }
  .report-id-chip code { font-weight: 600; color: var(--ink); }
  h1.report-main-title {
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.015em;
    color: var(--ink);
    margin: 0 0 16px;
    line-height: 1.3;
  }
  .report-meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    background: var(--sunk);
    border: 1px solid var(--rule-light);
    border-radius: 6px;
    padding: 12px 16px;
  }
  .meta-cell { display: flex; flex-direction: column; gap: 2px; }
  .meta-cell .m-lbl { font-size: 11px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
  .meta-cell .m-val { font-size: 13px; color: var(--ink); overflow-wrap: anywhere; }
  .meta-cell .m-val code { font-family: var(--mono); font-size: 12px; }

  /* Section Common */
  .report-section {
    margin-bottom: 28px;
    break-inside: avoid;
    page-break-inside: avoid;
  }
  h2.section-title {
    font-size: 16px;
    font-weight: 700;
    color: var(--ink);
    margin: 0 0 12px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--rule);
    letter-spacing: -0.01em;
    break-after: avoid;
    page-break-after: avoid;
  }
  .section-lede {
    font-size: 13px;
    color: var(--muted);
    margin: 0 0 14px;
    max-width: 90ch;
  }

  /* Posture Hero */
  .posture-hero-card {
    display: flex;
    align-items: stretch;
    border: 1px solid var(--rule);
    border-radius: 6px;
    background: var(--surface);
    overflow: hidden;
    break-inside: avoid;
  }
  .score-dial {
    flex: 0 0 130px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: var(--sunk);
    border-right: 1px solid var(--rule);
    padding: 18px 12px;
    text-align: center;
  }
  .score-dial .score-val {
    font-family: var(--mono);
    font-size: 38px;
    font-weight: 700;
    line-height: 1;
    color: var(--ink);
  }
  .score-dial .score-max {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
    margin-top: 2px;
  }
  .score-dial .score-grade {
    display: inline-block;
    margin-top: 8px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 2px 8px;
    border-radius: 4px;
    background: var(--surface);
    border: 1px solid var(--rule);
  }
  .score-dial.grade-a .score-grade { color: var(--ok); border-color: var(--ok); }
  .score-dial.grade-b .score-grade { color: var(--observed); border-color: var(--observed); }
  .score-dial.grade-c .score-grade { color: var(--med); border-color: var(--med); }
  .score-dial.grade-d .score-grade { color: var(--high); border-color: var(--high); }
  .score-dial.grade-e .score-grade { color: var(--crit); border-color: var(--crit); }

  .posture-meta {
    flex: 1 1 auto;
    padding: 16px 20px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }
  .posture-narrative {
    font-size: 13px;
    font-weight: 500;
    color: var(--ink);
    margin: 0 0 14px;
    line-height: 1.45;
  }
  .posture-metrics-strip {
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
    background: var(--sunk);
    border: 1px solid var(--rule-light);
    border-radius: 4px;
    padding: 8px 12px;
  }
  .p-metric { display: flex; align-items: baseline; gap: 5px; }
  .p-metric .pm-val { font-family: var(--mono); font-size: 14px; font-weight: 700; }
  .p-metric .pm-val.crit { color: var(--crit); }
  .p-metric .pm-val.high { color: var(--high); }
  .p-metric .pm-val.med { color: var(--med); }
  .p-metric .pm-val.low { color: var(--low); }
  .p-metric .pm-val.info { color: var(--info); }
  .p-metric .pm-lbl { font-size: 11px; color: var(--muted); }
  .p-divider { width: 1px; height: 16px; background: var(--rule); margin: 0 4px; }

  /* Wire Ribbon */
  .wire-ribbon-wrap {
    border: 1px solid var(--rule);
    border-radius: 6px;
    background: var(--surface);
    overflow: hidden;
    margin-bottom: 10px;
    break-inside: avoid;
  }
  .wire-ribbon-header {
    background: var(--sunk);
    border-bottom: 1px solid var(--rule);
    padding: 6px 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
  }
  .w-link-tag {
    font-family: var(--mono);
    font-weight: 700;
    text-transform: uppercase;
    font-size: 10px;
    color: var(--muted);
    background: var(--surface);
    border: 1px solid var(--rule);
    padding: 1px 6px;
    border-radius: 3px;
  }
  .w-link-peers { font-family: var(--mono); font-weight: 600; color: var(--ink); }
  .wire-ribbon-body {
    display: flex;
    align-items: stretch;
    flex-wrap: nowrap;
    overflow-x: auto;
  }
  .report-ribbon-field {
    flex: 1 1 0;
    min-width: 78px;
    padding: 12px 10px;
    border-right: 1px solid var(--rule);
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
  }
  .report-ribbon-field:last-child { border-right: none; }
  .report-ribbon-field.obs { background: var(--observed-bg); }
  .report-ribbon-field.obs .r-field-name { color: var(--observed); }
  .report-ribbon-field.inf {
    background: var(--inferred-bg);
    background-image: repeating-linear-gradient(-45deg, transparent 0 6px, rgba(109,78,156,0.08) 6px 12px);
  }
  .report-ribbon-field.inf .r-field-name { color: var(--inferred); }
  .r-field-name {
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 700;
    margin-bottom: 6px;
    overflow-wrap: anywhere;
  }
  .r-field-val {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--ink);
    line-height: 1.35;
    overflow-wrap: anywhere;
  }
  .report-ribbon-seam {
    flex: 0 0 auto;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 8px 10px;
    background: var(--surface);
    border-left: 3px double var(--ink);
    border-right: 3px double var(--ink);
  }
  .r-seam-bar { width: 1px; height: 6px; background: var(--ink); }
  .r-seam-label {
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    color: var(--ink);
    text-align: center;
    line-height: 1.2;
    margin: 4px 0;
    width: min-content;
  }

  .wire-legend {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    font-size: 11px;
    color: var(--muted);
  }
  .legend-chip { display: inline-flex; align-items: center; gap: 6px; }
  .swatch { width: 10px; height: 10px; border-radius: 2px; flex: none; }
  .swatch.obs { background: var(--observed); }
  .swatch.seam { background: var(--ink); }
  .swatch.inf { background: var(--inferred); }

  /* Findings Grouped by Severity */
  .findings-group {
    margin-bottom: 20px;
    break-inside: avoid;
    page-break-inside: avoid;
  }
  h3.group-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
    font-weight: 600;
    color: var(--ink);
    margin: 0 0 10px;
    padding-bottom: 4px;
    border-bottom: 1px solid var(--rule-light);
  }
  .sev-sq {
    width: 8px;
    height: 8px;
    border-radius: 2px;
    flex: none;
    display: inline-block;
  }
  .sev-sq.critical { background: var(--crit); }
  .sev-sq.high { background: var(--high); }
  .sev-sq.medium { background: var(--med); }
  .sev-sq.low { background: var(--low); }
  .sev-sq.info { background: var(--info); }

  .group-items { display: flex; flex-direction: column; gap: 10px; }
  .report-finding {
    border: 1px solid var(--rule);
    border-left: 4px solid var(--info);
    border-radius: 4px;
    padding: 10px 14px;
    background: var(--surface);
    break-inside: avoid;
    page-break-inside: avoid;
  }
  .report-finding.critical { border-left-color: var(--crit); }
  .report-finding.high { border-left-color: var(--high); }
  .report-finding.medium { border-left-color: var(--med); }
  .report-finding.low { border-left-color: var(--low); }
  .report-finding.info { border-left-color: var(--info); }

  .f-head { display: flex; align-items: baseline; gap: 8px; margin-bottom: 6px; flex-wrap: wrap; }
  .f-rule {
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 700;
    background: var(--sunk);
    border: 1px solid var(--rule);
    padding: 1px 6px;
    border-radius: 3px;
    color: var(--ink);
  }
  h4.f-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--ink);
    margin: 0;
  }
  .f-target {
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 6px;
  }
  .f-target code { font-family: var(--mono); font-size: 11px; color: var(--ink); }
  .f-detail {
    font-size: 12.5px;
    color: var(--ink);
    margin: 0 0 8px;
    line-height: 1.45;
  }
  .f-fix {
    font-size: 12px;
    background: var(--sunk);
    border-left: 2px solid var(--observed);
    padding: 6px 10px;
    border-radius: 0 4px 4px 0;
    color: var(--ink);
    margin-top: 4px;
  }

  /* Hardening Plan */
  .plan-card {
    border: 1px solid var(--rule);
    border-radius: 6px;
    background: var(--surface);
    padding: 14px 16px;
    margin-bottom: 14px;
    break-inside: avoid;
    page-break-inside: avoid;
  }
  .plan-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 10px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--rule-light);
  }
  h3.plan-title { font-size: 13.5px; font-weight: 600; margin: 0; color: var(--ink); }
  .plan-badges { display: flex; gap: 8px; align-items: center; }
  .plan-badge {
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 4px;
    border: 1px solid var(--rule);
  }
  .plan-badge.badge-ok { color: var(--ok); background: #eafaf1; border-color: var(--ok); }
  .plan-badge.badge-err { color: var(--crit); background: #fdf2f2; border-color: var(--crit); }
  .plan-badge.badge-status { color: var(--ink); background: var(--sunk); }

  .code-block { margin-top: 8px; }
  .code-label { font-size: 11px; font-weight: 600; color: var(--muted); text-transform: uppercase; margin-bottom: 4px; }
  pre {
    margin: 0;
    font-family: var(--mono);
    font-size: 11.5px;
    background: #0f172a;
    color: #e2e8f0;
    padding: 12px;
    border-radius: 4px;
    overflow-x: auto;
    line-height: 1.45;
  }
  code { font-family: var(--mono); }

  /* Tables */
  table.report-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
    margin-bottom: 12px;
  }
  table.report-table th, table.report-table td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--rule);
    text-align: left;
    vertical-align: top;
  }
  table.report-table th { width: 30%; color: var(--muted); font-weight: 600; }
  table.report-table td { color: var(--ink); }
  table.report-table code { font-family: var(--mono); font-size: 11.5px; }

  /* Empty States & Notes */
  .empty-state {
    font-size: 13px;
    color: var(--muted);
    font-style: italic;
    background: var(--sunk);
    border: 1px dashed var(--rule);
    padding: 12px 16px;
    border-radius: 4px;
    margin: 0 0 12px;
  }
  .note { font-size: 12px; color: var(--muted); margin: 0 0 10px; }
  .note.warn {
    color: var(--high);
    background: #fff8f5;
    border-left: 3px solid var(--high);
    padding: 6px 10px;
    border-radius: 0 4px 4px 0;
  }
  .epistemic-disclaimer {
    font-size: 11px;
    color: var(--muted);
    border-top: 1px solid var(--rule-light);
    padding-top: 8px;
    margin: 8px 0 0;
  }

  /* Document Footer */
  .report-footer {
    border-top: 1px solid var(--rule);
    padding-top: 12px;
    margin-top: 32px;
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    color: var(--muted);
    font-family: var(--mono);
  }

  /* @media print overrides */
  @media print {
    body {
      background: #ffffff !important;
      padding: 0 !important;
      font-size: 11pt !important;
    }
    .toolbar { display: none !important; }
    .report-page-container {
      max-width: 100% !important;
      border: none !important;
      box-shadow: none !important;
      padding: 0 !important;
      margin: 0 !important;
    }
    .report-section, .posture-hero-card, .wire-ribbon-wrap, .findings-group, .report-finding, .plan-card, table {
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }
    h1, h2, h3, h4 {
      break-after: avoid !important;
      page-break-after: avoid !important;
    }
    pre {
      background: #f8fafc !important;
      color: #0f172a !important;
      border: 1px solid #cbd5e1 !important;
    }
    .report-ribbon-field.obs { background: #e2eff4 !important; }
    .report-ribbon-field.inf { background: #ece5f5 !important; }
  }
</style>
</head>
<body>
  <div class="toolbar">
    <button type="button" id="report-print">Print or save as PDF</button>
    <button type="button" id="report-json" class="secondary">Download as JSON</button>
  </div>

  <div class="report-page-container">
    <header class="report-header">
      <div class="report-badge-bar">
        <span class="report-brand-badge">CipherGuard \u00b7 Cryptographic Assessment</span>
        <span class="report-id-chip">Report ID: <code>${esc(reportDigest)}</code></span>
      </div>
      <h1 class="report-main-title">This report documents the cryptographic assessment for ${esc(captureName)}.</h1>
      <div class="report-meta-grid">
        <div class="meta-cell">
          <span class="m-lbl">Target capture</span>
          <span class="m-val"><code>${esc(captureName)}</code></span>
        </div>
        <div class="meta-cell">
          <span class="m-lbl">Assessment timestamp</span>
          <span class="m-val">${v(r.ipsec ? r.ipsec.assessed : r.generated)}</span>
        </div>
        <div class="meta-cell">
          <span class="m-lbl">Report digest</span>
          <span class="m-val"><code>${esc(reportDigest)}</code></span>
        </div>
        <div class="meta-cell">
          <span class="m-lbl">Tool & version</span>
          <span class="m-val">${esc(r.tool)}</span>
        </div>
      </div>
    </header>

    ${body}

    <footer class="report-footer">
      <div class="f-left">CipherGuard \u00b7 Cryptographic assessment report \u00b7 NTRO SIH26160</div>
      <div class="f-right">Generated ${esc(r.generated.slice(0, 10))} \u00b7 Zero-Payload Verification</div>
    </footer>
  </div>
</body>
</html>`;
}

function exportSecurityAuditReport(){
  const report = collectReport();
  if (!report.ipsec && !report.wifi){
    showToast("Nothing to export yet. Assess a capture first.", "error");
    return;
  }
  const win = window.open("", "_blank", "width=920,height=850");
  if (!win){
    showToast("Allow pop-ups for this page in your browser settings to open the exported report.", "error", 8000);
    return;
  }
  win.document.write(reportHtml(report));
  win.document.close();

  // Wired from parent window to respect CSP without inline scripts
  const on = (id, fn) => {
    const el = win.document.getElementById(id);
    if (el) el.addEventListener("click", fn);
  };
  on("report-print", () => win.print());
  on("report-json", () => {
    const stamp = report.generated.slice(0, 19).replace(/[:T]/g, "-");
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const a = win.document.createElement("a");
    a.href = url;
    a.download = `cipherguard-report-${stamp}.json`;
    win.document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
}
