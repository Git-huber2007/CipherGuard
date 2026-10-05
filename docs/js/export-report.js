/* CipherGuard dashboard. The printable report. */
"use strict";

/* ------------------------------------------------------- printable report */

const REPORT_SEVERITIES = ["critical", "high", "medium", "low", "info"];

/* What the report contains: only sections with data behind them. The Wi-Fi
 * section records whether it is a scan or the bundled example, so a printed
 * page cannot pass the example off as a site survey. */
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
      capture_sha256: (a.provenance && a.provenance.capture_sha256) || null,
      report_digest: (a.provenance && a.provenance.report_digest) || a.digest || null,
      disabled_rules: (a.stats && a.stats.disabled_rules) || [],
      findings: a.findings || []
    } : null,
    wifi: wifi ? {
      source: state.wifiIsLive ? "scan" : "example",
      score: wifi.score,
      grade: wifi.grade,
      interface: wifi.interface || null,
      vpn,
      findings: [...(wifi.findings || []), ...((vpn && vpn.findings) || [])]
    } : null,
    remediation_plans: (state.remediationPlans || []).map(p => ({
      platform: p.platform_name,
      status: p.status,
      approver: p.approver || null,
      syntax_valid: p.syntax_valid,
      forward_config: p.forward_config,
      rollback_config: p.rollback_config
    }))
  };
}

function reportHtml(r){
  const v = x => (x === null || x === undefined || x === "") ? "\u2014" : esc(x);
  const row = (k, value) => `<tr><th scope="row">${esc(k)}</th><td>${value}</td></tr>`;
  const sevClass = s => REPORT_SEVERITIES.includes(s) ? s : "info";
  const finding = f => `
    <article class="finding ${sevClass(f.severity)}">
      <h3><span class="rule">${v(f.rule_id)}</span> ${v(f.title)} <span class="sev">${v(f.severity)}</span></h3>
      <p class="subject">${v(f.subject)}</p>
      <p>${v(f.detail)}</p>
      ${f.remediation ? `<p class="fix"><b>Fix:</b> ${esc(f.remediation)}</p>` : ""}
    </article>`;
  const findings = list => list.length ? list.map(finding).join("") : "<p>No findings.</p>";

  let body = "";
  if (r.ipsec){
    const i = r.ipsec;
    const counts = REPORT_SEVERITIES.filter(s => i.counts[s]).map(s => `${i.counts[s]} ${s}`).join(", ");
    body += `
      <section>
        <h2>IPsec assessment</h2>
        <table>
          ${row("Capture", v(i.capture))}
          ${row("Assessed", v(i.assessed))}
          ${row("Posture", `${v(i.score)}/100, grade ${v(i.grade)}`)}
          ${row("Findings", counts ? esc(counts) : "none")}
          ${row("IKE sessions / ESP tunnels", `${v(i.sessions)} / ${v(i.flows)}`)}
          ${row("Capture SHA-256", `<code>${v(i.capture_sha256)}</code>`)}
          ${row("Report digest", `<code>${v(i.report_digest)}</code>`)}
          ${i.disabled_rules.length ? row("Rules switched off", esc(i.disabled_rules.join(", "))) : ""}
        </table>
        <p class="note">IKE values are parsed from cleartext. ESP suites are inferred from packet framing; nothing is decrypted.</p>
        ${findings(i.findings)}
      </section>`;
  }
  if (r.wifi){
    const w = r.wifi;
    const iface = w.interface || {};
    const vpn = w.vpn;
    body += `
      <section>
        <h2>Wi-Fi</h2>
        ${w.source === "example" ? `<p class="note warn">This is the example scan bundled with the page. Its networks are invented; it does not describe a real site.</p>` : ""}
        <table>
          ${row("Network", v(iface.ssid))}
          ${row("Access point", `<code>${v(iface.bssid)}</code>`)}
          ${row("Posture", `${v(w.score)}/100, grade ${v(w.grade)}`)}
          ${row("Authentication and cipher", `${v(iface.authentication)} / ${v(iface.cipher)}`)}
          ${row("Band and channel", `${v(iface.band)}, channel ${v(iface.channel)}`)}
          ${row("DNS resolvers", v((iface.dns_servers || []).join(", ")))}
          ${vpn ? row("VPN", vpn.connected ? `connected (${v(vpn.vpn_type)})` : "not connected") : ""}
          ${vpn && vpn.connected ? row("DNS leak", vpn.dns_leak_detected ? "detected" : "not detected") : ""}
        </table>
        ${findings(w.findings)}
      </section>`;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CipherGuard report${r.ipsec ? " \u00b7 " + esc(r.ipsec.capture) : ""}</title>
<style>
  body{font-family:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.5;color:#14212b;background:#fff;max-width:820px;margin:0 auto;padding:28px}
  h1{font-size:1.4rem;margin:0}
  h2{font-size:1.05rem;margin:28px 0 10px;padding-bottom:4px;border-bottom:1px solid #c3cfd8}
  h3{font-size:.92rem;margin:0 0 4px;font-weight:600}
  p{margin:0 0 6px;font-size:.88rem}
  table{border-collapse:collapse;width:100%;margin-bottom:12px;font-size:.88rem}
  th,td{text-align:left;vertical-align:top;padding:5px 8px;border-bottom:1px solid #e3e9ee}
  th{width:32%;font-weight:500;color:#4b5a66}
  code,.rule{font-family:"IBM Plex Mono",ui-monospace,Consolas,monospace;font-size:.82rem;overflow-wrap:anywhere}
  header.top{border-bottom:2px solid #14212b;padding-bottom:12px;margin-bottom:8px}
  header.top p{color:#4b5a66}
  .toolbar{display:flex;gap:10px;margin-bottom:20px}
  .toolbar button{font:inherit;font-size:.85rem;font-weight:600;padding:7px 14px;border-radius:6px;border:1px solid #14212b;background:#14212b;color:#fff;cursor:pointer}
  .toolbar button.secondary{background:#fff;color:#14212b}
  .note{color:#4b5a66}
  .note.warn{color:#7d630e;border-left:3px solid #7d630e;padding-left:10px}
  .finding{border-left:4px solid #5b6872;padding:8px 12px;margin-bottom:10px;background:#f3f6f8;break-inside:avoid}
  .finding.critical{border-left-color:#a81e13}
  .finding.high{border-left-color:#a84b1d}
  .finding.medium{border-left-color:#7d630e}
  .finding.low{border-left-color:#3a6b8a}
  .sev{font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;border:1px solid #c3cfd8;border-radius:4px;padding:1px 6px;margin-left:6px;font-weight:600}
  .subject{color:#4b5a66}
  @media print{.toolbar{display:none}body{padding:0}}
</style>
</head>
<body>
  <div class="toolbar">
    <button type="button" id="report-print">Print or save as PDF</button>
    <button type="button" id="report-json" class="secondary">Download as JSON</button>
  </div>
  <header class="top">
    <h1>CipherGuard assessment report</h1>
    <p>Generated ${esc(r.generated)} by ${esc(r.tool)}</p>
  </header>
  ${body}
</body>
</html>`;
}

function exportSecurityAuditReport(){
  const report = collectReport();
  if (!report.ipsec && !report.wifi){
    showToast("There is nothing to report yet. Assess a capture first.", "error");
    return;
  }
  const win = window.open("", "_blank", "width=920,height=850");
  if (!win){
    showToast("The report opens in a new window. Allow pop-ups for this page, then export again.", "error", 8000);
    return;
  }
  win.document.write(reportHtml(report));
  win.document.close();

  // Wired from this page: the report window inherits this page's content
  // security policy, which allows no inline script.
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
