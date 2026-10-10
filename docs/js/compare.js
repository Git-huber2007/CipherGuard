/* CipherGuard dashboard. Comparing two captures. */
"use strict";

/* Compare mode: two server payloads side by side. Nothing is re-derived here;
 * the rows line up fields the server already computed (links, strength,
 * worst_severity, counts), matched by link id, which is the sorted address
 * pair. Every difference is marked in text as well as style. */
const CompareView = (() => {
  const SEVS = ["critical", "high", "medium", "low", "info"];

  function rows(a, b){
    const byId = new Map();
    for (const l of (a.links || [])) byId.set(l.id, { id: l.id, a: l, b: null });
    for (const l of (b.links || [])){
      const r = byId.get(l.id) || { id: l.id, a: null, b: null };
      r.b = l;
      byId.set(l.id, r);
    }
    return [...byId.values()].map(r => {
      const sa = r.a && r.a.strength, sb = r.b && r.b.strength;
      let kind = "same", change = "no change";
      if (!r.a){ kind = "only-b"; change = "only in B"; }
      else if (!r.b){ kind = "only-a"; change = "only in A"; }
      else if (sa && sb && sa.classical_bits !== sb.classical_bits){
        kind = sb.classical_bits > sa.classical_bits ? "stronger" : "weaker";
        change = `${Fmt.signed(sb.classical_bits - sa.classical_bits)} classical bits`;
      } else if (sa && sb && sa.quantum_bits !== sb.quantum_bits){
        kind = sb.quantum_bits > sa.quantum_bits ? "stronger" : "weaker";
        change = `${Fmt.signed(sb.quantum_bits - sa.quantum_bits)} quantum bits`;
      } else if (r.a.worst_severity !== r.b.worst_severity){
        kind = "severity";
        change = `worst finding ${r.a.worst_severity || "none"} → ${r.b.worst_severity || "none"}`;
      }
      return { ...r, kind, change, differs: kind !== "same" };
    }).sort((x, y) => (y.differs - x.differs) || x.id.localeCompare(y.id));
  }

  function strengthCell(link){
    if (!link) return `<span class="cmp-absent">not in this capture</span>`;
    const s = link.strength;
    const bits = s ? `${Fmt.count(s.classical_bits)} / ${Fmt.count(s.quantum_bits)}` : "no IKE observed";
    const sev = link.worst_severity
      ? ` <span class="sev-chip ${esc(link.worst_severity)}">${esc(link.worst_severity)}</span>` : "";
    return `<span class="cmp-bits">${bits}</span>${sev}`;
  }

  function rowsHTML(list){
    if (!list.length) return `<tr><td colspan="4">${UIState.box("The two captures share no links. Choose a capture B with the same gateways.", "Choose capture B", "focus-capture-b")}</td></tr>`;
    return list.map(r => {
      const label = linkLabel(r.a || r.b);
      const mark = r.differs ? `<span class="cmp-mark" aria-hidden="true">●</span> ` : "";
      return `<tr class="cmp-row cmp-${r.kind}">`
        + `<th scope="row" class="mono">${mark}${esc(label)}</th>`
        + `<td>${strengthCell(r.a)}</td><td>${strengthCell(r.b)}</td>`
        + `<td class="cmp-change">${r.differs ? "<b>" + esc(r.change) + "</b>" : esc(r.change)}</td></tr>`;
    }).join("");
  }

  // B's chips carry their change from A, so a count that moved says so
  function sevChips(counts, other){
    const out = SEVS.filter(k => (counts && counts[k]) || (other && other[k])).map(k => {
      const n = (counts && counts[k]) || 0, was = other ? ((other[k]) || 0) : n;
      const delta = other && n !== was ? ` (${Fmt.signed(n - was)})` : "";
      return `<span class="sev-chip ${k}${delta ? " cmp-diff" : ""}">${Fmt.count(n)} ${k}${delta}</span>`;
    });
    return out.join(" ") || `<span class="sev-chip info">clean</span>`;
  }

  return { rows, rowsHTML, sevChips };
})();
window.CompareView = CompareView;

function renderDiffView(a, b){
  if (!a || !b) return;

  const cmp = CompareView.rows(a, b);
  const differing = cmp.filter(r => r.differs).length;
  if ($("diff-links-tbody")) $("diff-links-tbody").innerHTML = CompareView.rowsHTML(cmp);
  if ($("diff-links-sub")) $("diff-links-sub").textContent =
    `${cmp.length} link${cmp.length === 1 ? "" : "s"} across both captures; `
    + `${differing} differ${differing === 1 ? "s" : ""}. Links are matched by address pair.`;

  const scoreA = a.score ?? 0;
  const scoreB = b.score ?? 0;
  const delta = scoreB - scoreA;

  // 1. Delta Hero Badge
  const badge = $("diff-delta-badge");
  const deltaNum = $("diff-delta-num");
  if (badge && deltaNum){
    if (delta > 0){
      badge.className = "diff-delta-badge positive";
      deltaNum.textContent = `+${delta}`;
    } else if (delta < 0){
      badge.className = "diff-delta-badge negative";
      deltaNum.textContent = `${delta}`;
    } else {
      badge.className = "diff-delta-badge neutral";
      deltaNum.textContent = `0`;
    }
  }

  // 2. Summary Cards
  if ($("diff-name-a")) $("diff-name-a").textContent = a.capture || "Capture A";
  if ($("diff-score-a")) $("diff-score-a").textContent = `${scoreA}/100`;
  const gradeAEl = $("diff-grade-a");
  if (gradeAEl){
    gradeAEl.textContent = `Grade ${a.grade || "—"}`;
    gradeAEl.className = `diff-grade-pill grade-badge ${a.grade ? a.grade.replace("+", "") : "B"}`;
  }
  if ($("diff-sevs-a")) $("diff-sevs-a").innerHTML = CompareView.sevChips(a.counts, null);
  if ($("diff-meta-a")){
    $("diff-meta-a").innerHTML = `
      <div class="diff-meta-line">
        ${(a.sessions || []).length} IKE sessions &middot; ${(a.flows || []).length} ESP SAs &middot; ${(a.findings || []).length} findings
      </div>
    `;
  }

  if ($("diff-name-b")) $("diff-name-b").textContent = b.capture || "Capture B";
  if ($("diff-score-b")) $("diff-score-b").textContent = `${scoreB}/100`;
  const gradeBEl = $("diff-grade-b");
  if (gradeBEl){
    gradeBEl.textContent = `Grade ${b.grade || "—"}`;
    gradeBEl.className = `diff-grade-pill grade-badge ${b.grade ? b.grade.replace("+", "") : "B"}`;
  }
  if ($("diff-sevs-b")) $("diff-sevs-b").innerHTML = CompareView.sevChips(b.counts, a.counts);
  if ($("diff-meta-b")){
    $("diff-meta-b").innerHTML = `
      <div class="diff-meta-line">
        ${(b.sessions || []).length} IKE sessions &middot; ${(b.flows || []).length} ESP SAs &middot; ${(b.findings || []).length} findings
      </div>
    `;
  }

  const verdictEl = $("diff-transform-verdict");
  const statDeltaEl = $("diff-stat-delta");
  if (verdictEl && statDeltaEl){
    if (delta > 0){
      verdictEl.innerHTML = `<span class="tone-success">&#9650; +${delta} points</span>`;
      statDeltaEl.textContent = `Grade ${a.grade} to ${b.grade}`;
    } else if (delta < 0){
      verdictEl.innerHTML = `<span class="tone-crit">&#9660; ${delta} points</span>`;
      statDeltaEl.textContent = `Grade ${a.grade} to ${b.grade}`;
    } else {
      verdictEl.innerHTML = `<span class="tone-muted">No change</span>`;
      statDeltaEl.textContent = `Both captures score the same`;
    }
  }

  // 3. Side-by-Side Wire Ribbons
  if ($("diff-ribbon-title-a")) $("diff-ribbon-title-a").textContent = a.capture || "Capture A";
  if ($("diff-ribbon-title-b")) $("diff-ribbon-title-b").textContent = b.capture || "Capture B";
  renderRibbonTo("diff-ribbon-a", a);
  renderRibbonTo("diff-ribbon-b", b);

  // 4. Cryptographic Upgrade Matrix
  const infoA = extractSuiteInfo(a);
  const infoB = extractSuiteInfo(b);

  // one rule for every row: nothing claims an upgrade the data does not show
  const WEAK_DH = [1, 2, 5, 22, 25];
  const verdict = (same, aWeak, bWeak) => same ? { text: "Same", cls: "diff-status-same" }
    : (aWeak && !bWeak) ? { text: "Improved", cls: "diff-status-upgraded" }
    : (bWeak && !aWeak) ? { text: "Worse", cls: "diff-status-downgraded" }
    : { text: "Changed", cls: "diff-status-same" };
  const weakHash = s => BAD_HASH.test(s) || WEAK_HASH.test(s);
  const weakEsp = s => /64-bit|3?DES|NULL|unencrypted/i.test(s);
  const matrixRows = [
    { param: "IKE version", valA: infoA.ikeVersion, valB: infoB.ikeVersion,
      status: verdict(infoA.ikeVersion === infoB.ikeVersion,
                      infoA.ikeVersion === "IKEv1", infoB.ikeVersion === "IKEv1") },
    { param: "IKE cipher", valA: infoA.ikeCipher, valB: infoB.ikeCipher,
      status: verdict(infoA.ikeCipher === infoB.ikeCipher, BAD.test(infoA.ikeCipher), BAD.test(infoB.ikeCipher)) },
    { param: "Integrity and PRF", valA: infoA.ikePrf, valB: infoB.ikePrf,
      status: verdict(infoA.ikePrf === infoB.ikePrf, weakHash(infoA.ikePrf), weakHash(infoB.ikePrf)) },
    { param: "Diffie-Hellman group", valA: infoA.dhGroup, valB: infoB.dhGroup,
      status: verdict(infoA.dhGroup === infoB.dhGroup,
                      WEAK_DH.includes(infoA.dhVal), WEAK_DH.includes(infoB.dhVal)) },
    { param: "ESP suite", valA: infoA.espSuite, valB: infoB.espSuite,
      status: verdict(infoA.espSuite === infoB.espSuite, weakEsp(infoA.espSuite), weakEsp(infoB.espSuite)) },
    { param: "Quantum-exposed links",
      valA: infoA.pqSafe ? "none" : `${infoA.pqCount}`,
      valB: infoB.pqSafe ? "none" : `${infoB.pqCount}`,
      status: infoA.pqCount === infoB.pqCount ? { text: "Same", cls: "diff-status-same" }
        : infoB.pqCount < infoA.pqCount ? { text: "Fewer", cls: "diff-status-upgraded" }
        : { text: "More", cls: "diff-status-downgraded" } },
  ];

  const tbody = $("diff-matrix-tbody");
  if (tbody){
    tbody.innerHTML = matrixRows.map(row => `
      <tr>
        <td><b>${esc(row.param)}</b></td>
        <td><code>${esc(row.valA)}</code></td>
        <td><code>${esc(row.valB)}</code></td>
        <td class="cell-center"><span class="${row.status.cls}">${esc(row.status.text)}</span></td>
      </tr>
    `).join("");
  }

  // 5. Vulnerability Resolution & Risk Elimination
  const findingsA = a.findings || [];
  const findingsB = b.findings || [];

  const bRules = new Set(findingsB.map(f => f.rule_id));
  const bTitles = new Set(findingsB.map(f => f.title));

  const resolved = findingsA.filter(f => !bRules.has(f.rule_id) && !bTitles.has(f.title));
  const persisting = findingsB.filter(f => findingsA.some(fa => fa.rule_id === f.rule_id || fa.title === f.title));
  const newInB = findingsB.filter(f => !findingsA.some(fa => fa.rule_id === f.rule_id || fa.title === f.title));

  if ($("diff-resolved-count")) $("diff-resolved-count").textContent = resolved.length;
  if ($("diff-persisting-count")) $("diff-persisting-count").textContent = persisting.length + newInB.length;

  const resList = $("diff-resolved-list");
  if (resList){
    if (resolved.length === 0){
      resList.innerHTML = UIState.box("Capture B resolves none of the findings in capture A.", "See the hardening plan", "jump-remediation");
    } else {
      resList.innerHTML = resolved.map(f => `
        <div class="diff-finding-card resolved">
          <div class="title">
            <span class="tone-success">&#10004;</span>
            <span>${esc(f.title)}</span>
            <span class="sev-chip ${esc(f.severity.toLowerCase())}">${esc(f.severity)}</span>
          </div>
          <div class="meta">${esc(f.rule_id)} &middot; ${esc(f.subject)}</div>
        </div>
      `).join("");
    }
  }

  const persistList = $("diff-persisting-list");
  if (persistList){
    const remaining = [...persisting, ...newInB];
    if (remaining.length === 0){
      persistList.innerHTML = UIState.box("Capture B resolves every finding in capture A.", "Export report", "export-report");
    } else {
      persistList.innerHTML = remaining.map(f => `
        <div class="diff-finding-card persisting">
          <div class="title">

            <span>${esc(f.title)}</span>
            <span class="sev-chip ${esc(f.severity.toLowerCase())}">${esc(f.severity)}</span>
          </div>
          <div class="meta">${esc(f.rule_id)} &middot; ${esc(f.subject)}</div>
          <div class="fix"><b>Fix:</b> ${esc(f.remediation || "See the hardening plan")}</div>
        </div>
      `).join("");
    }
  }
}
