/* CipherGuard dashboard. The RFC 4303 working behind one tunnel's attribution, and the findings list. */
"use strict";

/* ------------------------------------------------ framing evidence panel */
/* The working behind one ESP attribution, laid out so a reviewer can redo it
   by hand from the capture. Everything above the final block is RFC 4303
   arithmetic over observed ciphertext lengths: deterministic, recomputable,
   and drawn in the "observed" colour. The learned models' ranking sits in a
   separate block in the "inferred" colour, because a probability is not
   something a reviewer can check, and the two must never read as one claim.
   Suite names and reasons are server strings derived from attacker-chosen
   packet lengths, so every one goes through esc(). */
const EvidencePanel = (() => {
  let lastTrigger = null;
  let bound = false;

  const NOTE_LABEL = {
    skipped: "Test did not run",
    fallback: "No suite fits the framing",
    unresolved: "Arithmetic did not decide",
  };
  const VERDICT_CLASS = { prohibited: "bad", legacy: "warn", acceptable: "good" };

  function pct(n, d){ return Fmt.percent(d ? n / d : 0); }

  /* One residue histogram as inline SVG. Surviving suites whose padding
     boundary equals this modulus mark the residue they require. */
  function histogram(mod, counts, survivors){
    const W = 320, H = 138, TOP = 24, BASE = 108;
    const total = counts.reduce((s, c) => s + c, 0);
    const max = Math.max(1, ...counts);
    const bw = W / mod;
    const gap = Math.min(4, bw * 0.18);

    const expected = {};
    for (const s of survivors){
      if (s.boundary !== mod) continue;
      (expected[s.expected_residue] = expected[s.expected_residue] || []).push(s.suite);
    }

    let body = "";
    counts.forEach((c, r) => {
      const h = c ? Math.max(1.5, (c / max) * (BASE - TOP)) : 0;
      const x = r * bw + gap / 2;
      const cx = r * bw + bw / 2;
      const marked = expected[r];
      if (marked){
        body += `<line class="ev-guide" x1="${cx.toFixed(1)}" y1="${TOP - 6}" x2="${cx.toFixed(1)}" y2="${BASE}"/>`
              + `<path class="ev-mark" d="M${(cx - 5).toFixed(1)},${TOP - 16} h10 l-5,8 z"/>`;
      }
      body += `<rect class="ev-bar${marked ? " is-expected" : ""}" x="${x.toFixed(1)}" `
            + `y="${(BASE - h).toFixed(1)}" width="${(bw - gap).toFixed(1)}" height="${h.toFixed(1)}">`
            + `<title>residue ${r}: ${esc(c)} of ${esc(total)} lengths (${pct(c, total)})</title></rect>`
            + `<text class="ev-axis" x="${cx.toFixed(1)}" y="${BASE + 15}" text-anchor="middle">${r}</text>`;
    });
    body += `<line class="ev-base" x1="0" y1="${BASE}" x2="${W}" y2="${BASE}"/>`;

    const peak = counts.indexOf(Math.max(...counts));
    const peakText = total
      ? `${pct(counts[peak], total)} of lengths fall at residue ${peak}.`
      : "No lengths observed.";
    const marks = Object.keys(expected).map(r =>
      `residue ${r} required by ${expected[r].join(", ")} `
      + `(${pct(counts[r], total)} of lengths comply)`);
    const aria = `Ciphertext length mod ${mod}. ${peakText} `
      + (marks.length ? `Marked: ${marks.join("; ")}.` : "No surviving suite pads to this boundary.");

    const caption = marks.length
      ? Object.keys(expected).map(r =>
          `<li><span class="ev-tri" aria-hidden="true">&#9660;</span> residue ${esc(r)}: `
          + `${esc(expected[r].join(", "))} <span class="ev-dim">(${pct(counts[r], total)} comply)</span></li>`).join("")
      : `<li class="ev-dim">No surviving suite pads to ${mod === 8 ? "an" : "a"} ${mod}-byte boundary.</li>`;

    return `<figure class="ev-hist">
      <figcaption><b>len mod ${mod}</b> <span class="ev-dim">${esc(peakText)}</span></figcaption>
      <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(aria)}" preserveAspectRatio="none">${body}</svg>
      <ul class="ev-marks">${caption}</ul>
    </figure>`;
  }

  function measured(f, fa){
    const g = f.granularity_usable
      ? `${esc(f.length_granularity)}&nbsp;B`
      : `<span class="ev-warn-text">not measurable</span>`;
    const ent = f.mean_entropy == null
      ? `<span class="ev-warn-text">not measurable</span>`
      : `${f.mean_entropy.toFixed(2)} bits/byte`;
    return `<dl class="ev-facts">
      <div><dt>Ciphertext lengths</dt><dd>${esc(fa.lengths_observed)}</dd></div>
      <div><dt>Distinct lengths</dt><dd>${esc(f.distinct_lengths)}</dd></div>
      <div><dt>Length granularity</dt><dd>${g}</dd></div>
      <div><dt>Mean payload entropy</dt><dd>${ent}<span class="ev-dim"> over ${esc(fa.entropy_samples)} samples</span></dd></div>
    </dl>`;
  }

  /* All catalogued suites in the order the constraints eliminated them, each
     with its specific reason, then the ones that survived everything. */
  function eliminations(f, fa){
    const notRun = new Set((f.inference_notes || [])
      .filter(n => n.kind === "skipped").map(n => n.test || "all"));
    const steps = fa.constraints.map(c => {
      const out = fa.suites.filter(s => s.eliminated_by === c.id);
      const ran = !(notRun.has(c.id) || notRun.has("all"));
      const items = out.map(s => `<li>
          <s class="ev-suite">${esc(s.suite)}</s>
          <span class="visually-hidden">eliminated:</span>
          <span class="ev-reason">${esc(s.reason)}</span>
        </li>`).join("");
      const status = !ran
        ? `<span class="ev-status is-skipped">did not run</span>`
        : out.length ? `<span class="ev-status">eliminated ${out.length}</span>`
        : `<span class="ev-status is-none">eliminated none</span>`;
      return `<li class="ev-step">
        <div class="ev-step-head"><span class="ev-step-n">${esc(c.step)}</span>
          <b>${esc(c.title)}</b> ${status}</div>
        <div class="ev-rule">${esc(c.rule)}</div>
        ${items ? `<ul class="ev-suites">${items}</ul>` : ""}
      </li>`;
    }).join("");

    const alive = fa.suites.filter(s => !s.eliminated_by);
    const survivors = alive.length
      ? alive.map(s => `<li><span class="ev-suite is-alive">${esc(s.suite)}</span>
          <span class="ev-reason">IV ${esc(s.iv)}&nbsp;B, ICV ${esc(s.icv)}&nbsp;B, `
          + `pads to ${esc(s.boundary)}&nbsp;B, requires residue ${esc(s.expected_residue)}</span></li>`).join("")
      : `<li class="ev-warn-text">None. Every catalogued suite failed at least one constraint.</li>`;

    return `<ol class="ev-steps">${steps}</ol>
      <div class="ev-survivors"><div class="ev-step-head"><b>Survived every constraint</b>
        <span class="ev-status is-alive">${alive.length} of ${fa.suites.length}</span></div>
        <ul class="ev-suites">${survivors}</ul></div>`;
  }

  function classes(fa){
    if (fa.fallback || !fa.classes.length){
      return `<p class="ev-warn-text">No framing class is consistent with this flow, so any
        attribution shown for it rests on the learned models alone.</p>`;
    }
    return fa.classes.map(c => {
      const partial = c.members.length < c.all_members.length
        ? `<div class="ev-dim">Other members of this class were eliminated above.</div>` : "";
      return `<div class="ev-class">
        <div class="ev-class-head"><b>${esc(c.name)}</b>
          <span class="alg ${VERDICT_CLASS[c.verdict] || ""}">${esc(c.verdict)}</span></div>
        <div class="ev-sig">${esc(c.signature)}</div>
        <ul class="ev-members">${c.members.map(m => `<li>${esc(m)}</li>`).join("")}</ul>
        ${partial}
        <p class="ev-why">${esc(c.why_inseparable)}</p>
      </div>`;
    }).join("");
  }

  function notes(f){
    const list = (f.inference_notes || []).filter(n => n.kind !== "summary");
    if (!list.length){
      return `<p class="ev-ok">Every constraint ran on enough data. Nothing was skipped.</p>`;
    }
    return list.map(n => `<div class="ev-note is-${esc(n.kind)}" role="note">
        <b>${esc(NOTE_LABEL[n.kind] || "Note")}</b>
        <p>${esc(n.text)}</p>
      </div>`).join("");
  }

  function model(f){
    const ranked = (f.ranked || []).map(([name, p]) => `<li>
        <span>${esc(name)}</span>
        <span class="ev-model-bar" aria-hidden="true"><i data-w="${Math.round(p * 100)}"></i></span>
        <span class="ev-model-p">${Fmt.percent(p)}</span></li>`).join("");
    return `<section class="ev-model" aria-labelledby="ev-model-h">
      <h3 id="ev-model-h">Learned models' ranking <span class="domain-tag inf">Not arithmetic</span></h3>
      <p class="ev-dim">Random Forest and 1D-CNN probabilities, after the mask above. They
        choose among the survivors and cannot be checked by hand; the arithmetic above can.</p>
      ${ranked ? `<ol class="ev-model-list">${ranked}</ol>` : `<p class="ev-dim">No model was loaded for this assessment.</p>`}
    </section>`;
  }

  function render(f){
    const fa = f.framing_arithmetic;
    if (!fa){
      return `<p class="ev-warn-text">This assessment was produced before the framing
        arithmetic was recorded. Assess the capture again to see the working.</p>` + model(f);
    }
    const caveats = (f.inference_notes || []).filter(n => n.kind !== "summary").length;
    const alert = caveats
      ? `<button type="button" class="ev-alert" data-jump="ev-notes">
          <b>${caveats} caveat${caveats > 1 ? "s" : ""}</b> apply to this inference.
          <span>Read them before relying on it &darr;</span></button>`
      : "";
    const survivors = fa.suites.filter(s => !s.eliminated_by);
    return `${alert}
      <div class="ev-arith">
        <section aria-labelledby="ev-a"><h3 id="ev-a"><span class="ev-sec-n">a</span>What the capture shows</h3>
          ${measured(f, fa)}
          <div class="ev-hists">${[4, 8, 16].map(m =>
            histogram(m, (f.residues || {})[m] || new Array(m).fill(0), survivors)).join("")}</div>
          <p class="ev-dim">&#9660; marks the residue each surviving suite requires, on the histogram
            for its padding boundary. RFC 4303 forces len &equiv; (IV + ICV) mod boundary.</p>
        </section>
        <section aria-labelledby="ev-b"><h3 id="ev-b"><span class="ev-sec-n">b</span>Constraints, in the order applied</h3>
          ${eliminations(f, fa)}
        </section>
        <section aria-labelledby="ev-c"><h3 id="ev-c"><span class="ev-sec-n">c</span>What survives</h3>
          ${classes(fa)}
        </section>
        <section id="ev-notes" tabindex="-1" aria-labelledby="ev-d"><h3 id="ev-d"><span class="ev-sec-n">d</span>Caveats</h3>
          ${notes(f)}
        </section>
      </div>
      ${model(f)}`;
  }

  function focusables(){
    const card = document.querySelector("#evidence-modal .evidence-card");
    return card ? [...card.querySelectorAll(
      'button, [href], [tabindex]:not([tabindex="-1"]), input, select, textarea')]
      .filter(el => !el.disabled && el.offsetParent !== null) : [];
  }

  function onKey(e){
    if (e.key === "Escape" || e.key === "Esc"){ e.preventDefault(); close(); return; }
    if (e.key !== "Tab") return;
    const els = focusables();
    if (!els.length) return;
    const first = els[0], last = els[els.length - 1];
    if (e.shiftKey && document.activeElement === first){ e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last){ e.preventDefault(); first.focus(); }
  }

  function bind(){
    if (bound) return;
    bound = true;
    const modal = $("evidence-modal");
    modal.addEventListener("keydown", onKey);
    modal.addEventListener("click", (e) => {
      if (e.target === modal) { close(); return; }
      const jump = e.target.closest("[data-jump]");
      if (jump){
        const target = $(jump.dataset.jump);
        if (target){ target.scrollIntoView({behavior: "smooth", block: "start"}); target.focus({preventScroll: true}); }
      }
    });
    $("evidence-modal-close").addEventListener("click", close);
  }

  function open(flow, trigger){
    const modal = $("evidence-modal");
    if (!modal) return;
    bind();
    lastTrigger = trigger || document.activeElement;
    $("evidence-modal-subtitle").textContent =
      `${flow.src} → ${flow.dst} · SPI ${flow.spi} · ${flow.packets} packets`;
    $("evidence-body").innerHTML = render(flow);
    $("evidence-body").scrollTop = 0;
    modal.hidden = false;
    $("evidence-modal-close").focus();
  }

  function close(){
    const modal = $("evidence-modal");
    if (!modal || modal.hidden) return;
    modal.hidden = true;
    if (lastTrigger && document.contains(lastTrigger)) lastTrigger.focus();
    lastTrigger = null;
  }

  return { open, close, render };
})();
window.EvidencePanel = EvidencePanel;

function renderFindings(a){
  const el = $("findings");
  if (!a.findings.length){
    el.innerHTML = UIState.box("This assessment raised no findings.", "Assess capture", "run-analysis");
    $("findsub").textContent = "Nothing to review.";
    const fb = $("findings-filter-bar");
    if (fb){ fb.hidden = true; fb.innerHTML = ""; }
    return;
  }
  const inferred = a.findings.filter(f => f.inferred).length;
  const allGroups = a.finding_groups || [];
  whyByRule = Object.fromEntries(allGroups.filter(g => g.why_it_matters)
    .map(g => [g.rule_id, g.why_it_matters]));

  const filteredLink = state.linkFilter && a.links
    ? a.links.find(l => l.id === state.linkFilter)
    : null;

  const filterBar = $("findings-filter-bar");
  if (filterBar){
    if (filteredLink){
      filterBar.hidden = false;
      filterBar.innerHTML = `<span class="filter-label">Filtered to link <strong class="mono">${esc(linkLabel(filteredLink))}</strong> (${filteredLink.findings.length} finding${filteredLink.findings.length === 1 ? "" : "s"})</span>
        <button type="button" class="btn-clear linkish" id="findings-clear-filter">Show all findings (${a.findings.length})</button>`;
    } else {
      filterBar.hidden = true;
      filterBar.innerHTML = "";
    }
  }

  if (filteredLink){
    $("findsub").textContent =
      `Filtered to ${linkLabel(filteredLink)}: ${filteredLink.findings.length} of ${a.findings.length} findings visible.`;
  } else {
    $("findsub").textContent =
      `${a.findings.length} findings`
      + (allGroups.length ? ` in ${allGroups.length} distinct problems` : "")
      + ` · ${a.findings.length - inferred} from parsed bytes, `
      + `${inferred} inferred from encrypted traffic.`;
  }

  document.querySelectorAll("[data-fview]").forEach(b =>
    b.setAttribute("aria-pressed", b.dataset.fview === state.findingsView ? "true" : "false"));

  if (state.findingsView === "link" && a.links){
    el.innerHTML = findingsByLinkHTML(a);
  } else {
    let groupsToRender = allGroups;
    let findingsToRender = a.findings;

    if (filteredLink){
      const allowed = new Set(filteredLink.findings);
      if (allGroups.length){
        groupsToRender = allGroups.map(g => {
          const m = g.findings.filter(i => allowed.has(i));
          return m.length ? { ...g, count: m.length, findings: m } : null;
        }).filter(Boolean);
      } else {
        findingsToRender = a.findings.filter((_, i) => allowed.has(i));
      }
      if (filteredLink.findings.length === 0){
        el.innerHTML = UIState.box("This link has no findings.", "Clear link filter", "clear-link-filter");
        attachFindingsHandlers(el);
        return;
      }
    }

    el.innerHTML = groupsToRender.length
      ? renderSeverityGroupedHTML(groupsToRender, a, true, "rule")
      : renderSeverityGroupedHTML(findingsToRender.map((f, i) => ({f, i})), a, false, "rule");
  }

  attachFindingsHandlers(el);
}

function attachFindingsHandlers(el){
  el.onclick = (e) => {
    const clearBtn = e.target.closest("#findings-clear-filter");
    if (clearBtn){
      state.linkFilter = null;
      renderFindings(state.assessment);
      return;
    }
    const open = e.target.closest("[data-open-link]");
    if (open){
      selectLink(open.dataset.openLink);
      $("links-panel").scrollIntoView({behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start"});
      $("link-detail").focus({preventScroll: true});
      return;
    }
    toggleDisclosure(e);
  };

  const filterBar = $("findings-filter-bar");
  if (filterBar && !filterBar._hasListener){
    filterBar.addEventListener("click", (e) => {
      if (e.target.closest("#findings-clear-filter")){
        state.linkFilter = null;
        renderFindings(state.assessment);
      }
    });
    filterBar._hasListener = true;
  }
}

/* One disclosure pattern for every expandable row: a real <button> carrying
   aria-expanded and aria-controls, so Enter, Space and screen readers work
   without per-row key handlers. Supports both finding rows and severity group headers. */
function toggleDisclosure(e){
  const btn = e.target.closest("button[aria-controls]");
  if (!btn || (!btn.classList.contains("fhead") && !btn.classList.contains("sev-group-head"))) return;
  const open = btn.getAttribute("aria-expanded") !== "true";
  btn.setAttribute("aria-expanded", open ? "true" : "false");
  const panel = document.getElementById(btn.getAttribute("aria-controls"));
  if (panel) panel.hidden = !open;
  const host = btn.parentElement;
  if (host) host.classList.toggle("open", open);
}

let disclosureSeq = 0;

// rule_id -> the server's plain-language sentence, from a.finding_groups
let whyByRule = {};

function whyHTML(ruleId){
  const why = whyByRule[ruleId];
  return why ? `<p class="fwhy"><b>Why this matters:</b> ${esc(why)}</p>` : "";
}

function findingHTML(f, i, prefix, {hideBadge = false} = {}){
  const id = `${prefix}-${i}-${++disclosureSeq}`;
  // members of an expanded group don't repeat the sentence the group shows
  const why = prefix === "gm" ? "" : whyHTML(f.rule_id);
  const badge = hideBadge ? "" : `<span class="sev-mark ${esc(f.severity)}">${esc(cap(f.severity))}</span>`;
  return `<div class="finding" data-i="${i}">
      <button type="button" class="fhead" aria-expanded="false" aria-controls="${id}">
        ${badge}
        <span class="fmain">
          <span class="ftitle">${esc(f.title)}</span>
          ${f.inferred ? `<span class="domain-tag inf inline">Inferred</span>` : ``}
          <span class="fsub">${esc(f.rule_id)} · ${esc(f.subject)}</span>
        </span>
        <span class="chev" aria-hidden="true">&#9662;</span>
      </button>
      <div class="fbody" id="${id}" hidden>
        ${why}
        <p>${Glossary.mark(esc(f.detail))}</p>
        <div class="ref">${esc(f.reference)}</div>
        <div class="fix"><b>Fix:</b> ${esc(f.remediation)}</div>
      </div>
    </div>`;
}

/* A group is one rule firing on one or more subjects. A group of one is shown
   as the finding itself, so a single occurrence is one click from its fix. */
function groupHTML(g, a, {hideBadge = false} = {}){
  if (g.count === 1) return findingHTML(a.findings[g.findings[0]], g.findings[0], "g", {hideBadge});
  const id = `grp-${++disclosureSeq}`;
  const where = g.subjects && g.subjects.length === 1
    ? g.subjects[0]
    : `${g.subjects ? g.subjects.length : g.findings.length} subjects`;
  const badge = hideBadge ? "" : `<span class="sev-mark ${esc(g.severity)}">${esc(cap(g.severity))}</span>`;
  return `<div class="fgroup">
      <button type="button" class="fhead" aria-expanded="false" aria-controls="${id}">
        ${badge}
        <span class="fmain">
          <span class="ftitle">${esc(g.title)}</span>
          ${g.inferred ? `<span class="domain-tag inf inline">Inferred</span>` : ``}
          <span class="fsub">${esc(g.rule_id)} · ${esc(where)}</span>
        </span>
        <span class="gcount" aria-label="${esc(g.count)} occurrences">&times;${esc(g.count)}</span>
        <span class="chev" aria-hidden="true">&#9662;</span>
      </button>
      <div class="gbody" id="${id}" hidden>
        ${whyHTML(g.rule_id)}
        ${g.findings.map(i => findingHTML(a.findings[i], i, "gm", {hideBadge: true})).join("")}
      </div>
    </div>`;
}

const SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"];
const SEV_LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info"
};

function renderSeverityGroupedHTML(items, a, isGroupList = true, prefix = "sev"){
  if (!items || !items.length) return UIState.box("This assessment raised no findings.", "Assess capture", "run-analysis");

  const bySev = {};
  for (const lvl of SEVERITY_LEVELS) bySev[lvl] = [];
  for (const item of items){
    const s = (item.severity || (item.f && item.f.severity) || "low").toLowerCase();
    if (!bySev[s]) bySev[s] = [];
    bySev[s].push(item);
  }

  const activeSeverities = SEVERITY_LEVELS.filter(lvl => bySev[lvl].length > 0);
  if (!activeSeverities.length) return UIState.box("This assessment raised no findings.", "Assess capture", "run-analysis");

  const hasCritical = bySev.critical && bySev.critical.length > 0;

  return activeSeverities.map(sev => {
    const sevItems = bySev[sev];
    const totalCount = isGroupList
      ? sevItems.reduce((acc, g) => acc + (g.count || 1), 0)
      : sevItems.length;

    // Critical is open; rest collapsed. If no critical, open first active severity.
    const isOpen = (sev === "critical") || (!hasCritical && sev === activeSeverities[0]);
    const bodyId = `${prefix}-body-${sev}-${++disclosureSeq}`;

    const rowsHTML = isGroupList
      ? sevItems.map(g => groupHTML(g, a, {hideBadge: true})).join("")
      : sevItems.map(item => {
          const f = item.f || item;
          const idx = item.i !== undefined ? item.i : a.findings.indexOf(f);
          return findingHTML(f, idx >= 0 ? idx : 0, prefix, {hideBadge: true});
        }).join("");

    return `<div class="sev-group ${sev} ${isOpen ? "open" : ""}" data-severity="${sev}">
      <button type="button" class="sev-group-head" aria-expanded="${isOpen ? "true" : "false"}"
              aria-controls="${bodyId}">
        <span class="sev-group-label">
          <span class="sev-heading-name ${sev}">${SEV_LABELS[sev] || sev}</span>
          <span class="sev-heading-count">${totalCount}</span>
        </span>
        <span class="chev" aria-hidden="true">&#9662;</span>
      </button>
      <div class="sev-group-body" id="${bodyId}" ${isOpen ? "" : "hidden"}>
        ${rowsHTML}
      </div>
    </div>`;
  }).join("");
}

function findingsByLinkHTML(a){
  let links = (a.links || []).filter(l => l.findings && l.findings.length);
  if (state.linkFilter){
    links = links.filter(l => l.id === state.linkFilter);
  }
  const sections = links.map(l => {
    const linkFindings = l.findings.map(i => ({ f: a.findings[i], i }));
    const groupedHTML = renderSeverityGroupedHTML(linkFindings, a, false, `link-${l.id}`);
    return `
    <section class="flink" aria-label="Findings for ${esc(linkLabel(l))}">
      <div class="flink-head">
        <span class="sev-mark ${esc(l.worst_severity || "none")}">${esc(cap(l.worst_severity || "none"))}</span>
        <span class="flink-peers mono">${esc(linkLabel(l))}</span>
        <span class="flink-count">${l.findings.length} finding${l.findings.length === 1 ? "" : "s"}</span>
        <button type="button" class="linkish" data-open-link="${esc(l.id)}">Open link</button>
      </div>
      ${groupedHTML}
    </section>`;
  });
  const loose = (a.unlinked_findings || []);
  if (!state.linkFilter && loose.length){
    const looseFindings = loose.map(i => ({ f: a.findings[i], i }));
    const looseHTML = renderSeverityGroupedHTML(looseFindings, a, false, "unlinked");
    sections.push(`<section class="flink" aria-label="Findings not tied to a link">
      <div class="flink-head"><span class="flink-peers">Not tied to a link</span>
        <span class="flink-count">${loose.length} finding${loose.length === 1 ? "" : "s"}</span></div>
      ${looseHTML}
    </section>`);
  }
  return sections.join("") || UIState.box(
    state.linkFilter ? "This link has no findings." : "This assessment raised no findings.",
    state.linkFilter ? "Clear link filter" : "Assess capture",
    state.linkFilter ? "clear-link-filter" : "run-analysis"
  );
}
