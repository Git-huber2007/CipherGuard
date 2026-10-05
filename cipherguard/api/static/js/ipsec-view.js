/* CipherGuard dashboard. The IPsec view: wire ribbon, link list, score, sessions and tunnels. */
"use strict";

/* --------------------------------------------------------- wire ribbon */

const DEFAULT_RIBBON = [
  {d:"obs", n:"IP header",        v:"peer addresses, protocol"},
  {d:"obs", n:"UDP 500 / 4500",   v:"IKE or NAT-T encapsulation"},
  {d:"obs", n:"IKE header",       v:"SPIs, exchange type, flags"},
  {d:"obs", n:"SA proposal",      v:"cipher, PRF, integrity, DH group"},
  {d:"obs", n:"KE / Nonce / VID", v:"group, vendor fingerprint"},
  {d:"seam"},
  {d:"inf", n:"SK payload",       v:"child SA proposal — encrypted"},
  {d:"inf", n:"ESP header",       v:"SPI, sequence number"},
  {d:"inf", n:"ESP ciphertext",   v:"suite inferred from framing"}
];

/* Links come from the server (Assessment.to_dict()["links"]), worst first.
   These helpers only look them up; no grouping or ordering happens here. */
function worstLink(a){ return (a && a.links && a.links[0]) || null; }
function linkById(a, id){
  return (id && a && (a.links || []).find(l => l.id === id)) || null;
}
function linkLabel(l){ return `${l.peers[0]} ↔ ${l.peers[1]}`; }

/* The ribbon describes ONE link: the selected one, or the worst in the
   capture. Payloads from before links existed fall back to the first
   session and flow. Nothing is truncated: SPIs and vendor IDs wrap. */
function renderRibbonTo(targetId, a, link){
  const el = $(targetId);
  if (!el) return;
  const parts = DEFAULT_RIBBON.map(f => Object.assign({}, f));
  if (a){
    link = link || worstLink(a);
    const s = link ? a.sessions[link.sessions[0]] : (a.sessions || [])[0];
    const f = link ? a.flows[link.flows[0]] : (a.flows || [])[0];
    if (link) parts[0].v = linkLabel(link);
    if (s){
      const prop = pickIkeProposal(s);
      parts[2].v = `${s.version} · initiator SPI ${s.initiator_spi}`;
      if (prop) parts[3].v = prop.transforms.map(pretty).join(" · ");
      const vid = (s.vendor_ids || [])[0];
      if (vid) parts[4].v = vid;
    } else if (link){
      parts[2].v = parts[3].v = parts[4].v = "no IKE observed on this link";
    }
    if (f){
      if (f.encapsulated) parts[1].v = "UDP 4500 · ESP in NAT-T";
      parts[7].v = `SPI ${f.spi} · ${Fmt.count(f.packets)} packets`
        + (link && link.tunnels > 1 ? ` · 1 of ${link.tunnels} tunnels` : "");
      parts[8].v = `${f.framing_class || f.predicted_suite || "unresolved"} `
        + `(${Fmt.percent(f.framing_confidence ?? f.confidence ?? 0)})`;
    } else if (link){
      parts[7].v = parts[8].v = "no ESP observed on this link";
    }
  }
  el.innerHTML = parts.map(f =>
    f.d === "seam"
      ? `<div class="seam" role="separator" aria-label="Key boundary: fields after this are encrypted">`
        + `<span class="seam-label">key boundary</span></div>`
      : `<div class="field ${f.d}">`
      + `<div class="fname">${Glossary.mark(esc(f.n))}</div>`
      + `<div class="fval">${esc(f.v)}</div></div>`
  ).join("");
}

function renderRibbon(a){
  const link = linkById(a, state.selectedLink) || worstLink(a);
  renderRibbonTo("ribbon", a, link);
  const label = $("ribbon-link");
  if (!label) return;
  if (!a){ label.textContent = "No capture assessed yet."; return; }
  if (!link){ label.textContent = "No gateway pair observed in this capture."; return; }
  const sev = link.worst_severity;
  label.innerHTML = `Showing <span class="mono">${esc(linkLabel(link))}</span>`
    + (sev ? ` <span class="sev-mark ${esc(sev)}">${esc(sev)}</span>` : ` <span class="ribbon-quiet">no findings</span>`)
    + (link === worstLink(a) && (a.links || []).length > 1
        ? ` <span class="ribbon-quiet">worst of ${a.links.length} links</span>` : "")
    + ((a.links || []).length > 1
        ? ` <button type="button" class="linkish ribbon-choose">Choose another link</button>` : "");
  const choose = label.querySelector(".ribbon-choose");
  if (choose) choose.onclick = () => {
    $("links-panel").scrollIntoView({behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start"});
    const current = document.querySelector(`#link-list .link-item[aria-current="true"]`);
    if (current) current.focus({preventScroll: true});
  };
}

function prefersReducedMotion(){
  return !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
}

/* ------------------------------------------------------------------ links */

function readHash(){
  const p = new URLSearchParams(location.hash.replace(/^#/, ""));
  return {capture: p.get("capture"), link: p.get("link")};
}

function writeHash(capture, link){
  const p = new URLSearchParams();
  if (capture) p.set("capture", capture);
  if (link) p.set("link", link);
  // replaceState: selecting links should not fill the Back button with
  // entries, and it does not fire hashchange, so there is no feedback loop.
  history.replaceState(null, "", "#" + p.toString());
}

function linkMeta(l){
  const n = l.findings.length;
  const st = l.strength;
  return [
    l.worst_severity ? `worst ${l.worst_severity}` : "no findings",
    `${n} finding${n === 1 ? "" : "s"}`,
    `${l.tunnels} tunnel${l.tunnels === 1 ? "" : "s"}`,
    st ? `${st.classical_bits}/${Fmt.bits(st.quantum_bits)}` : "no IKE observed"
  ].join(" · ");
}

function renderLinks(a){
  const list = $("link-list"), detail = $("link-detail");
  if (!list || !detail) return;
  const links = a.links || [];
  if (!links.length){
    list.innerHTML = "";
    detail.innerHTML = `<div class="empty">No gateway pair observed in this capture.</div>`;
    return;
  }
  $("links-sub").textContent = `${links.length} gateway pair${links.length === 1 ? "" : "s"}, `
    + "worst first. Select one to see its handshake, tunnel and findings together.";
  list.innerHTML = links.map(l => `<li>
      <button type="button" class="link-item" data-link="${esc(l.id)}"
              aria-current="${l.id === state.selectedLink ? "true" : "false"}">
        <span class="link-bar ${esc(l.worst_severity || "none")}" aria-hidden="true"></span>
        <span class="link-main">
          <span class="link-peers">${esc(linkLabel(l))}</span>
          <span class="link-meta">${esc(linkMeta(l))}</span>
        </span>
      </button></li>`).join("");

  list.onclick = (e) => {
    const btn = e.target.closest(".link-item");
    if (btn) selectLink(btn.dataset.link, {focusDetail: false});
  };
  // Arrow keys move between links; Tab still leaves the list normally.
  list.onkeydown = (e) => {
    const items = [...list.querySelectorAll(".link-item")];
    const at = items.indexOf(document.activeElement);
    if (at < 0) return;
    const next = {ArrowDown: at + 1, ArrowUp: at - 1, Home: 0, End: items.length - 1}[e.key];
    if (next === undefined) return;
    e.preventDefault();
    const target = items[Math.max(0, Math.min(items.length - 1, next))];
    target.focus();
    selectLink(target.dataset.link);
  };
  detail.onclick = (e) => {
    const ev = e.target.closest("[data-evidence]");
    if (ev){
      const flow = state.assessment.flows[Number(ev.dataset.evidence)];
      if (flow) EvidencePanel.open(flow, ev);
      return;
    }
    toggleDisclosure(e);
  };
  renderLinkDetail(a, linkById(a, state.selectedLink) || links[0]);
}

function renderLinkDetail(a, link){
  const el = $("link-detail");
  if (!el || !link) return;
  const sessions = link.sessions.map(i => a.sessions[i]);
  const flows = link.flows.map(i => ({f: a.flows[i], i}));
  const st = link.strength;

  const head = `<div class="ld-head">
      <h3 class="ld-title mono">${esc(linkLabel(link))}</h3>
      <div class="ld-chips">
        ${link.worst_severity
          ? `<span class="sev-mark ${esc(link.worst_severity)}">${esc(link.worst_severity)}</span>`
          : `<span class="ribbon-quiet">no findings</span>`}
        ${st ? `<span class="ld-strength">${st.classical_bits}-bit classical · `
             + `${st.quantum_bits}-bit post-quantum · ${esc(st.kex_family.toUpperCase())}</span>` : ""}
      </div>
    </div>`;

  const handshake = sessions.length
    ? sessions.map(s => {
        const prop = pickIkeProposal(s);
        const algs = prop
          ? prop.transforms.map(t => `<span class="alg ${algClass(t)}">${esc(pretty(t))}</span>`).join("")
          : `<span class="alg">proposal not observed</span>`;
        return `<div class="ld-rec">
          <div class="meta">${esc(s.version)} · ${esc(s.vendor_family)} · ${s.messages.length} messages${esc(hybridNote(s))}</div>
          <div class="ld-spi mono">initiator SPI ${esc(s.initiator_spi)}</div>
          <div class="algs">${algs}</div>
        </div>`;
      }).join("")
    : `<p class="ld-none">No IKE negotiation observed for this pair. The tunnel below is
        inferred with no handshake to corroborate it.</p>`;

  const tunnel = flows.length
    ? flows.map(({f, i}) => {
        const conf = Fmt.percent(f.framing_confidence ?? f.confidence ?? 0);
        const label = f.framing_class || f.predicted_suite || "unresolved";
        return `<div class="ld-rec">
          <div class="meta">${esc(f.src)} &rarr; ${esc(f.dst)} · ${Fmt.count(f.packets)} packets${f.encapsulated ? " · NAT-T" : ""}</div>
          <div class="ld-spi mono">SPI ${esc(f.spi)}</div>
          <div class="algs"><span class="alg ${suiteClass(label)}">${esc(label)}</span>
            <span class="ld-conf">${conf} confidence in the ${Glossary.term("framing-class", "framing class")}</span></div>
          ${f.ambiguous ? `<div class="cand">${esc(f.framing_candidates.join(" or "))}</div>` : ""}
          <button type="button" class="linkish ld-evidence" data-evidence="${i}" aria-haspopup="dialog">Show the framing arithmetic</button>
        </div>`;
      }).join("")
    : `<p class="ld-none">No ESP traffic observed for this pair.</p>`;

  const findings = link.findings.length
    ? link.findings.map(i => findingHTML(a.findings[i], i, "ld")).join("")
    : `<p class="ld-none">No findings on this link.</p>`;

  el.innerHTML = `${head}
    <div class="ld-cols">
      <section class="ld-block obs" aria-label="Handshake">
        <h4>Handshake <span class="domain-tag obs">observed</span></h4>${handshake}
      </section>
      <section class="ld-block inf" aria-label="Tunnel">
        <h4>Tunnel <span class="domain-tag inf">inferred</span></h4>${tunnel}
      </section>
    </div>
    <p class="ld-note">ESP is matched to IKE by address pair: the child SA's SPI is negotiated
      inside encrypted IKE_AUTH, so it cannot be linked cryptographically.${link.pooled
        ? ` This pair carries ${link.tunnels} tunnels, pooled here.` : ""}</p>
    <section class="ld-findings" aria-label="Findings on this link">
      <h4>Findings on this link <span class="ld-count">${link.findings.length}</span></h4>
      ${findings}
    </section>`;
}

function selectLink(id, {updateHash = true, focusDetail = false} = {}){
  const a = state.assessment;
  const link = linkById(a, id) || worstLink(a);
  if (!link) return;
  state.selectedLink = link.id;
  document.querySelectorAll("#link-list .link-item").forEach(b =>
    b.setAttribute("aria-current", b.dataset.link === link.id ? "true" : "false"));
  renderLinkDetail(a, link);
  renderRibbon(a);
  if (updateHash) writeHash(a.capture, link.id);
  if (focusDetail) $("link-detail").focus();
}

/* --------------------------------------------------------------- panels */

function renderScore(a){
  const score = a.score, circ = 2 * Math.PI * 49;
  const colour = score >= 75 ? "var(--ok)" : score >= 50 ? "var(--med)" : "var(--crit)";
  const arc = $("arc");
  arc.setAttribute("stroke", colour);
  arc.setAttribute("stroke-dasharray",
    `${(score / 100 * circ).toFixed(1)} ${circ.toFixed(1)}`);
  $("dialnum").textContent = score;

  $("grade").textContent = `Grade ${a.grade}`;
  const crit = a.counts.critical, high = a.counts.high;
  $("gradesub").textContent =
    crit ? `${crit} critical ${crit === 1 ? "issue needs" : "issues need"} `
         + "attention before this link is fit for sensitive traffic."
    : high ? `No critical issues. ${high} high-severity `
           + `${high === 1 ? "item" : "items"} to schedule.`
    : "No critical or high-severity issues on the observed associations.";

  $("sevrow").innerHTML = ["critical", "high", "medium", "low", "info"]
    .filter(k => a.counts[k])
    .map(k => `<span class="sev-chip ${k}">${a.counts[k]} ${esc(k)}</span>`)
    .join("") || `<span class="sev-chip info">clean</span>`;

  const s = a.stats;
  // The server decides whether a rate is meaningful (pipeline.throughput_
  // estimate). Payloads from before that rule carry no `measurable` flag and
  // a rate computed with model load included, so they are treated as not
  // measurable rather than shown.
  const tp = a.throughput || {};
  const measurable = tp.measurable === true && tp.packets_per_second != null;
  const processing = tp.processing_seconds ?? s.processing_seconds;
  $("stats").innerHTML = [
    [Fmt.count(s.packets_read), "packets read"],
    [Fmt.count(s.ike_sessions), "IKE sessions"],
    [Fmt.count(s.esp_flows_assessed), "ESP tunnels"],
    measurable
      ? [Fmt.count(tp.packets_per_second), "packets/sec, model load excluded"]
      : [Fmt.duration(processing ?? s.analysis_seconds), "processing time"],
    [Fmt.duration(s.analysis_seconds), "total, incl. model load"],
    [Fmt.count(s.parse_errors), "parse errors"]
  ].map(([k, l]) =>
    `<div class="stat"><div class="k">${esc(k)}</div>`
    + `<div class="l">${esc(l)}</div></div>`).join("");

  const note = $("stat-note");
  if (note){
    note.hidden = measurable;
    note.textContent = measurable ? "" : (tp.note
      || "Capture too small to measure throughput. Run `cipherguard bench` for a reproducible figure.");
  }

  $("capmeta").textContent =
    `${a.capture} · assessed ${a.started} · report ${a.digest}`;
}

function renderSessions(a){
  const el = $("sessions");
  if (!a.sessions.length){
    el.innerHTML = `<div class="empty">No IKE negotiation observed in this capture.</div>`;
    return;
  }
  el.innerHTML = a.sessions.map(s => {
    const prop = pickIkeProposal(s);
    const algs = prop
      ? prop.transforms.map(t =>
          `<span class="alg ${algClass(t)}">${esc(pretty(t))}</span>`).join("")
      : `<span class="alg">proposal not observed</span>`;
    const notes = (s.notifies || []).length ? ` · ${s.notifies.length} notify` : "";
    const retx = s.retransmissions ? ` · ${s.retransmissions} retransmitted` : "";
    return `<div class="rec">
      <div class="peers">${esc(s.peer_a)} &harr; ${esc(s.peer_b)}</div>
      <div class="meta">${esc(s.version)} · ${esc(s.vendor_family)} · `
      + `${s.messages.length} messages${esc(notes)}${esc(retx)}${esc(hybridNote(s))}</div>
      <div class="algs">${algs}</div>
    </div>`;
  }).join("");
}

function renderFlows(a){
  const el = $("flows");
  if (!a.flows.length){
    el.innerHTML = `<div class="empty">No ESP traffic observed in this capture.</div>`;
    return;
  }
  // Delegated rather than inline, so a flow is looked up by index and no
  // attacker-influenced string is ever interpolated into a handler.
  el.onclick = (e) => {
    const btn = e.target.closest(".flow-open");
    if (!btn) return;
    const flow = a.flows[Number(btn.dataset.flow)];
    if (flow) EvidencePanel.open(flow, btn);
  };
  el.innerHTML = a.flows.map((f, i) => {
    // Report the framing class and its total probability mass, not a single
    // member at its exact-suite score. Naming one suite out of a set the wire
    // cannot separate reads as a wrong answer to anyone who checks it against
    // the negotiated IKE proposal shown alongside.
    const ratio = f.framing_confidence ?? f.confidence ?? 0;
    const pct = Math.round(ratio * 100);          // bar width only
    const label = f.framing_class || f.predicted_suite || "unresolved";
    const candidates = f.ambiguous
      ? `<div class="cand">${esc(f.framing_candidates.join(" or "))}</div>`
        + `<div class="cand">framing-identical; not separable passively</div>`
      : "";
    const skipped = (f.inference_notes || []).filter(n => n.kind !== "summary").length;
    const warn = skipped
      ? ` <span class="flow-open-warn">${skipped} caveat${skipped > 1 ? "s" : ""}</span>`
      : "";
    return `<div class="rec">
      <button type="button" class="flow-open" data-flow="${i}" aria-haspopup="dialog">
        <span class="peers">${esc(f.src)} &rarr; ${esc(f.dst)}</span>
        <span class="meta">SPI ${esc(f.spi)} · ${f.packets} packets · mean ${f.mean_payload}B${f.encapsulated ? " · NAT-T" : ""}</span>
        <span class="algs"><span class="alg ${suiteClass(label)}">${esc(label)}</span></span>
        <span class="flow-open-hint">Show the framing arithmetic${warn}</span>
      </button>
      <div class="confbar"><i style="width:${pct}%"></i></div>
      <div class="cand">${Fmt.percent(ratio)} confidence in the ${Glossary.term("framing-class", "framing class")}</div>
      ${candidates}
    </div>`;
  }).join("");
}
