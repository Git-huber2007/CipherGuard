/* CipherGuard dashboard. Posture replay: one link's recorded history from the baseline store. */
"use strict";

/* Posture replay: one link's recorded history from the baseline store, so the
 * downgrade detection can be watched rather than described.
 *
 * Every mark is an observation the store recorded, and every verdict is the one
 * record() reached at the time. None of it is recomputed here: a replay that
 * re-derived verdicts could disagree with the detector once retention has
 * pruned rows. The store is only ever read, live through the read-only
 * /api/fleet endpoints, or in the static build from a history baked at export
 * by running the demo `cipherguard watch` commands.
 *
 * The x axis is observation order, not time: two watch runs a second apart
 * would otherwise sit on one point. Playback advances in discrete steps; only
 * the cursor glides between them, and prefers-reduced-motion removes that. */
const PostureReplay = (() => {
  const STEP_MS = 1000;
  const CHART_H = 190;
  const LABEL_DOWNGRADES_UP_TO = 4;   // beyond this the table carries the deltas
  let hist = null, index = 0, timer = null, loader = null, bound = false, request = 0;

  const signedBits = Fmt.signed;
  const stamp = iso => iso ? String(iso).replace("T", " ").replace(/(\+00:00|Z)$/, " UTC") : "";

  // What each observation was judged against. A "new" observation set the
  // baseline, so it is its own reference; rows recorded before verdicts
  // existed have none, and the reference line breaks there rather than guess.
  function referenceBits(o){
    if (o.baseline_bits != null) return o.baseline_bits;
    return o.verdict === "new" ? o.classical_bits : null;
  }

  function diffTransforms(before, after){
    const a = new Set(before || []), b = new Set(after || []);
    return { removed: (before || []).filter(t => !b.has(t)),
             added: (after || []).filter(t => !a.has(t)) };
  }

  function startIndex(obs){
    for (let i = obs.length - 1; i >= 0; i--) if (obs[i].verdict === "downgrade") return i;
    return Math.max(obs.length - 1, 0);
  }

  function geometry(obs, width){
    const m = { l: 44, r: 20, t: 14, b: 34 };
    const pw = Math.max(width - m.l - m.r, 40), ph = CHART_H - m.t - m.b;
    const top = Math.max(128, ...obs.map(o => Math.max(o.classical_bits, referenceBits(o) || 0)));
    const yMax = Math.ceil(top / 64) * 64;
    const n = obs.length;
    const x = i => m.l + (n === 1 ? pw / 2 : i * pw / (n - 1));
    const y = v => m.t + ph - (v / yMax) * ph;
    const ticks = [];
    for (let v = 0; v <= yMax; v += 64) ticks.push(v);
    return { m, pw, ph, x, y, ticks, width, n };
  }

  // step-after: a link holds its posture until the next observation
  function stepPath(points){
    let d = "", pen = false;
    for (const p of points){
      if (!p){ pen = false; continue; }
      const [px, py] = [p[0].toFixed(1), p[1].toFixed(1)];
      d += pen ? `H${px}V${py}` : `M${px},${py}`;
      pen = true;
    }
    return d;
  }

  function chartSVG(obs, width){
    const g = geometry(obs, width);
    const { m, x, y } = g;
    const right = width - m.r, bottom = CHART_H - m.b;
    const downs = obs.filter(o => o.verdict === "downgrade");
    const label = downs.length <= LABEL_DOWNGRADES_UP_TO;

    const grid = g.ticks.map(v =>
      `<line class="rp-grid" x1="${m.l}" x2="${right}" y1="${y(v)}" y2="${y(v)}"/>`
      + `<text class="rp-tick" x="${m.l - 8}" y="${y(v)}" dy="0.32em" text-anchor="end">${v}</text>`).join("");
    const series = stepPath(obs.map((o, i) => [x(i), y(o.classical_bits)]));
    const ref = stepPath(obs.map((o, i) => {
      const r = referenceBits(o);
      return r == null ? null : [x(i), y(r)];
    }));

    const marks = obs.map((o, i) => {
      const cx = x(i), cy = y(o.classical_bits);
      if (o.verdict === "downgrade"){
        // under the mark: the line runs off to the right at this level, and
        // below a downgrade there is always room above zero
        return `<line class="rp-drop" x1="${cx}" x2="${cx}" y1="${y(o.baseline_bits)}" y2="${cy}"/>`
          + `<path class="rp-mark rp-down" d="M${cx - 6},${cy - 5}H${cx + 6}L${cx},${cy + 6}Z"/>`
          + (label ? `<text class="rp-dlabel" x="${cx}" y="${cy + 21}" text-anchor="middle">`
                     + `${signedBits(o.delta_bits)}</text>` : "");
      }
      const cls = o.verdict === "unconfirmed" ? "rp-mark rp-unconf" : "rp-mark";
      return `<circle class="${cls}" cx="${cx}" cy="${cy}" r="4.5"/>`;
    }).join("");

    const n = obs.length;
    const xlab = (n === 1 ? [0] : [0, n - 1]).map(i =>
      `<text class="rp-tick" x="${x(i)}" y="${bottom + 16}" text-anchor="middle">${i + 1}</text>`).join("");
    const summary = `Negotiated classical bits over ${n} observation${n === 1 ? "" : "s"}`
      + `, ${downs.length} downgrade${downs.length === 1 ? "" : "s"}`;

    return `<svg class="rp-svg" width="${width}" height="${CHART_H}" viewBox="0 0 ${width} ${CHART_H}"`
      + ` role="img" aria-label="${summary}">`
      + grid
      + `<line class="rp-axis" x1="${m.l}" x2="${right}" y1="${bottom}" y2="${bottom}"/>`
      + xlab
      + `<text class="rp-axis-title" x="${m.l + g.pw / 2}" y="${bottom + 30}" text-anchor="middle">`
      + `observation, in recorded order (not to time scale)</text>`
      // The cursor is a pale column behind the data, not a line over it: a
      // full-height rule at the selected point read as the link dropping to 0.
      + `<g class="rp-cursor" transform="translate(0 0)">`
      + `<rect class="rp-band" x="-9" y="${m.t - 6}" width="18" height="${bottom - m.t + 6}" rx="3"/>`
      + `<circle class="rp-current" cx="0" cy="0" r="9"/></g>`
      + `<path class="rp-ref" d="${ref}"/>`
      + `<path class="rp-line" d="${series}"/>`
      + marks
      + `<rect class="rp-hit" x="${m.l - 10}" y="0" width="${g.pw + 20}" height="${CHART_H}"/>`
      + `</svg>`;
  }

  function legendHTML(obs){
    const item = (sw, text) => `<span class="rp-key">${sw}<span>${text}</span></span>`;
    return `<div class="rp-legend">`
      + item(`<svg width="22" height="10" aria-hidden="true"><line class="rp-line" x1="1" x2="21" y1="5" y2="5"/></svg>`,
             "Negotiated strength (classical bits)")
      + item(`<svg width="22" height="10" aria-hidden="true"><line class="rp-ref" x1="1" x2="21" y1="5" y2="5"/></svg>`,
             "Baseline it was compared against")
      + item(`<svg width="14" height="12" aria-hidden="true"><path class="rp-mark rp-down" d="M1,1H13L7,11Z"/></svg>`,
             "Downgrade")
      + (obs.some(o => o.verdict === "unconfirmed")
         ? item(`<svg width="12" height="12" aria-hidden="true"><circle class="rp-mark rp-unconf" cx="6" cy="6" r="4"/></svg>`,
                "Stronger, not yet promoted") : "")
      + `</div>`;
  }

  function txList(list, mark){
    return `<ul class="rp-tx">` + (list || []).map(t => {
      const kind = mark(t);
      const sign = kind === "gone" ? "− " : kind === "new" ? "+ " : "";
      const note = kind === "gone" ? " (not negotiated here)" : kind === "new" ? " (not in the baseline)" : "";
      return `<li class="${kind}"><span aria-hidden="true">${sign}</span>${esc(t)}`
        + (note ? `<span class="visually-hidden">${note}</span>` : "") + `</li>`;
    }).join("") + `</ul>`;
  }

  const VERDICT_TEXT = {
    new: () => "Baseline established",
    steady: o => `Matches the baseline (${Fmt.bits(o.baseline_bits)})`,
    unconfirmed: o => `Stronger than the ${o.baseline_bits}-bit baseline, not yet promoted`,
    improvement: o => `Baseline promoted: ${o.baseline_bits} → ${Fmt.bits(o.classical_bits)}`,
    withheld: () => "Baseline withheld: new-peer limit reached",
  };

  function detailHTML(obs, i, verdicts){
    const o = obs[i];
    const head = `<div class="rp-head"><b>Observation ${i + 1} of ${obs.length}</b>`
      + ` · ${esc(stamp(o.observed_at))} · <span class="rp-cap">${esc(o.capture)}</span></div>`;
    const strength = `<div class="rp-strength">${o.classical_bits} classical / ${o.quantum_bits} quantum bits`
      + (o.dh_group != null ? ` · DH group ${o.dh_group}` : "")
      + (o.ike_version ? ` · ${esc(o.ike_version)}` : "") + `</div>`;

    if (o.verdict === "downgrade"){
      const d = diffTransforms(o.baseline_transforms, o.transforms);
      return head
        + `<div class="rp-verdict is-down"><span aria-hidden="true">▼ </span>Downgrade: `
        + `${o.baseline_bits} → ${Fmt.bits(o.classical_bits)} (${signedBits(o.delta_bits)})</div>`
        + `<div class="rp-compare">`
        + `<div class="rp-col"><div class="rp-col-h">Baseline · ${Fmt.bits(o.baseline_bits)}</div>`
        + txList(o.baseline_transforms, t => d.removed.includes(t) ? "gone" : "") + `</div>`
        + `<div class="rp-col"><div class="rp-col-h">Negotiated here · ${Fmt.bits(o.classical_bits)}</div>`
        + txList(o.transforms, t => d.added.includes(t) ? "new" : "") + `</div>`
        + `</div>` + strength;
    }
    const text = o.verdict ? (VERDICT_TEXT[o.verdict] || (() => o.verdict))(o)
      : "No verdict stored: recorded before the store kept verdicts";
    return head
      + `<div class="rp-verdict is-${esc(o.verdict || "none")}">${esc(text)}</div>`
      // the server's explanation, where it adds something to the headline
      + (o.verdict && o.verdict !== "steady" && verdicts && verdicts[o.verdict]
         ? `<div class="rp-why">${esc(verdicts[o.verdict])}</div>` : "")
      + strength + txList(o.transforms, () => "");
  }

  function tableHTML(obs){
    return `<table class="rp-table"><thead><tr><th scope="col">#</th><th scope="col">Observed</th>`
      + `<th scope="col">Capture</th><th scope="col">Classical bits</th><th scope="col">Quantum bits</th>`
      + `<th scope="col">Verdict</th><th scope="col">vs baseline</th><th scope="col">Transforms</th></tr></thead><tbody>`
      + obs.map((o, i) => `<tr${o.verdict === "downgrade" ? ` class="is-down"` : ""}><td>${i + 1}</td>`
        + `<td>${esc(stamp(o.observed_at))}</td><td>${esc(o.capture)}</td>`
        + `<td>${o.classical_bits}</td><td>${o.quantum_bits}</td><td>${esc(o.verdict || "—")}</td>`
        + `<td>${o.delta_bits == null ? "—" : signedBits(o.delta_bits)}</td>`
        + `<td>${esc((o.transforms || []).join(", "))}</td></tr>`).join("")
      + `</tbody></table>`;
  }

  // -- wiring ----------------------------------------------------------------

  function setIndex(i){
    if (!hist) return;
    const obs = hist.observations;
    index = Math.min(Math.max(i, 0), obs.length - 1);
    const o = obs[index];
    const scrub = $("replay-scrub");
    scrub.value = String(index);
    scrub.setAttribute("aria-valuetext", `Observation ${index + 1} of ${obs.length}: `
      + `${Fmt.bits(o.classical_bits)}` + (o.verdict === "downgrade" ? `, downgrade ${signedBits(o.delta_bits)}` : ""));
    $("replay-pos").textContent = `${index + 1} / ${obs.length}`;
    $("replay-detail").innerHTML = detailHTML(obs, index, hist.verdicts);

    const svg = $("replay-chart").querySelector ? $("replay-chart").querySelector(".rp-svg") : null;
    if (svg){
      const g = geometry(obs, Number(svg.getAttribute("width")));
      const cur = svg.querySelector(".rp-cursor");
      cur.style.transform = `translateX(${g.x(index)}px)`;
      cur.querySelector(".rp-current").setAttribute("cy", String(g.y(o.classical_bits)));
    }
  }

  function stop(){
    if (timer !== null){ clearInterval(timer); timer = null; }
    const btn = $("replay-play");
    btn.textContent = "Play";
    btn.setAttribute("aria-pressed", "false");
  }

  function play(){
    if (!hist || hist.observations.length < 2) return;
    if (timer !== null) return stop();
    const last = hist.observations.length - 1;
    if (index >= last) setIndex(0);
    const btn = $("replay-play");
    btn.textContent = "Pause";
    btn.setAttribute("aria-pressed", "true");
    timer = setInterval(() => {
      setIndex(index + 1);
      if (index >= last) stop();
    }, STEP_MS);
  }

  function chartWidth(){
    const el = $("replay-chart");
    return Math.max(Math.round((el && el.clientWidth) || 720), 280);
  }

  function renderChart(){
    const chart = $("replay-chart");
    chart.innerHTML = chartSVG(hist.observations, chartWidth())
      + legendHTML(hist.observations) + `<div class="rp-tip" id="replay-tip" hidden></div>`;
    const svg = chart.querySelector ? chart.querySelector(".rp-svg") : null;
    if (!svg) return;
    const nearest = ev => {
      const box = svg.getBoundingClientRect();
      const g = geometry(hist.observations, Number(svg.getAttribute("width")));
      const px = ev.clientX - box.left;
      const n = hist.observations.length;
      return n === 1 ? 0 : Math.min(Math.max(Math.round((px - g.m.l) / (g.pw / (n - 1))), 0), n - 1);
    };
    const tip = chart.querySelector(".rp-tip");
    svg.addEventListener("pointermove", ev => {
      const i = nearest(ev), o = hist.observations[i];
      const g = geometry(hist.observations, Number(svg.getAttribute("width")));
      tip.hidden = false;
      tip.textContent = `${i + 1}: ${Fmt.bits(o.classical_bits)}`
        + (o.verdict ? ` · ${o.verdict}` : "")
        + (o.verdict === "downgrade" ? ` ${signedBits(o.delta_bits)}` : "");
      tip.style.left = `${Math.min(g.x(i) + 10, g.width - 150)}px`;
      tip.style.top = `${Math.max(g.y(o.classical_bits) - 30, 0)}px`;
    });
    svg.addEventListener("pointerleave", () => { tip.hidden = true; });
    svg.addEventListener("click", ev => { stop(); setIndex(nearest(ev)); });
  }

  function show(history){
    stop();
    hist = history;
    const obs = hist.observations;
    const scrub = $("replay-scrub");
    scrub.max = String(Math.max(obs.length - 1, 0));
    $("replay-play").disabled = obs.length < 2;
    renderChart();
    $("replay-table").innerHTML = tableHTML(obs);
    $("replay-table-wrap").hidden = false;
    setIndex(startIndex(obs));
  }

  function empty(message){
    stop();
    hist = null;
    $("replay-controls").hidden = true;
    $("replay-table-wrap").hidden = true;
    $("replay-chart").innerHTML = "";
    $("replay-detail").innerHTML = "";
    const el = $("replay-empty");
    el.hidden = false;
    el.innerHTML = message;
  }

  async function selectLink(peer){
    const mine = ++request;
    stop();
    try {
      const history = await loader(peer);
      if (mine !== request) return;            // a later selection won
      if (!history) return empty(`No recorded history for ${esc(peer)}.`);
      show(history);
    } catch (e){
      if (mine === request) empty(`Could not read this link's history: ${esc(e.message)}`);
    }
  }

  function showFleet(fleet, sourceHTML){
    if (!fleet || !fleet.tracked){
      return empty("No baseline store yet. Record captures with "
        + "<code>cipherguard watch &lt;capture&gt; --db &lt;file&gt;</code>, then serve with the same "
        + "<code>--db</code>.");
    }
    if (!fleet.links.length) return empty("The baseline store has no links yet.");
    const sel = $("replay-link");
    // "a|b" is the storage form of a peer pair; the value stays the real key
    sel.innerHTML = fleet.links.map(l =>
      `<option value="${esc(l.peer_key)}">${esc(l.peer_key.split("|").join(" ↔ "))}`
      + ` · ${Fmt.bits(l.current_bits)}`
      + `${l.degraded ? " · degraded" : ""}</option>`).join("");
    const first = fleet.links.find(l => l.degraded) || fleet.links[0];
    sel.value = first.peer_key;
    $("replay-controls").hidden = false;
    $("replay-empty").hidden = true;
    $("replay-source").innerHTML = sourceHTML;
    return selectLink(first.peer_key);
  }

  function bind(){
    if (bound) return;
    bound = true;
    $("replay-link").addEventListener("change", e => selectLink(e.target.value));
    $("replay-play").addEventListener("click", play);
    $("replay-scrub").addEventListener("input", e => { stop(); setIndex(Number(e.target.value)); });
    let resize = null;
    window.addEventListener("resize", () => {
      clearTimeout(resize);
      resize = setTimeout(() => { if (hist){ renderChart(); setIndex(index); } }, 150);
    });
  }

  async function init(){
    bind();
    try {
      if (staticMode.active){
        const res = await fetch("data/fleet_demo.json", { cache: "no-store" });
        if (!res.ok) return empty("This static build has no posture replay demo.");
        const demo = await res.json();
        loader = async peer => demo.histories[peer];
        const how = (demo.commands || []).map(c =>
          `<code>${esc(c.command)}</code> (exit ${c.exit_code})`).join(" then ");
        return showFleet(demo.fleet, how ? `Static demo, recorded at export time by running ${how}.`
                                         : "Static demo, recorded at export time.");
      }
      const fleet = await (await api("/api/fleet", { silent: true })).json();
      loader = async peer =>
        (await api(`/api/fleet/history?peer=${encodeURIComponent(peer)}`, { silent: true })).json();
      return showFleet(fleet, "Read-only from this server's baseline store.");
    } catch (e){
      return empty(`Could not read the baseline store: ${esc(e.message)}`);
    }
  }

  return { referenceBits, diffTransforms, startIndex, chartSVG, legendHTML, detailHTML,
           tableHTML, show, play, stop, setIndex, init, showFleet,
           get index(){ return index; }, get playing(){ return timer !== null; } };
})();
window.PostureReplay = PostureReplay;
