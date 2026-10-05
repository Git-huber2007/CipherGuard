/* CipherGuard dashboard. Post-quantum exposure: the harvest clock and the ranked link list. */
"use strict";

/* Harvest clock: an instrument reading, not an alarm.
 *
 * Left, the bytes an adversary recording today could already read once a
 * quantum computer exists: the ESP volume observed on quantum-exposed links in
 * the capture, then extrapolated at the observed rate for as long as this view
 * is open. The two parts are labelled separately because only the first is
 * measured.
 *
 * Right, Mosca's deadline for a chosen data classification. The formula is
 * duplicated from mosca_gap() in cipherguard/intel/pqc.py, operand for operand,
 * and a test runs both over a table of inputs. The classification table itself
 * is not duplicated: the roadmap publishes it.
 *
 * With prefers-reduced-motion the counter moves in 5-second steps instead of
 * running continuously. Its value is always derived from elapsed time, so a
 * paused or throttled tab never drifts. */
const HarvestClock = (() => {
  const STEP_MS = { smooth: 100, reduced: 5000 };
  let timer = null;
  let teardown = [];

  // Same operands, same order as pqc.py, so both compute the same double.
  function moscaGap(secrecyYears, migrationYears, crqcYears){
    return (secrecyYears + migrationYears) - crqcYears;
  }

  // pqc.py: "already_late": gap > 0. Exactly zero is on time, not late.
  function isLate(gap){ return gap > 0; }

  function splitYears(gap){
    const total = Math.round(Math.abs(gap) * 12);
    return { late: isLate(gap), years: Math.floor(total / 12), months: total % 12,
             totalMonths: total };
  }

  function describeDeadline(gap){
    const s = splitYears(gap);
    const value = s.totalMonths === 0 ? "under 1 month"
      : `${s.years} yr ${String(s.months).padStart(2, "0")} mo`;
    return { late: s.late, value,
             label: s.late ? "Past the Mosca deadline" : "Until the Mosca deadline" };
  }

  // observed bytes plus rate x elapsed; the rate is megabits per second
  function harvested(baseBytes, rateMbps, elapsedMs){
    return baseBytes + rateMbps * 1e6 / 8 * (Math.max(elapsedMs, 0) / 1000);
  }

  function stepMs(reducedMotion){ return reducedMotion ? STEP_MS.reduced : STEP_MS.smooth; }

  function signed(x){
    return `${x > 0 ? "+" : x < 0 ? "−" : ""}${Math.abs(x).toFixed(1)}`;
  }

  function stop(){
    if (timer !== null){ clearInterval(timer); timer = null; }
    teardown.forEach(fn => fn());
    teardown = [];
  }

  function mount(plan){
    stop();
    const box = $("hclock");
    if (!plan || !plan.links || !plan.links.length){ box.hidden = true; return; }
    box.hidden = false;
    const as = plan.assumptions, sm = plan.summary;
    const exposed = plan.links.filter(l => !l.quantum_safe);
    const rate = typeof sm.harvest_rate_mbps === "number" ? sm.harvest_rate_mbps
      : exposed.reduce((t, l) => t + (l.harvest_rate_mbps || 0), 0);
    const base = sm.total_bytes_harvestable || 0;

    // -- deadline ------------------------------------------------------------
    const table = as.secrecy_lifetimes;
    const sel = $("hclock-class");
    const classes = table ? Object.keys(table).sort((a, b) => table[a] - table[b])
                          : [as.data_class];
    sel.innerHTML = classes.map(c =>
      `<option value="${esc(c)}"${c === as.data_class ? " selected" : ""}>${esc(c)}</option>`
    ).join("");
    // an export baked before the table was published can only show its own class
    sel.disabled = !table;

    const showDeadline = cls => {
      const secrecy = table ? table[cls] : as.secrecy_lifetime_years;
      const gap = moscaGap(secrecy, as.migration_years, as.crqc_years);
      const d = describeDeadline(gap);
      $("hclock-deadline").textContent = d.value;
      $("hclock-mosca-label").textContent = d.label;
      const status = $("hclock-status");
      status.textContent = d.late ? "late" : "margin";
      status.className = "hclock-status " + (d.late ? "is-late" : "is-ok");
      $("hclock-mosca").classList.toggle("is-late", d.late);
      $("hclock-terms").textContent =
        `${secrecy} yr secrecy + ${as.migration_years} yr migration − `
        + `${as.crqc_years} yr quantum assumption = ${signed(gap)} yr`;
      $("hclock-secrecy").textContent =
        `${cls} data must stay confidential for ${secrecy} years`;
    };
    const onClass = () => showDeadline(sel.value);
    sel.addEventListener("change", onClass);
    teardown.push(() => sel.removeEventListener("change", onClass));
    showDeadline(as.data_class);

    const arrival = new Date();
    arrival.setMonth(arrival.getMonth() + Math.round(as.crqc_years * 12));
    $("hclock-note").innerHTML =
      `${Glossary.term("crqc", "Quantum arrival")} in ${as.crqc_years} years (${arrival.getFullYear()}) is a `
      + `<b>planning assumption, not a forecast</b>. Substitute your agency's figure `
      + `with <code>cipherguard roadmap --crqc-years N</code>. The deadline is `
      + `below are for the <b>${esc(as.data_class)}</b> class this capture was `
      + `analysed under; the ranking order does not depend on the class.`;

    // -- counter -------------------------------------------------------------
    const bytesEl = $("hclock-bytes"), rateEl = $("hclock-rate");
    if (!exposed.length){
      bytesEl.textContent = Fmt.bytes(0);
      rateEl.textContent = "No quantum-exposed links observed.";
      return;
    }
    if (!(rate > 0)){
      bytesEl.textContent = Fmt.bytes(base);
      rateEl.textContent = "Observed in the capture. No ESP rate measured on "
        + "exposed links, so nothing to extrapolate.";
      return;
    }

    const opened = Date.now();
    const mq = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
    const reduced = () => !!(mq && mq.matches);
    const tick = () => { bytesEl.textContent = Fmt.bytes(harvested(base, rate, Date.now() - opened)); };
    const describeRate = () => {
      rateEl.textContent = `${Fmt.bytes(base)} observed in the capture, then `
        + `extrapolated at the ${Fmt.mbps(rate)} observed on exposed links since this `
        + `view opened` + (reduced() ? " · updates every 5 s" : "");
    };
    const schedule = () => {
      if (timer !== null) clearInterval(timer);
      timer = document.hidden ? null : setInterval(tick, stepMs(reduced()));
    };
    const onMotion = () => { describeRate(); schedule(); };
    const onVisible = () => { tick(); schedule(); };
    if (mq){
      mq.addEventListener("change", onMotion);
      teardown.push(() => mq.removeEventListener("change", onMotion));
    }
    document.addEventListener("visibilitychange", onVisible);
    teardown.push(() => document.removeEventListener("visibilitychange", onVisible));
    describeRate();
    tick();
    schedule();
  }

  return { moscaGap, isLate, splitYears, describeDeadline, harvested,
           stepMs, mount, stop };
})();
window.HarvestClock = HarvestClock;

function renderPQ(a){
  const plan = a.roadmap;
  const el = $("pqlinks");
  HarvestClock.mount(plan);
  if (!plan || !plan.links.length){
    el.innerHTML = `<div class="empty">No IKE negotiation observed, `
      + `so no key exchange to assess.</div>`;
    return;
  }
  const sm = plan.summary;
  $("pqsub").textContent =
    `${sm.quantum_exposed} of ${sm.links_assessed} links are quantum-exposed, `
    + `carrying ${Fmt.bytes(sm.total_bytes_harvestable)} of observed traffic.`;

  const links = plan.links.map(l => `
    <div class="pql ${l.quantum_safe ? "" : "exposed"}">
      <span class="pqrank">${l.priority}</span>
      <span class="pqbody">
        <div class="pqpeer">${esc(l.peer)}</div>
        <div class="pqbits">${l.classical_bits} classical / ${l.quantum_bits} `
      + `quantum bits · ${esc(l.kex_family.toUpperCase())} · `
      + `${Fmt.bytes(l.bytes_observed)} at ${Fmt.mbps(l.harvest_rate_mbps)}</div>
        <div class="pqwhy">${Glossary.mark(esc(l.rationale))}</div>
      </span>
      <span class="pqidx ${l.quantum_safe ? "safe" : "exposed"}">`
      + `${l.quantum_safe ? "PQ-safe" : "exposure " + l.exposure_index}</span>
    </div>`).join("");

  const phases = plan.phases.length
    ? `<div class="phases">` + plan.phases.map(ph => `
        <div class="phase">
          <h3>Phase ${ph.phase} — ${esc(ph.window)}</h3>
          <p>${esc(ph.action)}</p>
          <div class="tgt">${esc(ph.target)}</div>
        </div>`).join("") + `</div>`
    : "";

  el.innerHTML = links + phases;
}
