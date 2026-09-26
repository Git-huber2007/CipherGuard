"""The harvest clock on the post-quantum panel.

The clock recomputes Mosca's deadline in the browser when the classification
changes, which puts a copy of `mosca_gap()` in JavaScript. A copy is a place for
the two to disagree, so the JS is run here under Node against the Python over a
table of inputs, and must return the identical double, not merely a close one.
"""

from __future__ import annotations

import itertools
import json
import os
import re
import shutil
import subprocess
from typing import Any

import pytest

from cipherguard.api.server import STATIC_DIR
from cipherguard.core.models import Assessment
from cipherguard.intel.pqc import SECRECY_LIFETIME, mosca_gap, roadmap
from tests.jsmodules import module

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _read(*parts: str) -> str:
    with open(os.path.join(STATIC_DIR, *parts), encoding="utf-8") as fh:
        return fh.read()


def _clock_source() -> str:
    js = _read("js", "dashboard.js")
    start = js.index("const HarvestClock = (() => {")
    end = js.index("})();", start) + len("})();")
    return js[start:end]


# A minimal DOM: enough for mount() to run, with setInterval recorded rather
# than scheduled so the test can see which step the counter was given.
_PRELUDE = r"""
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function makeEl(id){
  const classes = new Set();
  return { id, textContent: "", innerHTML: "", hidden: true, disabled: false,
    value: "", className: "", listeners: {},
    classList: { toggle(c, on){ on ? classes.add(c) : classes.delete(c); },
                 contains(c){ return classes.has(c); } },
    addEventListener(t, f){ (this.listeners[t] = this.listeners[t] || []).push(f); },
    removeEventListener(t, f){
      this.listeners[t] = (this.listeners[t] || []).filter(g => g !== f); } };
}
const els = {};
const $ = id => els[id] || (els[id] = makeEl(id));
const intervals = [], cleared = [];
let nextTimer = 1;
global.setInterval = (fn, ms) => { intervals.push(ms); return nextTimer++; };
global.clearInterval = h => { cleared.push(h); };
const motion = { matches: false, listeners: [],
  addEventListener(t, f){ this.listeners.push(f); },
  removeEventListener(t, f){ this.listeners = this.listeners.filter(g => g !== f); } };
const window = { matchMedia: () => motion };
const document = { hidden: false, listeners: [],
  addEventListener(t, f){ this.listeners.push(f); },
  removeEventListener(t, f){ this.listeners = this.listeners.filter(g => g !== f); } };
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = (x) => process.stdout.write(JSON.stringify(x));
"""


def _node(body: str, data) -> Any:
    # the clock formats through Fmt and marks terms through Glossary
    script = (_PRELUDE + module("Fmt") + "\n" + module("Glossary") + "\n"
              + _clock_source() + "\n" + body)
    proc = subprocess.run(["node", "-e", script], input=json.dumps(data),
                          capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _plan(data_class: str = "official", **kw) -> dict:
    return roadmap(Assessment(capture="t.pcap", started="now"), data_class=data_class, **kw)


# ---------------------------------------------------------------------------
# The formula, both sides
# ---------------------------------------------------------------------------

SECRECY = sorted(set(SECRECY_LIFETIME.values()) | {0.0, 0.1, 2.5, 7.3})
MIGRATION = [0.0, 0.2, 0.5, 1.0, 3.0, 7.25, 10.1]
CRQC = [0.3, 5.0, 10.0, 12.0, 13.0, 15.5, 30.0, 100.0]
CASES = list(itertools.product(SECRECY, MIGRATION, CRQC)) + [
    (10.0, 2.0, 12.0),     # exactly on the deadline: not late
    (0.1, 0.2, 0.3),       # 0.1 + 0.2 != 0.3 in doubles; operand order decides
    (0.3, 0.0, 0.3),
    (1e-9, 0.0, 0.0),
]


@pytest.mark.no_model
@needs_node
def test_js_and_python_mosca_formulas_agree():
    got = _node("out(input.map(([s, m, c]) => { const g = HarvestClock.moscaGap(s, m, c);"
                " return [g, HarvestClock.isLate(g)]; }));", CASES)
    assert len(got) == len(CASES)
    for (s, m, c), (js_gap, js_late) in zip(CASES, got):
        py = mosca_gap(s, m, c)
        assert js_gap == py, f"gap differs for {(s, m, c)}: js {js_gap!r}, py {py!r}"
        assert js_late is (py > 0), f"late flag differs for {(s, m, c)}"


@pytest.mark.no_model
@needs_node
def test_js_recomputes_every_class_as_the_roadmap_would():
    """What the selector shows for a class must be what the server would have
    said had the capture been analysed under that class."""
    plans = {cls: _plan(cls, migration_years=3.0, crqc_years=12.0)["assumptions"]
             for cls in SECRECY_LIFETIME}
    table = plans["official"]["secrecy_lifetimes"]
    got = _node("out(Object.keys(input.table).map(k => { const g = HarvestClock.moscaGap("
                "input.table[k], 3.0, 12.0); return [k, g, HarvestClock.isLate(g)]; }));",
                {"table": table})
    for cls, gap, late in got:
        assert round(gap, 1) == plans[cls]["mosca_gap_years"]
        assert late is plans[cls]["already_late"]


# ---------------------------------------------------------------------------
# Readings
# ---------------------------------------------------------------------------


@pytest.mark.no_model
@needs_node
def test_deadline_reads_in_years_and_months():
    gaps = [1.0, -9.0, 1.5, -0.04, 0.0, 0.01, 25.999, -2.75]
    got = _node("out(input.map(g => HarvestClock.describeDeadline(g)));", gaps)
    by_gap = dict(zip(gaps, got))
    assert by_gap[1.0] == {"late": True, "value": "1 yr 00 mo",
                           "label": "Past the Mosca deadline"}
    assert by_gap[-9.0]["value"] == "9 yr 00 mo" and not by_gap[-9.0]["late"]
    assert by_gap[-9.0]["label"] == "Until the Mosca deadline"
    assert by_gap[1.5]["value"] == "1 yr 06 mo"
    assert by_gap[-2.75]["value"] == "2 yr 09 mo"
    assert by_gap[25.999]["value"] == "26 yr 00 mo"
    assert by_gap[-0.04] == {"late": False, "value": "under 1 month",
                             "label": "Until the Mosca deadline"}
    assert by_gap[0.0]["late"] is False           # on the deadline is not past it
    assert by_gap[0.01]["late"] is True and by_gap[0.01]["value"] == "under 1 month"


@pytest.mark.no_model
@needs_node
def test_counter_arithmetic_and_units():
    got = _node("""out({
      one_second: HarvestClock.harvested(1e6, 8, 1000),
      no_rate: HarvestClock.harvested(1234, 0, 60000),
      clock_skew: HarvestClock.harvested(500, 100, -5000),
      units: [0, 999, 1000, 1146388, 2.5e12, 5e18].map(Fmt.bytes),
      steps: [HarvestClock.stepMs(true), HarvestClock.stepMs(false)],
    });""", None)
    assert got["one_second"] == 2_000_000      # 8 Mb/s is 1 MB/s
    assert got["no_rate"] == 1234
    assert got["clock_skew"] == 500            # a clock stepped back never un-harvests
    assert got["units"] == ["0 B", "999 B", "1.0 KB", "1.1 MB", "2.5 TB",
                            "5000000.0 TB"]
    reduced, smooth = got["steps"]
    assert reduced >= 1000 > smooth


# ---------------------------------------------------------------------------
# Mounted behaviour
# ---------------------------------------------------------------------------


def _backbone_plan() -> dict:
    plan = _plan("official")
    plan["links"] = [
        {"peer": "a <-> b", "quantum_safe": False, "harvest_rate_mbps": 50.55,
         "bytes_observed": 398376, "classical_bits": 112, "quantum_bits": 0,
         "kex_family": "modp", "exposure_index": 3.1, "priority": 1, "rationale": ""},
        {"peer": "c <-> d", "quantum_safe": True, "harvest_rate_mbps": 9.0,
         "bytes_observed": 1000, "classical_bits": 128, "quantum_bits": 128,
         "kex_family": "mlkem", "exposure_index": 0.0, "priority": 2, "rationale": ""},
    ]
    plan["summary"].update(total_bytes_harvestable=398376, harvest_rate_mbps=50.55,
                           quantum_exposed=1, links_assessed=2)
    return plan


_MOUNT = r"""
motion.matches = input.reduced;
HarvestClock.mount(input.plan);
const last = () => intervals.length ? intervals[intervals.length - 1] : null;
const first = { interval: last(), rate: $("hclock-rate").textContent,
  bytes: $("hclock-bytes").textContent, deadline: $("hclock-deadline").textContent,
  label: $("hclock-mosca-label").textContent, status: $("hclock-status").textContent,
  late: $("hclock-mosca").classList.contains("is-late"),
  options: $("hclock-class").innerHTML, disabled: $("hclock-class").disabled,
  note: $("hclock-note").innerHTML, hidden: $("hclock").hidden };
const sel = $("hclock-class");
sel.value = "routine";
(sel.listeners.change || []).forEach(f => f());
const routine = { deadline: $("hclock-deadline").textContent,
  late: $("hclock-mosca").classList.contains("is-late"),
  terms: $("hclock-terms").textContent };
// the OS setting flips while the page is open
motion.matches = !input.reduced;
motion.listeners.forEach(f => f());
const flipped = last();
// a second assessment replaces the first: nothing from the first may survive
const before = { motion: motion.listeners.length, vis: document.listeners.length };
HarvestClock.mount(input.plan);
out({ first, routine, flipped, cleared: cleared.length,
      listeners_before: before,
      listeners_after: { motion: motion.listeners.length, vis: document.listeners.length },
      change_handlers: (sel.listeners.change || []).length });
"""


@pytest.mark.no_model
@needs_node
@pytest.mark.parametrize("reduced", [True, False])
def test_mounted_clock_steps_under_reduced_motion(reduced):
    got = _node(_MOUNT, {"plan": _backbone_plan(), "reduced": reduced})
    first = got["first"]
    if reduced:
        assert first["interval"] == 5000
        assert "updates every 5 s" in first["rate"]
        assert got["flipped"] == 100
    else:
        assert first["interval"] == 100
        assert "updates every" not in first["rate"]
        assert got["flipped"] == 5000
    # only the quantum-exposed link's rate drives the counter
    assert "50.5 Mb/s" in first["rate"] and "398.4 KB observed" in first["rate"]
    assert first["bytes"].endswith("KB") or first["bytes"].endswith("MB")


@pytest.mark.no_model
@needs_node
def test_mounted_clock_recomputes_on_class_change_and_states_the_assumption():
    got = _node(_MOUNT, {"plan": _backbone_plan(), "reduced": False})
    first, routine = got["first"], got["routine"]

    assert first["hidden"] is False
    # official: 10 + 3 - 12 = +1 year, late
    assert first["deadline"] == "1 yr 00 mo" and first["late"] is True
    assert first["status"] == "late" and first["label"] == "Past the Mosca deadline"
    # routine: 3 + 3 - 12 = -6 years, margin
    assert routine["deadline"] == "6 yr 00 mo" and routine["late"] is False
    assert "−6.0 yr" in routine["terms"]

    assert first["disabled"] is False
    assert re.findall(r'value="(\w+)"', first["options"]) == sorted(
        SECRECY_LIFETIME, key=SECRECY_LIFETIME.get)
    assert 'value="official" selected' in first["options"]

    assert "planning assumption, not a forecast" in first["note"]
    assert "--crqc-years" in first["note"]


@pytest.mark.no_model
@needs_node
def test_remounting_releases_the_previous_clock():
    """Every capture the analyst opens mounts the clock again. Timers and
    listeners from the last one must go with it, or each capture viewed adds
    another interval ticking forever."""
    got = _node(_MOUNT, {"plan": _backbone_plan(), "reduced": False})
    assert got["cleared"] >= 2       # the reschedule on the motion flip, then the remount
    assert got["listeners_after"] == got["listeners_before"] == {"motion": 1, "vis": 1}
    assert got["change_handlers"] == 1


@pytest.mark.no_model
@needs_node
def test_an_old_static_export_without_the_class_table_still_renders():
    """docs/data baked before `secrecy_lifetimes` existed must not break the
    page: it shows the deadline for the class it was analysed under and
    disables the selector rather than inventing a table."""
    plan = _backbone_plan()
    del plan["assumptions"]["secrecy_lifetimes"]
    del plan["summary"]["harvest_rate_mbps"]
    got = _node(_MOUNT, {"plan": plan, "reduced": False})
    assert got["first"]["disabled"] is True
    assert re.findall(r'value="(\w+)"', got["first"]["options"]) == ["official"]
    assert got["first"]["deadline"] == "1 yr 00 mo"
    assert "50.5 Mb/s" in got["first"]["rate"]     # summed from the links instead


@pytest.mark.no_model
@needs_node
def test_nothing_ticks_without_exposed_volume():
    plan = _backbone_plan()
    plan["summary"]["harvest_rate_mbps"] = 0.0
    got = _node(_MOUNT, {"plan": plan, "reduced": False})
    assert got["first"]["interval"] is None
    assert "nothing to extrapolate" in got["first"]["rate"]


# ---------------------------------------------------------------------------
# Server output, styling, static build
# ---------------------------------------------------------------------------


def test_roadmap_publishes_the_class_table_and_the_tick_rate(tmp_path):
    import cipherguard.pipeline as pipeline
    from cipherguard.lab import pcapgen

    path = str(tmp_path / "backbone.pcap")
    pcapgen.scenario_mixed_backbone(path)
    plan = roadmap(pipeline.analyze(path))

    assert plan["assumptions"]["secrecy_lifetimes"] == SECRECY_LIFETIME
    exposed = [l for l in plan["links"] if not l["quantum_safe"]]
    assert exposed, "scenario has no exposed links; test is vacuous"
    assert plan["summary"]["harvest_rate_mbps"] == round(
        sum(l["harvest_rate_mbps"] for l in exposed), 2)
    assert plan["summary"]["harvest_rate_mbps"] > 0


@pytest.mark.no_model
def test_clock_styling_has_no_glow_or_motion():
    """An instrument reading, not an alarm: no animation, shadow, glow or
    filter on anything belonging to the clock."""
    css = _read("css", "dashboard.css")
    rules = re.findall(r"([^{}]*hclock[^{}]*)\{([^}]*)\}", css)
    assert rules, "no harvest clock rules found"
    for selector, body in rules:
        for banned in ("animation", "transition", "box-shadow", "text-shadow",
                       "filter", "@keyframes"):
            assert banned not in body, f"{selector.strip()} uses {banned}"
    assert "hclock" not in "".join(re.findall(r"@keyframes[^{]*\{", css))


@pytest.mark.no_model
def test_static_export_carries_the_clock(tmp_path):
    import json as _json

    from cipherguard.export.static_site import export
    from cipherguard.lab import pcapgen

    caps = tmp_path / "caps"
    caps.mkdir()
    pcapgen.scenario_mixed_backbone(str(caps / "backbone.pcap"))
    out = tmp_path / "site"
    manifest = export(capture_dir=str(caps), out_dir=str(out), model_dir="models",
                      verbose=False)

    html = (out / "index.html").read_text(encoding="utf-8")
    assert 'id="hclock"' in html and 'id="hclock-class"' in html
    assert "const HarvestClock" in (out / "js" / "dashboard.js").read_text(encoding="utf-8")
    payload = _json.loads((out / manifest["captures"][0]["file"]).read_text(encoding="utf-8"))
    assert payload["roadmap"]["assumptions"]["secrecy_lifetimes"] == SECRECY_LIFETIME
    assert "harvest_rate_mbps" in payload["roadmap"]["summary"]
