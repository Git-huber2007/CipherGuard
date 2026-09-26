"""The framing-evidence panel: the RFC 4303 working behind each ESP inference.

The point of the panel is that a reviewer can redo the attribution by hand. So
these tests hold the arithmetic to that standard — every catalogued suite gets
a stated reason or survives, constraints apply in a fixed order, skipped tests
are reported rather than silently passed — and check that the reasons survive
the trip from the classifier through `to_dict` into the static build and the
rendered panel.
"""

from __future__ import annotations

import json
import os
import random
import re
import shutil
import subprocess

import pytest
from tests.jsmodules import module

from cipherguard.core import framing
from cipherguard.core.constants import ESP_SUITES
from cipherguard.core.models import EspFlow
from cipherguard.ml.synth import synth_flow

STATIC = os.path.join(os.path.dirname(__file__), "..", "cipherguard", "api", "static")
CBC = "AES-CBC-128 / HMAC-SHA1-96"
GCM = "AES-GCM-256 (ICV 16)"
NULL = "NULL encryption / HMAC-SHA1-96"
STEP = {c["id"]: c["step"] for c in framing.CONSTRAINTS}


# ---------------------------------------------------------------------------
# The arithmetic
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_every_catalogued_suite_is_eliminated_with_a_reason_or_survives():
    trace = framing.evaluate(synth_flow(CBC, random.Random(2), packets=400))
    assert [r["suite"] for r in trace["suites"]] == list(ESP_SUITES)
    for r in trace["suites"]:
        if r["eliminated_by"] is None:
            assert r["reason"] is None and r["step"] is None
        else:
            assert r["reason"] and r["step"] == STEP[r["eliminated_by"]]
    assert trace["survivors"] == [CBC]


@pytest.mark.parametrize("suite", list(ESP_SUITES))
@pytest.mark.no_model
def test_the_true_suite_is_never_eliminated(suite):
    """The arithmetic is only worth showing if it never rules out the truth."""
    flow = synth_flow(suite, random.Random(11), packets=400)
    trace = framing.evaluate(flow)
    assert suite in trace["survivors"], [
        (r["suite"], r["reason"]) for r in trace["suites"] if r["suite"] == suite
    ]


@pytest.mark.no_model
def test_constraints_apply_in_the_documented_order():
    """A suite failing both granularity and residue is attributed to
    granularity, the first constraint applied, never to a later one."""
    trace = framing.evaluate(synth_flow(CBC, random.Random(2), packets=400))
    tdes = next(r for r in trace["suites"] if r["suite"].startswith("3DES"))
    assert tdes["eliminated_by"] == "granularity"
    assert [c["step"] for c in framing.CONSTRAINTS] == [1, 2, 3, 4]


@pytest.mark.no_model
def test_residue_histograms_and_granularity_are_what_a_reviewer_would_count():
    flow = synth_flow(CBC, random.Random(2), packets=400)
    trace = framing.evaluate(flow)
    lengths = flow.payload_lengths
    for m in (4, 8, 16):
        hist = trace["residues"][str(m)]
        assert len(hist) == m and sum(hist) == len(lengths)
        for r in range(m):
            assert hist[r] == sum(1 for n in lengths if n % m == r)
    # AES-CBC with a 16-byte IV and 12-byte ICV: every length is 12 mod 16
    assert trace["residues"]["16"][12] == len(lengths)
    assert trace["granularity"] == 16
    assert trace["distinct_lengths"] == len(set(lengths))


@pytest.mark.no_model
def test_entropy_separates_null_from_gcm():
    gcm = framing.evaluate(synth_flow(GCM, random.Random(5), packets=400))
    null = next(r for r in gcm["suites"] if r["suite"] == NULL)
    assert null["eliminated_by"] == "entropy" and "encrypted" in null["reason"]


@pytest.mark.no_model
def test_too_few_distinct_lengths_is_reported_as_a_skipped_test():
    flow = EspFlow(spi=1, src="a", dst="b", packets=40,
                   payload_lengths=[92, 108, 124] * 10 + [140] * 10,
                   entropy_samples=[7.8] * 20)
    trace = framing.evaluate(flow)
    skipped = [n for n in trace["notes"] if n["kind"] == "skipped"]
    assert [n["test"] for n in skipped] == ["granularity"]
    assert "4 distinct ciphertext lengths" in skipped[0]["text"]
    assert trace["granularity_usable"] is False
    # without granularity, 64-bit and 128-bit block ciphers can both survive
    assert not any(r["eliminated_by"] == "granularity" for r in trace["suites"])


@pytest.mark.no_model
def test_missing_entropy_samples_are_reported_not_silently_passed():
    """Previously the entropy test was skipped without a word, which is the
    one test that separates ESP-NULL from AES-GCM."""
    flow = synth_flow(GCM, random.Random(5), packets=400)
    flow.entropy_samples = flow.entropy_samples[:5]
    trace = framing.evaluate(flow)
    assert trace["mean_entropy"] is None
    assert any(n["kind"] == "skipped" and n["test"] == "entropy" for n in trace["notes"])
    assert NULL in trace["survivors"]


@pytest.mark.no_model
def test_empty_flow_runs_nothing_and_says_so():
    trace = framing.evaluate(EspFlow(spi=1, src="a", dst="b"))
    assert trace["survivors"] == list(ESP_SUITES)
    assert trace["notes"][0]["kind"] == "skipped"


@pytest.mark.no_model
def test_no_surviving_suite_is_a_fallback_note():
    flow = EspFlow(spi=1, src="a", dst="b", packets=50,
                   payload_lengths=[37, 41, 43, 47, 53, 59, 61, 67, 71, 73])
    trace = framing.evaluate(flow)
    assert trace["fallback"] and not trace["survivors"] and not trace["classes"]
    assert any(n["kind"] == "fallback" for n in trace["notes"])


@pytest.mark.no_model
def test_surviving_class_explains_why_members_are_inseparable():
    trace = framing.evaluate(synth_flow(GCM, random.Random(5), packets=400))
    assert [c["name"] for c in trace["classes"]] == ["AEAD or counter mode"]
    why = trace["classes"][0]["why_inseparable"]
    assert "8-byte IV" in why and "16-byte ICV" in why and "4-byte padding" in why
    assert len(trace["classes"][0]["members"]) == 4


@pytest.mark.no_model
def test_several_surviving_classes_are_flagged_as_unresolved():
    flow = EspFlow(spi=1, src="a", dst="b", packets=40,
                   payload_lengths=[108, 124] * 20, entropy_samples=[7.8] * 20)
    trace = framing.evaluate(flow)
    assert len(trace["classes"]) > 1
    assert any(n["kind"] == "unresolved" for n in trace["notes"])


@pytest.mark.no_model
def test_plausibility_mask_is_derived_from_the_same_trace():
    """The panel must show the computation that set the mask, not a parallel
    reimplementation that could drift from it."""
    from cipherguard.ml.classifier import plausibility

    for seed, suite in enumerate(ESP_SUITES):
        flow = synth_flow(suite, random.Random(seed), packets=300)
        labels = sorted(ESP_SUITES)
        mask, excluded, _ = plausibility(flow, labels)
        trace = framing.evaluate(flow)
        by_suite = {r["suite"]: r for r in trace["suites"]}
        assert dict(excluded) == {
            s: r["reason"] for s, r in by_suite.items() if r["eliminated_by"]
        }
        for i, label in enumerate(labels):
            assert (mask[i] == 0) == (by_suite[label]["eliminated_by"] is not None)


# ---------------------------------------------------------------------------
# Persistence: classifier -> EspFlow -> to_dict
# ---------------------------------------------------------------------------


REQUIRED = ("exclusions", "inference_notes", "residues", "length_granularity",
            "granularity_usable", "distinct_lengths", "mean_entropy",
            "framing_arithmetic")


@pytest.mark.no_model
def test_to_dict_carries_the_arithmetic_even_without_a_model():
    d = synth_flow(CBC, random.Random(2), packets=400).to_dict()
    for key in REQUIRED:
        assert key in d, key
    assert set(d["residues"]) == {"4", "8", "16"}
    assert len(d["framing_arithmetic"]["suites"]) == len(ESP_SUITES)
    assert len(d["exclusions"]) == len(ESP_SUITES) - 1
    json.dumps(d)  # must serialise as-is for the API and the static build


def test_annotate_persists_exclusions_and_notes(model_dir):
    from cipherguard.ml.classifier import SuiteClassifier

    model = SuiteClassifier.load(model_dir)
    flow = synth_flow(GCM, random.Random(5), packets=400)
    flow.entropy_samples = flow.entropy_samples[:5]  # force a skipped test
    [pred] = model.annotate([flow])

    assert flow.exclusions == pred.excluded and flow.exclusions
    assert flow.framing_trace is pred.trace
    assert any(n["test"] == "entropy" for n in flow.inference_notes)

    d = flow.to_dict()
    assert [(e["suite"], e["reason"]) for e in d["exclusions"]] == pred.excluded
    assert d["inference_notes"] == flow.inference_notes


def test_static_build_bakes_the_evidence_into_its_json(tmp_path, model_dir):
    from cipherguard.export.static_site import export
    from cipherguard.lab import pcapgen

    caps = tmp_path / "caps"
    caps.mkdir()
    pcapgen.scenario_mixed_backbone(str(caps / "backbone.pcap"))
    out = tmp_path / "site"
    manifest = export(capture_dir=str(caps), out_dir=str(out),
                      model_dir=model_dir, verbose=False)

    payload = json.loads((out / manifest["captures"][0]["file"]).read_text(encoding="utf-8"))
    assert payload["flows"], "fixture scenario should contain ESP flows"
    for flow in payload["flows"]:
        for key in REQUIRED:
            assert key in flow, key
        fa = flow["framing_arithmetic"]
        assert len(fa["suites"]) == len(ESP_SUITES)
        assert fa["constraints"][0]["id"] == "granularity"

    html = (out / "index.html").read_text(encoding="utf-8")
    assert 'id="evidence-modal"' in html


# ---------------------------------------------------------------------------
# Front end
# ---------------------------------------------------------------------------


def _read(*parts):
    with open(os.path.join(STATIC, *parts), encoding="utf-8") as fh:
        return fh.read()


@pytest.mark.no_model
def test_panel_is_an_accessible_dialog():
    html = _read("index.html")
    m = re.search(r'<div id="evidence-modal"[^>]*>', html)
    assert m, "evidence dialog missing"
    tag = m.group(0)
    for attr in ('role="dialog"', 'aria-modal="true"', "aria-labelledby=", "hidden"):
        assert attr in tag
    assert "Arithmetic from RFC 4303 framing" in html
    assert 'id="evidence-modal-close"' in html


@pytest.mark.no_model
def test_panel_wiring_keyboard_and_no_chart_library():
    js = _read("js", "dashboard.js")
    assert 'class="flow-open"' in js and '<button type="button" class="flow-open"' in js
    # Escape closes it from the global handler and from inside the dialog
    escape_block = js[js.index('if (e.key === "Escape" || e.key === "Esc") {'):][:400]
    assert "EvidencePanel.close()" in escape_block
    assert "function onKey" in js and '"Tab"' in js
    html = _read("index.html")
    for lib in ("chart.js", "d3.", "echarts", "plotly", "highcharts"):
        assert lib not in html.lower()


def _panel_source() -> str:
    js = _read("js", "dashboard.js")
    start = js.index("const EvidencePanel = (() => {")
    end = js.index("})();", start) + len("})();")
    return js[start:end]


@pytest.mark.no_model
@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_panel_renders_the_working_in_order():
    """Run the real panel code against real to_dict output and check the
    rendered HTML: every suite, struck through with its reason, in constraint
    order, caveats present, and the model block kept separate and last."""
    flow = EspFlow(spi=0xABC, src="10.0.0.1", dst="10.0.0.2", packets=40,
                   payload_lengths=[92, 108, 124] * 10 + [140] * 10,
                   entropy_samples=[7.8] * 20)
    flow.ranked = [(CBC, 0.6), ("3DES-CBC / HMAC-MD5-96", 0.4)]
    flow.predicted_suite = CBC
    data = flow.to_dict()

    script = (
        "const esc = s => String(s == null ? '' : s).replace(/[&<>\"']/g, "
        "c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));\n"
        "const $ = () => null; const window = {};\n"
        + module("Fmt") + "\n"   # the panel formats percentages through Fmt
        + _panel_source()
        + "\nprocess.stdout.write(EvidencePanel.render(JSON.parse(require('fs')"
          ".readFileSync(0, 'utf8'))));\n"
    )
    out = subprocess.run(["node", "-e", script], input=json.dumps(data),
                         capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert out.returncode == 0, out.stderr
    html = out.stdout

    struck = re.findall(r'<s class="ev-suite">([^<]+)</s>', html)
    eliminated = [r for r in data["framing_arithmetic"]["suites"] if r["eliminated_by"]]
    expected_order = sorted(eliminated, key=lambda r: r["step"])
    assert struck == [r["suite"] for r in expected_order]
    for r in eliminated:
        assert r["reason"].replace("'", "&#39;") in html

    alive = [r["suite"] for r in data["framing_arithmetic"]["suites"] if not r["eliminated_by"]]
    assert set(re.findall(r'class="ev-suite is-alive">([^<]+)<', html)) == set(alive)

    assert html.count("<svg") == 3
    assert "did not run" in html                        # granularity skipped
    assert 'class="ev-alert"' in html                   # flagged up front
    assert html.index('class="ev-alert"') < html.index('id="ev-a"')
    order = [html.index(f'id="ev-{k}"') for k in "abcd"]
    assert order == sorted(order)
    assert html.index('id="ev-model-h"') > html.index('id="ev-notes"')
    assert html.index('<div class="ev-arith">') < html.index('class="ev-model"')
