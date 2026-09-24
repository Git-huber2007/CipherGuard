"""Throughput honesty, finding groups and per-link views.

Three things a reviewer reads first on the dashboard, each computed server-side
so the CLI, the API and the static build agree: the throughput figure, the
grouped findings, and the list of gateway links. These tests pin the rules
behind each one.
"""

from __future__ import annotations

import json
import os
import re
import time

import pytest

from cipherguard.core.grouping import (
    build_links,
    group_findings,
    pair_key,
    subject_pair,
)
from cipherguard.core.models import Assessment, EspFlow, Finding, IkeSession, Severity
from cipherguard.lab import pcapgen
from cipherguard.pipeline import MIN_PACKETS_FOR_RATE, analyze, throughput_estimate

STATIC = os.path.join(os.path.dirname(__file__), "..", "cipherguard", "api", "static")


@pytest.fixture(scope="module")
def backbone_path(tmp_path_factory) -> str:
    path = str(tmp_path_factory.mktemp("caps") / "backbone.pcap")
    pcapgen.scenario_mixed_backbone(path)
    return path


@pytest.fixture(scope="module")
def backbone(backbone_path, model_dir) -> dict:
    return analyze(backbone_path, model_dir=model_dir).to_dict()


# ---------------------------------------------------------------------------
# FIX 1: throughput
# ---------------------------------------------------------------------------


def test_model_load_is_timed_separately_and_excluded(backbone_path, model_dir, monkeypatch):
    """Make model loading deliberately slow: the processing time, and so the
    rate, must not move, while the total does."""
    from cipherguard.ml import classifier

    real_load = classifier.SuiteClassifier.load.__func__

    def slow_load(cls, *a, **kw):
        time.sleep(0.4)
        return real_load(cls, *a, **kw)

    monkeypatch.setattr(classifier.SuiteClassifier, "load", classmethod(slow_load))
    stats = analyze(backbone_path, model_dir=model_dir).stats

    assert stats["model_load_seconds"] >= 0.4
    assert stats["processing_seconds"] <= stats["analysis_seconds"] - 0.4 + 0.01
    assert stats["processing_seconds"] == pytest.approx(
        stats["analysis_seconds"] - stats["model_load_seconds"], abs=0.01)


def _assessment(packets: int, processing: float, load: float = 2.0) -> Assessment:
    return Assessment(capture="x.pcap", started="now", stats={
        "packets_read": packets, "processing_seconds": processing,
        "model_load_seconds": load, "analysis_seconds": processing + load,
    })


@pytest.mark.no_model
def test_throughput_uses_processing_time_only():
    tp = throughput_estimate(_assessment(50_000, processing=0.5, load=4.5))
    assert tp["measurable"] is True
    assert tp["packets_per_second"] == 100_000.0   # not 50,000 / 5.0 = 10,000


@pytest.mark.no_model
@pytest.mark.parametrize("packets", [0, 1528, MIN_PACKETS_FOR_RATE - 1])
def test_small_capture_gives_no_rate_at_all(packets):
    tp = throughput_estimate(_assessment(packets, processing=0.01))
    assert tp["measurable"] is False
    assert tp["packets_per_second"] is None
    assert "too small to measure throughput" in tp["note"]
    assert tp["processing_seconds"] == 0.01          # the timing is still reported


@pytest.mark.no_model
def test_rate_appears_at_the_threshold():
    tp = throughput_estimate(_assessment(MIN_PACKETS_FOR_RATE, processing=0.1))
    assert tp["measurable"] and tp["packets_per_second"] == MIN_PACKETS_FOR_RATE / 0.1


def test_backbone_capture_is_below_the_threshold(backbone_path, model_dir):
    tp = throughput_estimate(analyze(backbone_path, model_dir=model_dir))
    assert tp["packets_read"] < MIN_PACKETS_FOR_RATE
    assert tp["packets_per_second"] is None


def test_bench_generates_and_times_both_paths(tmp_path, model_dir):
    from cipherguard.lab.bench import generate, run

    cap = generate(str(tmp_path / "b.pcap"), packets=4000, links=4)
    assert cap["packets"] == 4000
    result = run(packets=12_000, model_dir=model_dir, repeat=1)
    assert result["reader"]["packets"] == result["capture"]["packets"]
    assert result["reader"]["packets_per_second"] > 0
    pl = result["pipeline"]
    assert pl["model_loaded"] and pl["esp_flows"] == 8 and pl["ike_sessions"] == 8
    assert pl["packets_per_second"] > 0                 # above the threshold


# ---------------------------------------------------------------------------
# FIX 2: finding groups
# ---------------------------------------------------------------------------


def test_backbone_groups_collapse_repeated_rules(backbone):
    groups, findings = backbone["finding_groups"], backbone["findings"]
    assert len(groups) < len(findings)
    assert sum(g["count"] for g in groups) == len(findings)

    members = sorted(i for g in groups for i in g["findings"])
    assert members == list(range(len(findings)))       # each finding in exactly one group

    dh = next(g for g in groups if g["rule_id"] == "IKE-006")
    assert dh["count"] == 2 and len(dh["subjects"]) == 2
    for g in groups:
        assert {findings[i]["rule_id"] for i in g["findings"]} == {g["rule_id"]}
        assert {findings[i]["title"] for i in g["findings"]} == {g["title"]}


@pytest.mark.no_model
def test_group_takes_highest_severity_and_any_inferred_and_sorts():
    def f(rule, title, sev, subject, inferred=False):
        return Finding(rule, title, sev, subject, "d", "r", "fix", inferred=inferred)

    findings = [
        f("R-1", "t", Severity.MEDIUM, "a <-> b"),
        f("R-1", "t", Severity.CRITICAL, "c <-> d", inferred=True),
        f("R-2", "u", Severity.CRITICAL, "a <-> b"),
        f("R-3", "v", Severity.LOW, "a <-> b"),
        f("R-1", "other title", Severity.LOW, "a <-> b"),
    ]
    groups = group_findings(findings)
    r1 = next(g for g in groups if g["key"] == "R-1|t")
    assert r1["severity"] == "critical" and r1["count"] == 2 and r1["inferred"]
    assert len(groups) == 4                            # title is part of the key
    order = [(g["severity"], g["count"]) for g in groups]
    assert order == [("critical", 2), ("critical", 1), ("low", 1), ("low", 1)]


# ---------------------------------------------------------------------------
# FIX 3: links
# ---------------------------------------------------------------------------


def test_backbone_has_four_links_each_with_its_session_and_flow(backbone):
    links = backbone["links"]
    assert len(links) == 4
    for link in links:
        assert len(link["sessions"]) == 1 and len(link["flows"]) == 1
        s = backbone["sessions"][link["sessions"][0]]
        f = backbone["flows"][link["flows"][0]]
        assert sorted(link["peers"]) == sorted([s["peer_a"], s["peer_b"]])
        assert sorted(link["peers"]) == sorted([f["src"], f["dst"]])
        assert link["strength"] is not None and link["tunnels"] == 1
    # worst first
    ranks = ["critical", "high", "medium", "low", "info", None]
    worst = [ranks.index(link["worst_severity"]) for link in links]
    assert worst == sorted(worst)


@pytest.mark.parametrize("scenario", sorted(pcapgen.SCENARIOS))
def test_every_finding_is_on_exactly_one_link_or_none(scenario, tmp_path, model_dir):
    fn, _ = pcapgen.SCENARIOS[scenario]
    path = str(tmp_path / f"{scenario}.pcap")
    fn(path)
    d = analyze(path, model_dir=model_dir).to_dict()

    placed = [i for link in d["links"] for i in link["findings"]] + d["unlinked_findings"]
    assert sorted(placed) == list(range(len(d["findings"])))   # no gaps, no duplicates

    for link in d["links"]:
        for i in link["findings"]:
            assert subject_pair(d["findings"][i]["subject"]) == tuple(link["peers"])


@pytest.mark.no_model
@pytest.mark.parametrize("subject, pair", [
    ("203.0.113.7 <-> 198.51.100.4", ("198.51.100.4", "203.0.113.7")),
    ("203.0.113.7->198.51.100.4:0xe88b7591", ("198.51.100.4", "203.0.113.7")),
    ("2001:db8::2->2001:db8::1:0x0000abcd", ("2001:db8::1", "2001:db8::2")),
    ("10.0.0.9 <-> 10.0.0.10", ("10.0.0.9", "10.0.0.10")),       # numeric, not lexical
    ("WLAN Adapter", None),
])
def test_subject_pair(subject, pair):
    assert subject_pair(subject) == pair


@pytest.mark.no_model
def test_esp_only_link_and_pooled_tunnels():
    """Two tunnels between one pair are pooled into one link, and a pair with
    ESP but no IKE gets no strength rather than an invented one."""
    flows = [EspFlow(spi=1, src="10.0.0.1", dst="10.0.0.2"),
             EspFlow(spi=2, src="10.0.0.2", dst="10.0.0.1"),
             EspFlow(spi=3, src="10.0.0.5", dst="10.0.0.6")]
    sess = IkeSession(b"\x01" * 8, b"\x02" * 8, "IKEv2", "10.0.0.1", "10.0.0.2")
    findings = [Finding("ESP-001", "t", Severity.HIGH, flows[2].key, "d", "r", "f"),
                Finding("X-1", "t", Severity.LOW, "somewhere else", "d", "r", "f")]
    links, unlinked = build_links([sess], flows, findings)

    by_id = {link["id"]: link for link in links}
    pooled = by_id["10.0.0.1~10.0.0.2"]
    assert pooled["flows"] == [0, 1] and pooled["pooled"] and pooled["tunnels"] == 2
    lonely = by_id["10.0.0.5~10.0.0.6"]
    assert lonely["sessions"] == [] and lonely["strength"] is None
    assert lonely["findings"] == [0] and lonely["worst_severity"] == "high"
    assert unlinked == [1]
    assert links[0]["id"] == "10.0.0.5~10.0.0.6"        # the only link with a finding


@pytest.mark.no_model
def test_pair_key_is_direction_free():
    assert pair_key("203.0.113.7", "198.51.100.4") == pair_key("198.51.100.4", "203.0.113.7")


def test_static_build_bakes_groups_and_links(tmp_path, backbone_path, model_dir):
    import shutil

    from cipherguard.export.static_site import export

    caps = tmp_path / "caps"
    caps.mkdir()
    shutil.copy(backbone_path, caps / "backbone.pcap")
    out = tmp_path / "site"
    manifest = export(capture_dir=str(caps), out_dir=str(out), model_dir=model_dir, verbose=False)
    payload = json.loads((out / manifest["captures"][0]["file"]).read_text(encoding="utf-8"))
    assert len(payload["links"]) == 4
    assert payload["finding_groups"]
    assert payload["throughput"]["measurable"] is False
    html = (out / "index.html").read_text(encoding="utf-8")
    assert 'id="links-panel"' in html and 'id="ribbon-link"' in html


# ---------------------------------------------------------------------------
# FIX 4 and the renderer contract
# ---------------------------------------------------------------------------


def _read(*parts):
    with open(os.path.join(STATIC, *parts), encoding="utf-8") as fh:
        return fh.read()


@pytest.mark.no_model
def test_ribbon_text_is_at_least_13px_and_the_seam_label_is_not_rotated():
    css = _read("css", "dashboard.css")
    for selector in (r"\.field \.fname\{", r"\.field \.fval\{", r"\.seam-label\{"):
        block = re.search(selector + r"(.*?)\}", css, re.S).group(1)
        size = float(re.search(r"font-size:([\d.]+)rem", block).group(1))
        assert size * 16 >= 13, (selector, size)
    seam = re.search(r"\n\.seam\{(.*?)\}", css, re.S).group(1)
    assert "rotate" not in seam and "absolute" not in seam
    assert ".seam::after" not in css


@pytest.mark.no_model
def test_renderer_reads_server_structures_and_never_truncates_spis():
    js = _read("js", "dashboard.js")
    assert "shortSpi" not in js
    for key in ("finding_groups", "a.links", "unlinked_findings", "tp.measurable"):
        assert key in js, key
    assert "history.replaceState" in js and "hashchange" in js
    html = _read("index.html")
    assert 'data-fview="rule"' in html and 'data-fview="link"' in html
    lede = re.search(r'<p class="ribbon-lede">(.*?)</p>', html, re.S).group(1)
    assert len(re.sub(r"<[^>]+>|\s+", " ", lede).strip()) <= 120
