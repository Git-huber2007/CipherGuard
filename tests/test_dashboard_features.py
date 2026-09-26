"""Compare mode, downloads and provenance, upload, presentation mode, demo-safe
errors and loading placeholders.

Server-side pieces are tested through the API. Browser pieces that carry logic
run under Node against the real module code from dashboard.js with a small page
stub; the rest are checked in the markup and stylesheet they depend on.
"""

from __future__ import annotations

import hashlib
import json
import os
import re

import pytest

from tests.jsmodules import ESC, NODE, STATIC, dashboard_js, function, module, run_node

needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")


def _read(*parts: str) -> str:
    with open(os.path.join(STATIC, *parts), encoding="utf-8") as fh:
        return fh.read()


def _sha256(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# ---------------------------------------------------------------------------
# Provenance (server-side)
# ---------------------------------------------------------------------------


def test_analyze_payload_carries_provenance(tmp_path, model_dir):
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app
    from cipherguard.lab import pcapgen

    cap = tmp_path / "legacy.pcap"
    pcapgen.scenario_legacy(str(cap))
    client = TestClient(create_app(model_dir=model_dir, capture_dir=str(tmp_path)))
    payload = client.post("/api/analyze", json={"capture": "legacy.pcap"}).json()
    p = payload["provenance"]

    assert p["capture_sha256"] == _sha256(str(cap))
    assert p["model"]["manifest_sha256"] == _sha256(os.path.join(model_dir, "MANIFEST.sha256"))
    with open(os.path.join(model_dir, "meta.json"), encoding="utf-8") as fh:
        assert p["model"]["trained_at"] == json.load(fh)["provenance"]["trained_at"]
    assert p["report_digest"] == payload["digest"] and len(p["report_digest"]) == 16
    assert "rule-ID" in p["report_digest_covers"]


@pytest.mark.no_model
def test_provenance_names_no_model_when_none_was_loaded(tmp_path):
    from cipherguard.export.payload import provenance
    from cipherguard.core.models import Assessment

    cap = tmp_path / "x.pcap"
    cap.write_bytes(b"\x00" * 10)
    a = Assessment(capture="x.pcap", started="now", stats={"model_loaded": False})
    p = provenance(a, str(cap), str(tmp_path / "no-model"))
    assert p["model"] is None and p["capture_sha256"] == _sha256(str(cap))


@pytest.mark.no_model
def test_browser_never_hashes_anything():
    js = dashboard_js()
    assert "crypto.subtle" not in js and "digest(" not in module("Report", js)


# ---------------------------------------------------------------------------
# Upload gating
# ---------------------------------------------------------------------------


@pytest.mark.no_model
@pytest.mark.parametrize("allow", [True, False])
def test_health_reports_whether_uploads_work(tmp_path, allow):
    from fastapi.testclient import TestClient

    from cipherguard.api.server import MAX_UPLOAD_BYTES, create_app

    health = TestClient(create_app(capture_dir=str(tmp_path), allow_upload=allow)).get(
        "/api/health").json()
    assert health["uploads"] is allow
    assert health["max_upload_bytes"] == (MAX_UPLOAD_BYTES if allow else None)


@pytest.mark.no_model
def test_upload_errors_are_the_endpoints_own_words(tmp_path):
    """The page shows `detail` from these responses, so each must say what rule
    was broken."""
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app

    (tmp_path / "taken.pcap").write_bytes(b"\x00")
    client = TestClient(create_app(capture_dir=str(tmp_path)))
    dup = client.post("/api/upload", files={"file": ("taken.pcap", b"\x00")})
    bad = client.post("/api/upload", files={"file": ("notes.txt", b"\x00")})
    assert dup.status_code == 409 and "already exists" in dup.json()["detail"]
    assert bad.status_code == 400 and ".pcap" in bad.json()["detail"]


@pytest.mark.no_model
def test_upload_control_is_hidden_unless_it_can_work():
    html = _read("index.html")
    zone = re.search(r'<section class="upload-zone"[^>]*>', html).group(0)
    assert "hidden" in zone                                   # hidden until proven usable
    up = module("Upload", dashboard_js())
    assert "!staticMode.active" in up and "state.health.uploads === true" in up
    assert "err.detail" in up                                 # the server's own message
    js = dashboard_js()
    assert not re.search(r"localStorage\.setItem\([^)]*token", js, re.I)
    assert 'sessionStorage.setItem("cipherguard.token"' in js


# ---------------------------------------------------------------------------
# Compare mode
# ---------------------------------------------------------------------------


def _link(pid, bits, qbits=0, worst="high"):
    a, b = pid.split("~")
    return {"id": pid, "peers": [a, b], "worst_severity": worst,
            "strength": {"classical_bits": bits, "quantum_bits": qbits}}


@pytest.mark.no_model
@needs_node
def test_compare_rows_match_links_and_mark_every_difference():
    js = dashboard_js()
    script = (ESC + module("Fmt", js) + "\n" + function("linkLabel", js) + "\n"
              + module("CompareView", js) + r"""
      const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
      const rows = CompareView.rows(input.a, input.b);
      process.stdout.write(JSON.stringify({
        rows: rows.map(r => [r.id, r.kind, r.change, r.differs]),
        html: CompareView.rowsHTML(rows),
        chips: CompareView.sevChips(input.b.counts, input.a.counts),
      }));
    """)
    a = {"links": [_link("10.0.0.1~10.0.0.2", 128, worst="medium"),
                   _link("10.0.0.3~10.0.0.4", 64, worst="critical"),
                   _link("10.0.0.5~10.0.0.6", 112)],
         "counts": {"critical": 2, "high": 1}}
    b = {"links": [_link("10.0.0.1~10.0.0.2", 80, worst="critical"),
                   _link("10.0.0.5~10.0.0.6", 112),
                   _link("10.0.0.7~10.0.0.8", 128, worst="low")],
         "counts": {"critical": 3, "high": 1}}
    got = run_node(script, {"a": a, "b": b})
    rows = {r[0]: r[1:] for r in got["rows"]}
    assert rows["10.0.0.1~10.0.0.2"] == ["weaker", "−48 classical bits", True]
    assert rows["10.0.0.3~10.0.0.4"][:2] == ["only-a", "only in A"]
    assert rows["10.0.0.7~10.0.0.8"][:2] == ["only-b", "only in B"]
    assert rows["10.0.0.5~10.0.0.6"] == ["same", "no change", False]
    assert [r[0] for r in got["rows"]][-1] == "10.0.0.5~10.0.0.6"   # differences first
    # marked in words and a symbol, not colour alone
    assert got["html"].count("●") == 3 and "<b>−48 classical bits</b>" in got["html"]
    assert "3 critical (+1)" in got["chips"] and "cmp-diff" in got["chips"]
    assert "1 high</span>" in got["chips"]                          # unchanged: no delta


@pytest.mark.no_model
def test_demo_pairing_is_legacy_against_hardened():
    fn = function("populateCaptureSelects", dashboard_js())
    assert 'byName("legacy.pcap")' in fn and 'byName("hardened.pcap")' in fn


def test_static_compare_needs_only_baked_json(tmp_path):
    """Compare mode in the static build reads the per-capture JSON; both demo
    captures must be baked with links and strength."""
    from cipherguard.export.static_site import export
    from cipherguard.lab import pcapgen

    caps = tmp_path / "caps"
    caps.mkdir()
    pcapgen.scenario_legacy(str(caps / "legacy.pcap"))
    pcapgen.scenario_hardened(str(caps / "hardened.pcap"))
    out = tmp_path / "site"
    manifest = export(capture_dir=str(caps), out_dir=str(out), model_dir="models", verbose=False)
    for entry in manifest["captures"]:
        d = json.loads((out / entry["file"]).read_text(encoding="utf-8"))
        assert d["links"] and all("strength" in l for l in d["links"])
        assert (out / entry["cbom"]).is_file()                       # downloadable, not broken
        assert d["provenance"]["capture_sha256"]


# ---------------------------------------------------------------------------
# Downloads and copy
# ---------------------------------------------------------------------------


_PAGE = r"""
function makeEl(id){ return { id, hidden: false, href: "", textContent: "", attrs: {},
  setAttribute(k, v){ this.attrs[k] = v; }, getAttribute(k){ return this.attrs[k]; },
  addEventListener(){} }; }
const els = {};
const $ = id => els[id] || (els[id] = makeEl(id));
const document = { querySelector: () => null, querySelectorAll: () => [] };
const window = {};
const state = { platform: "strongswan", playbookMode: "forward" };
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const staticMode = input.staticMode;
"""


@pytest.mark.no_model
@needs_node
@pytest.mark.parametrize("has_cbom", [True, False])
def test_static_downloads_point_at_baked_files_and_hide_a_missing_cbom(has_cbom):
    js = dashboard_js()
    entry = {"name": "legacy.pcap", "file": "data/legacy_pcap.json"}
    if has_cbom:
        entry["cbom"] = "data/cbom/legacy_pcap.cdx.json"
    got = run_node(ESC + module("Fmt", js) + _PAGE + module("Report", js) + r"""
      Report.update({ capture: "legacy.pcap", provenance: {} });
      process.stdout.write(JSON.stringify({
        report: [$("dl-report").href, $("dl-report").attrs.download],
        cbom: [$("dl-cbom").hidden, $("dl-cbom").href],
      }));
    """, {"staticMode": {"active": True, "manifest": {"captures": [entry]}}})
    assert got["report"] == ["data/legacy_pcap.json", "legacy-report.json"]
    if has_cbom:
        assert got["cbom"] == [False, "data/cbom/legacy_pcap.cdx.json"]
    else:
        assert got["cbom"][0] is True                         # hidden, not a broken link


@pytest.mark.no_model
def test_copy_confirms_truthfully():
    rep = module("Report", dashboard_js())
    assert 'Copy was blocked by the browser' in rep            # failure is said, not hidden
    assert 'alert("Copied' not in dashboard_js()               # the old false success
    html = _read("index.html")
    for id_ in ("playbook-copy-status", "dl-status", "prov-status"):
        assert re.search(rf'id="{id_}"[^>]*role="status"', html), id_


# ---------------------------------------------------------------------------
# Demo-safe errors and loading placeholders
# ---------------------------------------------------------------------------


@pytest.mark.no_model
@needs_node
def test_failed_requests_never_put_a_raw_body_on_screen():
    js = dashboard_js()
    got = run_node(function("apiError", js) + "\n" + function("explainFailure", js) + r"""
      const staticMode = { active: false };
      const mk = (status, body) => ({ status, text: async () => body });
      (async () => {
        const html = await apiError(mk(500, "<html><body>Traceback (most recent call last)...</body></html>"));
        const json = await apiError(mk(409, JSON.stringify({ detail: "x.pcap already exists; rename it first" })));
        const net = new TypeError("Failed to fetch");
        process.stdout.write(JSON.stringify({
          html: [html.message, html.status, html.body.length > 0, explainFailure(html)],
          json: [json.message, json.detail],
          net: explainFailure(net),
          missing: explainFailure(await apiError(mk(404, "{}"))),
        }));
      })();
    """)
    assert got["html"][0] == "HTTP 500" and "Traceback" not in got["html"][0]
    assert got["html"][2] is True                              # kept for the console
    assert got["html"][3] == "The server could not complete the analysis."
    assert got["json"] == ["x.pcap already exists; rename it first"] * 2
    assert got["net"] == "The analysis server is not responding."
    assert got["missing"] == "That capture is no longer available on the server."


@pytest.mark.no_model
def test_a_failed_assessment_keeps_the_previous_result():
    run = function("runAnalysis", dashboard_js())
    catch = run[run.index("}catch(err){"):]
    assert "console.error(" in catch                           # full error for debugging
    assert "renderAssessment(previous.assessment" in catch     # previous result kept
    assert "previous result" in catch and '"Retry"' in catch
    assert "err.message" not in catch.replace("err && err.status", "")


@pytest.mark.no_model
def test_placeholders_are_static_under_reduced_motion():
    css = _read("css", "dashboard.css")
    base = re.search(r"\n\.skeleton \{(.*?)\}", css, re.S).group(1)
    assert "animation" not in base                             # static by default
    assert re.search(r"@media \(prefers-reduced-motion: no-preference\) \{\s*\.skeleton \{ animation",
                     css)
    sk = module("Skeleton", dashboard_js())
    for container in ("ribbon", "stats", "link-list", "findings", "pqlinks"):
        assert f'"{container}"' in sk or f"{container}:" in sk
    assert "spinner" not in sk.lower()


# ---------------------------------------------------------------------------
# Presentation mode
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_presentation_steps_exist_in_order():
    pres = module("Present", dashboard_js())
    ids = re.findall(r'\{ id: "([\w-]+)",\s*label: "([^"]+)"', pres)
    assert [label for _, label in ids] == [
        "Posture score", "Wire ribbon", "Worst link", "Top finding group", "Hardening plan"]
    html = _read("index.html")
    for id_, _ in ids:
        assert f'id="{id_}"' in html, id_
    assert '"ArrowRight"' in pres and '"ArrowLeft"' in pres and '"Escape"' in pres
    assert 'has("present")' in pres                           # ?present in the URL
    assert 'behavior: reduced() ? "auto"' in pres              # no smooth scroll if reduced
    css = _read("css", "dashboard.css")
    assert "html.presenting{font-size:" in css and "#header-controls" in css
