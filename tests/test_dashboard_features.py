"""Compare mode, downloads and provenance, upload, presentation mode, demo-safe
errors and loading placeholders.

Server-side pieces are tested through the API. Browser pieces that carry logic
run under Node against the real module code from dashboard.js with a small page
stub; the rest are checked in the markup and stylesheet they depend on.
"""

from __future__ import annotations

import hashlib
from html import unescape as _unescape
import json
import os
import re

import pytest

from tests.jsmodules import ESC, NODE, STATIC, dashboard_js, function, module, run_node

needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")

# An empty but valid pcap; the upload endpoint checks the magic number.
PCAP_HEADER = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")


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

    health = TestClient(create_app(capture_dir=str(tmp_path), allow_upload=allow)).get("/api/health").json()
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
    dup = client.post("/api/upload", files={"file": ("taken.pcap", PCAP_HEADER)})
    bad = client.post("/api/upload", files={"file": ("notes.txt", b"\x00")})
    assert dup.status_code == 409 and "already exists" in dup.json()["detail"]
    assert bad.status_code == 400 and ".pcap" in bad.json()["detail"]


@pytest.mark.no_model
def test_upload_control_is_hidden_unless_it_can_work():
    html = _read("index.html")
    zone = re.findall(r'<section class="upload-zone"[^>]*>', html)[0]
    assert "hidden" in zone  # hidden until proven usable
    up = module("Upload", dashboard_js())
    assert "!staticMode.active" in up and "state.health.uploads === true" in up
    assert "err.detail" in up  # the server's own message
    js = dashboard_js()
    assert not re.search(r"localStorage\.setItem\([^)]*token", js, re.I)
    assert 'sessionStorage.setItem("cipherguard.token"' in js


# ---------------------------------------------------------------------------
# Compare mode
# ---------------------------------------------------------------------------


def _link(pid, bits, qbits=0, worst="high"):
    a, b = pid.split("~")
    return {
        "id": pid,
        "peers": [a, b],
        "worst_severity": worst,
        "strength": {"classical_bits": bits, "quantum_bits": qbits},
    }


@pytest.mark.no_model
@needs_node
def test_compare_rows_match_links_and_mark_every_difference():
    js = dashboard_js()
    script = (
        ESC
        + module("Fmt", js)
        + "\n"
        + function("linkLabel", js)
        + "\n"
        + module("CompareView", js)
        + r"""
      const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
      const rows = CompareView.rows(input.a, input.b);
      process.stdout.write(JSON.stringify({
        rows: rows.map(r => [r.id, r.kind, r.change, r.differs]),
        html: CompareView.rowsHTML(rows),
        chips: CompareView.sevChips(input.b.counts, input.a.counts),
      }));
    """
    )
    a = {
        "links": [
            _link("10.0.0.1~10.0.0.2", 128, worst="medium"),
            _link("10.0.0.3~10.0.0.4", 64, worst="critical"),
            _link("10.0.0.5~10.0.0.6", 112),
        ],
        "counts": {"critical": 2, "high": 1},
    }
    b = {
        "links": [
            _link("10.0.0.1~10.0.0.2", 80, worst="critical"),
            _link("10.0.0.5~10.0.0.6", 112),
            _link("10.0.0.7~10.0.0.8", 128, worst="low"),
        ],
        "counts": {"critical": 3, "high": 1},
    }
    got = run_node(script, {"a": a, "b": b})
    rows = {r[0]: r[1:] for r in got["rows"]}
    assert rows["10.0.0.1~10.0.0.2"] == ["weaker", "−48 classical bits", True]
    assert rows["10.0.0.3~10.0.0.4"][:2] == ["only-a", "only in A"]
    assert rows["10.0.0.7~10.0.0.8"][:2] == ["only-b", "only in B"]
    assert rows["10.0.0.5~10.0.0.6"] == ["same", "no change", False]
    assert [r[0] for r in got["rows"]][-1] == "10.0.0.5~10.0.0.6"  # differences first
    # marked in words and a symbol, not colour alone
    assert got["html"].count("●") == 3 and "<b>−48 classical bits</b>" in got["html"]
    assert "3 critical (+1)" in got["chips"] and "cmp-diff" in got["chips"]
    assert "1 high</span>" in got["chips"]  # unchanged: no delta


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
        assert (out / entry["cbom"]).is_file()  # downloadable, not broken
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
    got = run_node(
        ESC
        + module("Fmt", js)
        + _PAGE
        + module("Report", js)
        + r"""
      Report.update({ capture: "legacy.pcap", provenance: {} });
      process.stdout.write(JSON.stringify({
        report: [$("dl-report").href, $("dl-report").attrs.download],
        cbom: [$("dl-cbom").hidden, $("dl-cbom").href],
      }));
    """,
        {"staticMode": {"active": True, "manifest": {"captures": [entry]}}},
    )
    assert got["report"] == ["data/legacy_pcap.json", "legacy-report.json"]
    if has_cbom:
        assert got["cbom"] == [False, "data/cbom/legacy_pcap.cdx.json"]
    else:
        assert got["cbom"][0] is True  # hidden, not a broken link


@pytest.mark.no_model
def test_copy_confirms_truthfully():
    rep = module("Report", dashboard_js())
    assert "Copy was blocked by the browser" in rep  # failure is said, not hidden
    assert 'alert("Copied' not in dashboard_js()  # the old false success
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
    got = run_node(
        function("apiError", js)
        + "\n"
        + function("explainFailure", js)
        + r"""
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
    """
    )
    assert got["html"][0] == "HTTP 500" and "Traceback" not in got["html"][0]
    assert got["html"][2] is True  # kept for the console
    assert got["html"][3] == "The server could not complete the assessment."
    assert got["json"] == ["x.pcap already exists; rename it first"] * 2
    assert got["net"] == "The server is not responding."
    assert got["missing"] == "That capture is no longer available on the server."


@pytest.mark.no_model
def test_a_failed_assessment_keeps_the_previous_result():
    run = function("runAnalysis", dashboard_js())
    catch = run[run.index("}catch(err){") :]
    assert "console.error(" in catch  # full error for debugging
    assert "renderAssessment(previous.assessment" in catch  # previous result kept
    assert "previous result" in catch and '"Retry"' in catch
    assert "err.message" not in catch.replace("err && err.status", "")


@pytest.mark.no_model
def test_placeholders_are_static_under_reduced_motion():
    css = _read("css", "dashboard.css")
    base = re.findall(r"\n\.skeleton \{(.*?)\}", css, re.S)[0]
    assert "animation" not in base  # static by default
    assert re.search(r"@media \(prefers-reduced-motion: no-preference\) \{\s*\.skeleton \{ animation", css)
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
        "Posture score",
        "Wire ribbon",
        "Worst link",
        "Top finding group",
        "Hardening plan",
    ]
    html = _read("index.html")
    for id_, _ in ids:
        assert f'id="{id_}"' in html, id_
    assert '"ArrowRight"' in pres and '"ArrowLeft"' in pres and '"Escape"' in pres
    assert 'has("present")' in pres  # ?present in the URL
    assert 'behavior: reduced() ? "auto"' in pres  # no smooth scroll if reduced
    css = _read("css", "dashboard.css")
    assert "html.presenting{font-size:" in css and "#header-controls" in css


# ---------------------------------------------------------------------------
# Theme: light by default, Dark and System on request
# ---------------------------------------------------------------------------

_THEME_PAGE = r"""
let osDark = true, stored = null, storageThrows = false;
const listeners = [];
const attrs = {};
const document = { documentElement: { setAttribute: (k, v) => { attrs[k] = v; } } };
const sel = { value: "", addEventListener: (ev, fn) => { sel.onchange = fn; } };
const $ = id => (id === "theme-select" ? sel : null);
const localStorage = {
  getItem: k => { if (storageThrows) throw new Error("denied"); return stored; },
  setItem: (k, v) => { if (storageThrows) throw new Error("denied"); stored = v; },
};
const mq = {
  get matches(){ return osDark; },
  addEventListener: (ev, fn) => listeners.push(fn),
};
const window = { matchMedia: () => mq };
const matchMedia = window.matchMedia;
"""


@pytest.mark.skipif(NODE is None, reason="node is not installed")
@pytest.mark.no_model
def test_theme_is_light_unless_the_reader_asks():
    js = dashboard_js()
    got = run_node(
        _THEME_PAGE
        + module("Theme", js)
        + r"""
const out = {};
Theme.init();                       out.fresh_on_dark_os = attrs["data-theme"];
sel.value = "dark"; sel.onchange(); out.picked_dark = attrs["data-theme"]; out.saved = stored;
sel.value = "system"; sel.onchange(); out.system_dark_os = attrs["data-theme"];
osDark = false; listeners.forEach(f => f()); out.os_turns_light = attrs["data-theme"];
sel.value = "light"; sel.onchange(); osDark = true; listeners.forEach(f => f());
out.light_ignores_os = attrs["data-theme"];
stored = "neon"; Theme.init();      out.junk_saved = attrs["data-theme"];
storageThrows = true; Theme.init(); out.no_storage = attrs["data-theme"];
Theme.set("dark");                  out.no_storage_still_switches = attrs["data-theme"];
console.log(JSON.stringify(out));
"""
    )
    assert got == {
        "fresh_on_dark_os": "light",
        "picked_dark": "dark",
        "saved": "dark",
        "system_dark_os": "dark",
        "os_turns_light": "light",
        "light_ignores_os": "light",
        "junk_saved": "light",
        "no_storage": "light",
        "no_storage_still_switches": "dark",
    }


@pytest.mark.no_model
def test_saved_theme_is_applied_before_the_stylesheet_paints():
    html = _read("index.html")
    head = html[: html.index("</head>")]
    tag = re.search(r'<script src="[^"]*js/theme-init\.js"></script>', head)
    assert tag, "theme-init.js must load in <head>, without defer or async"
    assert tag.start() < head.index('rel="stylesheet"')  # no flash of the wrong theme
    init = _read("js", "theme-init.js")
    assert 'localStorage.getItem("cipherguard.theme")' in init
    assert '"cipherguard.theme"' in module("Theme", dashboard_js())
    options = re.findall(r'<option value="(\w+)">', html[html.index('id="theme-select"') :][:400])
    assert options == ["light", "dark", "system"]


# ---------------------------------------------------------------------------
# Capture contents are hostile: names from packets and uploads render as text
# ---------------------------------------------------------------------------

HOSTILE = "<img src=x onerror=alert(1)>"

_SINK_PAGE = r"""
function makeEl(id){ return { id, innerHTML: "", value: "", selectedIndex: 0, hidden: false,
  classList: { add(){}, remove(){} }, setAttribute(){}, addEventListener(){},
  querySelectorAll: () => [] }; }
const els = {};
const $ = id => els[id] || (els[id] = makeEl(id));
const name = JSON.parse(require('fs').readFileSync(0, 'utf8')).name;
const state = { wifiGroupMode: true, wifiAssessment: null, currentWifiNetworks: [] };
const network = { ssid: name, bssid: name, authentication: name, encryption: name, band: name,
                  channel: 6, signal_percent: 70, rssi_dbm: -50, security_grade: name };
"""


def _elements_and_text(html: str) -> tuple[set[str], str]:
    from html.parser import HTMLParser

    tags, text = set(), []

    class Collect(HTMLParser):
        def handle_starttag(self, tag, attrs):
            tags.add(tag)

        def handle_data(self, data):
            text.append(data)

    Collect().feed(html)
    return tags, "".join(text)


@pytest.mark.no_model
@needs_node
def test_hostile_network_and_capture_names_render_as_text():
    """An SSID comes from a beacon and a capture name from an upload, so both
    are attacker-chosen. Rendered through the page's own code, the markup must
    come out as text: no <img> element, and the name readable as written."""
    js = dashboard_js()
    got = run_node(
        function("esc", js)
        + module("Fmt", js)
        + module("UIState", js)
        + _SINK_PAGE
        + function("signalTone", js)
        + function("renderWifiNetworksTable", js)
        + function("populateCaptureSelects", js)
        + r"""
      const out = {};
      renderWifiNetworksTable([network, Object.assign({}, network, { bssid: name + "2" })]);
      out.grouped = $("wifi-networks-tbody").innerHTML;
      state.wifiGroupMode = false;
      renderWifiNetworksTable([network]);
      out.flat = $("wifi-networks-tbody").innerHTML;
      populateCaptureSelects([{ name, size_bytes: 1200 }]);
      out.captures = $("capture").innerHTML;
      process.stdout.write(JSON.stringify(out));
    """,
        {"name": HOSTILE},
    )
    for view, html in got.items():
        tags, text = _elements_and_text(html)
        assert "img" not in tags, view
        assert HOSTILE in text, view
        assert "<img" not in html, view


# The renderers below reach into more of the page than the two above, so the
# whole of each script is loaded against a stub document instead of picking
# functions out one by one. Any element asked for by id exists and keeps what
# is written to its innerHTML.
_WHOLE_PAGE = r"""
const made = {};
const makeEl = id => new Proxy(
  { id, innerHTML: "", textContent: "", hidden: false, dataset: {}, style: { setProperty(){} },
    classList: { add(){}, remove(){}, toggle(){ return false; }, contains(){ return false; } } },
  { get(t, k){ if (k in t) return t[k];
               if (k === "querySelectorAll") return () => [];
               if (k === "querySelector") return () => null;
               return () => undefined; },
    set(t, k, v){ t[k] = v; return true; } });
const document = { currentScript: null, getElementById: id => made[id] || (made[id] = makeEl(id)),
                   querySelector: () => null, querySelectorAll: () => [], addEventListener(){} };
const window = {};
const name = JSON.parse(require('fs').readFileSync(0, 'utf8')).name;
"""


@pytest.mark.no_model
@needs_node
def test_hostile_findings_vendor_ids_proposals_and_ssids_render_as_text(tmp_path):
    """Finding text, IKE vendor IDs, SA proposal values and SSIDs are all read
    out of packets. Each is rendered here by the page's own code, through every
    panel that shows it, and must come out as text: no element is created."""
    scripts = "".join(_read("js", f) for f in ("core.js", "ipsec-view.js", "evidence.js", "wifi.js", "spectrum.js"))
    # five whole scripts are too long for a command line, so Node loads them from a file
    page = tmp_path / "page.js"
    page.write_text(
        _WHOLE_PAGE
        + scripts
        + r"""
      const html = id => document.getElementById(id).innerHTML;
      const finding = { severity: "critical", rule_id: "IKE-004", title: name, subject: name, detail: name,
                        remediation: name, reference: name, inferred: false };
      const assessment = {
        capture: name,
        sessions: [{ version: "IKEv2", vendor_family: name, vendor_ids: [name], initiator_spi: name,
                     peer_a: name, peer_b: name,
                     messages: [{ is_response: true, proposals: [{ protocol: "IKE",
                       transforms: [{ type_id: 1, type_name: "ENCR", value_id: 3, name, key_length: null }] }] }] }],
        flows: [{ src: name, dst: name, spi: name, packets: 5, framing_class: name, framing_confidence: 1,
                  ambiguous: true, framing_candidates: [name], encapsulated: false }],
        findings: [finding],
      };
      const link = { id: "a~b", peers: [name, name], sessions: [0], flows: [0], worst_severity: "critical",
                     strength: { classical_bits: 64, quantum_bits: 0, kex_family: name }, tunnels: 1, pooled: false };
      assessment.links = [link];

      const out = {};
      out.finding = findingHTML(finding, 0, "g");
      renderWifiFindings([finding]);
      out.wifiFinding = html("wifi-findings");
      renderRibbonTo("ribbon", assessment, link);
      out.ribbon = html("ribbon");
      renderLinkDetail(assessment, link);
      out.linkDetail = html("link-detail");
      state.spectrumBand = "2.4";
      renderRfSpectrum([{ ssid: name, bssid: name, channel: 6, band: "2.4 GHz", rssi_dbm: -50, signal_percent: 70,
                          authentication: name, encryption: name, connected: true }]);
      out.spectrum = html("wifi-spectrum-svg");
      process.stdout.write(JSON.stringify(out));
    """,
        encoding="utf-8",
    )
    got = run_node(f"require({json.dumps(str(page))})", {"name": HOSTILE})
    for view, html in got.items():
        tags, text = _elements_and_text(html)
        assert not tags & {"img", "script"}, view
        # the chart label is cut to 14 characters; everywhere else the name is whole
        assert (HOSTILE[:14] if view == "spectrum" else HOSTILE) in text, view

    # the chart's tooltip reads its text back out of an attribute: it must survive the round trip
    spec = re.search(r'data-spec="([^"]*)"', got["spectrum"])
    assert spec and json.loads(_unescape(spec.group(1)))["ssid"] == HOSTILE
