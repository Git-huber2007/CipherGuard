"""The guarantees the README makes, held to by the code.

Four promises were stated in the documentation and broken in the code: no
outbound calls, no unauthenticated exposure, only measured data on screen, and
an approval step that actually gates anything. Each section below is the
regression test for one of them. A test here failing means the README is once
again describing a tool that does not exist.
"""

from __future__ import annotations

import io
import json
import os
import re
import struct
import urllib.request

import pytest

from tests.jsmodules import STATIC, dashboard_js

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _root_file(name: str) -> str:
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


def _index_html() -> str:
    with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# 1. No outbound calls unless asked
# ---------------------------------------------------------------------------


@pytest.fixture
def urlopen_calls(monkeypatch):
    """Record every urlopen call and answer like the first lookup service.

    A recorder, not a stub that raises: the lookup swallows exceptions per
    endpoint, so a raising stub would be caught and the test would pass while
    requests were still being attempted.
    """
    from cipherguard.vpn import detector

    calls: list[str] = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url if hasattr(req, "full_url") else str(req))
        return io.BytesIO(json.dumps({
            "ip": "198.51.100.7", "country": "Testland", "city": "Testville",
            "connection": {"isp": "Example Transit"},
        }).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(detector, "_GLOBAL_EGRESS_CACHE", {})
    monkeypatch.setattr(detector, "_GLOBAL_EGRESS_CACHE_TS", 0.0)
    monkeypatch.delenv("CIPHERGUARD_EGRESS_LOOKUP", raising=False)
    monkeypatch.delenv("CIPHERGUARD_NO_EGRESS_LOOKUP", raising=False)
    return calls


@pytest.mark.no_model
def test_vpn_audit_makes_no_outbound_request_by_default(urlopen_calls):
    """Regression: every dashboard load asked four public services for this
    machine's address, on a tool documented as making no outbound calls."""
    from cipherguard.vpn.detector import VpnDetector

    info = VpnDetector().detect_current()

    assert urlopen_calls == []
    assert info.egress_queried is False
    assert (info.egress_ip, info.egress_isp, info.egress_country, info.egress_city) == ("", "", "", "")
    # the payload says "not queried" in a field, not with a made-up address
    assert info.to_dict()["egress_queried"] is False
    assert info.findings, "the audit still reports without egress data"


@pytest.mark.no_model
def test_egress_lookup_is_opt_in_and_https_only(urlopen_calls, monkeypatch):
    from cipherguard.vpn import detector

    assert all(url.startswith("https://") for url, _kind in detector.EGRESS_ENDPOINTS)

    monkeypatch.setenv("CIPHERGUARD_EGRESS_LOOKUP", "1")
    info = detector.VpnDetector()._get_egress_info()
    assert info["ip"] == "198.51.100.7" and info["isp"] == "Example Transit"
    assert urlopen_calls and all(u.startswith("https://") for u in urlopen_calls)


@pytest.mark.no_model
def test_the_old_opt_out_still_wins(urlopen_calls, monkeypatch):
    from cipherguard.vpn import detector

    monkeypatch.setenv("CIPHERGUARD_EGRESS_LOOKUP", "1")
    monkeypatch.setenv("CIPHERGUARD_NO_EGRESS_LOOKUP", "1")
    assert detector.VpnDetector()._get_egress_info() == {}
    assert urlopen_calls == []


@pytest.mark.no_model
def test_dashboard_script_contacts_no_external_host():
    """Regression: the page itself fetched a public IP-lookup service when it
    fell back to the saved scan, and rewrote the saved VPN state from the
    answer. test_offline covered the markup and stylesheet but not the script."""
    hosts = {h.lower() for h in re.findall(r"https?://([a-zA-Z0-9.-]+)", dashboard_js())}
    assert not (hosts - LOOPBACK), sorted(hosts - LOOPBACK)


# ---------------------------------------------------------------------------
# 2. Never exposed unauthenticated
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_launcher_listens_on_loopback_unless_lan_mode_sets_a_token():
    """Regression: the launcher bound 0.0.0.0 with --insecure-bind and no token,
    publishing which links are weak to the whole network."""
    bat = _root_file("launch_dashboard.bat")
    assert "--insecure-bind" not in bat
    assert 'set "BIND_HOST=127.0.0.1"' in bat
    serve = [line for line in bat.splitlines() if "cipherguard.cli serve" in line and not line.upper().startswith("REM")]
    assert len(serve) == 1 and "--host !BIND_HOST!" in serve[0]
    # 0.0.0.0 is only ever assigned on the --lan path, which then requires a token
    lan = bat[bat.index('set "BIND_HOST=0.0.0.0"'):bat.index("\n:token_ready")]
    assert "CIPHERGUARD_TOKEN" in lan and "exit /b 1" in lan
    assert bat[:bat.index('set "BIND_HOST=0.0.0.0"')].rstrip().endswith("if not defined LAN_MODE goto :bind_ready")


@pytest.mark.no_model
@pytest.mark.parametrize("name", ["Dockerfile", "render.yaml"])
def test_deployment_files_never_start_the_server_unauthenticated(name):
    text = _root_file(name)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "insecure-bind" not in code
    if name == "render.yaml":
        assert "CIPHERGUARD_TOKEN" in code


@pytest.mark.no_model
def test_serve_refuses_a_non_loopback_bind_without_a_token(monkeypatch, capsys):
    """What makes the Dockerfile and render.yaml safe once the override is gone."""
    from cipherguard.cli import main

    monkeypatch.delenv("CIPHERGUARD_TOKEN", raising=False)
    assert main(["serve", "--host", "0.0.0.0"]) == 1
    assert "refusing to bind" in capsys.readouterr().err


@pytest.mark.no_model
def test_packet_stream_requires_the_token(tmp_path):
    """Regression: /api/sniff/stream was the one data route with no guard."""
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app

    client = TestClient(create_app(capture_dir=str(tmp_path), auth_token="s3cret",
                                   baseline_db=str(tmp_path / "b.db")))
    assert client.get("/api/sniff/stream").status_code == 401
    assert client.get("/api/sniff/stream",
                      headers={"Authorization": "Bearer wrong"}).status_code == 401
    for route in ("/api/sniff/status", "/api/remediation-plans"):
        assert client.get(route).status_code == 401, route


@pytest.mark.no_model
def test_every_api_route_except_health_is_guarded(tmp_path):
    """So the next route added without the dependency fails here, not in review."""
    from cipherguard.api.server import create_app

    app = create_app(capture_dir=str(tmp_path), auth_token="s3cret",
                     baseline_db=str(tmp_path / "b.db"))
    unguarded = [getattr(r, "path", "") for r in app.routes
                 if getattr(r, "path", "").startswith("/api/")
                 and not getattr(r, "dependencies", None)]
    assert unguarded == ["/api/health"]


@pytest.mark.no_model
def test_page_reads_the_stream_with_fetch_so_the_token_is_a_header():
    js = dashboard_js()
    assert "EventSource" not in re.sub(r"/\*.*?\*/|//[^\n]*", "", js, flags=re.S)
    stream = js[js.index("async function connectStream"):]
    stream = stream[:stream.index("function resetFeed")]
    assert 'resolveApiPath("/api/sniff/stream")' in stream
    assert "headers: authHeaders(" in stream
    assert "token=" not in stream and "state.token" not in stream  # never in the URL


@pytest.mark.no_model
def test_cross_origin_access_is_off_by_default(tmp_path):
    """Regression: every origin was allowed, so any web page open in the
    analyst's browser could read the tokenless loopback API."""
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app

    client = TestClient(create_app(capture_dir=str(tmp_path), baseline_db=str(tmp_path / "b.db")))
    res = client.get("/api/rules", headers={"Origin": "https://evil.example"})
    assert res.status_code == 200
    assert "access-control-allow-origin" not in res.headers

    preflight = client.options("/api/analyze", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in preflight.headers


@pytest.mark.no_model
def test_cross_origin_access_is_limited_to_the_configured_origins(tmp_path):
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app

    allowed = "https://dashboard.example"
    client = TestClient(create_app(capture_dir=str(tmp_path), baseline_db=str(tmp_path / "b.db"),
                                   cors_origins=[allowed + "/"]))
    ok = client.get("/api/rules", headers={"Origin": allowed})
    assert ok.headers["access-control-allow-origin"] == allowed
    assert "access-control-allow-credentials" not in ok.headers
    other = client.get("/api/rules", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in other.headers

    with pytest.raises(ValueError):
        create_app(capture_dir=str(tmp_path), baseline_db=str(tmp_path / "b.db"), cors_origins=["*"])


@pytest.mark.no_model
def test_serve_takes_cors_origins_from_the_command_line():
    from cipherguard.cli import build_parser

    args = build_parser().parse_args(
        ["serve", "--cors-origin", "https://a.example", "--cors-origin", "https://b.example"])
    assert args.cors_origin == ["https://a.example", "https://b.example"]
    assert build_parser().parse_args(["serve"]).cors_origin is None


# ---------------------------------------------------------------------------
# 3. Replayed samples are never shown as live traffic
# ---------------------------------------------------------------------------


def _ipv4(proto: int, body: bytes, src: str = "203.0.113.5", dst: str = "198.51.100.9",
          frag: int = 0) -> bytes:
    import socket

    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, frag, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + body


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


@pytest.fixture
def sample_dir(tmp_path, monkeypatch):
    """A samples directory the replay can read, independent of the working tree."""
    from cipherguard.capture import live_sniffer
    from cipherguard.lab import pcapgen

    samples = tmp_path / "samples"
    samples.mkdir()
    pcapgen.scenario_hardened(str(samples / "hardened.pcap"))
    monkeypatch.setattr(live_sniffer, "_samples_dir", lambda: str(samples))
    return samples


def _refuse_socket(monkeypatch):
    from cipherguard.capture.live_sniffer import LiveSniffer

    def refuse(self):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(LiveSniffer, "_open_socket", refuse)


@pytest.mark.no_model
def test_a_capture_that_cannot_start_fails_and_does_not_replay(sample_dir, monkeypatch):
    """Regression: with no raw-socket privilege, which is every ordinary
    workstation, the sniffer replayed sample captures and the page called it
    live. The samples are present here, so the old fallback would have run."""
    from cipherguard.capture.live_sniffer import LiveSniffer

    _refuse_socket(monkeypatch)
    sniffer = LiveSniffer()
    status = sniffer.start()

    assert status["running"] is False and status["mode"] == "failed"
    assert "raw socket was refused" in status["error"]
    assert status["packets_captured"] == 0 and status["source"] is None
    assert sniffer.thread is None and not sniffer.packet_buffer


@pytest.mark.no_model
def test_replay_runs_only_on_request_and_says_what_it_is(sample_dir):
    import time

    from cipherguard.capture.live_sniffer import LiveSniffer

    sniffer = LiveSniffer()
    status = sniffer.start(replay=True)
    try:
        assert status["running"] is True
        assert status["mode"] == "replay" and status["source"] == "replay"
        assert "replay" in status["interface"].lower()
        time.sleep(0.3)
    finally:
        sniffer.stop()
    # the source outlives stop(), so a later snapshot is still labelled
    assert sniffer.buffer_source == "replay" and sniffer.packet_buffer


@pytest.mark.no_model
def test_replay_with_no_samples_fails_instead_of_inventing_packets(tmp_path, monkeypatch):
    """Regression: with no sample files the replay streamed a random packet."""
    from cipherguard.capture import live_sniffer

    monkeypatch.setattr(live_sniffer, "_samples_dir", lambda: str(tmp_path / "missing"))
    status = live_sniffer.LiveSniffer().start(replay=True)
    assert status["running"] is False and status["mode"] == "failed"
    assert "cipherguard lab" in status["error"]


@pytest.mark.no_model
def test_live_path_keeps_only_ike_and_esp():
    """Regression: the live path counted every UDP datagram on the host as ESP,
    read its port numbers as an SPI, and buffered all traffic for the snapshot."""
    from cipherguard.capture.live_sniffer import LiveSniffer

    sniffer = LiveSniffer()
    esp = struct.pack("!II", 0xC3A1F00D, 1) + b"\x55" * 64
    feed = [
        _ipv4(50, esp),                                                  # ESP
        _ipv4(17, _udp(500, 500, b"\x11" * 28)),                         # IKE
        _ipv4(17, _udp(4500, 4500, b"\x00" * 4 + b"\x11" * 28)),         # IKE over NAT-T
        _ipv4(17, _udp(4500, 4500, esp)),                                # UDP-encapsulated ESP
        _ipv4(17, _udp(4500, 4500, b"\xff")),                            # NAT keepalive
        _ipv4(17, _udp(53124, 53, b"\x12\x34" + b"\x00" * 30)),          # DNS
        _ipv4(17, _udp(443, 50000, b"\x40" * 40)),                       # QUIC
        _ipv4(6, b"\x00" * 40),                                          # TCP
        _ipv4(50, esp, frag=0x0010),                                     # non-first fragment
        b"\x45\x00",                                                     # runt
    ]
    for datagram in feed:
        sniffer._handle_datagram(datagram, 1.0)

    assert sniffer.packets_captured == 4
    assert sniffer.ike_count == 2 and sniffer.esp_count == 2
    assert set(sniffer.active_spis) == {"0xc3a1f00d"}
    assert {p[3] for p in sniffer.packet_buffer} == {17, 50}
    assert all(p[4] in (0, 500, 4500) for p in sniffer.packet_buffer)
    assert sniffer.bytes_captured == sum(len(p[6]) for p in sniffer.packet_buffer)


@pytest.mark.no_model
def test_snapshot_round_trips_ike_with_its_ports(tmp_path):
    """Regression: the snapshot wrote UDP payloads with no UDP header, so the
    IKE packets in it could not be read back."""
    from cipherguard.capture.live_sniffer import LiveSniffer
    from cipherguard.dissector.pcap import read_packets

    sniffer = LiveSniffer()
    sniffer.buffer_source = "live"
    ike = b"\x11" * 28
    sniffer._handle_datagram(_ipv4(17, _udp(500, 500, ike)), 1.0)
    sniffer._handle_datagram(_ipv4(50, struct.pack("!II", 7, 1) + b"\x55" * 32), 2.0)

    out = sniffer.snapshot_to_pcap(str(tmp_path / "snap.pcap"))
    assert out["packets_written"] == 2 and out["source"] == "live"
    udp, esp = list(read_packets(out["path"]))
    assert (udp.protocol, udp.sport, udp.dport, udp.payload) == (17, 500, 500, ike)
    assert esp.protocol == 50 and esp.payload[:4] == struct.pack("!I", 7)


@pytest.mark.no_model
def test_throughput_is_computed_from_bytes_seen():
    """Regression: kbps was packets x an assumed 800 bytes."""
    import inspect

    from cipherguard.capture.live_sniffer import LiveSniffer

    assert "800" not in inspect.getsource(LiveSniffer.get_status)


@pytest.fixture
def sniff_api(tmp_path, monkeypatch):
    """The API with a fresh sniffer in place of the process-wide one."""
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app
    from cipherguard.capture import live_sniffer

    sniffer = live_sniffer.LiveSniffer()
    monkeypatch.setattr(live_sniffer, "global_sniffer", sniffer)
    captures = tmp_path / "captures"
    captures.mkdir()

    def build(**kw):
        return TestClient(create_app(capture_dir=str(captures),
                                     baseline_db=str(tmp_path / "b.db"), **kw))

    yield build, sniffer, captures
    sniffer.stop()


@pytest.mark.no_model
def test_api_reports_a_failed_capture_with_the_reason(sniff_api, sample_dir, monkeypatch):
    build, sniffer, _captures = sniff_api
    _refuse_socket(monkeypatch)

    res = build().post("/api/sniff/start", json={"interface": "All Interfaces"})
    assert res.status_code == 503
    assert "raw socket was refused" in res.json()["detail"]
    assert res.json()["status"]["mode"] == "failed"
    assert sniffer.running is False

    # nothing was captured, so there is nothing to assess, and no file is written
    assert build().post("/api/sniff/analyze").status_code == 409


@pytest.mark.no_model
def test_only_an_explicit_true_starts_a_replay(sniff_api, sample_dir, monkeypatch):
    build, sniffer, _captures = sniff_api
    _refuse_socket(monkeypatch)
    client = build()
    for body in ({}, {"replay": "yes"}, {"replay": 1}, {"force_simulation": True}):
        assert client.post("/api/sniff/start", json=body).status_code == 503, body
        assert sniffer.running is False

    res = client.post("/api/sniff/start", json={"replay": True})
    assert res.status_code == 200 and res.json()["mode"] == "replay"


def test_assessment_of_a_replay_is_labelled_as_one(sniff_api, sample_dir, model_dir):
    import time

    build, sniffer, captures = sniff_api
    client = build(model_dir=model_dir)
    assert client.post("/api/sniff/start", json={"replay": True}).status_code == 200
    deadline = time.time() + 5
    while not sniffer.packet_buffer and time.time() < deadline:
        time.sleep(0.05)
    client.post("/api/sniff/stop")

    payload = client.post("/api/sniff/analyze").json()
    assert payload["capture_source"] == "replay"
    assert payload["provenance"]["capture"] == "replay_snapshot.pcap"
    assert sorted(os.listdir(captures)) == ["replay_snapshot.pcap"]   # never live_snapshot


@pytest.mark.no_model
def test_page_labels_replay_and_offers_it_only_as_its_own_button():
    html, js = _index_html(), dashboard_js()
    assert 'id="btn-sniffer-replay"' in html and 'id="sniffer-source-notice"' in html
    engine = js[js.index("const LiveSnifferEngine"):js.index("window.LiveSnifferEngine")]
    assert "NOT LIVE" in engine and "not live traffic" in engine.lower()
    assert 'btnStart.addEventListener("click", () => startSniffing(false))' in engine
    assert 'btnReplay.addEventListener("click", () => startSniffing(true))' in engine
    assert 'data.capture_source === "replay"' in engine
    assert "force_simulation" not in js


# ---------------------------------------------------------------------------
# 4. Approval gates the dry-run, and the approver is self-declared
# ---------------------------------------------------------------------------


@pytest.fixture
def plans_api(tmp_path, model_dir):
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app
    from cipherguard.lab import pcapgen

    captures = tmp_path / "captures"
    captures.mkdir()
    pcapgen.scenario_legacy(str(captures / "legacy.pcap"))
    audit = tmp_path / "audit.jsonl"
    client = TestClient(create_app(model_dir=model_dir, capture_dir=str(captures),
                                   baseline_db=str(tmp_path / "b.db"), audit_log=str(audit)))
    plans = client.get("/api/remediation/legacy.pcap").json()["plans"]

    def events():
        with open(audit, encoding="utf-8") as fh:
            return [r for r in map(json.loads, fh) if r["event"] == "remediation"]

    return client, plans[0], events


def test_a_plan_cannot_be_staged_until_it_is_approved(plans_api):
    """Regression: /apply staged any plan id, approved or not."""
    client, plan, events = plans_api
    pid = plan["plan_id"]
    assert plan["status"] == "PENDING_REVIEW" and plan["approver_identity"] is None

    refused = client.post(f"/api/remediation/{pid}/apply", json={"dry_run": True})
    assert refused.status_code == 409 and "must be approved" in refused.json()["detail"]
    stored = {p["plan_id"]: p for p in client.get("/api/remediation-plans").json()["plans"]}
    assert stored[pid]["status"] == "PENDING_REVIEW"

    approved = client.post(f"/api/remediation/{pid}/approve",
                           json={"actor": "A. Analyst", "comment": "change window 4"})
    assert approved.status_code == 200
    assert approved.json()["plan"]["approver_identity"] == "self-declared"

    staged = client.post(f"/api/remediation/{pid}/apply", json={"dry_run": True})
    assert staged.status_code == 200 and staged.json()["mode"] == "dry-run"
    stored = {p["plan_id"]: p for p in client.get("/api/remediation-plans").json()["plans"]}
    assert stored[pid]["status"] == "STAGED"
    # staging no longer overwrites who approved it
    assert stored[pid]["approver"] == "A. Analyst"

    log = events()
    assert [(e["action"], e["outcome"]) for e in log] == [
        ("apply", "refused: not approved"), ("approve", ""), ("apply", "dry-run")]
    assert all(e["actor_identity"] == "self-declared" and e["plan_id"] == pid for e in log)
    assert log[1]["declared_actor"] == "A. Analyst"
    # the audit trail identifies the plan; it does not copy the configuration
    assert not any("forward_config" in e or "crypto" in json.dumps(e) for e in log)


def test_an_approved_plan_is_still_never_applied_to_a_gateway(plans_api):
    client, plan, _events = plans_api
    pid = plan["plan_id"]
    client.post(f"/api/remediation/{pid}/approve", json={"actor": "A. Analyst"})
    live = client.post(f"/api/remediation/{pid}/apply",
                       json={"dry_run": False, "target": "192.0.2.1"}).json()
    assert live["success"] is False and live["mode"] == "live_apply_prohibited"
    stored = {p["plan_id"]: p for p in client.get("/api/remediation-plans").json()["plans"]}
    assert stored[pid]["status"] == "APPROVED"


def test_an_approval_needs_a_name_and_the_name_is_cleaned(plans_api):
    """Regression: a request with no name was recorded as approved by
    "Security Administrator"."""
    client, plan, _events = plans_api
    pid = plan["plan_id"]
    for body in ({}, {"actor": ""}, {"actor": "   "}, {"actor": 7}):
        res = client.post(f"/api/remediation/{pid}/approve", json=body)
        assert res.status_code == 400, body
    assert client.post("/api/remediation/no-such-plan/approve",
                       json={"actor": "x"}).status_code == 404

    res = client.post(f"/api/remediation/{pid}/approve",
                      json={"actor": "Eve\n! injected line\t" + "x" * 200})
    saved = res.json()["plan"]["approver"]
    assert "\n" not in saved and "\t" not in saved and len(saved) <= 80
    assert saved.startswith("Eve ! injected line")


@pytest.mark.no_model
def test_page_shows_the_approver_as_self_declared():
    js = dashboard_js()
    assert "APPROVED (self-declared: " in js
    assert "does not authenticate individual people" in js
