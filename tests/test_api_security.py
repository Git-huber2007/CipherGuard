"""The API's request-level protections.

Each test here is a request that used to succeed and should not have: it was
sent to a default, tokenless server and either came from another web site or
carried input nothing had checked.
"""

from __future__ import annotations

import json
import struct

import pytest

pytestmark = pytest.mark.no_model

PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
EVIL = "https://evil.example"


def _app(tmp_path, **kw):
    from cipherguard.api.server import create_app

    kw.setdefault("capture_dir", str(tmp_path))
    kw.setdefault("baseline_db", str(tmp_path / "b.db"))
    return create_app(**kw)


def _client(tmp_path, **kw):
    from fastapi.testclient import TestClient

    return TestClient(_app(tmp_path, **kw), raise_server_exceptions=False)


@pytest.fixture
def lab_captures(tmp_path):
    from cipherguard.lab import pcapgen

    pcapgen.scenario_legacy(str(tmp_path / "legacy.pcap"))
    return tmp_path


# -- Host allowlist ---------------------------------------------------------


def test_tokenless_server_answers_loopback_names_only(tmp_path):
    """DNS rebinding: the hostile page is same-origin to the browser, so CORS
    never applies. Its Host header is the one thing that gives it away."""
    client = _client(tmp_path)
    for host in ("127.0.0.1:8000", "localhost:8000", "[::1]:8000", "LOCALHOST"):
        assert client.get("/api/rules", headers={"Host": host}).status_code == 200, host
    for host in ("attacker.example", "attacker.example:8000", "127.0.0.1.attacker.example", ""):
        res = client.get("/api/rules", headers={"Host": host})
        assert res.status_code == 400, host
        assert "captures" not in res.text


def test_host_check_covers_pages_and_static_files(tmp_path):
    client = _client(tmp_path)
    for path in ("/", "/static/js/main.js", "/api/health"):
        assert client.get(path, headers={"Host": "attacker.example"}).status_code == 400, path


def test_a_token_or_an_explicit_list_changes_which_hosts_are_answered(tmp_path):
    with_token = _client(tmp_path, auth_token="s3cret")
    res = with_token.get("/api/rules", headers={"Host": "sensor.agency.example", "Authorization": "Bearer s3cret"})
    assert res.status_code == 200

    named = _client(tmp_path, allowed_hosts=["tunnel.example"])
    assert named.get("/api/rules", headers={"Host": "tunnel.example"}).status_code == 200
    assert named.get("/api/rules", headers={"Host": "127.0.0.1"}).status_code == 400


def test_serve_adds_named_hosts_to_the_loopback_list(monkeypatch):
    import cipherguard.api.server as server
    from cipherguard.cli import build_parser, cmd_serve

    seen = {}
    monkeypatch.setattr(server, "create_app", lambda **kw: seen.update(kw) or object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **kw: None)
    monkeypatch.delenv("CIPHERGUARD_TOKEN", raising=False)
    monkeypatch.delenv("CIPHERGUARD_ALLOWED_HOSTS", raising=False)

    args = build_parser().parse_args(["serve", "--allowed-host", "tunnel.example", "--audit-log", ""])
    assert cmd_serve(args) == 0
    assert set(seen["allowed_hosts"]) == {"127.0.0.1", "localhost", "::1", "testserver", "tunnel.example"}


# -- cross-site requests ----------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/api/sniff/start",
        "/api/sniff/stop",
        "/api/sniff/analyze",
        "/api/wifi/scan",
        "/api/remediation/cg-plan-00000000/approve",
        "/api/remediation/cg-plan-00000000/apply",
        "/api/analyze",
        "/api/upload",
    ],
)
def test_state_changing_requests_from_another_site_are_refused(tmp_path, path):
    """A text/plain POST needs no preflight, so the browser just sends it."""
    client = _client(tmp_path)
    res = client.post(path, content="{}", headers={"Content-Type": "text/plain", "Origin": EVIL})
    assert res.status_code == 403, res.text
    for origin in ("null", "http://testserver.evil.example", "http://evil.example:80"):
        assert client.post(path, content="{}", headers={"Origin": origin}).status_code == 403, origin


def test_a_cross_site_request_with_no_origin_header_is_still_refused(tmp_path):
    client = _client(tmp_path)
    res = client.post("/api/sniff/stop", headers={"Sec-Fetch-Site": "cross-site"})
    assert res.status_code == 403


def test_the_page_itself_and_non_browser_clients_are_not_refused(tmp_path):
    client = _client(tmp_path)
    same = client.post("/api/sniff/stop", headers={"Origin": "http://testserver"})
    assert same.status_code == 200
    assert client.post("/api/sniff/stop").status_code == 200  # curl, scripts


def test_a_configured_origin_may_post(tmp_path):
    allowed = "https://dashboard.example"
    client = _client(tmp_path, cors_origins=[allowed])
    assert client.post("/api/sniff/stop", headers={"Origin": allowed}).status_code == 200
    assert client.post("/api/sniff/stop", headers={"Origin": EVIL}).status_code == 403


def test_a_json_body_must_be_declared_as_json(lab_captures):
    client = _client(lab_captures)
    plan_id = client.get("/api/remediation/legacy.pcap").json()["plans"][0]["plan_id"]
    body = json.dumps({"actor": "someone"})

    forged = client.post(f"/api/remediation/{plan_id}/approve", content=body, headers={"Content-Type": "text/plain"})
    assert forged.status_code == 415
    listed = client.get("/api/remediation-plans").json()["plans"]
    assert all(p["status"] != "APPROVED" for p in listed)

    broken = client.post(
        f"/api/remediation/{plan_id}/approve", content="{not json", headers={"Content-Type": "application/json"}
    )
    assert broken.status_code == 400

    real = client.post(f"/api/remediation/{plan_id}/approve", json={"actor": "someone"})
    assert real.status_code == 200


# -- response headers and exposed surface -----------------------------------


@pytest.mark.parametrize("path", ["/", "/api/rules", "/static/js/main.js", "/api/nope"])
def test_every_response_carries_the_security_headers(tmp_path, path):
    res = _client(tmp_path).get(path)
    csp = res.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    script_src = next(d for d in csp.split("; ") if d.startswith("script-src"))
    assert script_src == "script-src 'self'"  # no inline, no eval, no CDN
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["referrer-policy"] == "no-referrer"
    assert "strict-transport-security" not in res.headers  # plain http: HSTS would be ignored


def test_api_responses_are_not_cached_and_https_gets_hsts(tmp_path):
    client = _client(tmp_path)
    assert client.get("/api/rules").headers["cache-control"] == "no-store"
    behind_tls = client.get("/api/rules", headers={"X-Forwarded-Proto": "https"})
    assert "max-age=" in behind_tls.headers["strict-transport-security"]


def test_the_page_needs_no_inline_script():
    """script-src 'self' blocks inline handlers, so the page must not use any."""
    import os
    import re

    from tests.jsmodules import STATIC

    for name in ("index.html", "404.html"):
        with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
            html = fh.read()
        assert not re.search(r"\son[a-z]+\s*=", html), f"inline event handler in {name}"
        assert not re.search(r"<script(?![^>]*\ssrc=)[^>]*>", html), f"inline script in {name}"
        assert "javascript:" not in html


def test_static_files_carry_no_inline_event_handlers():
    """Markup built in script is still markup: a handler attribute in a template
    string is blocked by script-src 'self' just like one in the page, and the
    button silently does nothing. Scripts name an action instead (data-action)."""
    import glob
    import os
    import re

    from tests.jsmodules import STATIC

    handler = re.compile(r"""[\s"'`]on[a-z]+\s*=\s*\\?["']""")
    paths = [os.path.join(STATIC, n) for n in ("index.html", "404.html")] + glob.glob(
        os.path.join(STATIC, "js", "*.js")
    )
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        assert not handler.search(text), f"inline event handler in {os.path.basename(path)}"
        assert "javascript:" not in text, os.path.basename(path)


def test_every_action_name_has_a_handler_that_exists():
    """data-action names are matched by one listener in shell.js. A name with no
    entry, or an entry calling a function that is not defined, is a dead button."""
    import os
    import re

    from tests.jsmodules import STATIC, dashboard_js

    js = dashboard_js()
    block = js[js.index("const ACTIONS = {") : js.index("};", js.index("const ACTIONS = {"))]
    actions = set(re.findall(r'^\s*"([a-z-]+)":', block, re.M))

    with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as fh:
        used = set(re.findall(r'data-action="([a-z-]+)"', fh.read()))
    # in script the name is the argument after the button label
    used |= set(re.findall(r'(?:UIState\.box|\bempty)\(.*"([a-z]+(?:-[a-z]+)+)"(?:, (?:true|false))?\)', js))
    used |= set(re.findall(r'\? "([a-z]+(?:-[a-z]+)+)" : "([a-z]+(?:-[a-z]+)+)"\n\s*\)', js)[0])
    assert used and used <= actions, sorted(used - actions)

    called = set(re.findall(r"\b([A-Za-z_]\w*)(?=\(|\.init\()", block)) - {"click", "focus", "scrollIntoView", "init"}
    missing = {name for name in called if not re.search(rf"(?:function {name}\(|const {name} = )", js)}
    assert called and not missing, sorted(missing)


def test_script_policy_allows_nothing_inline(tmp_path):
    csp = _client(tmp_path).get("/").headers["content-security-policy"]
    directives = dict(d.split(" ", 1) for d in csp.split("; "))
    for name in ("default-src", "script-src"):
        for token in ("'unsafe-inline'", "'unsafe-hashes'", "'unsafe-eval'"):
            assert token not in directives[name], f"{name} allows {token}"


def test_interactive_api_docs_are_not_served(tmp_path):
    """They were open without the token and loaded scripts from a CDN."""
    client = _client(tmp_path, auth_token="s3cret")
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404, path


def test_importing_the_server_module_builds_nothing(tmp_path):
    """It used to build an app, which opened the plan store in the current
    directory of whatever process imported it."""
    import os
    import subprocess
    import sys

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PYTHONPATH=repo)
    subprocess.run(
        [sys.executable, "-c", "import cipherguard.api.server"], cwd=tmp_path, env=env, check=True, timeout=120
    )
    assert not list(tmp_path.iterdir())


# -- authentication ---------------------------------------------------------


def test_a_non_ascii_token_is_a_401_not_a_crash(tmp_path):
    client = _client(tmp_path, auth_token="s3cret")
    res = client.get("/api/rules", headers={"Authorization": b"Bearer caf\xe9"})
    assert res.status_code == 401


def test_repeated_wrong_tokens_lock_the_client_out(tmp_path):
    from cipherguard.api.server import AUTH_FAILURE_LIMIT

    client = _client(tmp_path, auth_token="s3cret")
    good = {"Authorization": "Bearer s3cret"}
    assert client.get("/api/rules", headers=good).status_code == 200

    for i in range(AUTH_FAILURE_LIMIT):
        assert client.get("/api/rules", headers={"Authorization": f"Bearer guess{i}"}).status_code == 401
    locked = client.get("/api/rules", headers={"Authorization": "Bearer one-more"})
    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) >= 1
    # the right token is refused too: a guess must not be testable during the lockout
    assert client.get("/api/rules", headers=good).status_code == 429
    assert client.get("/api/health").status_code == 200


def test_limiter_forgets_old_events_and_bounds_its_table(monkeypatch):
    from cipherguard.api import security

    now = [1000.0]
    monkeypatch.setattr(security.time, "monotonic", lambda: now[0])
    limiter = security.SlidingWindowLimiter(limit=2, window=10.0, max_keys=3)
    assert limiter.hit("a") == 0 and limiter.hit("a") == 0
    assert limiter.hit("a") >= 1
    now[0] += 10.5
    assert limiter.hit("a") == 0

    for key in "bcdefg":
        limiter.hit(key)
    assert len(limiter._events) <= 3


def test_heavy_routes_are_throttled_per_client(lab_captures):
    client = _client(lab_captures, heavy_requests_per_minute=3)
    codes = [client.get("/api/remediation/legacy.pcap").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert client.get("/api/rules").status_code == 200  # cheap reads are not counted


# -- input validation -------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"capture": "legacy.pcap", "min_packets": 0},
        {"capture": "legacy.pcap", "min_packets": -5},
        {"capture": "legacy.pcap", "min_packets": 10**12},
        {"capture": "legacy.pcap", "disabled": ["NOT-A-RULE"]},
        {"capture": "legacy.pcap", "disabled": [f"X-{i}" for i in range(5000)]},
        {"capture": "x" * 500 + ".pcap"},
        {"capture": ""},
        {},
    ],
)
def test_analyze_rejects_out_of_range_input(lab_captures, body):
    assert _client(lab_captures).post("/api/analyze", json=body).status_code == 422


def test_disabled_rules_are_stated_in_the_report_and_the_audit_log(lab_captures, model_dir):
    """A client can switch rules off; it cannot do so invisibly. The same
    capture scored 100/A with every rule disabled and nothing recorded why."""
    from cipherguard.api.server import KNOWN_RULE_IDS

    audit = lab_captures / "audit.jsonl"
    client = _client(lab_captures, model_dir=model_dir, audit_log=str(audit))

    normal = client.post("/api/analyze", json={"capture": "legacy.pcap"}).json()
    assert normal["stats"]["disabled_rules"] == [] and normal["findings"]

    off = sorted(KNOWN_RULE_IDS)
    quiet = client.post("/api/analyze", json={"capture": "legacy.pcap", "disabled": off}).json()
    assert quiet["findings"] == []
    assert quiet["stats"]["disabled_rules"] == off

    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert [r["disabled_rules"] for r in records if r["event"] == "assessment"] == [[], off]


def test_unknown_data_class_is_refused_instead_of_defaulted(lab_captures, model_dir):
    client = _client(lab_captures, model_dir=model_dir)
    bad = client.get("/api/roadmap", params={"capture": "legacy.pcap", "data_class": "bogus"})
    assert bad.status_code == 400 and "official" in bad.json()["detail"]
    ok = client.get("/api/roadmap", params={"capture": "legacy.pcap", "data_class": "strategic"})
    assert ok.status_code == 200


@pytest.mark.parametrize("spi", ["zzzz", "0x", "0x123456789", "12 34", "-1"])
def test_wire_endpoint_rejects_a_malformed_spi(lab_captures, spi):
    res = _client(lab_captures).get(f"/api/captures/legacy.pcap/flows/{spi}/wire")
    assert res.status_code in (400, 404)


def test_a_file_that_is_not_a_capture_is_a_422_with_the_reason(tmp_path):
    (tmp_path / "bad.pcap").write_bytes(b"this is not a capture" * 50)
    res = _client(tmp_path).post("/api/analyze", json={"capture": "bad.pcap"})
    assert res.status_code == 422
    assert "bad.pcap" in res.json()["detail"] and "not a pcap" in res.json()["detail"]


def test_an_unexpected_error_tells_the_client_nothing(tmp_path, monkeypatch):
    import cipherguard.api.server as server

    def boom(*a, **kw):
        raise RuntimeError(r"secret path C:\Users\analyst\keys.db")

    monkeypatch.setattr(server, "rule_catalogue", boom)
    res = _client(tmp_path).get("/api/rules")
    assert res.status_code == 500
    assert res.json() == {"detail": "internal error; see the server log"}
    assert "analyst" not in res.text and "Traceback" not in res.text


# -- uploads ----------------------------------------------------------------


def test_upload_checks_the_content_not_just_the_name(tmp_path):
    client = _client(tmp_path)
    for body in (b"<script>alert(1)</script>", b"this is not a capture", b"", b"\xd4\xc3"):
        res = client.post("/api/upload", files={"file": ("x.pcap", body)})
        assert res.status_code == 400 and "not a pcap" in res.json()["detail"]
    assert not list(tmp_path.glob("*.pcap"))

    ok = client.post("/api/upload", files={"file": ("real.pcap", PCAP_HEADER)})
    assert ok.status_code == 200 and ok.json()["size_bytes"] == len(PCAP_HEADER)
    assert (tmp_path / "real.pcap").read_bytes() == PCAP_HEADER

    pcapng = client.post("/api/upload", files={"file": ("ng.pcapng", b"\x0a\x0d\x0d\x0a" + b"\x00" * 24)})
    assert pcapng.status_code == 200


def test_upload_name_length_is_bounded(tmp_path):
    res = _client(tmp_path).post("/api/upload", files={"file": ("a" * 300 + ".pcap", PCAP_HEADER)})
    assert res.status_code == 400 and "longer than" in res.json()["detail"]


def test_oversize_body_is_refused_from_its_declared_length(tmp_path):
    """Before anything is read or spooled to disk."""
    from cipherguard.api.server import MAX_UPLOAD_BYTES

    client = _client(tmp_path)
    huge = client.post(
        "/api/upload",
        content=b"x",
        headers={
            "Content-Type": "multipart/form-data; boundary=x",
            "Content-Length": str(MAX_UPLOAD_BYTES + (1 << 20)),
        },
    )
    assert huge.status_code == 413 and "500 MB" in huge.json()["detail"]

    big_json = client.post(
        "/api/analyze", content=b"{" + b" " * (70 << 10) + b"}", headers={"Content-Type": "application/json"}
    )
    assert big_json.status_code == 413


def test_upload_stops_at_the_directory_quota(tmp_path, monkeypatch):
    import cipherguard.api.server as server

    monkeypatch.setattr(server, "MAX_CAPTURE_DIR_BYTES", 100)
    (tmp_path / "old.pcap").write_bytes(b"\x00" * 90)
    res = _client(tmp_path).post("/api/upload", files={"file": ("new.pcap", PCAP_HEADER)})
    assert res.status_code == 507
    assert not (tmp_path / "new.pcap").exists()
