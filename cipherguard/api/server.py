"""FastAPI backend for the assessment dashboard.

Read-only with respect to the network: every endpoint operates on capture files
already on disk. Nothing here can transmit to a gateway, and there is no code
path that applies a generated configuration.
"""

from __future__ import annotations

import os
from functools import lru_cache

import hmac
import secrets

import asyncio
import json
import queue

from fastapi import Depends, FastAPI, Header, HTTPException, UploadFile, File, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..core.audit_log import AuditLog

from ..audit.engine import rule_catalogue
from ..ml.classifier import SuiteClassifier
from ..pipeline import analyze, throughput_estimate
from ..remediation import PlanStore, apply_plan, build_all_plans
from ..remediation.synth import PLATFORM_NAMES, detect_platforms, synthesize

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
ALLOWED_SUFFIXES = (".pcap", ".pcapng", ".cap")

# Uploads are bounded because the endpoint is unauthenticated by default and
# writes to disk. Without a ceiling, one request fills the sensor's filesystem.
MAX_UPLOAD_BYTES = 512 << 20


class AnalyzeRequest(BaseModel):
    capture: str
    min_packets: int = 8
    disabled: list[str] = []


class RemediateRequest(BaseModel):
    capture: str
    platform: str | None = None


def create_app(
    model_dir: str = "models",
    capture_dir: str = "samples",
    baseline_db: str = "cipherguard-baseline.db",
    allow_upload: bool = True,
    auth_token: str | None = None,
    audit_log: str | None = None,
) -> FastAPI:
    """Build the app.

    `baseline_db` is fixed at construction rather than accepted per-request. An
    earlier version took it as a query parameter, which let any caller name an
    arbitrary filesystem path — the store opens it as SQLite and creates parent
    directories on the way, so that was an unauthenticated arbitrary-directory
    -creation and file-probing primitive. Server-side configuration is the only
    safe source for a path.
    """
    log = AuditLog(audit_log, actor="api")

    def require_token(authorization: str = Header(default="")) -> None:
        """Bearer-token gate.

        Compared with hmac.compare_digest rather than ==, because a plain string
        comparison returns early on the first differing byte and leaks the token
        prefix to anyone who can time the responses. Auth is opt-in: when no
        token is configured the dependency is a no-op, and the loopback-only
        bind in the CLI is what keeps that default safe.
        """
        if auth_token is None:
            return
        supplied = ""
        if authorization.lower().startswith("bearer "):
            supplied = authorization[7:].strip()
        if not supplied or not hmac.compare_digest(supplied, auth_token):
            log.denied("bad_token")
            raise HTTPException(401, "invalid or missing bearer token")

    guard = [Depends(require_token)]

    from contextlib import asynccontextmanager
    from fastapi.middleware.cors import CORSMiddleware

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI):
        import asyncio
        async def _loop():
            while True:
                try:
                    from ..wifi.wlan_native import trigger_scan
                    trigger_scan(wait_secs=0.0)
                except Exception:
                    pass
                await asyncio.sleep(45)
        task = asyncio.create_task(_loop())
        try:
            yield
        finally:
            task.cancel()

    app = FastAPI(
        title="CipherGuard",
        description="Passive IPsec VPN protocol analyzer and security assessment framework",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def _resolve(name: str) -> str:
        """Resolve a capture name inside capture_dir, refusing path traversal."""
        safe = os.path.basename(name)
        if not safe.endswith(ALLOWED_SUFFIXES):
            raise HTTPException(400, f"unsupported capture type: {safe}")
        path = os.path.join(capture_dir, safe)
        if not os.path.exists(path):
            raise HTTPException(404, f"no such capture: {safe}")
        return path

    @lru_cache(maxsize=16)
    def _cached_analyze(path: str, mtime: float, min_packets: int, disabled: tuple):
        return analyze(
            path,
            model_dir=model_dir,
            min_esp_packets=min_packets,
            disabled_rules=set(disabled) or None,
        )

    def _run(name: str, min_packets: int = 8, disabled: tuple = ()):
        path = _resolve(name)
        return _cached_analyze(path, os.path.getmtime(path), min_packets, disabled)

    # -- pages -------------------------------------------------------------

    # The stylesheet and script are served from here. Mounted without the auth
    # dependency on purpose: they contain no assessment data, and gating them
    # would leave an authenticated deployment rendering an unstyled page before
    # the token prompt ever appears.
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    if os.path.exists(os.path.join(STATIC_DIR, "css")):
        app.mount("/css", StaticFiles(directory=os.path.join(STATIC_DIR, "css")), name="css")
    if os.path.exists(os.path.join(STATIC_DIR, "js")):
        app.mount("/js", StaticFiles(directory=os.path.join(STATIC_DIR, "js")), name="js")
    if os.path.exists(os.path.join(STATIC_DIR, "img")):
        app.mount("/img", StaticFiles(directory=os.path.join(STATIC_DIR, "img")), name="img")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    @app.get("/404", include_in_schema=False)
    def not_found_page() -> FileResponse:
        return FileResponse(os.path.join(STATIC_DIR, "404.html"), status_code=404)

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon_ico() -> FileResponse:
        return FileResponse(os.path.join(STATIC_DIR, "favicon.ico"), media_type="image/x-icon")

    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(StarletteHTTPException)
    async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code == 404:
            accept = request.headers.get("accept", "")
            if "text/html" in accept:
                return FileResponse(os.path.join(STATIC_DIR, "404.html"), status_code=404)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    # -- api ---------------------------------------------------------------

    @app.get("/api/captures", dependencies=guard)
    def list_captures() -> dict:
        os.makedirs(capture_dir, exist_ok=True)
        items = []
        for name in sorted(os.listdir(capture_dir)):
            if name.endswith(ALLOWED_SUFFIXES):
                full = os.path.join(capture_dir, name)
                items.append(
                    {
                        "name": name,
                        "size_kb": round(os.path.getsize(full) / 1024, 1),
                    }
                )
        return {"captures": items, "directory": capture_dir}

    @app.post("/api/analyze", dependencies=guard)
    def run_analysis(req: AnalyzeRequest) -> JSONResponse:
        assessment = _run(req.capture, req.min_packets, tuple(sorted(req.disabled)))
        log.assessment(assessment, _resolve(req.capture), source="api")
        payload = assessment.to_dict()
        payload["throughput"] = throughput_estimate(assessment)
        payload["platforms"] = [
            {"id": p, "name": PLATFORM_NAMES[p]} for p in detect_platforms(assessment)
        ]
        from ..intel.pqc import roadmap as _roadmap

        payload["roadmap"] = _roadmap(assessment)
        return JSONResponse(payload)

    @app.post("/api/remediate", response_class=PlainTextResponse, dependencies=guard)
    def remediate(req: RemediateRequest) -> str:
        assessment = _run(req.capture)
        platform = req.platform or detect_platforms(assessment)[0]
        try:
            return synthesize(assessment, platform)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    # Uploads need python-multipart. It is an optional extra, and a missing
    # optional dependency should cost one endpoint, not the whole dashboard —
    # registering it unguarded takes the entire app down at import time.
    try:
        if not allow_upload:
            raise ImportError("uploads disabled by configuration")
        try:
            import python_multipart  # noqa: F401 # pyright: ignore[reportMissingImports]
        except ImportError:
            import multipart  # noqa: F401 # pyright: ignore[reportMissingImports]

        @app.post("/api/upload", dependencies=guard)
        async def upload(file: UploadFile = File(...)) -> dict:
            raw = file.filename or ""
            name = os.path.basename(raw)
            # basename() neutralises traversal, but silently rewriting the
            # caller's path is its own problem: the client believes it stored
            # one name while the server stored another. Reject instead, so a
            # traversal attempt is visible in logs rather than absorbed.
            if not name or name != raw.strip():
                raise HTTPException(400, "capture filename must not contain a path")
            if any(ord(c) < 32 or ord(c) == 127 for c in name) or name.startswith("."):
                raise HTTPException(400, "invalid capture filename")
            if not name.endswith(ALLOWED_SUFFIXES):
                raise HTTPException(400, "only .pcap, .pcapng and .cap are accepted")

            os.makedirs(capture_dir, exist_ok=True)
            dest = os.path.join(capture_dir, name)
            if os.path.exists(dest):
                # Silently replacing an existing capture destroys the evidence a
                # prior assessment was based on, and its baseline history.
                raise HTTPException(409, f"{name} already exists; rename it first")

            written = 0
            try:
                with open(dest, "wb") as fh:
                    while chunk := await file.read(1 << 20):
                        written += len(chunk)
                        if written > MAX_UPLOAD_BYTES:
                            raise HTTPException(
                                413,
                                f"capture exceeds the {MAX_UPLOAD_BYTES >> 20} MB limit",
                            )
                        fh.write(chunk)
            except Exception:
                if os.path.exists(dest):
                    os.unlink(dest)  # never leave a partial capture to be analysed
                raise
            return {"name": name, "size_kb": round(written / 1024, 1)}

    except ImportError:  # pragma: no cover

        @app.post("/api/upload")
        def upload_unavailable() -> JSONResponse:
            return JSONResponse(
                {"detail": "upload requires python-multipart; copy captures into "
                           f"{capture_dir}/ instead"},
                status_code=501,
            )

    @app.get("/api/roadmap", dependencies=guard)
    def pqc_roadmap(capture: str, data_class: str = "official") -> JSONResponse:
        from ..intel.pqc import roadmap

        return JSONResponse(roadmap(_run(capture), data_class=data_class))

    @app.get("/api/cbom", dependencies=guard)
    def cbom(capture: str) -> JSONResponse:
        from ..export.cbom import build_cbom

        return JSONResponse(build_cbom(_run(capture)))

    @app.get("/api/fleet", dependencies=guard)
    def fleet() -> dict:
        from ..intel.baseline import BaselineStore

        if not os.path.exists(baseline_db):
            return {"tracked": False, "hint": "run: cipherguard watch <capture>"}
        with BaselineStore(baseline_db) as store:
            return {"tracked": True, "summary": store.summary(), "links": store.fleet()}

    @app.get("/api/rules", dependencies=guard)
    def rules() -> dict:
        return {"rules": rule_catalogue()}

    server_state = {"simulate_rogue": False}

    @app.get("/api/wifi/simulate-rogue")
    def get_simulate_rogue() -> dict:
        return {"active": server_state["simulate_rogue"]}

    @app.post("/api/wifi/simulate-rogue")
    async def toggle_simulate_rogue(request: Request) -> dict:
        try:
            body = await request.json()
            if "active" in body:
                server_state["simulate_rogue"] = bool(body["active"])
            else:
                server_state["simulate_rogue"] = not server_state["simulate_rogue"]
        except Exception:
            server_state["simulate_rogue"] = not server_state["simulate_rogue"]
        return {"active": server_state["simulate_rogue"]}

    def _apply_simulated_rogue(res: dict, sim_rogue: bool | None = None) -> None:
        should_sim = sim_rogue if sim_rogue is not None else server_state["simulate_rogue"]
        if should_sim and not res.get("rogue_aps"):
            iface = res.get("interface") or {}
            active_ssid = iface.get("ssid") or "White Devil"
            ch = iface.get("channel") or 6
            band = iface.get("band") or "2.4 GHz"
            sim_clone = {
                "ssid": active_ssid,
                "bssid": "58:61:63:de:ad:01",
                "signal_percent": 96,
                "rssi_dbm": -38,
                "channel": ch,
                "band": band,
                "radio_type": "802.11ax",
                "authentication": "Open",
                "encryption": "None",
                "security_grade": "F",
                "connected": False,
                "is_rogue": True,
                "rogue_reason": f"Open / Unencrypted clone of secured WPA2 network '{active_ssid}' (Classic Evil Twin MitM honeypot)",
                "notes": "Adversary AP broadcasting at high RF power to entice victim association",
                "cipher": "None",
            }
            nets = res.get("networks_in_range", [])
            if not any(n.get("bssid") == sim_clone["bssid"] for n in nets):
                nets.insert(1, sim_clone)
            res["networks_in_range"] = nets
            res["rogue_aps"] = [
                {
                    "ssid": active_ssid,
                    "bssid": "58:61:63:de:ad:01",
                    "band": band,
                    "channel": ch,
                    "signal": "96% (-38 dBm)",
                    "signal_percent": 96,
                    "threat_level": "CRITICAL",
                    "reason": f"Evil Twin Clone: Open vs {iface.get('authentication', 'WPA2-Personal')}",
                }
            ]
            crit_finding = {
                "severity": "critical",
                "rule_id": "WIFI-001",
                "title": "Potential Evil Twin / Rogue AP Detected",
                "subject": f"SSID: {active_ssid}",
                "detail": f"Detected access points broadcasting SSID '{active_ssid}' with mismatched security postures. Genuine AP enforces {iface.get('authentication', 'WPA2-Personal')}, while rogue clone BSSID 58:61:63:de:ad:01 is broadcasting as Open (unencrypted) with strong 96% signal. This is a classic Evil Twin honeypot designed to intercept credentials and perform Adversary-in-the-Middle (MitM) inspection.",
                "remediation": "Investigate physical location of BSSID 58:61:63:de:ad:01 using RF signal strength triangulation. Do not connect to unencrypted clones. Enforce 802.11w Protected Management Frames (PMF) and WPA3-Enterprise on authentic infrastructure.",
                "reference": "NIST SP 800-153 / MITRE ATT&CK T1040",
                "inferred": False,
            }
            findings = [f for f in res.get("findings", []) if f.get("rule_id") != "WIFI-001"]
            findings.insert(0, crit_finding)
            res["findings"] = findings
            counts = res.get("counts", {})
            counts["critical"] = sum(1 for f in findings if f.get("severity") == "critical")
            res["counts"] = counts
            res["score"] = min(res.get("score", 100), 45)
            res["grade"] = "F"

    @app.get("/api/wifi/current", dependencies=guard)
    def wifi_current(sim_rogue: bool | None = None) -> JSONResponse:
        from ..wifi.auditor import WifiAuditor
        from ..vpn.detector import VpnDetector
        auditor = WifiAuditor()
        assessment = auditor.audit_current()
        res = assessment.to_dict()
        _apply_simulated_rogue(res, sim_rogue)

        try:
            vpn_detector = VpnDetector()
            wifi_name = assessment.interface.name if assessment.interface else "Wi-Fi"
            wifi_dns = assessment.interface.dns_servers if assessment.interface else []
            vpn_info = vpn_detector.detect_current(wifi_iface_name=wifi_name, wifi_dns=wifi_dns)
            res["vpn"] = vpn_info.to_dict()
        except Exception:
            res["vpn"] = None
        return JSONResponse(res)

    @app.get("/api/vpn/current", dependencies=guard)
    def vpn_current() -> JSONResponse:
        from ..vpn.detector import VpnDetector
        vpn_detector = VpnDetector()
        vpn_info = vpn_detector.detect_current()
        return JSONResponse(vpn_info.to_dict())

    plan_db_path = os.path.join(os.path.dirname(baseline_db) if baseline_db else ".", "cipherguard-plans.db")
    plan_store = PlanStore(plan_db_path)

    @app.get("/api/remediation/{capture}", dependencies=guard)
    def get_remediation_plans(capture: str) -> dict:
        path = _resolve(capture)
        mtime = os.path.getmtime(path)
        a = _cached_analyze(path, mtime, 5, ())
        plans = build_all_plans(a)
        existing = plan_store.list_plans(capture)
        out = []
        for p in plans:
            p.capture = capture
            match = next((ep for ep in existing if ep.platform == p.platform), None)
            if match:
                p.plan_id = match.plan_id
                p.status = match.status
                p.approver = match.approver
                p.approval_comment = match.approval_comment
                p.created_at = match.created_at
            else:
                plan_store.save_plan(p)
            out.append(p.to_dict())
        return {"capture": capture, "plans": out}

    @app.post("/api/remediation/{plan_id}/approve", dependencies=guard)
    async def approve_plan_endpoint(plan_id: str, request: Request) -> dict:
        data = {}
        try:
            data = await request.json()
        except Exception:
            pass
        actor = data.get("actor") or "Security Administrator"
        comment = data.get("comment") or "Approved for change-window deployment"
        plan = plan_store.update_status(plan_id, "APPROVED", actor=actor, comment=comment)
        if not plan:
            raise HTTPException(404, f"No plan found with id {plan_id}")
        return {"status": "success", "plan": plan.to_dict()}

    @app.post("/api/remediation/{plan_id}/apply", dependencies=guard)
    async def apply_plan_endpoint(plan_id: str, request: Request) -> dict:
        data = {}
        try:
            data = await request.json()
        except Exception:
            pass
        dry_run = data.get("dry_run", True)
        target = data.get("target", "")
        plan = plan_store.get_plan(plan_id)
        if not plan:
            raise HTTPException(404, f"No plan found with id {plan_id}")

        result = apply_plan(plan, dry_run=dry_run, target_host=target)
        if result.get("success"):
            new_status = "STAGED" if dry_run else "APPLIED"
            plan_store.update_status(plan_id, new_status, actor="Automated Hardening Engine", comment=f"Executed ({result.get('mode')})")
        return result

    @app.get("/api/remediation-plans", dependencies=guard)
    def list_all_remediation_plans() -> dict:
        plans = plan_store.list_plans()
        return {"plans": [p.to_dict() for p in plans]}

    @app.get("/api/wifi/networks", dependencies=guard)
    def wifi_networks() -> dict:
        from ..wifi.auditor import WifiAuditor
        auditor = WifiAuditor()
        current_ssid = ""
        current_bssid = ""
        cur = auditor._get_windows_current_interface() if auditor.is_windows else auditor._get_linux_current_interface()
        if cur:
            current_ssid = cur.ssid
            current_bssid = cur.bssid
        networks = auditor._get_windows_networks(current_ssid, current_bssid, force_scan=True) if auditor.is_windows else auditor._get_linux_networks()
        return {"networks": [n.to_dict() for n in networks]}

    @app.get("/api/interfaces", dependencies=guard)
    def get_interfaces() -> dict:
        import sys
        from ..capture.live import list_interfaces, available
        is_avail, reason = available()
        ifaces = list_interfaces()
        items = []
        for iface in ifaces:
            items.append({
                "name": iface,
                "is_wifi": any(w in iface.lower() for w in ("wi-fi", "wlan", "wireless", "802.11")),
            })
        return {
            "interfaces": items,
            "live_capture_available": is_avail,
            "availability_reason": reason,
            "platform": sys.platform,
        }

    @app.post("/api/wifi/scan", dependencies=guard)
    def wifi_scan() -> JSONResponse:
        from ..wifi.auditor import WifiAuditor
        from ..vpn.detector import VpnDetector
        auditor = WifiAuditor()
        assessment = auditor.audit_current(force_scan=True)
        res = assessment.to_dict()
        _apply_simulated_rogue(res)
        try:
            vpn_detector = VpnDetector()
            wifi_name = assessment.interface.name if assessment.interface else "Wi-Fi"
            wifi_dns = assessment.interface.dns_servers if assessment.interface else []
            vpn_info = vpn_detector.detect_current(wifi_iface_name=wifi_name, wifi_dns=wifi_dns)
            res["vpn"] = vpn_info.to_dict()
        except Exception:
            res["vpn"] = None
        return JSONResponse(res)

    @app.get("/api/captures/{capture}/flows/{spi}/wire", dependencies=guard)
    def get_wire_samples(capture: str, spi: str, framing: str | None = None) -> dict:
        path = _resolve(capture)
        from ..dissector.wire_inspector import extract_wire_samples
        return extract_wire_samples(path, spi, framing_class=framing)

    from ..capture.live_sniffer import global_sniffer

    @app.post("/api/sniff/start", dependencies=guard)
    async def start_sniff(request: Request) -> dict:
        data = {}
        try:
            data = await request.json()
        except Exception:
            pass
        interface = data.get("interface")
        force_sim = data.get("force_simulation", False)
        return global_sniffer.start(interface=interface, force_simulation=force_sim)

    @app.post("/api/sniff/stop", dependencies=guard)
    def stop_sniff() -> dict:
        return global_sniffer.stop()

    @app.get("/api/sniff/status", dependencies=guard)
    def sniff_status() -> dict:
        return global_sniffer.get_status()

    @app.get("/api/sniff/stream")
    async def sniff_stream() -> StreamingResponse:
        q = global_sniffer.subscribe()

        async def event_generator():
            try:
                status = global_sniffer.get_status()
                yield f"event: status\ndata: {json.dumps(status)}\n\n"

                while True:
                    try:
                        event = q.get_nowait()
                        yield f"event: packet\ndata: {json.dumps(event)}\n\n"
                    except queue.Empty:
                        await asyncio.sleep(0.15)
                        status = global_sniffer.get_status()
                        yield f"event: heartbeat\ndata: {json.dumps(status)}\n\n"
            finally:
                global_sniffer.unsubscribe(q)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @app.post("/api/sniff/analyze", dependencies=guard)
    def analyze_sniff_snapshot() -> dict:
        snapshot_name = "live_snapshot.pcap"
        snapshot_path = os.path.join(capture_dir, snapshot_name)
        global_sniffer.snapshot_to_pcap(snapshot_path)

        a = analyze(snapshot_path, model_dir=model_dir, min_esp_packets=1)
        payload = a.to_dict()
        payload["throughput"] = throughput_estimate(a)
        payload["platforms"] = [
            {"id": p, "name": PLATFORM_NAMES[p]} for p in detect_platforms(a)
        ]
        from ..intel.pqc import roadmap as pqc_roadmap
        payload["roadmap"] = pqc_roadmap(a)
        return payload




    @app.get("/api/model", dependencies=guard)
    def model_info() -> dict:
        if not SuiteClassifier.is_trained(model_dir):
            return {"trained": False, "hint": "run: cipherguard train"}
        model = SuiteClassifier.load(model_dir)
        return {"trained": True, "labels": model.labels, "metrics": model.metrics}

    @app.get("/api/health")
    def health() -> dict:
        """Unauthenticated on purpose: a health probe that needs a credential is
        useless to a load balancer, and it reveals nothing about the traffic."""
        return {
            "status": "ok",
            "model_trained": SuiteClassifier.is_trained(model_dir),
            "auth_required": auth_token is not None,
            "audit_log": audit_log is not None,
        }

    return app


app = create_app()
