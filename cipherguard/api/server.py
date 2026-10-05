"""FastAPI backend for the assessment dashboard.

Read-only with respect to the network: every endpoint operates on capture files
already on disk. Nothing here can transmit to a gateway, and there is no code
path that applies a generated configuration.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import queue
import re
import sys
from collections.abc import Iterable
from contextlib import asynccontextmanager
from functools import lru_cache
from typing import Any, Literal

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import __version__
from ..audit.engine import rule_catalogue
from ..core.audit_log import AuditLog
from ..dissector.pcap import CaptureError
from ..intel.pqc import SECRECY_LIFETIME
from ..ml.classifier import SuiteClassifier
from ..pipeline import analyze
from ..remediation import PlanStore, apply_plan, build_all_plans
from ..remediation.synth import detect_platforms, synthesize
from . import security
from .security import RequestGuard, SlidingWindowLimiter, normalise_origins

logger = logging.getLogger(__name__)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
ALLOWED_SUFFIXES = (".pcap", ".pcapng", ".cap")

# Uploads are bounded because the endpoint is unauthenticated by default and
# writes to disk. Without a ceiling, one request fills the sensor's filesystem.
# Decimal megabytes, the unit the dashboard shows sizes in.
MAX_UPLOAD_BYTES = 500 * 1000 * 1000

# A per-file cap alone still lets a client fill the disk one file at a time.
MAX_CAPTURE_DIR_BYTES = 4 * 1000 ** 3

MAX_CAPTURE_NAME = 128

# pcap (microsecond and nanosecond, either byte order) and pcapng. A file that
# starts with anything else is not a capture, whatever it is called.
CAPTURE_MAGICS = frozenset({
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
})

# Two IPv6 addresses with zone IDs and the separator fit well inside this; a
# longer "peer key" is not one.
MAX_PEER_KEY = 256

MIN_PACKETS_RANGE = (1, 100_000)

SPI_PATTERN = re.compile(r"(0[xX])?[0-9a-fA-F]{1,8}")

# A plan can be dry-run once it has been approved; a staged plan was approved.
APPLY_ALLOWED_FROM = ("APPROVED", "STAGED")

# The sniffer's snapshot is written under a name that says where the packets
# came from, so the capture list can never show replayed samples as live.
SNAPSHOT_NAMES = {"live": "live_snapshot.pcap", "replay": "replay_snapshot.pcap"}

# Wrong tokens from one address before it is locked out for the window.
AUTH_FAILURE_LIMIT = 10
AUTH_FAILURE_WINDOW_SECONDS = 60.0

# Requests per minute, per client, to the routes that analyse a capture, write
# a file or run an operating-system command.
DEFAULT_HEAVY_REQUESTS_PER_MINUTE = 120

WIFI_BACKGROUND_SCAN_SECONDS = 45
STREAM_IDLE_SECONDS = 0.15

KNOWN_RULE_IDS = frozenset(r["id"] for r in rule_catalogue())


def _clean_label(value: object, limit: int = 80) -> str:
    """Caller-supplied text bound for the plan store, the audit log and the
    page: one line, printable, bounded."""
    if not isinstance(value, str):
        return ""
    return " ".join("".join(c if c.isprintable() else " " for c in value).split())[:limit]


class AnalyzeRequest(BaseModel):
    capture: str = Field(min_length=1, max_length=MAX_CAPTURE_NAME)
    min_packets: int = Field(default=8, ge=MIN_PACKETS_RANGE[0], le=MIN_PACKETS_RANGE[1])
    disabled: list[str] = Field(default_factory=list, max_length=len(KNOWN_RULE_IDS))

    @field_validator("disabled")
    @classmethod
    def _only_known_rules(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - KNOWN_RULE_IDS)
        if unknown:
            raise ValueError(f"unknown rule id: {', '.join(unknown[:5])}")
        return sorted(set(value))


class RemediateRequest(BaseModel):
    capture: str = Field(min_length=1, max_length=MAX_CAPTURE_NAME)
    platform: str | None = Field(default=None, max_length=32)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def create_app(
    model_dir: str = "models",
    capture_dir: str = "samples",
    baseline_db: str = "cipherguard-baseline.db",
    allow_upload: bool = True,
    auth_token: str | None = None,
    audit_log: str | None = None,
    cors_origins: list[str] | None = None,
    allowed_hosts: Iterable[str] | Literal["auto"] | None = "auto",
    heavy_requests_per_minute: int = DEFAULT_HEAVY_REQUESTS_PER_MINUTE,
) -> FastAPI:
    """Build the app.

    `baseline_db` is fixed at construction rather than accepted per-request. An
    earlier version took it as a query parameter, which let any caller name an
    arbitrary filesystem path — the store opens it as SQLite and creates parent
    directories on the way, so that was an unauthenticated arbitrary-directory
    -creation and file-probing primitive. Server-side configuration is the only
    safe source for a path.

    `allowed_hosts` is the Host header allowlist. "auto" means loopback names
    when no token is set and any host when one is; see api/security.py.
    """
    log = AuditLog(audit_log, actor="api")
    auth_failures = SlidingWindowLimiter(AUTH_FAILURE_LIMIT, AUTH_FAILURE_WINDOW_SECONDS)
    heavy_requests = SlidingWindowLimiter(heavy_requests_per_minute, 60.0)
    token_bytes = auth_token.encode("utf-8") if auth_token is not None else None

    def require_token(request: Request, authorization: str = Header(default="")) -> None:
        """Bearer-token gate.

        Compared with hmac.compare_digest rather than ==, because a plain string
        comparison returns early on the first differing byte and leaks the token
        prefix to anyone who can time the responses. Auth is opt-in: when no
        token is configured the dependency is a no-op, and the loopback-only
        bind in the CLI is what keeps that default safe.

        An address that keeps sending wrong tokens is refused outright for a
        minute, right token or not: answering a correct guess during the
        lockout would leave nothing throttled.
        """
        if token_bytes is None:
            return
        client = _client_key(request)
        wait = auth_failures.retry_after(client)
        if wait:
            log.denied("auth_lockout")
            raise HTTPException(429, "too many failed attempts; try again later",
                                headers={"Retry-After": str(wait)})
        supplied = ""
        if authorization.lower().startswith("bearer "):
            supplied = authorization[7:].strip()
        # bytes, because compare_digest raises on a non-ASCII str
        if not supplied or not hmac.compare_digest(supplied.encode("utf-8"), token_bytes):
            auth_failures.record(client)
            log.denied("bad_token")
            raise HTTPException(401, "invalid or missing bearer token")

    def throttle(request: Request) -> None:
        wait = heavy_requests.hit(_client_key(request))
        if wait:
            raise HTTPException(429, "too many requests; slow down",
                                headers={"Retry-After": str(wait)})

    guard = [Depends(require_token)]
    heavy = [Depends(require_token), Depends(throttle)]

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI):
        async def _keep_wifi_scan_fresh() -> None:
            while True:
                try:
                    from ..wifi.wlan_native import trigger_scan
                    trigger_scan(wait_secs=0.0)
                except Exception:
                    # no adapter, or not Windows: the Wi-Fi view reports that itself
                    logger.debug("background Wi-Fi scan skipped", exc_info=True)
                await asyncio.sleep(WIFI_BACKGROUND_SCAN_SECONDS)
        task = asyncio.create_task(_keep_wifi_scan_fresh())
        try:
            yield
        finally:
            task.cancel()

    # The interactive API docs are off: they are served without the token and
    # load their scripts from a CDN, and this tool makes no outbound calls.
    app = FastAPI(
        title="CipherGuard",
        description="Passive IPsec VPN protocol analyzer and security assessment framework",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Cross-origin access is off unless specific origins are configured. The
    # app used to answer every origin, and with the default tokenless loopback
    # bind that meant any web page open in the analyst's browser could read
    # this API through 127.0.0.1 — the fleet's weak links included — and start
    # a capture. The loopback-only bind is only a boundary if other origins
    # cannot read through it. The one legitimate cross-origin client is the
    # hosted static dashboard connecting back to a local engine, and that
    # origin has to be named.
    origins = normalise_origins(cors_origins)
    if "*" in origins:
        raise ValueError("cors_origins must list specific origins; '*' is not accepted")
    if origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=False,  # the token travels in a header, not a cookie
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )

    if allowed_hosts == "auto":
        hosts: set[str] | None = set(security.LOOPBACK_HOSTS) if auth_token is None else None
    else:
        hosts = None if allowed_hosts is None else set(allowed_hosts)
    # Added last, so it is outermost: nothing is parsed for a refused request.
    app.add_middleware(
        RequestGuard,
        allowed_hosts=hosts,
        trusted_origins=origins,
        max_upload_bytes=MAX_UPLOAD_BYTES,
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
        try:
            return _cached_analyze(path, os.path.getmtime(path), min_packets, disabled)
        except CaptureError as exc:
            # the reader's message names what is wrong and where in the file
            raise HTTPException(422, f"{os.path.basename(path)} could not be read: {exc}") from None

    # -- pages -------------------------------------------------------------

    # The stylesheet and script are served from here. Mounted without the auth
    # dependency on purpose: they contain no assessment data, and gating them
    # would leave an authenticated deployment rendering an unstyled page before
    # the token prompt ever appears.
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    for sub in ("css", "js", "img"):
        if os.path.exists(os.path.join(STATIC_DIR, sub)):
            app.mount(f"/{sub}", StaticFiles(directory=os.path.join(STATIC_DIR, sub)), name=sub)

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    @app.get("/404", include_in_schema=False)
    def not_found_page() -> FileResponse:
        return FileResponse(os.path.join(STATIC_DIR, "404.html"), status_code=404)

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon_ico() -> FileResponse:
        return FileResponse(os.path.join(STATIC_DIR, "favicon.ico"), media_type="image/x-icon")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        if exc.status_code == 404 and "text/html" in request.headers.get("accept", ""):
            return FileResponse(os.path.join(STATIC_DIR, "404.html"), status_code=404)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                            headers=getattr(exc, "headers", None))

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        # The traceback goes to the server log. The client gets no file paths,
        # no exception text and no SQL.
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse({"detail": "internal error; see the server log"}, status_code=500)

    # -- api ---------------------------------------------------------------

    def _capture_files() -> list[tuple[str, int]]:
        os.makedirs(capture_dir, exist_ok=True)
        return [(name, os.path.getsize(os.path.join(capture_dir, name)))
                for name in sorted(os.listdir(capture_dir)) if name.endswith(ALLOWED_SUFFIXES)]

    @app.get("/api/captures", dependencies=guard)
    def list_captures() -> dict:
        # size_kb (1024-based) is kept for older clients; the dashboard
        # formats size_bytes itself, in the one unit convention it uses
        items = [{"name": name, "size_bytes": size, "size_kb": round(size / 1024, 1)}
                 for name, size in _capture_files()]
        return {"captures": items, "directory": capture_dir}

    @app.post("/api/analyze", dependencies=heavy)
    def run_analysis(req: AnalyzeRequest) -> JSONResponse:
        from ..export.payload import build_payload

        path = _resolve(req.capture)
        assessment = _run(req.capture, req.min_packets, tuple(req.disabled))
        log.assessment(assessment, path, source="api")
        return JSONResponse(build_payload(assessment, path, model_dir))

    @app.post("/api/remediate", response_class=PlainTextResponse, dependencies=heavy)
    def remediate(req: RemediateRequest) -> str:
        assessment = _run(req.capture)
        platform = req.platform or detect_platforms(assessment)[0]
        try:
            return synthesize(assessment, platform)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None

    # Uploads need python-multipart. It is an optional extra, and a missing
    # optional dependency should cost one endpoint, not the whole dashboard —
    # registering it unguarded takes the entire app down at import time.
    # /api/health reports the outcome, so the dashboard never shows an upload
    # control that cannot work.
    uploads_enabled = False
    try:
        if not allow_upload:
            raise ImportError("uploads disabled by configuration")
        try:
            import python_multipart  # noqa: F401 # pyright: ignore[reportMissingImports]
        except ImportError:
            import multipart  # noqa: F401 # pyright: ignore[reportMissingImports]

        @app.post("/api/upload", dependencies=heavy)
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
            if len(name) > MAX_CAPTURE_NAME:
                raise HTTPException(400, f"capture filename is longer than {MAX_CAPTURE_NAME} characters")
            if not name.endswith(ALLOWED_SUFFIXES):
                raise HTTPException(400, "only .pcap, .pcapng and .cap are accepted")

            stored = sum(size for _, size in _capture_files())
            if stored + (file.size or 0) > MAX_CAPTURE_DIR_BYTES:
                raise HTTPException(
                    507, f"the capture directory is at its {MAX_CAPTURE_DIR_BYTES // 1000 ** 3} GB limit; "
                         "remove captures on the server first")

            head = await file.read(4)
            if head not in CAPTURE_MAGICS:
                raise HTTPException(400, "not a pcap or pcapng capture")

            dest = os.path.join(capture_dir, name)
            written = 0
            try:
                # "x": creating the file is the existence check, so two uploads
                # of one name cannot both pass it. Silently replacing a capture
                # destroys the evidence a prior assessment was based on.
                with open(dest, "xb") as fh:
                    chunk = head
                    while chunk:
                        written += len(chunk)
                        if written > MAX_UPLOAD_BYTES:
                            raise HTTPException(
                                413,
                                f"capture exceeds the {MAX_UPLOAD_BYTES // 1_000_000} MB limit",
                            )
                        fh.write(chunk)
                        chunk = await file.read(1 << 20)
            except FileExistsError:
                raise HTTPException(409, f"{name} already exists; rename it first") from None
            except Exception:
                if os.path.exists(dest):
                    os.unlink(dest)  # never leave a partial capture to be analysed
                raise
            return {"name": name, "size_bytes": written, "size_kb": round(written / 1024, 1)}

        uploads_enabled = True

    except ImportError:  # pragma: no cover

        @app.post("/api/upload", dependencies=guard)
        def upload_unavailable() -> JSONResponse:
            return JSONResponse(
                {"detail": "upload requires python-multipart; copy captures into "
                           f"{capture_dir}/ instead"},
                status_code=501,
            )

    @app.get("/api/roadmap", dependencies=heavy)
    def pqc_roadmap(capture: str, data_class: str = "official") -> JSONResponse:
        from ..intel.pqc import roadmap

        if data_class not in SECRECY_LIFETIME:
            raise HTTPException(
                400, f"unknown data_class; expected one of: {', '.join(sorted(SECRECY_LIFETIME))}")
        return JSONResponse(roadmap(_run(capture), data_class=data_class))

    @app.get("/api/cbom", dependencies=heavy)
    def cbom(capture: str) -> JSONResponse:
        from ..export.cbom import build_cbom

        return JSONResponse(build_cbom(_run(capture)))

    # Both fleet endpoints open the store read-only. The normal constructor runs
    # the schema script and migrations, so opening it with that from a GET would
    # let a page view modify the database the sensor writes.
    @app.get("/api/fleet", dependencies=guard)
    def fleet() -> dict:
        from ..intel.baseline import BaselineStore

        if not os.path.isfile(baseline_db):
            return {"tracked": False, "hint": "run: cipherguard watch <capture>"}
        with BaselineStore.open_readonly(baseline_db) as store:
            return {"tracked": True, "summary": store.summary(), "links": store.fleet()}

    @app.get("/api/fleet/history", dependencies=guard)
    def fleet_history(peer: str) -> dict:
        """One link's recorded posture, oldest first, for the replay timeline.

        The store path is fixed at construction, like /api/fleet. The only input
        is a peer key, and it has to name a link already in the store: it is
        length-checked before the store is opened, only ever bound as an SQL
        parameter, and an unknown key is a 404 rather than an empty history, so
        the endpoint cannot be used to probe for observations of peers the
        fleet does not show.
        """
        from ..intel.baseline import BaselineStore

        if not peer or len(peer) > MAX_PEER_KEY or not peer.isprintable():
            raise HTTPException(400, "invalid peer key")
        if not os.path.isfile(baseline_db):
            raise HTTPException(404, "no baseline store")
        with BaselineStore.open_readonly(baseline_db) as store:
            try:
                return store.replay(peer)
            except KeyError:
                raise HTTPException(404, "no such link in the baseline store") from None

    @app.get("/api/rules", dependencies=guard)
    def rules() -> dict:
        return {"rules": rule_catalogue()}

    def _wifi_assessment(force_scan: bool) -> dict[str, Any]:
        from ..vpn.detector import VpnDetector
        from ..wifi.auditor import WifiAuditor

        assessment = WifiAuditor().audit_current(force_scan=force_scan)
        res = assessment.to_dict()
        try:
            wifi_name = assessment.interface.name if assessment.interface else "Wi-Fi"
            wifi_dns = assessment.interface.dns_servers if assessment.interface else []
            res["vpn"] = VpnDetector().detect_current(
                wifi_iface_name=wifi_name, wifi_dns=wifi_dns).to_dict()
        except Exception:
            # VPN detection shells out to OS tools that may be absent; the
            # Wi-Fi result is still worth returning without it.
            logger.warning("VPN detection failed", exc_info=True)
            res["vpn"] = None
        return res

    @app.get("/api/wifi/current", dependencies=guard)
    def wifi_current() -> JSONResponse:
        return JSONResponse(_wifi_assessment(force_scan=False))

    @app.post("/api/wifi/scan", dependencies=heavy)
    def wifi_scan() -> JSONResponse:
        return JSONResponse(_wifi_assessment(force_scan=True))

    @app.get("/api/vpn/current", dependencies=guard)
    def vpn_current() -> JSONResponse:
        from ..vpn.detector import VpnDetector

        return JSONResponse(VpnDetector().detect_current().to_dict())

    plan_db_path = os.path.join(os.path.dirname(baseline_db) if baseline_db else ".", "cipherguard-plans.db")
    plan_store = PlanStore(plan_db_path)

    @app.get("/api/remediation/{capture}", dependencies=heavy)
    def get_remediation_plans(capture: str) -> dict:
        a = _run(capture, min_packets=5)
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

    async def _json_body(request: Request) -> dict:
        """The request's JSON object, or {} when there is no body.

        A body has to be declared as JSON. A cross-site form or text/plain
        fetch is sent without a preflight, and parsing whatever arrived let
        another site's page submit one.
        """
        raw = await request.body()
        if not raw:
            return {}
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            raise HTTPException(415, "the request body must be application/json")
        try:
            data = json.loads(raw)
        except ValueError:
            raise HTTPException(400, "the request body is not valid JSON") from None
        if not isinstance(data, dict):
            raise HTTPException(400, "the request body must be a JSON object")
        return data

    @app.post("/api/remediation/{plan_id}/approve", dependencies=guard)
    async def approve_plan_endpoint(plan_id: str, request: Request) -> dict:
        """Record who signed a plan off.

        The name is whatever the caller typed. The API authenticates a shared
        token at most, never a person, so the approver is stored and returned
        as self-declared. No default name is filled in: an approval nobody put
        a name to is not recorded as somebody's.
        """
        data = await _json_body(request)
        actor = _clean_label(data.get("actor"))
        if not actor:
            raise HTTPException(400, "an approver name is required")
        comment = _clean_label(data.get("comment"), 200)
        plan = plan_store.update_status(plan_id, "APPROVED", actor=actor, comment=comment)
        if not plan:
            raise HTTPException(404, "no such plan")
        log.remediation("approve", plan, declared_actor=actor)
        return {"status": "success", "plan": plan.to_dict()}

    @app.post("/api/remediation/{plan_id}/apply", dependencies=guard)
    async def apply_plan_endpoint(plan_id: str, request: Request) -> dict:
        """Dry-run an approved plan. Nothing is ever sent to a gateway.

        A plan that was not approved is refused: staging one used to work on
        any plan id, which made the approval step decorative.
        """
        data = await _json_body(request)
        dry_run = data.get("dry_run", True)
        target = _clean_label(data.get("target"))
        plan = plan_store.get_plan(plan_id)
        if not plan:
            raise HTTPException(404, "no such plan")
        if plan.status not in APPLY_ALLOWED_FROM:
            log.remediation("apply", plan, outcome="refused: not approved")
            raise HTTPException(
                409, f"plan {plan.plan_id} is {plan.status}; it must be approved before it can be staged")

        result = apply_plan(plan, dry_run=dry_run, target_host=target)
        if result.get("success"):
            # the dispatcher only ever succeeds in dry-run; a live apply is refused there
            plan = plan_store.update_status(
                plan_id, "STAGED", actor="api", comment=f"Executed ({result.get('mode')})") or plan
        log.remediation("apply", plan, declared_actor=plan.approver,
                        outcome=str(result.get("mode", "")))
        return result

    @app.get("/api/remediation-plans", dependencies=guard)
    def list_all_remediation_plans() -> dict:
        plans = plan_store.list_plans()
        return {"plans": [p.to_dict() for p in plans]}

    @app.get("/api/wifi/networks", dependencies=heavy)
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
        from ..capture.live import available, list_interfaces
        is_avail, reason = available()
        items = [{
            "name": iface,
            "is_wifi": any(w in iface.lower() for w in ("wi-fi", "wlan", "wireless", "802.11")),
        } for iface in list_interfaces()]
        return {
            "interfaces": items,
            "live_capture_available": is_avail,
            "availability_reason": reason,
            "platform": sys.platform,
        }

    @app.get("/api/captures/{capture}/flows/{spi}/wire", dependencies=heavy)
    def get_wire_samples(capture: str, spi: str, framing: str | None = None) -> dict:
        from ..dissector.wire_inspector import extract_wire_samples

        if not SPI_PATTERN.fullmatch(spi):
            raise HTTPException(400, "spi must be up to 8 hex digits, optionally prefixed 0x")
        if framing is not None and (len(framing) > 64 or not framing.isprintable()):
            raise HTTPException(400, "invalid framing class")
        path = _resolve(capture)
        # always hex: a bare "10" names SPI 0x10, the way the dashboard writes it
        spi_hex = spi if spi.lower().startswith("0x") else "0x" + spi
        try:
            return extract_wire_samples(path, spi_hex, framing_class=framing)
        except CaptureError as exc:
            raise HTTPException(422, f"{os.path.basename(path)} could not be read: {exc}") from None

    from ..capture.live_sniffer import global_sniffer

    @app.post("/api/sniff/start", dependencies=heavy)
    async def start_sniff(request: Request) -> JSONResponse:
        """Start a live capture, or a replay of the sample captures when the
        body says `"replay": true`. A capture that cannot start is an error
        with the reason; it is never swapped for a replay."""
        data = await _json_body(request)
        status = global_sniffer.start(
            interface=_clean_label(data.get("interface")) or None,
            replay=data.get("replay") is True,
        )
        if status["mode"] == "failed":
            return JSONResponse({"detail": status["error"], "status": status}, status_code=503)
        return JSONResponse(status)

    @app.post("/api/sniff/stop", dependencies=guard)
    def stop_sniff() -> dict:
        return global_sniffer.stop()

    @app.get("/api/sniff/status", dependencies=guard)
    def sniff_status() -> dict:
        return global_sniffer.get_status()

    # Guarded like every other data route. It was the one exception, on the
    # grounds that EventSource cannot send a header; the page now reads the
    # stream with fetch() so the token goes in Authorization, not in the URL.
    @app.get("/api/sniff/stream", dependencies=guard)
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
                        await asyncio.sleep(STREAM_IDLE_SECONDS)
                        status = global_sniffer.get_status()
                        yield f"event: heartbeat\ndata: {json.dumps(status)}\n\n"
            finally:
                global_sniffer.unsubscribe(q)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @app.post("/api/sniff/analyze", dependencies=heavy)
    def analyze_sniff_snapshot() -> dict:
        source = global_sniffer.buffer_source
        if source not in SNAPSHOT_NAMES or not global_sniffer.packet_buffer:
            raise HTTPException(409, "no IKE or ESP packets have been captured yet")
        snapshot_path = os.path.join(capture_dir, SNAPSHOT_NAMES[source])
        global_sniffer.snapshot_to_pcap(snapshot_path)

        from ..export.payload import build_payload

        a = analyze(snapshot_path, model_dir=model_dir, min_esp_packets=1)
        payload = build_payload(a, snapshot_path, model_dir)
        # "live" or "replay": the page labels a replay-derived assessment
        payload["capture_source"] = source
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
            "version": __version__,
            "model_trained": SuiteClassifier.is_trained(model_dir),
            "auth_required": auth_token is not None,
            "audit_log": audit_log is not None,
            "uploads": uploads_enabled,
            "max_upload_bytes": MAX_UPLOAD_BYTES if uploads_enabled else None,
        }

    return app


def __getattr__(name: str) -> Any:
    """`cipherguard.api.server:app` for ASGI servers, built on first use.

    Building it at import time opened the plan store in whatever directory the
    importing process happened to be in, for every import of this module.
    """
    if name == "app":
        return create_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
