"""Request-level protections for the API: which requests are let in at all.

The default deployment is a tokenless server on loopback, and a loopback bind
only keeps out other machines. A web page open in the analyst's browser can
still reach 127.0.0.1, so the boundary the loopback default relies on has to be
enforced per request:

- Host allowlist. Under DNS rebinding a hostile page is same-origin with this
  server as far as the browser is concerned, and CORS never applies. The Host
  header still carries the attacker's name, so refusing unknown hosts closes it.
- Origin check on state-changing requests. A cross-site form or a text/plain
  fetch needs no preflight and is sent without asking; the browser does label
  it with an Origin, and that is refused unless the origin is this server or a
  configured one.
- Body size ceilings checked from Content-Length, before anything is read.
- Response headers that stop the page being framed, sniffed or scripted from
  anywhere but its own files.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from collections.abc import Iterable
from urllib.parse import urlsplit

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Every JSON body this API accepts is a few hundred bytes.
MAX_JSON_BODY_BYTES = 64 << 10

# Slack for the multipart boundary and part headers around an upload.
MULTIPART_OVERHEAD_BYTES = 64 << 10

# The page is plain files from this server. Inline style attributes are still
# used by the dashboard, so styles allow 'unsafe-inline'; scripts do not.
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}

HSTS = "max-age=31536000; includeSubDomains"


def hostname(host_header: str) -> str:
    """The name in a Host header, without the port and without IPv6 brackets."""
    host = host_header.strip().lower()
    if host.startswith("["):
        return host[1:host.find("]")] if "]" in host else ""
    return host.rsplit(":", 1)[0] if ":" in host else host


def normalise_origins(origins: Iterable[str] | None) -> list[str]:
    return [o.strip().rstrip("/") for o in (origins or []) if o and o.strip()]


class RequestGuard:
    """ASGI middleware applying the checks described in the module docstring.

    `allowed_hosts` of None accepts any Host, which is right once a token is
    required: a rebinding page cannot read another origin's stored token.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_hosts: Iterable[str] | None,
        trusted_origins: Iterable[str] = (),
        max_upload_bytes: int,
        upload_path: str = "/api/upload",
    ) -> None:
        self.app = app
        self.allowed_hosts = None if allowed_hosts is None else {h.lower() for h in allowed_hosts}
        self.trusted_origins = set(normalise_origins(trusted_origins))
        self.max_upload_bytes = max_upload_bytes
        self.upload_path = upload_path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        path: str = scope.get("path", "")
        secure = (scope.get("scheme") == "https"
                  or headers.get("x-forwarded-proto", "").lower() == "https")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                out = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    out.setdefault(name, value)
                if path.startswith("/api/"):
                    out.setdefault("Cache-Control", "no-store")
                if secure:
                    out.setdefault("Strict-Transport-Security", HSTS)
            await send(message)

        refusal = self._refusal(scope["method"], path, headers)
        if refusal is not None:
            status, detail = refusal
            await _send_json(send_with_headers, status, detail)
            return
        await self.app(scope, receive, send_with_headers)

    def _refusal(self, method: str, path: str, headers: Headers) -> tuple[int, str] | None:
        host = headers.get("host", "")
        if self.allowed_hosts is not None and hostname(host) not in self.allowed_hosts:
            return 400, "unrecognised Host header"

        if method not in UNSAFE_METHODS or not path.startswith("/api/"):
            return None

        origin = headers.get("origin")
        if origin is not None:
            if not self._origin_allowed(origin, host):
                return 403, "cross-site request refused"
        elif headers.get("sec-fetch-site", "").lower() == "cross-site":
            return 403, "cross-site request refused"

        limit = (self.max_upload_bytes + MULTIPART_OVERHEAD_BYTES
                 if path == self.upload_path else MAX_JSON_BODY_BYTES)
        length = headers.get("content-length")
        if length is None:
            # A body of unknown length cannot be bounded before it is read.
            if "transfer-encoding" in headers or path == self.upload_path:
                return 411, "Content-Length is required"
        elif not length.isdigit():
            return 400, "invalid Content-Length"
        elif int(length) > limit:
            if path == self.upload_path:
                return 413, f"capture exceeds the {self.max_upload_bytes // 1_000_000} MB limit"
            return 413, "request body too large"
        return None

    def _origin_allowed(self, origin: str, host: str) -> bool:
        origin = origin.strip().rstrip("/")
        if origin in self.trusted_origins:
            return True
        # Same origin: compared on host:port only, because behind a TLS proxy
        # this server sees http while the browser's origin says https.
        return bool(host) and urlsplit(origin).netloc.lower() == host.strip().lower()


async def _send_json(send: Send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii"))],
    })
    await send({"type": "http.response.body", "body": body})


class SlidingWindowLimiter:
    """At most `limit` events per `window` seconds for each key, in memory.

    Enough for one process serving a handful of analysts. Behind a reverse
    proxy every client shares the proxy's address, so rate limiting belongs on
    the proxy there; this is the backstop for the direct case.
    """

    def __init__(self, limit: int, window: float, max_keys: int = 4096) -> None:
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> deque[float]:
        events = self._events.get(key)
        if events is None:
            if len(self._events) >= self.max_keys:
                # Bounded: a flood of distinct keys evicts the oldest entry
                # instead of growing without limit.
                self._events.pop(next(iter(self._events)))
            events = self._events[key] = deque()
        cutoff = now - self.window
        while events and events[0] <= cutoff:
            events.popleft()
        return events

    def retry_after(self, key: str) -> int:
        """Seconds until `key` may try again, or 0 if it is under the limit."""
        if self.limit <= 0:
            return 0
        now = time.monotonic()
        with self._lock:
            events = self._recent(key, now)
            if len(events) < self.limit:
                return 0
            return max(1, int(events[0] + self.window - now) + 1)

    def record(self, key: str) -> None:
        if self.limit <= 0:
            return
        now = time.monotonic()
        with self._lock:
            self._recent(key, now).append(now)

    def hit(self, key: str) -> int:
        """Count one event. Returns 0 if allowed, else seconds to wait."""
        wait = self.retry_after(key)
        if wait == 0:
            self.record(key)
        return wait
