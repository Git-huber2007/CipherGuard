"""Structured audit logging.

Mirroring production traffic on a government backbone carries custody
obligations, and those obligations do not end when the packets are discarded.
An agency has to be able to answer, after the fact, who assessed which capture
and when — both to demonstrate the analyzer was used lawfully and to
reconstruct what an analyst knew at the time a decision was made.

The log is JSON Lines: one self-contained object per line, append-only, trivially
shippable to a SIEM without a parser. What it deliberately does not contain is
any part of the traffic itself. Findings are recorded by rule ID and subject, not
by detail text, so the audit trail cannot become a second copy of the
intelligence it is meant to account for.

The file is rotated by size (`audit.jsonl` -> `audit.jsonl.1` ... `.N`), because
a sensor appends to it for as long as it runs. Rotation and appends happen under
one inter-process lock, so the sensor, the dashboard and an analyst's CLI run
can share a log without interleaving partial lines or losing one to a rename.
"""

from __future__ import annotations

import errno
import json
import os
import socket
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator

_lock = threading.Lock()

DEFAULT_LOG = "cipherguard-audit.jsonl"
DEFAULT_MAX_BYTES = 16 << 20
DEFAULT_BACKUPS = 5


def retention_ceiling(max_bytes: int, backups: int, largest_record: int = 64 << 10) -> int:
    """The most disk the log and its rotated generations can occupy.

    The active file rotates before a write would take it past `max_bytes`, so
    each generation stays within it — except that a record larger than the
    limit is still written whole, alone in its generation, rather than split or
    dropped. Records are bounded (findings are IDs, not text); 64 KiB is a
    generous default for the largest.
    """
    if not max_bytes:
        return 0
    return (backups + 1) * max(max_bytes, largest_record)


class AuditLog:
    def __init__(
        self,
        path: str | None = DEFAULT_LOG,
        actor: str = "cli",
        max_bytes: int = DEFAULT_MAX_BYTES,
        backups: int = DEFAULT_BACKUPS,
    ):
        """`max_bytes=0` or `backups=0` disables rotation (the file then grows
        without bound, as it did before rotation existed)."""
        self.path = path
        self.actor = actor
        self.host = socket.gethostname()
        self.max_bytes = max_bytes
        self.backups = backups

    def generations(self) -> list[str]:
        """The active file and every rotated generation that exists, newest first."""
        if not self.path:
            return []
        names = [self.path] + [f"{self.path}.{i}" for i in range(1, self.backups + 1)]
        return [n for n in names if os.path.exists(n)]

    def _write(self, record: dict[str, Any]) -> None:
        path = self.path
        if not path:
            return
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "host": self.host,
            "actor": self.actor,
            "pid": os.getpid(),
            **record,
        }
        data = (json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n").encode()
        # Append under a lock and with a single write call: concurrent analysts
        # on one sensor must not interleave partial lines and corrupt the trail.
        # The thread lock alone is not enough once rotation exists — a rename
        # by one process between another's size check and its append would
        # send that append to a generation about to be discarded — so both
        # steps happen under a file lock every writer on the host honours.
        with _lock, _interprocess_lock(path + ".lock"):
            if self.max_bytes and self.backups:
                self._rotate_if_needed(path, len(data))
            with open(path, "ab") as fh:
                fh.write(data)

    def _rotate_if_needed(self, path: str, incoming: int) -> None:
        """Shift generations up by one and start a fresh active file.

        Each step is an `os.replace`, which is atomic, and the oldest
        generation is only ever discarded by being overwritten. The record
        about to be written always lands in the fresh active file, so the most
        recent assessment is never in a generation rotation can delete.

        If a rename fails (on Windows, a reader holding a generation open),
        the write goes to the active file un-rotated. The file overshoots its
        limit until the next write retries; no line is lost.
        """
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        if size == 0 or size + incoming <= self.max_bytes:
            return
        try:
            for i in range(self.backups - 1, 0, -1):
                src = f"{path}.{i}"
                if os.path.exists(src):
                    os.replace(src, f"{path}.{i + 1}")
            os.replace(path, f"{path}.1")
        except OSError:
            pass

    def assessment(self, assessment, capture_path: str, source: str = "cli") -> None:
        """Record that an assessment happened, without recording its content."""
        self._write(
            {
                "event": "assessment",
                "source": source,
                "capture": os.path.basename(capture_path),
                "capture_sha256": _digest(capture_path),
                "score": assessment.score(),
                "grade": assessment.grade(),
                "counts": assessment.counts(),
                "sessions": len(assessment.sessions),
                "esp_flows": len(assessment.flows),
                # rule IDs and subjects only — never finding detail, which
                # would duplicate the intelligence into the audit trail
                "findings": sorted(
                    {f"{f.rule_id}:{f.subject}" for f in assessment.findings}
                ),
                "report_digest": assessment.digest(),
            }
        )

    def export(self, kind: str, capture: str, destination: str | None) -> None:
        self._write(
            {
                "event": "export",
                "kind": kind,
                "capture": os.path.basename(capture),
                "destination": os.path.basename(destination) if destination else None,
            }
        )

    def denied(self, reason: str, detail: str = "") -> None:
        self._write({"event": "denied", "reason": reason, "detail": detail[:200]})


# EDEADLOCK is what msvcrt raises; macOS has no such name, and this is built at
# import time on every platform.
_LOCK_CONTENDED = {getattr(errno, "EDEADLOCK", errno.EDEADLK), errno.EACCES}


@contextmanager
def _interprocess_lock(path: str) -> Generator[None, None, None]:
    """Exclusive advisory lock on a sidecar file, held for one append.

    The OS releases it when the holder exits, however it exits, so a writer
    killed mid-append cannot leave the log permanently locked.
    """
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            # LK_LOCK retries for about ten seconds and then raises EDEADLOCK;
            # waiting longer is correct, since the alternative is an
            # unserialised write. Any other error is not contention and would
            # never clear, so it propagates instead of hanging the sensor.
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                    break
                except OSError as exc:
                    if exc.errno not in _LOCK_CONTENDED:
                        raise
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _digest(path: str) -> str | None:
    """SHA-256 of the capture, so a later reader can prove which bytes were
    assessed. A finding is only meaningful against a known input."""
    import hashlib

    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while chunk := fh.read(1 << 20):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None
