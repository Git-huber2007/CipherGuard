"""Sensor health: is an unattended sensor still doing its job?

A sensor that has crashed is easy to notice. The failures that matter for an
unattended deployment are quieter: a model directory that no longer matches its
manifest (every window then dies at load time and systemd restarts it forever),
a baseline store that became read-only (downgrade detection silently stops), a
disk that cannot absorb the retention ceiling the sensor is configured for, and
a capture loop that is alive but no longer completing windows.

`cipherguard healthcheck` checks exactly those, and exits 0 / 1 / 2 for
healthy / degraded / failed so that systemd, Nagios-style probes or a cron job
can act on it without parsing output.

The healthcheck never unpickles the model and never creates files: probing must
not be able to cause the failure it is looking for.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

OK, DEGRADED, FAILED = 0, 1, 2
STATUS_NAMES = {OK: "healthy", DEGRADED: "degraded", FAILED: "failed"}

SENSOR_STATE = ".sensor-state.json"

# Margin over the remaining retention growth below which the disk is reported
# degraded: headroom the sensor needs but that is not yet fully used.
DISK_MARGIN = 1.2


@dataclass
class Check:
    name: str
    status: int
    detail: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = STATUS_NAMES[self.status]
        return d


# -- sensor state ------------------------------------------------------------


def write_sensor_state(directory: str, **fields) -> str:
    """Record that a sensor window completed, atomically.

    Written to a temporary file and renamed into place, so a healthcheck that
    reads concurrently sees either the previous window or this one, never a
    truncated file.
    """
    path = os.path.join(directory, SENSOR_STATE)
    state = {
        "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "pid": os.getpid(),
        **fields,
    }
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, path)
    return path


def read_sensor_state(directory: str) -> dict | None:
    try:
        with open(os.path.join(directory, SENSOR_STATE), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# -- checks ------------------------------------------------------------------


def check_model(model_dir: str) -> Check:
    """Manifest and feature schema, without loading the pickle."""
    from ..ml.classifier import (
        SCHEMA_VERSION,
        ModelIntegrityError,
        SuiteClassifier,
        feature_hash,
    )

    present = [
        f for f in ("rf.joblib", "cnn.npz", "meta.json", "MANIFEST.sha256")
        if os.path.exists(os.path.join(model_dir, f))
    ]
    if not present:
        return Check("model", DEGRADED,
                     f"no trained model in {model_dir}; ESP inference is disabled")
    try:
        result = SuiteClassifier.verify(model_dir, require_manifest=True)
    except ModelIntegrityError as exc:
        return Check("model", FAILED, str(exc))
    except (OSError, ValueError) as exc:
        return Check("model", FAILED, f"manifest unreadable: {exc}")

    try:
        with open(os.path.join(model_dir, "meta.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, ValueError) as exc:
        return Check("model", FAILED, f"meta.json unreadable: {exc}")
    stored = meta.get("feature_hash")
    if stored is not None and stored != feature_hash():
        return Check("model", FAILED,
                     "feature schema changed since training; the sensor will "
                     "refuse to load it. Retrain with: cipherguard train")
    if meta.get("schema_version") != SCHEMA_VERSION:
        return Check("model", FAILED,
                     f"model schema version {meta.get('schema_version')} does not "
                     f"match {SCHEMA_VERSION}")
    missing = {"rf.joblib", "cnn.npz"} - set(result["files"])
    if missing:
        return Check("model", FAILED,
                     f"manifest does not cover {', '.join(sorted(missing))}")
    return Check("model", OK,
                 f"{len(result['files'])} files match MANIFEST.sha256")


def check_baseline_db(path: str | None, timeout: float = 5.0) -> Check:
    """Can the sensor actually write the baseline store?

    Opened with `mode=rw` so a missing store is reported rather than created,
    and probed with a write inside a transaction that is rolled back. A store
    that opens but cannot be written is the dangerous case: `watch` and the
    sensor keep running and downgrade detection quietly stops.
    """
    if not path:
        return Check("baseline_db", OK, "baseline store disabled")
    if not os.path.exists(path):
        parent = os.path.dirname(os.path.abspath(path))
        if os.path.isdir(parent) and os.access(parent, os.W_OK):
            return Check("baseline_db", OK,
                         f"{path} not created yet; its directory is writable")
        return Check("baseline_db", FAILED,
                     f"{path} does not exist and {parent} is not writable")

    uri = "file:" + os.path.abspath(path).replace("\\", "/") + "?mode=rw"
    conn = None
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=timeout, isolation_level=None)
        rows = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        peers = conn.execute("SELECT COUNT(*) FROM baselines").fetchone()[0]
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE _cipherguard_healthcheck_probe (x INTEGER)")
        conn.execute("ROLLBACK")
    except sqlite3.OperationalError as exc:
        msg = str(exc)
        if "locked" in msg or "busy" in msg:
            return Check("baseline_db", DEGRADED,
                         f"{path} stayed locked for {timeout:.0f}s: {msg}")
        return Check("baseline_db", FAILED, f"{path} is not writable: {msg}")
    except sqlite3.DatabaseError as exc:
        return Check("baseline_db", FAILED, f"{path}: {exc}")
    finally:
        if conn is not None:
            conn.close()
    size = os.path.getsize(path)
    return Check("baseline_db", OK,
                 f"writable; {peers} links, {rows} observations, "
                 f"{size / (1 << 20):.1f} MB")


def _existing_ancestor(path: str) -> str:
    path = os.path.abspath(path)
    while not os.path.exists(path):
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return path


def _evidence_bytes(directory: str) -> int:
    try:
        names = os.listdir(directory)
    except OSError:
        return 0
    total = 0
    for n in names:
        if n.startswith("window-") and n.endswith(".pcap"):
            try:
                total += os.path.getsize(os.path.join(directory, n))
            except OSError:
                pass
    return total


def check_disk(
    evidence_dir: str,
    max_disk_bytes: int,
    max_window_bytes: int,
    no_evidence: bool,
    audit_log: str | None,
    audit_max_bytes: int,
    audit_backups: int,
) -> Check:
    """Free space against what the sensor is still allowed to consume.

    The retention ceiling is the most the sensor's bounded outputs can occupy:
    retained evidence plus one window in flight (pruning runs after a window is
    written), and the audit log across all rotated generations. What matters
    is whether the disk can absorb the part of that ceiling not yet used; a
    sensor that will fill its disk before retention engages is already broken,
    it just has not failed yet. Paths on different filesystems are accounted
    separately.

    The baseline store is bounded by row retention rather than by bytes, so it
    is reported but not part of the ceiling.
    """
    from .audit_log import AuditLog, retention_ceiling

    needs: dict[int, dict] = {}

    def add(path: str, label: str, ceiling: int, used: int) -> None:
        anchor = _existing_ancestor(path)
        dev = os.stat(anchor).st_dev
        slot = needs.setdefault(dev, {"anchor": anchor, "remaining": 0, "labels": []})
        slot["remaining"] += max(ceiling - used, 0)
        slot["labels"].append(label)

    evidence_ceiling = max_window_bytes + (0 if no_evidence else max_disk_bytes)
    add(evidence_dir, "evidence", evidence_ceiling, _evidence_bytes(evidence_dir))

    unbounded = []
    if audit_log:
        if audit_max_bytes and audit_backups:
            log = AuditLog(audit_log, max_bytes=audit_max_bytes, backups=audit_backups)
            used = sum(os.path.getsize(p) for p in log.generations())
            add(os.path.dirname(os.path.abspath(audit_log)), "audit log",
                retention_ceiling(audit_max_bytes, audit_backups), used)
        else:
            unbounded.append("audit log rotation is disabled, so its growth is unbounded")

    status = OK
    parts = []
    for slot in needs.values():
        free = shutil.disk_usage(slot["anchor"]).free
        remaining = slot["remaining"]
        what = " + ".join(slot["labels"])
        parts.append(f"{slot['anchor']}: {free / (1 << 20):,.0f} MB free, "
                     f"{remaining / (1 << 20):,.0f} MB still needed for {what}")
        if free < remaining:
            status = FAILED
        elif free < remaining * DISK_MARGIN:
            status = max(status, DEGRADED)
    if unbounded:
        status = max(status, DEGRADED)
        parts.extend(unbounded)
    return Check("disk", status, "; ".join(parts))


def check_last_window(
    evidence_dir: str,
    stale_after: float | None = None,
    now: datetime | None = None,
) -> Check:
    """Age of the last window the sensor completed.

    A live process that no longer completes windows (a hung capture, a stuck
    analysis) passes every liveness probe systemd has, so the sensor records
    each completed window and this compares its age with the window length it
    was running. Degraded past `stale_after` (default two windows plus two
    minutes of analysis), failed past three times that.
    """
    state = read_sensor_state(evidence_dir)
    if state is None:
        return Check("last_window", DEGRADED,
                     f"no completed sensor window recorded in {evidence_dir}")
    try:
        completed = datetime.fromisoformat(state["completed_at"])
        window = float(state.get("window_seconds") or 60)
    except (KeyError, TypeError, ValueError):
        return Check("last_window", DEGRADED, "sensor state file is malformed")

    now = now or datetime.now(timezone.utc)
    age = (now - completed).total_seconds()
    limit = stale_after if stale_after is not None else 2 * window + 120
    detail = (f"window {state.get('window', '?')} completed {age:,.0f}s ago "
              f"({window:.0f}s windows; stale after {limit:.0f}s)")
    if age < -60:
        return Check("last_window", DEGRADED,
                     f"last window is stamped {-age:,.0f}s in the future; "
                     "the clock has been stepped")
    if age > 3 * limit:
        return Check("last_window", FAILED, detail)
    if age > limit:
        return Check("last_window", DEGRADED, detail)
    return Check("last_window", OK, detail)


def run_checks(
    model_dir: str,
    baseline_db: str | None,
    evidence_dir: str,
    max_disk_bytes: int,
    max_window_bytes: int,
    no_evidence: bool,
    audit_log: str | None,
    audit_max_bytes: int,
    audit_backups: int,
    stale_after: float | None = None,
) -> list[Check]:
    return [
        check_model(model_dir),
        check_baseline_db(baseline_db),
        check_disk(evidence_dir, max_disk_bytes, max_window_bytes, no_evidence,
                   audit_log, audit_max_bytes, audit_backups),
        check_last_window(evidence_dir, stale_after),
    ]


def overall(checks: list[Check]) -> int:
    return max((c.status for c in checks), default=OK)
