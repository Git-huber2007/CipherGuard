"""Soak test: run the sensor's per-window work in a loop and prove it stays bounded.

A sensor is meant to run unattended for weeks, and the ways that fails are all
slow: a leaked reference per window, a file descriptor never closed, a table or
log nobody prunes. None of them shows up in a unit test, because a unit test
does not run long enough to accumulate anything.

This replays captures through the same steps `cipherguard sensor` performs for
every window, in the same order:

    stage the capture as window-N.pcap  ->  analyze (model loaded, as the sensor does)
    ->  audit log  ->  baseline store (opened and closed per window)
    ->  evidence retention  ->  sensor state file

and samples RSS, open file descriptors (handles on Windows), baseline DB size
and rows, audit log size across generations, and retained evidence. It fails if
any of them exceeds a stated bound, or if retention ever deletes the evidence
behind the most recent assessment.

What it does not exercise: live capture (AF_PACKET), which needs a mirror port
and privileges. Each capture is read from disk instead.

    python scripts/soak.py --duration 3600 --json-out soak.json

Exit status is 0 if every bound held and 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from dataclasses import asdict, dataclass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from cipherguard.core.audit_log import AuditLog, retention_ceiling  # noqa: E402
from cipherguard.core.health import write_sensor_state  # noqa: E402
from cipherguard.core.retention import prune_evidence  # noqa: E402
from cipherguard.intel.baseline import BaselineStore  # noqa: E402
from cipherguard.pipeline import analyze  # noqa: E402

MB = 1 << 20
TREND_MIN_SPAN = 600.0


@dataclass
class Config:
    duration: float = 60.0
    sample_every: float = 2.0
    warmup: float = 10.0
    # retention settings, deliberately small so a short run reaches steady state
    retain_per_peer: int = 20
    retain_days: float = 90.0
    audit_max_bytes: int = 16 << 10
    audit_backups: int = 3
    retain_windows: int = 5
    max_evidence_bytes: int = 4 * MB
    # stated bounds
    max_rss_growth_mb: float = 48.0
    max_fd_growth: int = 16
    max_db_mb: float = 4.0


# -- measurement -------------------------------------------------------------


def _rss_and_fds() -> tuple[int | None, int | None]:
    try:
        import psutil

        proc = psutil.Process()
        rss = proc.memory_info().rss
        fds = proc.num_handles() if os.name == "nt" else proc.num_fds()
        return rss, fds
    except ImportError:
        pass
    rss = fds = None
    try:
        with open("/proc/self/statm") as fh:
            rss = int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
        fds = len(os.listdir("/proc/self/fd"))
    except (OSError, ValueError, AttributeError):
        pass
    return rss, fds


def _size(*paths: str) -> int:
    return sum(os.path.getsize(p) for p in paths if os.path.exists(p))


def _db_stats(db: str) -> tuple[int, int, int]:
    """(observation rows, distinct peers, baselines whose establishing row is gone)"""
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        peers = conn.execute(
            "SELECT COUNT(DISTINCT peer_key) FROM observations").fetchone()[0]
        orphaned = conn.execute(
            "SELECT COUNT(*) FROM baselines WHERE best_observation_id IS NOT NULL "
            "AND best_observation_id NOT IN (SELECT id FROM observations)").fetchone()[0]
        return rows, peers, orphaned
    finally:
        conn.close()


def _last_line(path: str) -> dict | None:
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        fh.seek(max(fh.tell() - (64 << 10), 0))
        lines = fh.read().splitlines()
    return json.loads(lines[-1]) if lines else None


def _slope_per_hour(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) < 3:
        return None
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    var = sum((x - mx) ** 2 for x in xs)
    if not var:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / var * 3600


# -- the loop ----------------------------------------------------------------


def _captures(directory: str | None, scratch: str) -> list[str]:
    if directory and os.path.isdir(directory):
        found = sorted(
            os.path.join(directory, n) for n in os.listdir(directory)
            if n.endswith(".pcap")
        )
        if found:
            return found
    from cipherguard.lab.pcapgen import generate_all

    return sorted(generate_all(os.path.join(scratch, "captures")))


def run(
    cfg: Config,
    model_dir: str = "models",
    captures_dir: str | None = "samples",
    workdir: str | None = None,
    inject_leak_kb: int = 0,
    log=print,
) -> dict:
    scratch = workdir or tempfile.mkdtemp(prefix="cipherguard-soak-")
    os.makedirs(scratch, exist_ok=True)
    captures = _captures(captures_dir, scratch)
    evidence = os.path.join(scratch, "evidence")
    os.makedirs(evidence, exist_ok=True)
    db = os.path.join(scratch, "baseline.db")
    audit = AuditLog(os.path.join(scratch, "audit.jsonl"), actor="soak",
                     max_bytes=cfg.audit_max_bytes, backups=cfg.audit_backups)
    assert audit.path

    # A soak that cannot measure is a soak that always passes, so refuse.
    if None in _rss_and_fds():
        raise RuntimeError("cannot measure RSS and open descriptors here: "
                           "install psutil, or run on Linux")

    leak: list[bytes] = []   # only for demonstrating that the soak catches a leak
    violations: list[str] = []
    samples: list[dict] = []
    largest_record = 0
    largest_capture = max(os.path.getsize(c) for c in captures)
    rows_pruned = evidence_removed = rotations = 0

    started = time.monotonic()
    deadline = started + cfg.duration
    next_sample = started
    iteration = 0

    log(f"soak: {cfg.duration:.0f}s over {len(captures)} captures in {scratch}")
    while True:
        now = time.monotonic()
        if now >= deadline and iteration >= len(captures):
            break
        iteration += 1
        cap = captures[(iteration - 1) % len(captures)]
        window = os.path.join(evidence, f"window-{iteration:08d}.pcap")
        shutil.copyfile(cap, window)

        assessment = analyze(window, model_dir=model_dir)
        active_before = _size(audit.path)
        audit.assessment(assessment, window, source="soak")
        if _size(audit.path) < active_before:
            rotations += 1
        with BaselineStore(db, retain_per_peer=cfg.retain_per_peer,
                           retain_days=cfg.retain_days) as store:
            count = "SELECT COUNT(*) FROM observations"
            before = store.conn.execute(count).fetchone()[0]
            store.record(assessment)
            inserted = sum(1 for s in assessment.sessions
                           if s.negotiated("IKE", confirmed_only=True))
            rows_pruned += before + inserted - store.conn.execute(count).fetchone()[0]
        removed, _ = prune_evidence(evidence, cfg.retain_windows,
                                    cfg.max_evidence_bytes, protect=window)
        evidence_removed += removed
        write_sensor_state(evidence, window=iteration, window_seconds=0,
                           score=assessment.score(), evidence=os.path.basename(window))

        # The constraint retention must never break: the most recent
        # assessment's evidence and audit record both still exist.
        if not os.path.exists(window):
            violations.append(f"iteration {iteration}: {window} was pruned")
        last = _last_line(audit.path)
        if not last or last.get("capture") != os.path.basename(window):
            violations.append(f"iteration {iteration}: latest audit record missing")
        largest_record = max(largest_record,
                             len(json.dumps(last or {}, separators=(",", ":"))) + 1)

        if inject_leak_kb:
            # filled rather than zeroed, so the pages are really touched
            leak.append(bytes([iteration & 0xFF | 1]) * (inject_leak_kb << 10))

        if time.monotonic() >= next_sample:
            next_sample += cfg.sample_every
            rss, fds = _rss_and_fds()
            rows, peers, orphaned = _db_stats(db)
            if orphaned:
                violations.append(f"iteration {iteration}: {orphaned} baseline(s) "
                                  "lost their establishing observation")
            samples.append({
                "t": round(time.monotonic() - started, 2),
                "iteration": iteration,
                "rss": rss,
                "fds": fds,
                "db_bytes": _size(db, db + "-journal", db + "-wal"),
                "db_rows": rows,
                "db_peers": peers,
                "log_bytes": sum(_size(p) for p in audit.generations()),
                "log_generations": len(audit.generations()),
                "evidence_bytes": _size(*[os.path.join(evidence, n)
                                          for n in os.listdir(evidence)
                                          if n.endswith(".pcap")]),
                "evidence_files": sum(1 for n in os.listdir(evidence)
                                      if n.endswith(".pcap")),
            })

    elapsed = time.monotonic() - started
    report = _evaluate(cfg, samples, len(captures), largest_record, largest_capture)
    report.update({
        "config": asdict(cfg),
        "host": {"python": sys.version.split()[0], "platform": sys.platform},
        "elapsed_seconds": round(elapsed, 1),
        "iterations": iteration,
        "captures": [os.path.basename(c) for c in captures],
        "exercised": {
            "observation_rows_pruned": rows_pruned,
            "evidence_files_pruned": evidence_removed,
            "audit_rotations": rotations,
            "audit_generations_at_end": len(audit.generations()),
            "largest_audit_record_bytes": largest_record,
        },
        "violations": violations[:20],
        "samples": samples,
        "workdir": scratch,
    })
    report["passed"] = report["passed"] and not violations
    del leak
    return report


def _evaluate(cfg: Config, samples: list[dict], n_captures: int,
              largest_record: int, largest_capture: int) -> dict:
    """Compare every metric with its bound.

    RSS and descriptors are judged by growth over the warm-up: the first
    `warmup` seconds, and at least one full pass over the captures, so that
    the model, every code path and the allocator's working set are all
    established before anything counts as growth. Everything on disk has an
    absolute bound derived from the retention configuration.
    """
    warm = [s for s in samples if s["t"] <= cfg.warmup or s["iteration"] <= n_captures]
    steady = samples[len(warm):]
    if not warm or not steady:
        return {"passed": False, "checks": {},
                "error": "run too short: no samples after warm-up"}

    def peak(rows, key):
        vals = [r[key] for r in rows if r[key] is not None]
        return max(vals) if vals else None

    checks = {}

    def check(name, value, bound, unit=""):
        ok = value is not None and value <= bound
        checks[name] = {"value": value, "bound": bound, "unit": unit, "ok": ok}

    rss_base = peak(warm, "rss")
    rss_peak = peak(steady, "rss")
    check("rss_growth_mb", round((rss_peak - rss_base) / MB, 1), cfg.max_rss_growth_mb, "MB")
    checks["rss_growth_mb"].update({
        "warmup_peak_mb": round(rss_base / MB, 1),
        "steady_peak_mb": round(rss_peak / MB, 1),
        "final_mb": round(samples[-1]["rss"] / MB, 1),
        # Over a span of seconds a slope is allocator noise extrapolated to an
        # hour; it is reported only once there is enough run to mean something.
        "trend_mb_per_hour": _round(_slope_per_hour(
            [s["t"] for s in steady], [s["rss"] / MB for s in steady]))
            if steady[-1]["t"] - steady[0]["t"] >= TREND_MIN_SPAN else None,
    })

    fd_base, fd_peak = peak(warm, "fds"), peak(steady, "fds")
    check("fd_growth", None if fd_base is None else fd_peak - fd_base, cfg.max_fd_growth)
    checks["fd_growth"].update({"warmup_peak": fd_base, "steady_peak": fd_peak,
                                "kind": "handles" if os.name == "nt" else "fds"})

    # Every peer keeps at most retain_per_peer rows plus its baseline-
    # establishing row, which may be older than the rest.
    peers = samples[-1]["db_peers"]
    check("db_rows", peak(samples, "db_rows"), peers * (cfg.retain_per_peer + 1), "rows")
    checks["db_rows"]["final"] = samples[-1]["db_rows"]
    check("db_mb", round(peak(samples, "db_bytes") / MB, 3), cfg.max_db_mb, "MB")

    log_bound = retention_ceiling(cfg.audit_max_bytes, cfg.audit_backups, largest_record)
    check("log_bytes", peak(samples, "log_bytes"), log_bound, "bytes")

    # The byte ceiling can be exceeded by exactly one window: the newest, which
    # pruning protects because the latest assessment was made from it.
    check("evidence_files", peak(samples, "evidence_files"), cfg.retain_windows, "files")
    check("evidence_bytes", peak(samples, "evidence_bytes"),
          cfg.max_evidence_bytes + largest_capture, "bytes")

    return {"passed": all(c["ok"] for c in checks.values()), "checks": checks,
            "warmup_samples": len(warm), "steady_samples": len(steady)}


def _round(x: float | None) -> float | None:
    return None if x is None else round(x, 1)


def _print(report: dict) -> None:
    print()
    verdict = "PASS" if report["passed"] else "FAIL"
    print(f"soak {verdict}: {report['iterations']} iterations in "
          f"{report['elapsed_seconds']}s ({report['host']['platform']}, "
          f"Python {report['host']['python']})")
    if "error" in report:
        print(f"  {report['error']}")
    for name, c in report.get("checks", {}).items():
        mark = "ok  " if c["ok"] else "FAIL"
        extra = {k: v for k, v in c.items() if k not in ("value", "bound", "unit", "ok")}
        print(f"  [{mark}] {name:<15} {c['value']} {c['unit']} (bound {c['bound']})"
              + (f"  {extra}" if extra else ""))
    print(f"  exercised: {report['exercised']}")
    for v in report["violations"]:
        print(f"  VIOLATION {v}")


def main(argv: list[str] | None = None) -> int:
    d = Config()
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--duration", type=float, default=d.duration, help="seconds to run")
    ap.add_argument("--sample-every", type=float, default=d.sample_every)
    ap.add_argument("--warmup", type=float, default=d.warmup)
    ap.add_argument("--models", default="models")
    ap.add_argument("--captures", default="samples",
                    help="directory of .pcap files; generated if empty or absent")
    ap.add_argument("--workdir", help="where the DB, log and evidence go (default: temp)")
    ap.add_argument("--retain-per-peer", type=int, default=d.retain_per_peer)
    ap.add_argument("--audit-max-bytes", type=int, default=d.audit_max_bytes)
    ap.add_argument("--audit-backups", type=int, default=d.audit_backups)
    ap.add_argument("--max-rss-growth-mb", type=float, default=d.max_rss_growth_mb)
    ap.add_argument("--max-fd-growth", type=int, default=d.max_fd_growth)
    ap.add_argument("--max-db-mb", type=float, default=d.max_db_mb)
    ap.add_argument("--json-out", help="write the full report, including samples")
    ap.add_argument("--inject-leak-kb", type=int, default=0, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    cfg = Config(
        duration=args.duration, sample_every=args.sample_every, warmup=args.warmup,
        retain_per_peer=args.retain_per_peer, audit_max_bytes=args.audit_max_bytes,
        audit_backups=args.audit_backups, max_rss_growth_mb=args.max_rss_growth_mb,
        max_fd_growth=args.max_fd_growth, max_db_mb=args.max_db_mb,
    )
    report = run(cfg, model_dir=args.models, captures_dir=args.captures,
                 workdir=args.workdir, inject_leak_kb=args.inject_leak_kb)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(report, fh, indent=2)
    _print(report)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
