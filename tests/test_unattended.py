"""Running unattended for weeks: retention, rotation, health, and the soak.

Every store a sensor writes to has to be bounded, and every bound has to leave
the evidence behind the most recent assessment intact. These tests pin both
halves: that growth stops, and that what an analyst is looking at right now is
never what gets deleted to stop it.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

from cipherguard.core.models import Assessment, IkeMessage, IkeSession, Proposal, Transform

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)

WEAK = [Transform(1, "ENCR", 3, "ENCR_3DES"), Transform(4, "DH", 2, "1024-bit MODP")]
STRONG = [Transform(1, "ENCR", 20, "ENCR_AES_GCM_16", key_length=256),
          Transform(4, "DH", 19, "256-bit random ECP")]


def _session(n: int, transforms) -> IkeSession:
    """A session whose responder was observed agreeing, so it is recordable."""
    a, b = f"10.8.{n}.1", f"10.8.{n}.2"
    response = IkeMessage(
        frame=n, timestamp=1.0, src=b, dst=a, sport=500, dport=500,
        version="IKEv2", exchange="IKE_SA_INIT", initiator_spi=bytes([n]) * 8,
        responder_spi=b"\x02" * 8, message_id=0, is_initiator=False, is_response=True,
    )
    response.proposals = [Proposal(number=1, protocol_id=1, protocol="IKE",
                                   transforms=list(transforms))]
    s = IkeSession(bytes([n]) * 8, b"\x02" * 8, "IKEv2", a, b)
    s.messages = [response]
    return s


def _assessment(capture: str, *sessions: IkeSession) -> Assessment:
    a = Assessment(capture=capture, started="now")
    a.sessions = list(sessions)
    return a


def _rows(store, peer: str | None = None) -> list[sqlite3.Row]:
    sql = "SELECT * FROM observations"
    args: tuple = ()
    if peer:
        sql, args = sql + " WHERE peer_key = ?", (peer,)
    return store.conn.execute(sql + " ORDER BY id", args).fetchall()


PEER1 = "10.8.1.1|10.8.1.2"
PEER2 = "10.8.2.1|10.8.2.2"


# ---------------------------------------------------------------------------
# Observation retention
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_observations_are_bounded_per_peer(tmp_path):
    """Regression: one row per session per window, forever. At 60-second
    windows that is half a million rows a year per link, on the sensor's disk."""
    from cipherguard.intel.baseline import BaselineStore

    with BaselineStore(str(tmp_path / "b.db"), retain_per_peer=5, retain_days=None) as store:
        for i in range(30):
            store.record(_assessment(f"w{i}.pcap", _session(1, WEAK)),
                         now=NOW + timedelta(minutes=i))
        rows = _rows(store, PEER1)
        captures = [r["capture"] for r in rows]

    # the five most recent, plus the row that established the baseline
    assert len(rows) == 6
    assert captures[0] == "w0.pcap"
    assert captures[1:] == [f"w{i}.pcap" for i in range(25, 30)]


@pytest.mark.no_model
def test_old_observations_age_out_but_the_baseline_row_does_not(tmp_path):
    from cipherguard.intel.baseline import BaselineStore

    with BaselineStore(str(tmp_path / "b.db"), retain_per_peer=None, retain_days=90) as store:
        store.record(_assessment("first.pcap", _session(1, WEAK)), now=NOW - timedelta(days=120))
        for d in (110, 100, 95):
            store.record(_assessment(f"d{d}.pcap", _session(1, WEAK)),
                         now=NOW - timedelta(days=d))
        store.record(_assessment("recent.pcap", _session(1, WEAK)), now=NOW - timedelta(days=5))
        store.record(_assessment("today.pcap", _session(1, WEAK)), now=NOW)
        captures = [r["capture"] for r in _rows(store)]

    assert captures == ["first.pcap", "recent.pcap", "today.pcap"]


@pytest.mark.no_model
def test_promoted_baseline_row_survives_retention(tmp_path):
    """The row a baseline was promoted from is the evidence behind every later
    "was N bits" in a downgrade alert. Deleting it would leave the alert
    asserting a reference point the store can no longer show."""
    from cipherguard.intel.baseline import BaselineStore

    with BaselineStore(str(tmp_path / "b.db"), retain_per_peer=3, retain_days=None) as store:
        store.record(_assessment("weak0.pcap", _session(1, WEAK)), now=NOW)
        store.record(_assessment("strong1.pcap", _session(1, STRONG)),
                     now=NOW + timedelta(minutes=1))
        store.record(_assessment("strong2.pcap", _session(1, STRONG)),
                     now=NOW + timedelta(minutes=2))
        best = store.conn.execute(
            "SELECT best_observation_id, best_classical_bits FROM baselines").fetchone()

        downgrades = []
        for i in range(20):
            drifts = store.record(_assessment(f"weak{i + 3}.pcap", _session(1, WEAK)),
                                  now=NOW + timedelta(minutes=3 + i))
            downgrades += [d for d in drifts if d.kind == "downgrade"]

        kept = {r["id"]: r["capture"] for r in _rows(store)}

    assert best["best_classical_bits"] > 80, "never promoted; test is vacuous"
    assert kept[best["best_observation_id"]] == "strong2.pcap"
    assert len(kept) == 4
    assert downgrades and downgrades[-1].previous_bits == best["best_classical_bits"]


@pytest.mark.no_model
def test_a_quiet_link_stays_in_the_fleet_view(tmp_path):
    """A link unseen for longer than the age ceiling must stay in the triage
    queue. `fleet()` joins each baseline to its latest observation, so deleting
    that row would make the link silently disappear."""
    from cipherguard.intel.baseline import BaselineStore

    with BaselineStore(str(tmp_path / "b.db"), retain_per_peer=2, retain_days=30) as store:
        store.record(_assessment("old.pcap", _session(1, WEAK)), now=NOW - timedelta(days=200))
        store.record(_assessment("old2.pcap", _session(1, WEAK)),
                     now=NOW - timedelta(days=199))
        store.record(_assessment("new.pcap", _session(2, STRONG)), now=NOW)
        fleet = {f["peer_key"]: f for f in store.fleet()}

    assert set(fleet) == {PEER1, PEER2}
    assert fleet[PEER1]["last_seen"].startswith((NOW - timedelta(days=199)).date().isoformat())


@pytest.mark.no_model
def test_a_peer_without_a_baseline_ages_out_completely(tmp_path):
    """Peers withheld by `max_new_peers` are what spoofed addresses look like.
    They get no protection, so they cannot accumulate forever."""
    from cipherguard.intel.baseline import BaselineStore

    with BaselineStore(str(tmp_path / "b.db"), retain_per_peer=None, retain_days=30) as store:
        store.record(_assessment("spoof.pcap", _session(1, WEAK)), max_new_peers=0,
                     now=NOW - timedelta(days=60))
        store.record(_assessment("real.pcap", _session(2, STRONG)), now=NOW)
        peers = {r["peer_key"] for r in _rows(store)}

    assert peers == {PEER2}


@pytest.mark.no_model
def test_the_latest_assessment_survives_a_clock_step(tmp_path):
    """If the clock jumps forward, every row looks old. The rows behind the
    most recent assessment must survive anyway: they are what the result an
    analyst is reading right now was computed from."""
    from cipherguard.intel.baseline import BaselineStore

    with BaselineStore(str(tmp_path / "b.db"), retain_per_peer=None, retain_days=30) as store:
        store.record(_assessment("earlier.pcap", _session(1, WEAK)), max_new_peers=0,
                     now=NOW - timedelta(minutes=5))
        store.record(_assessment("latest.pcap", _session(2, WEAK), _session(3, WEAK)),
                     max_new_peers=0, now=NOW)
        store.prune(now=NOW + timedelta(days=365))
        captures = [r["capture"] for r in _rows(store)]

    assert captures == ["latest.pcap", "latest.pcap"]


@pytest.mark.no_model
def test_retention_can_be_disabled(tmp_path):
    from cipherguard.intel.baseline import BaselineStore

    with BaselineStore(str(tmp_path / "b.db"), retain_per_peer=None, retain_days=None) as store:
        for i in range(10):
            store.record(_assessment(f"w{i}.pcap", _session(1, WEAK)),
                         now=NOW - timedelta(days=1000 - i))
        assert store.prune(now=NOW) == 0
        assert len(_rows(store)) == 10


@pytest.mark.no_model
def test_stores_from_before_retention_are_migrated(tmp_path):
    """An existing sensor's DB has no `best_observation_id`. Opening it must
    add the column and point it at the right row, or the first prune would be
    free to delete every baseline's evidence."""
    from cipherguard.intel.baseline import BaselineStore

    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, peer_key TEXT NOT NULL,
            observed_at TEXT NOT NULL, capture TEXT NOT NULL, ike_version TEXT,
            vendor_family TEXT, classical_bits INTEGER NOT NULL,
            quantum_bits INTEGER NOT NULL, dh_group INTEGER,
            transforms TEXT NOT NULL, score INTEGER NOT NULL);
        CREATE TABLE baselines (
            peer_key TEXT PRIMARY KEY, best_classical_bits INTEGER NOT NULL,
            best_quantum_bits INTEGER NOT NULL, best_transforms TEXT NOT NULL,
            best_seen_at TEXT NOT NULL, first_seen_at TEXT NOT NULL,
            observations INTEGER NOT NULL DEFAULT 1);
        INSERT INTO observations VALUES
            (1, 'p', '2026-01-01T00:00:00+00:00', 'a', 'IKEv2', '', 80, 0, 2, '[]', 10),
            (2, 'p', '2026-01-02T00:00:00+00:00', 'b', 'IKEv2', '', 128, 0, 19, '[]', 90),
            (3, 'p', '2026-01-03T00:00:00+00:00', 'c', 'IKEv2', '', 80, 0, 2, '[]', 10);
        INSERT INTO baselines VALUES
            ('p', 128, 0, '[]', '2026-01-02T00:00:00+00:00', '2026-01-01T00:00:00+00:00', 3);
    """)
    conn.commit()
    conn.close()

    with BaselineStore(path, retain_per_peer=1, retain_days=None) as store:
        assert store.conn.execute(
            "SELECT best_observation_id FROM baselines").fetchone()[0] == 2
        store.prune()
        assert [r["capture"] for r in _rows(store)] == ["b", "c"]


# ---------------------------------------------------------------------------
# Audit log rotation
# ---------------------------------------------------------------------------


def _read_all(log) -> list[dict]:
    """Every record across every generation, oldest first."""
    out = []
    for path in reversed(log.generations()):
        with open(path, encoding="utf-8") as fh:
            out.extend(json.loads(line) for line in fh)
    return out


@pytest.mark.no_model
def test_audit_log_rotates_by_size(tmp_path):
    from cipherguard.core.audit_log import AuditLog

    log = AuditLog(str(tmp_path / "audit.jsonl"), max_bytes=2048, backups=3)
    for i in range(200):
        log.denied(reason=f"r{i:04d}")

    gens = log.generations()
    assert gens == [log.path] + [f"{log.path}.{i}" for i in (1, 2, 3)]
    assert not os.path.exists(f"{log.path}.4")
    assert all(os.path.getsize(g) <= 2048 for g in gens)

    # what survives is a contiguous run ending at the newest record: rotation
    # discards whole old generations, never a line from the middle
    seq = [int(r["reason"][1:]) for r in _read_all(log)]
    assert seq == list(range(seq[0], 200))
    with open(log.path, encoding="utf-8") as fh:
        assert json.loads(fh.readlines()[-1])["reason"] == "r0199"


@pytest.mark.no_model
def test_the_latest_assessment_record_is_never_rotated_away(tmp_path):
    """Rotation happens before a write, so the record just written is always
    in the active file, even when writing it is what triggered rotation."""
    from cipherguard.core.audit_log import AuditLog

    log = AuditLog(str(tmp_path / "audit.jsonl"), max_bytes=600, backups=1)
    for i in range(50):
        log.export("cbom", f"capture-{i}.pcap", None)
        with open(log.path, encoding="utf-8") as fh:
            assert json.loads(fh.readlines()[-1])["capture"] == f"capture-{i}.pcap"


@pytest.mark.no_model
def test_an_oversized_record_is_written_whole(tmp_path):
    from cipherguard.core.audit_log import AuditLog, retention_ceiling

    log = AuditLog(str(tmp_path / "audit.jsonl"), max_bytes=100, backups=2)
    for i in range(5):
        log.denied(reason="x" * 150, detail=str(i))
    records = _read_all(log)
    assert [r["detail"] for r in records] == ["2", "3", "4"]
    total = sum(os.path.getsize(g) for g in log.generations())
    assert total <= retention_ceiling(100, 2, largest_record=os.path.getsize(log.path))


@pytest.mark.no_model
def test_rotation_can_be_disabled(tmp_path):
    from cipherguard.core.audit_log import AuditLog

    log = AuditLog(str(tmp_path / "audit.jsonl"), max_bytes=0)
    for i in range(100):
        log.denied(reason=f"r{i}")
    assert log.generations() == [log.path]
    assert len(_read_all(log)) == 100


_WRITER = """
import sys
sys.path.insert(0, {root!r})
from cipherguard.core.audit_log import AuditLog
log = AuditLog({path!r}, actor="w" + sys.argv[1], max_bytes=4096, backups=400)
for i in range({n}):
    log.denied(reason="seq", detail=sys.argv[1] + ":" + str(i))
"""


@pytest.mark.no_model
def test_concurrent_writers_neither_corrupt_nor_lose_a_line(tmp_path):
    """Several processes appending while rotation renames files underneath them.

    Without the inter-process lock, a writer can check the size, lose the CPU
    while another process rotates, and then append to a generation that is
    about to be discarded, or two appends can interleave partial lines. The
    generation count is set high enough that rotation discards nothing, so
    every line written must be found exactly once.
    """
    from cipherguard.core.audit_log import AuditLog

    path = str(tmp_path / "audit.jsonl")
    writers, per = 4, 150
    script = _WRITER.format(root=ROOT, path=path, n=per)
    procs = [subprocess.Popen([sys.executable, "-c", script, str(w)])
             for w in range(writers)]
    assert all(p.wait(timeout=120) == 0 for p in procs)

    log = AuditLog(path, max_bytes=4096, backups=400)
    assert len(log.generations()) > 5, "rotation never happened; test is vacuous"
    seen = [r["detail"] for r in _read_all(log)]    # raises on any torn line
    assert len(seen) == writers * per
    assert set(seen) == {f"{w}:{i}" for w in range(writers) for i in range(per)}


# ---------------------------------------------------------------------------
# Evidence retention
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_the_newest_window_survives_its_own_byte_ceiling(tmp_path):
    """Regression: a single window larger than --max-disk-mb deleted itself
    right after being assessed, so the latest finding had no evidence."""
    from cipherguard.cli import _prune_evidence

    for i in range(3):
        f = tmp_path / f"window-20260901T00000{i}.pcap"
        f.write_bytes(b"\x00" * 4096)
        os.utime(f, (1000 + i, 1000 + i))
    newest = tmp_path / "window-20260901T000009.pcap"
    newest.write_bytes(b"\x00" * (64 << 10))
    os.utime(newest, (2000, 2000))

    _prune_evidence(str(tmp_path), keep=24, max_bytes=16 << 10, protect=str(newest))
    assert [p.name for p in tmp_path.iterdir()] == [newest.name]

    _prune_evidence(str(tmp_path), keep=0, max_bytes=1, protect=str(newest))
    assert newest.exists()


# ---------------------------------------------------------------------------
# Healthcheck
# ---------------------------------------------------------------------------


def _deployment(tmp_path, model_dir: str) -> list[str]:
    """A healthy sensor layout and the healthcheck flags that describe it."""
    from cipherguard.core.health import write_sensor_state
    from cipherguard.intel.baseline import BaselineStore

    out = tmp_path / "captures"
    out.mkdir()
    db = tmp_path / "baseline.db"
    with BaselineStore(str(db)) as store:
        store.record(_assessment("w.pcap", _session(1, STRONG)))
    write_sensor_state(str(out), window=1, window_seconds=300)
    return ["--models", model_dir, "healthcheck", "--out", str(out), "--db", str(db),
            "--audit-log", str(tmp_path / "audit.jsonl"), "--max-disk-mb", "1",
            "--max-window-mb", "1", "--audit-max-mb", "1", "--json"]


def _healthcheck(argv, capsys) -> tuple[int, dict]:
    from cipherguard.cli import main

    code = main(argv)
    report = json.loads(capsys.readouterr().out)
    return code, {c["name"]: c for c in report["checks"]}


def test_healthcheck_passes_on_a_healthy_deployment(tmp_path, model_dir, capsys):
    code, checks = _healthcheck(_deployment(tmp_path, model_dir), capsys)
    assert code == 0, checks
    assert set(checks) == {"model", "baseline_db", "disk", "last_window"}


def test_healthcheck_fails_on_a_tampered_model(tmp_path, model_dir, capsys):
    staged = tmp_path / "models"
    shutil.copytree(model_dir, staged)
    blob = (staged / "cnn.npz").read_bytes()
    (staged / "cnn.npz").write_bytes(blob[:-1] + bytes([blob[-1] ^ 1]))

    argv = _deployment(tmp_path, str(staged))
    code, checks = _healthcheck(argv, capsys)
    assert code == 2
    assert checks["model"]["status"] == "failed"
    assert checks["baseline_db"]["status"] == "healthy"


@pytest.mark.no_model
def test_healthcheck_reports_a_missing_model_as_degraded(tmp_path):
    from cipherguard.core.health import DEGRADED, check_model

    assert check_model(str(tmp_path / "nothing")).status == DEGRADED


@pytest.mark.no_model
def test_healthcheck_fails_on_a_read_only_baseline(tmp_path):
    """A store that opens but cannot be written is the dangerous case: the
    sensor keeps running and downgrade detection quietly stops."""
    from cipherguard.core.health import FAILED, OK, check_baseline_db
    from cipherguard.intel.baseline import BaselineStore

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root ignores file permissions")
    db = tmp_path / "b.db"
    BaselineStore(str(db)).close()
    assert check_baseline_db(str(db)).status == OK
    os.chmod(db, stat.S_IREAD)
    try:
        result = check_baseline_db(str(db))
    finally:
        os.chmod(db, stat.S_IREAD | stat.S_IWRITE)
    assert result.status == FAILED, result.detail


@pytest.mark.no_model
def test_healthcheck_does_not_create_a_missing_store(tmp_path):
    from cipherguard.core.health import OK, check_baseline_db

    db = tmp_path / "later.db"
    assert check_baseline_db(str(db)).status == OK
    assert not db.exists()


@pytest.mark.no_model
def test_healthcheck_grades_the_age_of_the_last_window(tmp_path):
    from cipherguard.core.health import (
        DEGRADED, FAILED, OK, check_last_window, write_sensor_state,
    )

    assert check_last_window(str(tmp_path)).status == DEGRADED   # never ran

    write_sensor_state(str(tmp_path), window=7, window_seconds=300)
    assert not [n for n in os.listdir(tmp_path) if n.endswith(".tmp")]
    now = datetime.now(timezone.utc)
    stale = 2 * 300 + 120
    assert check_last_window(str(tmp_path), now=now).status == OK
    assert check_last_window(
        str(tmp_path), now=now + timedelta(seconds=stale + 5)).status == DEGRADED
    assert check_last_window(
        str(tmp_path), now=now + timedelta(seconds=3 * stale + 5)).status == FAILED
    assert check_last_window(
        str(tmp_path), now=now - timedelta(hours=1)).status == DEGRADED  # clock stepped


@pytest.mark.no_model
def test_healthcheck_compares_free_disk_with_the_retention_ceiling(tmp_path, monkeypatch):
    """Evidence ceiling plus one in-flight window plus every audit generation,
    less what is already used, has to fit in what is free."""
    from collections import namedtuple

    from cipherguard.core import health

    (tmp_path / "window-1.pcap").write_bytes(b"\x00" * (1 << 20))
    need = (100 << 20) + (10 << 20) - (1 << 20)            # evidence only
    usage = namedtuple("usage", "total used free")

    def disk(free):
        monkeypatch.setattr(health.shutil, "disk_usage", lambda _p: usage(0, 0, free))
        return health.check_disk(str(tmp_path), 100 << 20, 10 << 20, False,
                                 None, 0, 0).status

    assert disk(need - 1) == health.FAILED
    assert disk(need + 1) == health.DEGRADED
    assert disk(2 * need) == health.OK

    audit = health.check_disk(str(tmp_path), 100 << 20, 10 << 20, False,
                              str(tmp_path / "a.jsonl"), 0, 0)
    assert audit.status == health.DEGRADED and "unbounded" in audit.detail


# ---------------------------------------------------------------------------
# systemd unit
# ---------------------------------------------------------------------------


def _unit() -> dict[str, list[str]]:
    path = os.path.join(ROOT, "deploy", "cipherguard-sensor.service")
    with open(path, encoding="utf-8") as fh:
        text = fh.read().replace("\\\n", " ")
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "[")) and "=" in line:
            key, value = line.split("=", 1)
            out.setdefault(key, []).append(value.strip())
    return out


@pytest.mark.no_model
def test_systemd_unit_is_unprivileged_and_sandboxed():
    unit = _unit()
    assert unit["User"] == ["cipherguard"]
    caps = {"CAP_NET_RAW", "CAP_NET_ADMIN"}
    assert set(unit["AmbientCapabilities"][0].split()) == caps
    assert set(unit["CapabilityBoundingSet"][0].split()) == caps
    assert unit["NoNewPrivileges"] == ["yes"]
    assert unit["Restart"] == ["on-failure"]
    assert unit["ProtectSystem"] == ["strict"]


@pytest.mark.no_model
def test_systemd_unit_command_line_parses_and_writes_only_where_allowed():
    """ExecStart is checked against the real parser, so a renamed flag fails
    here rather than as a restart loop on a sensor, and every path the sensor
    writes must be inside ReadWritePaths or ProtectSystem=strict blocks it."""
    import shlex

    from cipherguard.cli import build_parser

    unit = _unit()
    argv = shlex.split(unit["ExecStart"][0].replace("${CG_INTERFACE}", "eth1"))[1:]
    args = build_parser().parse_args(argv)
    assert args.command == "sensor" and args.interface == "eth1"

    writable = unit["ReadWritePaths"][0].split()
    for path in (args.out, args.db, args.audit_log):
        assert any(path.startswith(w + "/") for w in writable), path


# ---------------------------------------------------------------------------
# Soak
# ---------------------------------------------------------------------------


def _soak(tmp_path, model_dir: str, *extra: str) -> tuple[int, dict, str]:
    report = tmp_path / "soak.json"
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "soak.py"),
         "--models", model_dir,
         "--captures", str(tmp_path / "generated"),   # absent: soak generates them
         "--workdir", str(tmp_path / "work"),
         "--json-out", str(report), *extra],
        capture_output=True, text=True, timeout=900,
    )
    output = proc.stdout + proc.stderr
    assert report.exists(), output
    return proc.returncode, json.loads(report.read_text()), output


@pytest.mark.soak
def test_sixty_second_soak_stays_within_every_bound(tmp_path, model_dir):
    """The sensor's per-window work, looped for a minute, in a fresh process.

    Short, but not vacuous: the retention settings are small enough that
    observation pruning, evidence pruning and log rotation all run many times,
    which is asserted below, so a regression in any of them shows up as a
    bound being exceeded rather than as a bound never being reached.
    """
    code, report, output = _soak(tmp_path, model_dir, "--duration", "60",
                                 "--retain-per-peer", "10")
    assert code == 0 and report["passed"], output
    assert report["elapsed_seconds"] >= 60
    ex = report["exercised"]
    assert ex["observation_rows_pruned"] > 0, "observation retention never engaged"
    assert ex["evidence_files_pruned"] > 0, "evidence retention never engaged"
    assert ex["audit_rotations"] > 0, "audit log never rotated"
    assert not report["violations"]


@pytest.mark.soak
def test_the_soak_detects_a_leak(tmp_path, model_dir):
    """A leak detector that has never been seen to detect a leak proves
    nothing. Leak 4 MB per window and the soak must fail on RSS, and only RSS."""
    code, report, output = _soak(tmp_path, model_dir, "--duration", "20",
                                 "--inject-leak-kb", "4096")
    assert code == 1, output
    failed = {name for name, c in report["checks"].items() if not c["ok"]}
    assert failed == {"rss_growth_mb"}, report["checks"]
