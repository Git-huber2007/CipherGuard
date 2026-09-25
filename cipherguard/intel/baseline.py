"""Temporal baseline: continuous assurance rather than point-in-time scanning.

The literature splits into two camps, and both miss the same thing. Static
configuration verification proves a policy correct on paper but never sees the
wire. Encrypted-traffic classification reads flow statistics but ignores what
was negotiated. Neither observes a peer pair *over time*, so neither can detect
the failure that matters most operationally:

    a link that used to negotiate AES-256 / Group 19 and now negotiates
    3DES / Group 2 with the same peer.

That is the signature of downgrade injection, of a botched firmware rollback, or
of a failover onto a legacy standby gateway. Every one of those is invisible to
a single capture, because a single capture has nothing to compare against — the
weak suite looks like it was always the policy. It is equally invisible to
configuration review, which sees the intended config rather than what the peers
actually settled on.

The store is deliberately small and boring: SQLite, one row per peer pair per
observation, with the best strength ever seen retained as the baseline. No
payload, no addresses beyond the peer pair already present in the capture.

Observation history is bounded. A sensor writes one row per session per window
for as long as it runs, so without retention the table is unbounded growth on
the sensor's own disk, the same failure `_prune_evidence` exists to prevent for
captures. The baseline itself is a single row per peer and is never pruned; only
the history behind it is.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ..core.models import Assessment, IkeSession
from ..core.strength import score_proposal

DEFAULT_DB = "cipherguard-baseline.db"

# At 300-second windows 500 observations is about 42 hours of history per link;
# at the 60-second CLI default, about 8 hours. The age ceiling is what bounds a
# peer that is seen rarely, and a spoofed peer key that is seen once.
DEFAULT_RETAIN_PER_PEER = 500
DEFAULT_RETAIN_DAYS = 90

# The detector's conclusion for each observation, stored as it is reached so a
# replay shows what was actually decided rather than a reconstruction of it. A
# reconstruction would drift from the truth as soon as retention pruned the
# rows the promotion rule had counted.
VERDICTS = {
    "new": "first confirmed sighting; established the baseline",
    "withheld": "new peer beyond the per-capture limit; no baseline created",
    "steady": "matched the baseline",
    "downgrade": "weaker than the baseline",
    "unconfirmed": "stronger than the baseline, not yet seen often enough to promote",
    "improvement": "stronger than the baseline, seen repeatedly; promoted",
}

# Columns added after a store may already exist, with their SQL types.
_ADDED_COLUMNS = {
    "baselines": {"best_observation_id": "INTEGER"},
    "observations": {"verdict": "TEXT", "baseline_bits": "INTEGER",
                     "baseline_transforms": "TEXT"},
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_key        TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    capture         TEXT NOT NULL,
    ike_version     TEXT,
    vendor_family   TEXT,
    classical_bits  INTEGER NOT NULL,
    quantum_bits    INTEGER NOT NULL,
    dh_group        INTEGER,
    transforms      TEXT NOT NULL,
    score           INTEGER NOT NULL,
    -- what record() concluded when it compared this observation with the
    -- baseline in effect at the time; see VERDICTS
    verdict             TEXT,
    baseline_bits       INTEGER,
    baseline_transforms TEXT
);
CREATE INDEX IF NOT EXISTS idx_peer ON observations(peer_key, observed_at);

CREATE TABLE IF NOT EXISTS baselines (
    peer_key            TEXT PRIMARY KEY,
    best_classical_bits INTEGER NOT NULL,
    best_quantum_bits   INTEGER NOT NULL,
    best_transforms     TEXT NOT NULL,
    best_seen_at        TEXT NOT NULL,
    first_seen_at       TEXT NOT NULL,
    observations        INTEGER NOT NULL DEFAULT 1,
    best_observation_id INTEGER
);
"""


@dataclass
class Drift:
    peer_key: str
    kind: str            # "downgrade" | "improvement" | "new"
    previous_bits: int
    current_bits: int
    previous_transforms: list[str]
    current_transforms: list[str]
    baseline_seen_at: str

    @property
    def delta(self) -> int:
        return self.current_bits - self.previous_bits

    def to_dict(self) -> dict:
        return {
            "peer_key": self.peer_key,
            "kind": self.kind,
            "previous_bits": self.previous_bits,
            "current_bits": self.current_bits,
            "delta": self.delta,
            "previous_transforms": self.previous_transforms,
            "current_transforms": self.current_transforms,
            "baseline_seen_at": self.baseline_seen_at,
        }


def peer_key(sess: IkeSession) -> str:
    """Direction-independent identity for a gateway pair.

    Sorted so that an initiator/responder role swap on re-negotiation does not
    read as a different link and silently reset its baseline.
    """
    return "|".join(sorted([sess.peer_a, sess.peer_b]))


class BaselineStore:
    def __init__(
        self,
        path: str = DEFAULT_DB,
        retain_per_peer: int | None = DEFAULT_RETAIN_PER_PEER,
        retain_days: float | None = DEFAULT_RETAIN_DAYS,
    ):
        """`retain_per_peer` and `retain_days` bound observation history; either
        may be None to disable that ceiling, and `record()` applies them after
        every write. A per-peer count below 1 is raised to 1, because the most
        recent observation of a baselined peer is what the fleet view reports
        as its current state."""
        self.path = path
        self.retain_per_peer = max(retain_per_peer, 1) if retain_per_peer else None
        self.retain_days = retain_days
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns to stores created before they existed.

        `best_observation_id` is backfilled: matching on the timestamp and
        strength the baseline recorded identifies the establishing row, because
        both were written from the same `now` in the same transaction. Verdicts
        are not backfilled. They cannot be recovered exactly once rows have been
        pruned, so older observations honestly carry none.
        """
        added = set()
        for table, columns in _ADDED_COLUMNS.items():
            have = {r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")}
            for name, sql_type in columns.items():
                if name not in have:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")
                    added.add(name)
        if "best_observation_id" not in added:
            return
        self.conn.execute(
            """
            UPDATE baselines SET best_observation_id = (
                SELECT o.id FROM observations o
                WHERE o.peer_key = baselines.peer_key
                  AND o.observed_at = baselines.best_seen_at
                  AND o.classical_bits = baselines.best_classical_bits
                ORDER BY o.id LIMIT 1
            )
            """
        )

    @classmethod
    def open_readonly(cls, path: str) -> "BaselineStore":
        """Open an existing store so that nothing can be written through it.

        The normal constructor is not a read: it creates parent directories,
        runs the schema script and migrates old stores with ALTER TABLE. The
        dashboard's endpoints only read, so they open the file with SQLite's
        `mode=ro`, which also refuses to create a missing file, and any write
        attempted through this handle raises instead of landing.
        """
        from pathlib import Path

        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        store = cls.__new__(cls)
        store.path = path
        store.retain_per_peer = None
        store.retain_days = None
        # as_uri() percent-encodes, so a path containing '?' or '#' cannot
        # smuggle in URI parameters that override mode=ro
        uri = Path(path).resolve().as_uri() + "?mode=ro"
        store.conn = sqlite3.connect(uri, uri=True)
        store.conn.row_factory = sqlite3.Row
        return store

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "BaselineStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- recording ---------------------------------------------------------

    def record(
        self,
        assessment: Assessment,
        min_observations: int = 2,
        max_new_peers: int = 64,
        now: datetime | None = None,
    ) -> list[Drift]:
        """Record every session and return the drift detected against baseline.

        Three constraints, all of them because this store is written from
        attacker-reachable traffic and its output gates a CI exit code:

        `confirmed_only` — only proposals a responder actually agreed to are
        recorded. An unanswered IKE_SA_INIT proves somebody sent a packet, and
        anyone on a mirrored segment can send one. Without this, a single
        spoofed datagram permanently sets a peer pair's baseline: set it high
        and a real downgrade never fires, set it low across many pairs and the
        resulting alert flood trains operators to ignore exit code 3.

        `min_observations` — a baseline is promoted only after the same or
        better strength has been seen more than once, so one anomalous exchange
        cannot define the reference point.

        `max_new_peers` — a cap on how many previously unseen peer pairs one
        capture may introduce, since peer keys are derived from IP addresses
        and spoofing them is free.

        `now` exists so tests can record observations in the past; the sensor
        always leaves it unset.
        """
        at = now or datetime.now(timezone.utc)
        stamp = at.isoformat(timespec="seconds")
        drifts: list[Drift] = []
        new_peers = 0

        for sess in assessment.sessions:
            prop = sess.negotiated("IKE", confirmed_only=True)
            if not prop:
                # An offer that was never agreed to, or a failed negotiation.
                # Recording it as fact would be wrong in both cases.
                continue
            strength = score_proposal(prop.transforms)
            transforms = sorted(t.label() for t in prop.transforms)
            key = peer_key(sess)
            dh = next((t.value_id for t in prop.by_type(4)), None)

            obs_id = self.conn.execute(
                "INSERT INTO observations (peer_key, observed_at, capture, "
                "ike_version, vendor_family, classical_bits, quantum_bits, "
                "dh_group, transforms, score) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (key, stamp, assessment.capture, sess.version, sess.vendor_family(),
                 strength.classical_bits, strength.quantum_bits, dh,
                 json.dumps(transforms), assessment.score()),
            ).lastrowid

            row = self.conn.execute(
                "SELECT * FROM baselines WHERE peer_key = ?", (key,)
            ).fetchone()

            def mark(verdict: str, against: sqlite3.Row | None = None) -> None:
                self.conn.execute(
                    "UPDATE observations SET verdict = ?, baseline_bits = ?, "
                    "baseline_transforms = ? WHERE id = ?",
                    (verdict,
                     against["best_classical_bits"] if against else None,
                     against["best_transforms"] if against else None,
                     obs_id),
                )

            if row is None:
                new_peers += 1
                if new_peers > max_new_peers:
                    # Beyond this, the capture is introducing peers faster than
                    # any real deployment changes, which is what address
                    # spoofing looks like. Observations are still recorded; only
                    # baseline creation is withheld.
                    mark("withheld")
                    continue
                mark("new")
                self.conn.execute(
                    "INSERT INTO baselines (peer_key, best_classical_bits, "
                    "best_quantum_bits, best_transforms, best_seen_at, first_seen_at, "
                    "best_observation_id) VALUES (?,?,?,?,?,?,?)",
                    (key, strength.classical_bits, strength.quantum_bits,
                     json.dumps(transforms), stamp, stamp, obs_id),
                )
                drifts.append(
                    Drift(key, "new", strength.classical_bits, strength.classical_bits,
                          transforms, transforms, stamp)
                )
                continue

            self.conn.execute(
                "UPDATE baselines SET observations = observations + 1 WHERE peer_key = ?",
                (key,),
            )
            best = row["best_classical_bits"]
            previous = json.loads(row["best_transforms"])

            if strength.classical_bits == best:
                mark("steady", row)
            elif strength.classical_bits < best:
                mark("downgrade", row)
                drifts.append(
                    Drift(key, "downgrade", best, strength.classical_bits,
                          previous, transforms, row["best_seen_at"])
                )
            else:
                # Promote only once the stronger suite has been seen enough
                # times to be a configuration rather than an anomaly.
                seen_at_least = self.conn.execute(
                    "SELECT COUNT(*) FROM observations WHERE peer_key = ? "
                    "AND classical_bits >= ?",
                    (key, strength.classical_bits),
                ).fetchone()[0]
                if seen_at_least < min_observations:
                    mark("unconfirmed", row)
                    continue
                mark("improvement", row)
                drifts.append(
                    Drift(key, "improvement", best, strength.classical_bits,
                          previous, transforms, row["best_seen_at"])
                )
                self.conn.execute(
                    "UPDATE baselines SET best_classical_bits = ?, best_quantum_bits = ?, "
                    "best_transforms = ?, best_seen_at = ?, best_observation_id = ? "
                    "WHERE peer_key = ?",
                    (strength.classical_bits, strength.quantum_bits,
                     json.dumps(transforms), stamp, obs_id, key),
                )

        self.conn.commit()
        if self.retain_per_peer or self.retain_days:
            self.prune(now=at)
        return drifts

    # -- retention ---------------------------------------------------------

    def prune(self, now: datetime | None = None) -> int:
        """Drop observation history beyond the retention ceilings.

        A row goes if it is outside its peer's most recent `retain_per_peer`
        observations, or older than `retain_days`. Three kinds of row are kept
        whatever their age or rank:

        - the row that established a peer's current baseline, so the evidence
          behind every "was N bits" in a downgrade alert still exists;
        - the most recent row of every baselined peer, which `fleet()` reports
          as the link's current state. A link that has gone quiet for longer
          than the age ceiling must stay in the triage queue, not vanish from it;
        - every row written by the most recent assessment, even if the clock
          has been stepped backwards, since those rows are what the latest
          result an analyst is looking at was computed from.

        Peers that never earned a baseline (withheld by `max_new_peers`) get no
        such protection, so a spoofed peer key ages out entirely.

        Promotion counts prior observations (`min_observations`), so a
        retention window shorter than the gap between repeat sightings delays
        promotion. The defaults are far above `min_observations`.

        Returns the number of rows removed. SQLite reuses the freed pages, so
        the file stops growing rather than shrinking.
        """
        if not (self.retain_per_peer or self.retain_days):
            return 0
        at = now or datetime.now(timezone.utc)
        cutoff = (
            (at - timedelta(days=self.retain_days)).isoformat(timespec="seconds")
            if self.retain_days else None
        )
        cur = self.conn.execute(
            """
            WITH ranked AS (
                SELECT id, peer_key, observed_at,
                       ROW_NUMBER() OVER (
                           PARTITION BY peer_key ORDER BY observed_at DESC, id DESC
                       ) AS rn
                FROM observations
            ),
            latest AS (
                SELECT observed_at, capture FROM observations ORDER BY id DESC LIMIT 1
            )
            DELETE FROM observations WHERE id IN (
                SELECT r.id FROM ranked r
                WHERE ((:keep IS NOT NULL AND r.rn > :keep)
                       OR (:cutoff IS NOT NULL AND r.observed_at < :cutoff))
                  AND r.id NOT IN (
                      SELECT best_observation_id FROM baselines
                      WHERE best_observation_id IS NOT NULL)
                  AND NOT (r.rn = 1 AND r.peer_key IN (SELECT peer_key FROM baselines))
                  AND r.id NOT IN (
                      SELECT o.id FROM observations o, latest l
                      WHERE o.observed_at = l.observed_at AND o.capture = l.capture)
            )
            """,
            {"keep": self.retain_per_peer, "cutoff": cutoff},
        )
        self.conn.commit()
        return cur.rowcount

    # -- querying ----------------------------------------------------------

    def history(self, key: str, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT observed_at, capture, classical_bits, quantum_bits, dh_group, "
            "transforms FROM observations WHERE peer_key = ? "
            "ORDER BY observed_at DESC, id DESC LIMIT ?",
            (key, limit),
        ).fetchall()
        return [
            {**dict(r), "transforms": json.loads(r["transforms"])} for r in rows
        ]

    def has_link(self, key: str) -> bool:
        """Whether `key` is a link with a baseline, i.e. one the fleet shows."""
        return self.conn.execute(
            "SELECT 1 FROM baselines WHERE peer_key = ?", (key,)).fetchone() is not None

    def replay(self, key: str, limit: int = 1000) -> dict:
        """A link's recorded history, oldest first, with the detector's verdicts.

        Only links with a baseline can be replayed: peers withheld by the new-
        peer limit are what spoofed addresses look like, and exposing their rows
        would let anyone who can put packets on the segment put content on the
        dashboard. Raises KeyError for any other key.

        Reads only. Works on a store opened with `open_readonly()`, including
        one created before verdicts were recorded, where they read as None.
        """
        if not self.has_link(key):
            raise KeyError(key)
        have = {r["name"] for r in self.conn.execute("PRAGMA table_info(observations)")}
        extra = ", ".join(c if c in have else f"NULL AS {c}"
                          for c in ("verdict", "baseline_bits", "baseline_transforms"))
        rows = self.conn.execute(
            "SELECT * FROM (SELECT id, observed_at, capture, classical_bits, quantum_bits, "
            f"dh_group, transforms, ike_version, {extra} FROM observations "
            "WHERE peer_key = ? ORDER BY observed_at DESC, id DESC LIMIT ?) "
            "ORDER BY observed_at ASC, id ASC",
            (key, limit + 1),
        ).fetchall()
        truncated = len(rows) > limit
        rows = rows[-limit:] if truncated else rows

        observations = []
        for r in rows:
            d = dict(r)
            d["transforms"] = json.loads(d["transforms"])
            bt = d.pop("baseline_transforms")
            d["baseline_transforms"] = json.loads(bt) if bt else None
            d["delta_bits"] = (d["classical_bits"] - d["baseline_bits"]
                               if d["baseline_bits"] is not None else None)
            observations.append(d)

        b = self.conn.execute("SELECT * FROM baselines WHERE peer_key = ?", (key,)).fetchone()
        return {
            "peer_key": key,
            "baseline": {
                "classical_bits": b["best_classical_bits"],
                "quantum_bits": b["best_quantum_bits"],
                "transforms": json.loads(b["best_transforms"]),
                "established_at": b["best_seen_at"],
                "first_seen_at": b["first_seen_at"],
                "observations_total": b["observations"],
            },
            "observations": observations,
            "truncated": truncated,
            "verdicts": VERDICTS,
        }

    def fleet(self) -> list[dict]:
        """One row per link, weakest current state first — the triage queue."""
        rows = self.conn.execute(
            """
            SELECT b.peer_key, b.best_classical_bits, b.best_quantum_bits,
                   b.first_seen_at, b.observations,
                   o.classical_bits AS current_bits, o.quantum_bits AS current_quantum,
                   o.observed_at AS last_seen, o.transforms AS current_transforms,
                   o.vendor_family, o.ike_version
            FROM baselines b
            JOIN observations o ON o.id = (
                SELECT id FROM observations WHERE peer_key = b.peer_key
                ORDER BY observed_at DESC, id DESC LIMIT 1
            )
            ORDER BY o.classical_bits ASC, b.peer_key ASC
            """
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["current_transforms"] = json.loads(d["current_transforms"])
            d["degraded"] = d["current_bits"] < d["best_classical_bits"]
            out.append(d)
        return out

    def summary(self) -> dict:
        fleet = self.fleet()
        if not fleet:
            return {"links": 0}
        quantum_safe = sum(1 for f in fleet if f["current_quantum"] >= 128)
        return {
            "links": len(fleet),
            "observations": sum(f["observations"] for f in fleet),
            "degraded": sum(1 for f in fleet if f["degraded"]),
            "below_112_bits": sum(1 for f in fleet if f["current_bits"] < 112),
            "quantum_safe": quantum_safe,
            "quantum_exposed": len(fleet) - quantum_safe,
            "weakest_bits": min(f["current_bits"] for f in fleet),
        }
