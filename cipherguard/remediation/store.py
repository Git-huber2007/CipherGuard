"""Persistent SQLite storage for Hardening Plans and maker-checker approval audit logs."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .models import HardeningPlan

SCHEMA = """
CREATE TABLE IF NOT EXISTS hardening_plans (
    plan_id TEXT PRIMARY KEY,
    capture TEXT NOT NULL,
    platform TEXT NOT NULL,
    platform_name TEXT NOT NULL,
    forward_config TEXT NOT NULL,
    rollback_config TEXT NOT NULL,
    syntax_valid INTEGER NOT NULL,
    syntax_errors TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    status TEXT NOT NULL,
    approver TEXT NOT NULL,
    approval_comment TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plan_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    actor TEXT NOT NULL,
    comment TEXT NOT NULL,
    timestamp TEXT NOT NULL
);
"""


class PlanStore:
    """Thread-safe SQLite store for remediation plans and maker-checker audit trails."""

    def __init__(self, db_path: str = "cipherguard-plans.db"):
        self.db_path = db_path
        self._shared = sqlite3.connect(":memory:", check_same_thread=False) if db_path == ":memory:" else None
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if self._shared is not None:
            self._shared.row_factory = sqlite3.Row
            return self._shared
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    def save_plan(self, plan: HardeningPlan) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO hardening_plans (
                    plan_id, capture, platform, platform_name, forward_config,
                    rollback_config, syntax_valid, syntax_errors, findings_json,
                    status, approver, approval_comment, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan.plan_id,
                    plan.capture,
                    plan.platform,
                    plan.platform_name,
                    plan.forward_config,
                    plan.rollback_config,
                    1 if plan.syntax_valid else 0,
                    json.dumps(plan.syntax_errors),
                    json.dumps(plan.findings_addressed),
                    plan.status,
                    plan.approver,
                    plan.approval_comment,
                    plan.created_at,
                    plan.updated_at,
                ),
            )

    def get_plan(self, plan_id: str) -> HardeningPlan | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM hardening_plans WHERE plan_id = ?", (plan_id,)).fetchone()
            if not row:
                return None
            return self._row_to_plan(row)

    def list_plans(self, capture: str | None = None) -> list[HardeningPlan]:
        with self._conn() as conn:
            if capture:
                rows = conn.execute(
                    "SELECT * FROM hardening_plans WHERE capture = ? ORDER BY created_at DESC",
                    (capture,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM hardening_plans ORDER BY created_at DESC").fetchall()
            return [self._row_to_plan(r) for r in rows]

    def update_status(
        self,
        plan_id: str,
        new_status: str,
        actor: str = "Admin",
        comment: str = "",
    ) -> HardeningPlan | None:
        plan = self.get_plan(plan_id)
        if not plan:
            return None

        old_status = plan.status
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        plan.status = new_status
        # Only an approval names an approver. Every transition is still in
        # plan_transitions with its own actor; overwriting these two fields on
        # each one replaced the person who signed the plan off with whatever
        # staged it afterwards.
        if new_status == "APPROVED":
            plan.approver = actor
            plan.approval_comment = comment
        plan.updated_at = now

        with self._conn() as conn:
            conn.execute(
                """
                UPDATE hardening_plans SET
                    status = ?, approver = ?, approval_comment = ?, updated_at = ?
                WHERE plan_id = ?
                """,
                (new_status, plan.approver, plan.approval_comment, now, plan_id),
            )
            conn.execute(
                """
                INSERT INTO plan_transitions (plan_id, from_state, to_state, actor, comment, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (plan_id, old_status, new_status, actor, comment, now),
            )
        return plan

    def get_transitions(self, plan_id: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM plan_transitions WHERE plan_id = ? ORDER BY id ASC",
                (plan_id,),
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["to_status"] = d["to_state"]
                d["from_status"] = d["from_state"]
                out.append(d)
            return out

    def history(self, plan_id: str) -> list[dict[str, Any]]:
        return self.get_transitions(plan_id)

    def _row_to_plan(self, row: sqlite3.Row) -> HardeningPlan:
        return HardeningPlan(
            plan_id=row["plan_id"],
            capture=row["capture"],
            platform=row["platform"],
            platform_name=row["platform_name"],
            forward_config=row["forward_config"],
            rollback_config=row["rollback_config"],
            syntax_valid=bool(row["syntax_valid"]),
            syntax_errors=json.loads(row["syntax_errors"]),
            findings_addressed=json.loads(row["findings_json"]),
            status=row["status"],
            approver=row["approver"],
            approval_comment=row["approval_comment"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
