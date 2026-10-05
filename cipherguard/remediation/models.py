"""Data models for Automated Remediation & Hardening Playbooks."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class HardeningPlan:
    plan_id: str = field(default_factory=lambda: f"cg-plan-{uuid.uuid4().hex[:8]}")
    capture: str = ""
    platform: str = "cisco"
    platform_name: str = "Cisco IOS / IOS-XE"
    forward_config: str = ""
    rollback_config: str = ""
    syntax_valid: bool = True
    syntax_errors: list[str] = field(default_factory=list)
    findings_addressed: list[dict[str, Any]] = field(default_factory=list)
    status: str = "PENDING_REVIEW"
    approver: str = ""
    approval_comment: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # The approver is a name someone typed. Nothing authenticated it, and
        # every client that shows it has to be able to say so.
        d["approver_identity"] = "self-declared" if self.approver else None
        return d
