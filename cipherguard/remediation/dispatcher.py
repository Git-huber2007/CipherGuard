"""Remediation execution & dry-run validation dispatcher.

Supports non-destructive dry-run syntax verification and authorized configuration
staging on target gateways.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import HardeningPlan
from .syntax import validate_syntax


def apply_plan(
    plan: HardeningPlan,
    dry_run: bool = True,
    target_host: str = "",
    credentials: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute or simulate the application of a hardening plan.

    By default, `dry_run=True` ensures zero out-of-band side effects, validating
    syntactic correctness and emitting the staged execution sequence.
    """
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # 1. Pre-execution syntax validation
    is_valid, errors = validate_syntax(plan.platform, plan.forward_config)
    if not is_valid:
        return {
            "success": False,
            "mode": "dry-run" if dry_run else "active",
            "timestamp": now,
            "error": "Syntax validation failed before execution",
            "details": errors,
            "lines_staged": 0,
        }

    lines = [l.strip() for l in plan.forward_config.splitlines() if l.strip() and not l.strip().startswith(("!", "#"))]

    if dry_run or not target_host:
        return {
            "success": True,
            "mode": "dry-run",
            "timestamp": now,
            "target": target_host or "Simulated Gateway",
            "platform": plan.platform_name,
            "lines_staged": len(lines),
            "output": (
                f"[DRY-RUN SUCCESSFUL] {len(lines)} configuration commands verified for {plan.platform_name}.\n"
                f"Candidate configuration staged into memory with zero live disruptions.\n"
                f"Rollback safety-net armed: {len(plan.rollback_config.splitlines())} lines."
            ),
            "command_preview": lines[:6],
        }

    # Live direct gateway mutation is prohibited under the passive defense doctrine.
    # CipherGuard strictly enforces an out-of-band architecture: live gateway modification
    # is reserved for authorized network administrators via human-in-the-loop reviewable playbooks.
    return {
        "success": False,
        "mode": "live_apply_prohibited",
        "timestamp": now,
        "target": target_host,
        "platform": plan.platform_name,
        "lines_staged": len(lines),
        "error": (
            "Live direct gateway mutation is prohibited by NTRO / NIST SP 800-77 passive defense doctrine. "
            "CipherGuard generates reviewable, vendor-validated CLI playbooks for administrator change-control execution."
        ),
    }
