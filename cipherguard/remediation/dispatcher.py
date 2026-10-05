"""Dry-run check of a hardening plan.

A dry run syntax-checks the plan and reports how many configuration lines it
holds. Nothing is ever sent to a gateway: there is no code path that connects
to one, and a request to apply a plan for real is refused.
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
    """Syntax-check `plan` and report what applying it would involve.

    `dry_run=False` with a target is refused. `credentials` is accepted for
    interface compatibility and never read.
    """
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # 1. Pre-execution syntax validation
    is_valid, errors = validate_syntax(plan.platform, plan.forward_config)
    if not is_valid:
        return {
            "success": False,
            "mode": "dry-run" if dry_run else "active",
            "timestamp": now,
            "error": "The plan failed its syntax check",
            "details": errors,
            "lines_staged": 0,
        }

    lines = [l.strip() for l in plan.forward_config.splitlines() if l.strip() and not l.strip().startswith(("!", "#"))]

    if dry_run or not target_host:
        return {
            "success": True,
            "mode": "dry-run",
            "timestamp": now,
            "target": target_host or None,
            "platform": plan.platform_name,
            "lines_staged": len(lines),
            "output": (
                f"Dry run: {len(lines)} configuration lines for {plan.platform_name} passed the syntax check.\n"
                f"Nothing was sent to a gateway.\n"
                f"The rollback plan has {len(plan.rollback_config.splitlines())} lines."
            ),
            "command_preview": lines[:6],
        }

    # The tool is passive by design: it has no code that connects to a gateway.
    # Applying a plan is an administrator's change, made under change control.
    return {
        "success": False,
        "mode": "live_apply_prohibited",
        "timestamp": now,
        "target": target_host,
        "platform": plan.platform_name,
        "lines_staged": len(lines),
        "error": (
            "CipherGuard does not apply configuration to gateways. Review the plan and "
            "apply it through your own change-control process."
        ),
    }
