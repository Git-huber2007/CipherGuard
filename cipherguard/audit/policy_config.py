"""External policy overlay.

The crypto baseline in `policy.py` encodes NIST SP 800-77 Rev. 1 and RFC 8247.
A deploying agency will have its own directive, and it will differ — a national
standard may mandate a 3072-bit floor, forbid an algorithm NIST permits, or
require a shorter SA lifetime than the RFC suggests.

Requiring them to edit module source to express that is wrong for two reasons
that matter more than convenience. It forks the tool, so every upgrade becomes a
merge. And it destroys auditability: "which policy produced this finding" stops
being answerable from the report, because the policy is diffused through code
that has since changed.

So the baseline is overlayable from a JSON file, and the applied overlay is
recorded in the assessment. The overlay can only be applied through
`apply_overlay`, which validates keys against the known policy surface — a typo
in a policy file must fail loudly rather than silently leave a check disabled,
because a control that quietly stops running is worse than one that was never
configured.
"""

from __future__ import annotations

import json
from typing import Any

from . import policy as P

# Policy surface an overlay may address, with the type each expects.
OVERLAYABLE: dict[str, type] = {
    "ENCR_PROHIBITED": dict,
    "ENCR_LEGACY": dict,
    "INTEG_PROHIBITED": dict,
    "INTEG_LEGACY": dict,
    "PRF_PROHIBITED": dict,
    "PRF_LEGACY": dict,
    "DH_PROHIBITED": dict,
    "DH_LEGACY": dict,
    "WEAK_AUTH": dict,
    "MIN_KEY_BITS": int,
    "MIN_DH_BITS": int,
    "MAX_IKE_SA_LIFETIME": int,
    "MAX_CHILD_SA_LIFETIME": int,
    "DH_PQ_GROUPS": set,
}

# Keys whose maps are indexed by DH group number rather than by name. JSON
# object keys are always strings, so these need coercing back to int or every
# lookup silently misses and the rule never fires.
INT_KEYED = {"DH_PROHIBITED", "DH_LEGACY"}


class PolicyError(ValueError):
    """An overlay file is malformed or names something that does not exist."""


def _validate(overlay: dict[str, Any]) -> None:
    unknown = set(overlay) - set(OVERLAYABLE) - {"name", "reference", "description"}
    if unknown:
        raise PolicyError(
            "policy overlay names settings that do not exist: "
            + ", ".join(sorted(unknown))
            + ". Valid settings: "
            + ", ".join(sorted(OVERLAYABLE))
        )
    for key, value in overlay.items():
        if key in ("name", "reference", "description"):
            continue
        expected = OVERLAYABLE[key]
        if expected is int and not isinstance(value, int):
            raise PolicyError(f"{key} must be an integer, got {type(value).__name__}")
        if expected is dict and not isinstance(value, dict):
            raise PolicyError(f"{key} must be an object, got {type(value).__name__}")


def load(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            overlay = json.load(fh)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(overlay, dict):
        raise PolicyError(f"{path} must contain a JSON object at the top level")
    _validate(overlay)
    return overlay


def apply_overlay(overlay: dict[str, Any], replace: bool = False) -> dict[str, Any]:
    """Apply an overlay to the live policy module and return a provenance record.

    By default an overlay *extends* the baseline: an agency adding a prohibition
    keeps every NIST prohibition as well. `replace` swaps a table wholesale,
    which is occasionally what is wanted and is never what is wanted by
    accident, so it has to be asked for.
    """
    _validate(overlay)
    applied: dict[str, Any] = {}

    for key, value in overlay.items():
        if key in ("name", "reference", "description"):
            continue
        if OVERLAYABLE[key] is int:
            setattr(P, key, value)
            applied[key] = value
            continue

        if key in INT_KEYED:
            value = {int(k): v for k, v in value.items()}
        current = dict(getattr(P, key))
        if replace:
            current = dict(value)
        else:
            current.update(value)
        setattr(P, key, current)
        applied[key] = sorted(str(k) for k in value)

    return {
        "name": overlay.get("name", "unnamed overlay"),
        "reference": overlay.get("reference"),
        "mode": "replace" if replace else "extend",
        "applied": applied,
    }


def load_and_apply(path: str, replace: bool = False) -> dict[str, Any]:
    record = apply_overlay(load(path), replace=replace)
    record["source"] = path
    return record


EXAMPLE = {
    "name": "Example national directive",
    "reference": "AGENCY-CRYPTO-DIRECTIVE-2026 s4",
    "description": "Stricter than the NIST baseline: 3072-bit floor, no CBC.",
    "MIN_DH_BITS": 3072,
    "MAX_IKE_SA_LIFETIME": 28800,
    "MAX_CHILD_SA_LIFETIME": 14400,
    "DH_PROHIBITED": {
        "14": "2048-bit MODP is below the national 3072-bit floor",
        "23": "2048-bit MODP is below the national 3072-bit floor",
    },
    "ENCR_PROHIBITED": {
        "ENCR_AES_CBC": "CBC is not permitted; AEAD only under the directive",
    },
}
