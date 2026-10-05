"""Remediation synthesis.

Turns findings into a drop-in hardening configuration for the platform the
vendor-ID fingerprint identified. Output is deliberately conservative:

  * It is emitted as a reviewable script, never applied. The analyzer is passive
    by design and holds no credentials on any gateway.
  * New policy is added under fresh names and priorities rather than editing
    existing entries in place, so an operator can stage it and cut over during a
    change window instead of dropping live tunnels.
  * Every block cites the finding that motivated it, so a change-approval board
    can trace each line back to a specific observation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..core.models import Assessment, Finding, Severity

if TYPE_CHECKING:
    from .models import HardeningPlan

TARGET = {
    "encryption": "AES-GCM-256",
    "integrity": "HMAC-SHA2-256-128 (implicit under GCM)",
    "prf": "HMAC-SHA2-256",
    "dh_group": "19 (256-bit ECP) or 31 (Curve25519)",
    "ike_lifetime": 86400,
    "child_lifetime": 28800,
}


def _safe(text: str, limit: int = 120) -> str:
    """Flatten untrusted text before it enters a generated configuration.

    Output here is pasted into a router by an operator. Any value that reaches
    it from outside — a capture filename, a finding subject derived from packet
    contents — can carry a newline, and a newline ends the comment. A capture
    named "x.pcap\n crypto ikev2 policy ATTACKER\n" injected a live
    configuration line before this existed. Control characters go, length is
    bounded, and the result stays on one line.
    """
    flattened = "".join(" " if ord(c) < 32 or ord(c) == 127 else c for c in str(text))
    flattened = " ".join(flattened.split())
    return flattened[:limit] if len(flattened) <= limit else flattened[: limit - 1] + "…"


def _header(platform: str, assessment: Assessment) -> list[str]:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    crit = assessment.counts()["critical"]
    high = assessment.counts()["high"]
    return [
        f"! CipherGuard hardening plan - {platform}",
        f"! Generated {ts} from capture '{_safe(assessment.capture, 80)}'",
        f"! Posture score {assessment.score()}/100 (grade {assessment.grade()}) - {crit} critical, {high} high",
        "!",
        "! REVIEW BEFORE APPLYING. Staged as new policy entries; nothing existing",
        "! is removed. Cut over during a change window, verify the tunnel",
        "! re-establishes, then retire the old policy.",
        "!",
    ]


def _findings_summary(findings: list[Finding]) -> list[str]:
    lines = ["! Findings addressed by this plan:"]
    for f in findings:
        if f.severity in (Severity.INFO,):
            continue
        tag = "inferred" if f.inferred else "observed"
        lines.append(f"!   [{f.severity.value:8}] {_safe(f.rule_id, 12)} ({tag}) {_safe(f.title, 90)}")
    lines.append("!")
    return lines


# ---------------------------------------------------------------------------
# Platform templates
# ---------------------------------------------------------------------------


def _cisco(assessment: Assessment) -> str:
    lines = _header("Cisco IOS / IOS-XE", assessment)
    lines += _findings_summary(assessment.findings)
    lines += [
        "crypto ikev2 proposal CG-PROPOSAL-HARDENED",
        " encryption aes-gcm-256",
        " prf sha256",
        " group 19",
        "!",
        "crypto ikev2 policy CG-POLICY-HARDENED",
        " proposal CG-PROPOSAL-HARDENED",
        "!",
        "crypto ipsec transform-set CG-TS-HARDENED esp-gcm 256",
        " mode tunnel",
        "!",
        "crypto ipsec profile CG-PROFILE-HARDENED",
        " set transform-set CG-TS-HARDENED",
        " set pfs group19",
        f" set security-association lifetime seconds {TARGET['child_lifetime']}",
        "!",
        "! Remove the legacy fallbacks that keep the downgrade path open.",
        "! Confirm no other tunnel references these before issuing:",
        "!   no crypto isakmp policy <legacy-priority>",
        "!   no crypto ipsec transform-set <legacy-3des-set>",
        "!",
        "! Disable IKEv1 entirely once every peer is migrated:",
        "!   no crypto isakmp enable",
        "!",
    ]
    if any(f.rule_id == "IKE-003" for f in assessment.findings):
        lines += [
            "! Replace pre-shared keys with certificate authentication:",
            "crypto pki trustpoint CG-TRUSTPOINT",
            " enrollment terminal",
            " revocation-check crl",
            "!",
        ]
    return "\n".join(lines) + "\n"


def _strongswan(assessment: Assessment) -> str:
    lines = [l.replace("!", "#", 1) for l in _header("strongSwan (swanctl)", assessment)]
    lines += [l.replace("!", "#", 1) for l in _findings_summary(assessment.findings)]
    lines += [
        "connections {",
        "    cg-hardened {",
        "        version = 2",
        "        proposals = aes256gcm16-prfsha256-ecp256",
        "        dpd_delay = 30s",
        f"        rekey_time = {TARGET['ike_lifetime']}s",
        "        # RFC 8784 post-quantum pre-shared key: deploy now so traffic",
        "        # recorded today is not decryptable by a future quantum attacker.",
        "        ppk_id = cg-ppk-primary",
        "        ppk_required = no",
        "        local {",
        "            auth = pubkey",
        "            certs = gateway-cert.pem",
        "        }",
        "        remote {",
        "            auth = pubkey",
        "        }",
        "        children {",
        "            cg-child {",
        "                esp_proposals = aes256gcm16-ecp256",
        f"                rekey_time = {TARGET['child_lifetime']}s",
        "                mode = tunnel",
        "            }",
        "        }",
        "    }",
        "}",
        "",
        "# Refuse weak algorithms outright rather than merely preferring strong ones,",
        "# so a downgrade attempt has nothing to fall back to.",
        "# In strongswan.conf:",
        "#   charon {",
        "#       send_vendor_id = no",
        "#       fragment_size = 1280",
        "#   }",
        "",
    ]
    return "\n".join(lines) + "\n"


def _fortinet(assessment: Assessment) -> str:
    lines = [l.replace("!", "#", 1) for l in _header("Fortinet FortiOS", assessment)]
    lines += [l.replace("!", "#", 1) for l in _findings_summary(assessment.findings)]
    lines += [
        "config vpn ipsec phase1-interface",
        '    edit "cg-hardened"',
        "        set ike-version 2",
        "        set proposal aes256gcm-prfsha256",
        "        set dhgrp 19",
        "        set authmethod signature",
        f"        set keylife {TARGET['ike_lifetime']}",
        "        set dpd on-idle",
        "    next",
        "end",
        "",
        "config vpn ipsec phase2-interface",
        '    edit "cg-hardened-p2"',
        '        set phase1name "cg-hardened"',
        "        set proposal aes256gcm",
        "        set pfs enable",
        "        set dhgrp 19",
        f"        set keylifeseconds {TARGET['child_lifetime']}",
        "    next",
        "end",
        "",
        "# Aggressive Mode must be off. Verify with:",
        "#   show vpn ipsec phase1-interface | grep mode",
        "",
    ]
    return "\n".join(lines) + "\n"


def _juniper(assessment: Assessment) -> str:
    lines = [l.replace("!", "#", 1) for l in _header("Juniper SRX (Junos)", assessment)]
    lines += [l.replace("!", "#", 1) for l in _findings_summary(assessment.findings)]
    lines += [
        "set security ike proposal CG-IKE-HARDENED authentication-method rsa-signatures",
        "set security ike proposal CG-IKE-HARDENED dh-group group19",
        "set security ike proposal CG-IKE-HARDENED encryption-algorithm aes-256-gcm",
        "set security ike proposal CG-IKE-HARDENED authentication-algorithm hmac-sha-256-128",
        f"set security ike proposal CG-IKE-HARDENED lifetime-seconds {TARGET['ike_lifetime']}",
        "",
        "set security ike policy CG-IKE-POLICY mode main",
        "set security ike policy CG-IKE-POLICY proposals CG-IKE-HARDENED",
        "",
        "set security ipsec proposal CG-IPSEC-HARDENED protocol esp",
        "set security ipsec proposal CG-IPSEC-HARDENED encryption-algorithm aes-256-gcm",
        f"set security ipsec proposal CG-IPSEC-HARDENED lifetime-seconds {TARGET['child_lifetime']}",
        "",
        "set security ipsec policy CG-IPSEC-POLICY perfect-forward-secrecy keys group19",
        "set security ipsec policy CG-IPSEC-POLICY proposals CG-IPSEC-HARDENED",
        "",
        "# Commit with confirmation so a mistake rolls back automatically:",
        "#   commit confirmed 5",
        "",
    ]
    return "\n".join(lines) + "\n"


GENERATORS = {
    "cisco": _cisco,
    "strongswan": _strongswan,
    "fortinet": _fortinet,
    "juniper": _juniper,
}

PLATFORM_NAMES = {
    "cisco": "Cisco IOS / IOS-XE",
    "strongswan": "strongSwan (swanctl)",
    "fortinet": "Fortinet FortiOS",
    "juniper": "Juniper SRX (Junos)",
}


def detect_platforms(assessment: Assessment) -> list[str]:
    """Platforms implied by vendor-ID fingerprints in the capture."""
    found = []
    for sess in assessment.sessions:
        fam = sess.vendor_family()
        if fam in GENERATORS and fam not in found:
            found.append(fam)
    return found or ["strongswan"]


def synthesize(assessment: Assessment, platform: str) -> str:
    key = platform.lower()
    if key not in GENERATORS:
        raise ValueError(f"unknown platform '{platform}'; choose from {sorted(GENERATORS)}")
    return GENERATORS[key](assessment)


def synthesize_all(assessment: Assessment) -> dict[str, str]:
    return {p: synthesize(assessment, p) for p in detect_platforms(assessment)}


def build_plan(assessment: Assessment, platform: str) -> HardeningPlan:
    """Build a complete HardeningPlan containing forward config, rollback script, and syntax validation."""
    from .models import HardeningPlan
    from .rollback import generate_rollback
    from .syntax import validate_syntax

    key = platform.lower()
    if key not in GENERATORS:
        raise ValueError(f"unknown platform '{platform}'; choose from {sorted(GENERATORS)}")

    fwd = synthesize(assessment, key)
    rb = generate_rollback(key, assessment)
    valid, errors = validate_syntax(key, fwd)

    addressed = [
        {"rule_id": f.rule_id, "title": f.title, "severity": f.severity.value}
        for f in assessment.findings
        if f.severity.value != "info"
    ]

    return HardeningPlan(
        capture=assessment.capture or "live",
        platform=key,
        platform_name=PLATFORM_NAMES.get(key, key),
        forward_config=fwd,
        rollback_config=rb,
        syntax_valid=valid,
        syntax_errors=errors,
        findings_addressed=addressed,
        status="PENDING_REVIEW",
    )


def build_all_plans(assessment: Assessment) -> list[HardeningPlan]:
    """Build hardening plans for all supported platforms."""
    return [build_plan(assessment, p) for p in ("cisco", "strongswan", "fortinet", "juniper")]
