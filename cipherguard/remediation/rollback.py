"""Rollback playbook synthesis.

Generates the exact, deterministic teardown/unwind configuration to cleanly
remove staged hardening policies without interrupting existing production tunnels.
"""

from __future__ import annotations

from ..core.models import Assessment


def generate_rollback(platform: str, assessment: Assessment | None = None) -> str:
    """Synthesize the inverse configuration script for the requested platform."""
    plat = platform.lower()
    if plat == "cisco":
        return _cisco_rollback()
    elif plat == "strongswan":
        return _strongswan_rollback()
    elif plat == "fortinet":
        return _fortinet_rollback()
    elif plat == "juniper":
        return _juniper_rollback()
    return f"# No rollback generator available for platform '{platform}'\n"


def _cisco_rollback() -> str:
    return (
        "\n".join(
            [
                "! CipherGuard Rollback Playbook - Cisco IOS / IOS-XE",
                "! Safely unbinds and deletes staged CipherGuard hardened policies.",
                "!",
                "no crypto ipsec profile CG-PROFILE-HARDENED",
                "no crypto ipsec transform-set CG-TS-HARDENED",
                "no crypto ikev2 policy CG-POLICY-HARDENED",
                "no crypto ikev2 proposal CG-PROPOSAL-HARDENED",
                "!",
                "! Verify active sessions return to previous baseline:",
                "!   show crypto ikev2 sa",
                "!   show crypto ipsec sa",
                "!",
            ]
        )
        + "\n"
    )


def _strongswan_rollback() -> str:
    return (
        "\n".join(
            [
                "# CipherGuard Rollback Playbook - strongSwan (swanctl)",
                "# Reverts staged connection 'cg-hardened' and unloads from charon.",
                "#",
                "# 1. Unload the staged connection:",
                "#    swanctl --terminate --ike cg-hardened",
                "#",
                "# 2. Remove configuration stanza:",
                "#    rm -f /etc/swanctl/conf.d/cg-hardened.conf",
                "#",
                "# 3. Reload active connections:",
                "#    swanctl --load-conns",
                "#",
            ]
        )
        + "\n"
    )


def _fortinet_rollback() -> str:
    return (
        "\n".join(
            [
                "# CipherGuard Rollback Playbook - Fortinet FortiOS",
                "# Deletes staged phase 2 and phase 1 interfaces.",
                "#",
                "config vpn ipsec phase2-interface",
                '    delete "cg-hardened-p2"',
                "end",
                "",
                "config vpn ipsec phase1-interface",
                '    delete "cg-hardened"',
                "end",
                "",
                "# Confirm tunnel status:",
                "#   diagnose vpn ike gateway list",
                "#",
            ]
        )
        + "\n"
    )


def _juniper_rollback() -> str:
    return (
        "\n".join(
            [
                "# CipherGuard Rollback Playbook - Juniper SRX (Junos)",
                "# Deletes staged security IKE and IPsec policies/proposals.",
                "#",
                "delete security ipsec policy CG-IPSEC-POLICY",
                "delete security ipsec proposal CG-IPSEC-HARDENED",
                "delete security ike policy CG-IKE-POLICY",
                "delete security ike proposal CG-IKE-HARDENED",
                "",
                "# Apply with confirmation safety net:",
                "commit confirmed 5",
                "#",
            ]
        )
        + "\n"
    )
