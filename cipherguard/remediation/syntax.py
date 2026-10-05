"""Grammar and syntax verification for vendor-specific hardening playbooks."""

from __future__ import annotations

import re


def validate_syntax(platform: str, config: str) -> tuple[bool, list[str]]:
    """Validate that the generated configuration script is syntactically coherent.

    Returns (is_valid, list_of_errors).
    """
    plat = platform.lower()
    if plat == "cisco":
        return _validate_cisco(config)
    elif plat == "strongswan":
        return _validate_strongswan(config)
    elif plat == "fortinet":
        return _validate_fortinet(config)
    elif plat == "juniper":
        return _validate_juniper(config)
    return True, []


def _validate_cisco(config: str) -> tuple[bool, list[str]]:
    errors: list[str] = []
    lines = [l.strip() for l in config.splitlines() if l.strip() and not l.strip().startswith("!")]

    # Must have crypto ikev2 and ipsec components
    has_ikev2_prop = any("crypto ikev2 proposal" in l for l in lines)
    has_ikev2_pol = any("crypto ikev2 policy" in l for l in lines)
    has_transform = any("crypto ipsec transform-set" in l for l in lines)

    if not has_ikev2_prop:
        errors.append("Missing 'crypto ikev2 proposal' definition")
    if not has_ikev2_pol:
        errors.append("Missing 'crypto ikev2 policy' definition")
    if not has_transform:
        errors.append("Missing 'crypto ipsec transform-set' definition")

    return len(errors) == 0, errors


def _validate_strongswan(config: str) -> tuple[bool, list[str]]:
    errors: list[str] = []
    # Count open and close braces
    open_braces = config.count("{")
    close_braces = config.count("}")
    if open_braces != close_braces:
        errors.append(f"Mismatched braces: {open_braces} open vs {close_braces} close")

    if "connections" not in config:
        errors.append("Missing top-level 'connections' section")
    if "proposals" not in config:
        errors.append("Missing IKE 'proposals' directive")
    if "esp_proposals" not in config:
        errors.append("Missing Child SA 'esp_proposals' directive")

    return len(errors) == 0, errors


def _validate_fortinet(config: str) -> tuple[bool, list[str]]:
    errors: list[str] = []
    config_count = len(re.findall(r"^\s*config\s+", config, re.MULTILINE))
    end_count = len(re.findall(r"^\s*end\b", config, re.MULTILINE))
    edit_count = len(re.findall(r"^\s*edit\s+", config, re.MULTILINE))
    next_count = len(re.findall(r"^\s*next\b", config, re.MULTILINE))

    if config_count != end_count:
        errors.append(f"Mismatched FortiOS blocks: {config_count} 'config' vs {end_count} 'end'")
    if edit_count != next_count:
        errors.append(f"Mismatched FortiOS entries: {edit_count} 'edit' vs {next_count} 'next'")

    if "phase1-interface" not in config:
        errors.append("Missing 'phase1-interface' configuration block")
    if "phase2-interface" not in config:
        errors.append("Missing 'phase2-interface' configuration block")

    return len(errors) == 0, errors


def _validate_juniper(config: str) -> tuple[bool, list[str]]:
    errors: list[str] = []
    lines = [l.strip() for l in config.splitlines() if l.strip() and not l.strip().startswith("#")]

    has_ike_prop = False
    has_ipsec_prop = False
    for line in lines:
        if line.startswith("set security ike proposal"):
            has_ike_prop = True
        elif line.startswith("set security ipsec proposal"):
            has_ipsec_prop = True

    if not has_ike_prop:
        errors.append("Missing Junos 'set security ike proposal' statement")
    if not has_ipsec_prop:
        errors.append("Missing Junos 'set security ipsec proposal' statement")

    return len(errors) == 0, errors


validate_cisco_syntax = _validate_cisco
validate_strongswan_syntax = _validate_strongswan
validate_fortinet_syntax = _validate_fortinet
validate_juniper_syntax = _validate_juniper
