import os
import pytest
from cipherguard.pipeline import analyze
from cipherguard.remediation import (
    HardeningPlan,
    PlanStore,
    apply_plan,
    build_all_plans,
    build_plan,
    generate_rollback,
)
from cipherguard.remediation.syntax import (
    validate_cisco_syntax,
    validate_fortinet_syntax,
    validate_juniper_syntax,
    validate_strongswan_syntax,
)


@pytest.fixture(scope="module")
def downgrade_assessment():
    capture_path = os.path.join(os.path.dirname(__file__), "..", "samples", "downgrade.pcap")
    return analyze(capture_path)


def test_hardening_plan_model_serialization():
    plan = HardeningPlan(
        plan_id="test-plan-001",
        capture="sample.pcap",
        platform="cisco",
        platform_name="Cisco IOS / IOS-XE",
        forward_config="crypto ikev2 policy TEST\n",
        rollback_config="no crypto ikev2 policy TEST\n",
        syntax_valid=True,
        syntax_errors=[],
        findings_addressed=[{"rule_id": "IKE-004"}],
        status="DRAFTED",
    )
    d = plan.to_dict()
    assert d["plan_id"] == "test-plan-001"
    assert d["platform"] == "cisco"
    assert d["syntax_valid"] is True
    assert d["status"] == "DRAFTED"
    assert "crypto ikev2" in d["forward_config"]
    assert "no crypto" in d["rollback_config"]


def test_build_plan_all_platforms(downgrade_assessment):
    platforms = ["cisco", "strongswan", "fortinet", "juniper"]
    for plat in platforms:
        plan = build_plan(downgrade_assessment, plat)
        assert plan.platform == plat
        assert plan.syntax_valid is True, f"Syntax validation failed for {plat}: {plan.syntax_errors}"
        assert len(plan.syntax_errors) == 0
        assert len(plan.forward_config.strip()) > 0
        assert len(plan.rollback_config.strip()) > 0
        assert len(plan.findings_addressed) > 0
        assert plan.status in ("DRAFTED", "PENDING_REVIEW")


def test_build_all_plans_helper(downgrade_assessment):
    plans = build_all_plans(downgrade_assessment)
    assert len(plans) == 4
    plat_ids = {p.platform for p in plans}
    assert plat_ids == {"cisco", "strongswan", "fortinet", "juniper"}
    for p in plans:
        assert p.syntax_valid is True


def test_syntax_validator_cisco():
    valid_cisco = """
crypto ikev2 proposal CG-PROPOSAL
 encryption aes-gcm-256
crypto ikev2 policy CG-POLICY
 proposal CG-PROPOSAL
crypto ipsec transform-set CG-TS esp-gcm 256
"""
    valid, errors = validate_cisco_syntax(valid_cisco)
    assert valid is True
    assert len(errors) == 0

    invalid_cisco = """
crypto ikev2 proposal CG-PROPOSAL
 encryption aes-gcm-256
"""
    valid, errors = validate_cisco_syntax(invalid_cisco)
    assert valid is False
    assert any("missing" in e.lower() for e in errors)


def test_syntax_validator_strongswan():
    valid_swan = """
connections {
    cg-hardened {
        version = 2
        proposals = aes256gcm16-sha384-ecp384
        children {
            cg-net {
                esp_proposals = aes256gcm16-sha384-ecp384
            }
        }
    }
}
"""
    valid, errors = validate_strongswan_syntax(valid_swan)
    assert valid is True
    assert len(errors) == 0

    unbalanced_swan = """
connections {
    cg-hardened {
        version = 2
        proposals = aes256gcm16
        esp_proposals = aes256gcm16
"""
    valid, errors = validate_strongswan_syntax(unbalanced_swan)
    assert valid is False
    assert any("mismatched braces" in e.lower() for e in errors)


def test_syntax_validator_fortinet():
    valid_forti = """
config vpn ipsec phase1-interface
    edit "CG-PHASE1"
        set ike-version 2
    next
end
config vpn ipsec phase2-interface
    edit "CG-PHASE2"
        set phase1name "CG-PHASE1"
    next
end
"""
    valid, errors = validate_fortinet_syntax(valid_forti)
    assert valid is True
    assert len(errors) == 0

    unclosed_forti = """
config vpn ipsec phase1-interface
    edit "CG-PHASE1"
        set ike-version 2
    next
"""
    valid, errors = validate_fortinet_syntax(unclosed_forti)
    assert valid is False
    assert any("mismatched" in e.lower() for e in errors)


def test_syntax_validator_juniper():
    valid_juniper = """
set security ike proposal CG-IKE-PROPOSAL authentication-algorithm sha-384
set security ipsec proposal CG-IPSEC-PROPOSAL protocol esp
"""
    valid, errors = validate_juniper_syntax(valid_juniper)
    assert valid is True
    assert len(errors) == 0

    invalid_juniper = """
set system host-name router-1
"""
    valid, errors = validate_juniper_syntax(invalid_juniper)
    assert valid is False
    assert any("missing" in e.lower() for e in errors)


def test_rollback_playbook_generation():
    cisco_rb = generate_rollback("cisco")
    assert "no crypto ikev2" in cisco_rb
    assert "no crypto ipsec" in cisco_rb

    swan_rb = generate_rollback("strongswan")
    assert "swanctl" in swan_rb

    forti_rb = generate_rollback("fortinet")
    assert "delete" in forti_rb

    juniper_rb = generate_rollback("juniper")
    assert "delete security" in juniper_rb


def test_plan_store_crud_and_lifecycle():
    store = PlanStore(":memory:")
    plan = HardeningPlan(
        plan_id="plan-xyz",
        capture="downgrade.pcap",
        platform="cisco",
        platform_name="Cisco IOS / IOS-XE",
        forward_config="forward cfg",
        rollback_config="rollback cfg",
        syntax_valid=True,
    )

    store.save_plan(plan)
    fetched = store.get_plan("plan-xyz")
    assert fetched is not None
    assert fetched.plan_id == "plan-xyz"
    assert fetched.status in ("DRAFTED", "PENDING_REVIEW")

    by_cap = store.list_plans(capture="downgrade.pcap")
    assert len(by_cap) == 1
    assert by_cap[0].plan_id == "plan-xyz"

    approved = store.update_status("plan-xyz", "APPROVED", actor="SecOps-Admin", comment="Signed off")
    assert approved is not None
    assert approved.status == "APPROVED"
    assert approved.approver == "SecOps-Admin"
    assert approved.approval_comment == "Signed off"

    staged = store.update_status("plan-xyz", "STAGED", actor="AutoEngine", comment="Dry run passed")
    assert staged is not None
    assert staged.status == "STAGED"

    history = store.history("plan-xyz")
    assert len(history) == 2
    assert history[0]["to_status"] == "APPROVED"
    assert history[0]["actor"] == "SecOps-Admin"
    assert history[1]["to_status"] == "STAGED"
    assert history[1]["actor"] == "AutoEngine"


def test_apply_plan_dry_run(downgrade_assessment):
    plan = build_plan(downgrade_assessment, "cisco")
    res = apply_plan(plan, dry_run=True)
    assert res["success"] is True
    assert res["mode"] == "dry-run"
    assert res["lines_staged"] > 0
    assert "DRY-RUN SUCCESSFUL" in res["output"]


def test_apply_plan_syntax_gate():
    invalid_plan = HardeningPlan(
        plan_id="plan-invalid-01",
        capture="downgrade.pcap",
        platform="cisco",
        platform_name="Cisco IOS / IOS-XE",
        forward_config="illegal bad command\n",
        rollback_config="no illegal bad command\n",
        syntax_valid=False,
        syntax_errors=["Syntax error on line 1"],
    )

    res = apply_plan(invalid_plan, dry_run=True)
    assert res["success"] is False
    assert "Syntax validation failed" in res["error"]


def test_apply_plan_live_prohibited(downgrade_assessment):
    plan = build_plan(downgrade_assessment, "cisco")
    res = apply_plan(plan, dry_run=False, target_host="192.168.1.1")
    assert res["success"] is False
    assert res["mode"] == "live_apply_prohibited"
    assert "passive defense doctrine" in res["error"]
