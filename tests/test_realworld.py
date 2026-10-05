"""Validation against real captures, skipped when they are not present.

These tests are the answer to the sharpest question this project faces: every
other accuracy figure is measured against traffic the project generated itself,
which proves only that it agrees with its own assumptions.

The captures are not vendored — they belong to the Wireshark project — so these
tests skip cleanly on an offline checkout. Run `scripts/fetch-real-captures.sh`
to enable them.
"""

from __future__ import annotations

import pytest

from cipherguard.lab import realworld

pytestmark = pytest.mark.no_model

AVAILABLE = realworld.available()

skip_if_absent = pytest.mark.skipif(
    not AVAILABLE,
    reason="real captures not downloaded; run scripts/fetch-real-captures.sh",
)


@skip_if_absent
@pytest.mark.parametrize("expectation", AVAILABLE, ids=lambda e: e.filename)
def test_real_capture_matches_external_ground_truth(expectation):
    """Wireshark names each capture after the algorithm it negotiates, so the
    expected result comes from the upstream maintainers rather than from
    anything written here. That is what makes this a test and not a
    restatement of our own generator's assumptions."""
    result = realworld.check(expectation)
    assert result["passed"], f"{expectation.filename}: " + "; ".join(result["problems"])


@skip_if_absent
def test_no_parse_errors_on_any_real_capture():
    """Regression: real Windows IKEv1 Main Mode sets the Encryption bit from
    message five onward, and the walker treated the ciphertext as a payload
    chain — six parse errors against a perfectly valid exchange. Synthetic
    captures never surfaced it, because the generator only emitted cleartext
    Main Mode. This is the bug that justified the whole exercise."""
    for expectation in AVAILABLE:
        result = realworld.check(expectation)
        errors = [p for p in result["problems"] if "parse error" in p]
        assert not errors, f"{expectation.filename}: {errors}"


@skip_if_absent
def test_aead_and_non_aead_contrast_holds_on_real_traffic():
    """The sharpest correctness check available: AES-GCM and AES-CCM carry no
    INTEG transform, AES-CTR must carry one. Verified against captures from
    real implementations rather than against our own encoder."""
    seen_aead = seen_plain = False
    for expectation in AVAILABLE:
        result = realworld.check(expectation)
        if expectation.aead:
            assert not result["integrity"], (
                f"{expectation.filename} is AEAD but reported integrity {result['integrity']}"
            )
            seen_aead = True
        else:
            assert result["integrity"], f"{expectation.filename} is not AEAD but reported no integrity"
            seen_plain = True
    assert seen_aead and seen_plain, "corpus must contain both cases to be meaningful"


@skip_if_absent
def test_real_windows_vendor_ids_are_fingerprinted():
    """A real Windows IKEv1 stack emits ten vendor IDs, most of which this
    project had never encountered. Unknown ones must degrade to a readable
    marker rather than crashing or being dropped."""
    target = next((e for e in AVAILABLE if e.expect_vendor_ids), None)
    if target is None:
        pytest.skip("no vendor-ID-bearing capture downloaded")

    result = realworld.check(target)
    vids = result["vendor_ids"]
    assert len(vids) >= 5
    assert any("Windows" in v or "NAT-T" in v or "Dead Peer" in v for v in vids), vids
    assert all(isinstance(v, str) and v for v in vids)


@skip_if_absent
def test_real_captures_produce_expected_findings():
    """End to end: a real legacy gateway must raise the legacy findings, and a
    real modern one must not raise anything beyond post-quantum exposure."""
    import os

    from cipherguard.pipeline import analyze

    for expectation in AVAILABLE:
        if not expectation.findings_expected:
            continue
        path = os.path.join(realworld.REAL_CAPTURE_DIR, expectation.filename)
        assessment = analyze(path, model_dir="models")
        fired = {f.rule_id for f in assessment.findings}
        missing = set(expectation.findings_expected) - fired
        assert not missing, f"{expectation.filename} did not raise {sorted(missing)}; raised {sorted(fired)}"


@skip_if_absent
def test_modern_real_capture_scores_well():
    """A real AES-GCM-256 / P-256 gateway should score highly. If the audit
    engine penalised sound configurations it would be unusable in the field."""
    import os

    from cipherguard.pipeline import analyze

    target = next((e for e in AVAILABLE if e.aead and e.encryption == "ENCR_AES_GCM_16"), None)
    if target is None:
        pytest.skip("no AES-GCM capture downloaded")

    path = os.path.join(realworld.REAL_CAPTURE_DIR, target.filename)
    assessment = analyze(path, model_dir="models")
    severe = [f for f in assessment.findings if f.severity.value in ("critical", "high")]
    assert not severe, f"sound real config flagged: {[f.rule_id for f in severe]}"
    assert assessment.score() >= 75


@skip_if_absent
def test_real_legacy_capture_is_graded_poorly():
    import os

    from cipherguard.pipeline import analyze

    target = next((e for e in AVAILABLE if e.version == "IKEv1"), None)
    if target is None:
        pytest.skip("no IKEv1 capture downloaded")

    path = os.path.join(realworld.REAL_CAPTURE_DIR, target.filename)
    assessment = analyze(path, model_dir="models")
    assert assessment.score() < 50
    assert assessment.grade() in ("D", "E")
