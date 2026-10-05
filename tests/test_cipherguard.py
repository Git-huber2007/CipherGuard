"""Test suite.

Several tests exist because the corresponding bug was actually made during
development and is easy to reintroduce: the label-ordering mismatch between the
plausibility mask and the classifier, the downward bias of the plug-in entropy
estimator, and the one-directional nature of the modulo framing constraint.
Those are marked as regression tests.
"""

from __future__ import annotations

import math
import os
import random
import struct
import tempfile

import numpy as np
import pytest

from cipherguard.audit import policy as P
from cipherguard.audit.engine import evaluate
from cipherguard.core import constants as C
from cipherguard.core.models import Assessment, Finding, Severity
from cipherguard.dissector import ike as ike_mod
from cipherguard.dissector.esp import EspTracker, shannon_entropy
from cipherguard.dissector.pcap import Packet, PcapWriter, read_packets
from cipherguard.lab import pcapgen
from cipherguard.ml import features as F
from cipherguard.ml.classifier import plausibility
from cipherguard.ml.synth import esp_ciphertext_length, synth_flow
from cipherguard.pipeline import analyze
from cipherguard.remediation.synth import GENERATORS, synthesize


# ---------------------------------------------------------------------------
# Capture I/O
# ---------------------------------------------------------------------------


def test_pcap_roundtrip_udp():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.pcap")
        with PcapWriter(path) as w:
            w.write_udp(1000.5, "10.0.0.1", "10.0.0.2", 500, 500, b"payload-bytes")
        pkts = list(read_packets(path))
    assert len(pkts) == 1
    p = pkts[0]
    assert (p.src, p.dst, p.sport, p.dport) == ("10.0.0.1", "10.0.0.2", 500, 500)
    assert p.payload == b"payload-bytes"
    assert abs(p.timestamp - 1000.5) < 1e-6


def test_pcap_roundtrip_esp():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.pcap")
        with PcapWriter(path) as w:
            w.write_esp(5.0, "10.0.0.1", "10.0.0.2", 0xDEADBEEF, 7, b"x" * 64)
        pkts = list(read_packets(path))
    assert pkts[0].protocol == 50
    assert len(pkts[0].payload) == 8 + 64


def test_ipv4_header_checksum_is_valid():
    """A wrong checksum makes every capture we emit useless to Wireshark."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.pcap")
        with PcapWriter(path) as w:
            w.write_udp(1.0, "192.0.2.1", "192.0.2.9", 4500, 4500, b"abc")
        raw = open(path, "rb").read()
    ip = raw[24 + 16 + 14 : 24 + 16 + 14 + 20]  # global hdr + rec hdr + ethernet
    total = 0
    for i in range(0, 20, 2):
        total += (ip[i] << 8) | ip[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    assert total == 0xFFFF  # ones-complement sum of a valid header


# ---------------------------------------------------------------------------
# IKE dissection
# ---------------------------------------------------------------------------


def _parse_single(datagram: bytes, sport=500, dport=500):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.pcap")
        with PcapWriter(path) as w:
            w.write_udp(1.0, "10.0.0.1", "10.0.0.2", sport, dport, datagram)
        pkt = next(iter(read_packets(path)))
    return ike_mod.parse_message(pkt)


def test_ikev2_sa_init_transforms_are_recovered():
    suite = dict(encr=20, key_bits=256, prf=5, integ=12, dh=31, esn=1)
    raw = pcapgen.ikev2_sa_init(b"\x01" * 8, b"\x02" * 8, suite, response=True)
    msg = _parse_single(raw)

    assert msg is not None
    assert msg.version == "IKEv2"
    assert msg.exchange == "IKE_SA_INIT"
    assert msg.is_response
    assert not msg.parse_errors

    prop = msg.proposals[0]
    encr = prop.first(1)
    assert encr is not None
    assert encr.name == "ENCR_AES_GCM_16"
    assert encr.key_length == 256
    assert prop.by_type(2)[0].name == "PRF_HMAC_SHA2_256"
    assert prop.by_type(4)[0].value_id == 31
    assert msg.ke_group == 31


def test_ikev2_aead_proposal_omits_integrity():
    """AEAD suites carry no INTEG transform; inventing one would be a false read."""
    suite = dict(encr=20, key_bits=256, prf=5, integ=12, dh=19)
    msg = _parse_single(pcapgen.ikev2_sa_init(b"\x03" * 8, b"\x04" * 8, suite, True))
    assert msg is not None
    assert msg.proposals[0].by_type(3) == []


def test_ikev2_notifies_and_vendor_id():
    suite = dict(encr=12, key_bits=128, prf=2, integ=2, dh=14)
    raw = pcapgen.ikev2_sa_init(
        b"\x05" * 8, b"\x06" * 8, suite, True,
        extra_notifies=[16430, 16388], vendor=b"strongSwan",
    )
    msg = _parse_single(raw)
    assert msg is not None
    assert "IKEV2_FRAGMENTATION_SUPPORTED" in msg.notifies
    assert "NAT_DETECTION_SOURCE_IP" in msg.notifies
    assert "strongSwan" in msg.vendor_ids


def test_ikev2_multiple_proposals_are_all_parsed():
    suite = dict(encr=12, key_bits=128, prf=2, integ=2, dh=14, legacy_fallback=True)
    msg = _parse_single(pcapgen.ikev2_sa_init(b"\x07" * 8, b"\x08" * 8, suite, False))
    assert msg is not None
    assert len(msg.proposals) == 2
    assert msg.proposals[1].by_type(1)[0].name == "ENCR_3DES"


def test_ikev1_attributes_are_recovered():
    sa = pcapgen.ikev1_sa_payload(0, encr=5, hash_alg=1, auth=1, group=2, lifetime=172800)
    raw = pcapgen.ikev1_message(b"\x09" * 8, b"\x00" * 8, 4, [(1, sa)])
    msg = _parse_single(raw)

    assert msg is not None
    assert msg.version == "IKEv1"
    assert "Aggressive" in msg.exchange
    assert msg.auth_method == "PRE_SHARED_KEY"
    assert msg.lifetime_seconds == 172800
    assert msg.ke_group == 2
    assert msg.proposals[0].by_type(1)[0].name == "3DES_CBC"


def test_natt_non_esp_marker_required_on_4500():
    suite = dict(encr=20, key_bits=256, prf=5, integ=12, dh=31)
    raw = pcapgen.ikev2_sa_init(b"\x0a" * 8, b"\x0b" * 8, suite, True)
    assert _parse_single(raw, 4500, 4500) is None          # no marker: it is ESP
    assert _parse_single(b"\x00" * 4 + raw, 4500, 4500)    # marker present: it is IKE


def test_non_ike_traffic_is_rejected():
    assert _parse_single(b"\x00" * 40) is None
    assert _parse_single(b"GET / HTTP/1.1\r\n\r\n" + b"z" * 40) is None


def test_truncated_payload_does_not_raise():
    suite = dict(encr=12, key_bits=128, prf=2, integ=2, dh=14)
    raw = pcapgen.ikev2_sa_init(b"\x0c" * 8, b"\x0d" * 8, suite, True)
    msg = _parse_single(raw[:40])  # cut mid-SA-payload
    assert msg is None or msg.parse_errors  # degrades, never crashes


# ---------------------------------------------------------------------------
# ESP framing arithmetic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("suite,spec", list(C.ESP_SUITES.items()))
def test_framing_residue_is_constant(suite, spec):
    """RFC 4303 fixes len == (IV + ICV) mod blocksize. The audit engine leans on
    this being arithmetic rather than a tendency, so it is asserted directly."""
    modulus = max(spec["block"], 4)
    expected = (spec["iv"] + spec["icv"]) % modulus
    for inner in range(40, 1500, 7):
        length = esp_ciphertext_length(inner, spec["block"], spec["iv"], spec["icv"])
        assert length % modulus == expected


def test_esp_tracker_groups_by_spi():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.pcap")
        with PcapWriter(path) as w:
            for i in range(30):
                w.write_esp(i * 0.01, "10.0.0.1", "10.0.0.2", 0xAAAA, i, b"y" * 100)
                w.write_esp(i * 0.01, "10.0.0.1", "10.0.0.2", 0xBBBB, i, b"y" * 200)
        tracker = EspTracker()
        for pkt in read_packets(path):
            tracker.consume(pkt)
    flows = tracker.results()
    assert len(flows) == 2
    assert {f.packets for f in flows} == {30}


def test_replay_gap_detection():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.pcap")
        with PcapWriter(path) as w:
            for i, seq in enumerate([1, 2, 3, 9, 10, 11, 40, 41]):
                w.write_esp(i * 0.01, "10.0.0.1", "10.0.0.2", 0xCCCC, seq, b"z" * 80)
        tracker = EspTracker()
        for pkt in read_packets(path):
            tracker.consume(pkt)
    assert tracker.results(min_packets=1)[0].replay_gaps() == 2


# ---------------------------------------------------------------------------
# Entropy estimator  (regression)
# ---------------------------------------------------------------------------


def test_entropy_bias_correction_on_random_data():
    """Regression: the uncorrected plug-in estimator reads about 7.26 on 256
    random bytes, below the 7.0-ish region used to detect ESP-NULL once short
    packets pull the mean down. That made correctly encrypted AES-GCM tunnels
    report as unencrypted."""
    data = os.urandom(512)
    assert shannon_entropy(data, correct_bias=False) < shannon_entropy(data)
    assert shannon_entropy(data) > 7.8


def test_entropy_separates_plaintext_from_ciphertext():
    rng = random.Random(3)
    plain = pcapgen._esp_payload(rng, 512, "NULL encryption / HMAC-SHA1-96")
    cipher = pcapgen._esp_payload(rng, 512, "AES-GCM-256 (ICV 16)")
    assert shannon_entropy(plain) < 6.5
    assert shannon_entropy(cipher) > 7.5


# ---------------------------------------------------------------------------
# Features and plausibility
# ---------------------------------------------------------------------------


def test_feature_vector_shape_and_finiteness():
    flow = synth_flow("AES-GCM-256 (ICV 16)", random.Random(1), packets=200)
    vec = F.extract(flow)
    assert vec.shape == (len(F.FEATURE_NAMES),)
    assert np.isfinite(vec).all()
    assert F.signal(vec).shape == (F.SIGNAL_LEN,)


def test_empty_flow_yields_zero_vector():
    from cipherguard.core.models import EspFlow

    assert F.extract(EspFlow(spi=1, src="a", dst="b")).sum() == 0


def test_plausibility_respects_caller_label_order():
    """Regression: the mask was built in ESP_SUITES catalogue order while the
    classifier stores labels sorted, so each suite's constraint was silently
    applied to a different suite. AES-CBC tunnels were reported as 3DES with
    100% confidence — a wrong answer stated with maximum certainty."""
    flow = synth_flow("AES-CBC-128 / HMAC-SHA1-96", random.Random(2), packets=400)
    labels = sorted(C.ESP_SUITES)
    mask, _excluded, _ = plausibility(flow, labels)
    survivors = {labels[i] for i in range(len(labels)) if mask[i] > 0}
    assert survivors == {"AES-CBC-128 / HMAC-SHA1-96"}


def test_plausibility_uses_granularity_not_only_residue():
    """Regression: len == 12 (mod 16) implies len == 4 (mod 8), so the residue
    test alone can never exclude 3DES from an AES-CBC flow. Granularity, the GCD
    of gaps between distinct lengths, breaks the implication."""
    flow = synth_flow("AES-CBC-128 / HMAC-SHA1-96", random.Random(4), packets=400)
    labels = sorted(C.ESP_SUITES)
    mask, excluded, _ = plausibility(flow, labels)
    assert mask[labels.index("3DES-CBC / HMAC-MD5-96")] == 0
    assert any("granularity" in why for _name, why in excluded)


def test_plausibility_excludes_null_when_payload_is_random():
    flow = synth_flow("AES-GCM-256 (ICV 16)", random.Random(5), packets=400)
    labels = sorted(C.ESP_SUITES)
    mask, _e, _n = plausibility(flow, labels)
    assert mask[labels.index("NULL encryption / HMAC-SHA1-96")] == 0


def test_plausibility_never_masks_everything():
    """A flow matching nothing must fall back rather than produce an all-zero
    distribution the caller would normalise into NaNs."""
    from cipherguard.core.models import EspFlow

    flow = EspFlow(spi=1, src="a", dst="b", packets=50,
                   payload_lengths=[37, 41, 43, 47, 53, 59, 61, 67, 71, 73])
    mask, _e, notes = plausibility(flow, sorted(C.ESP_SUITES))
    assert mask.sum() > 0
    assert any("No catalogued suite" in n for n in notes)


# ---------------------------------------------------------------------------
# Audit engine
# ---------------------------------------------------------------------------


def _assess(path: str, model_dir: str | None = None, **kw) -> Assessment:
    """Analyse via the module attribute so the conftest fixture's redirection to
    the session-trained model applies."""
    import cipherguard.pipeline as pipeline

    if model_dir is not None:
        kw["model_dir"] = model_dir
    return pipeline.analyze(path, **kw)


def test_legacy_capture_raises_the_expected_rules(tmp_path):
    path = str(tmp_path / "legacy.pcap")
    pcapgen.scenario_legacy(path)
    a = _assess(path)
    fired = {f.rule_id for f in a.findings}
    assert {"IKE-001", "IKE-002", "IKE-006"} <= fired  # IKEv1, Aggressive, DH 2
    assert any(f.severity is Severity.CRITICAL for f in a.findings)
    assert a.score() < 40


def test_hardened_capture_is_broadly_clean(tmp_path):
    path = str(tmp_path / "hardened.pcap")
    pcapgen.scenario_hardened(path)
    a = _assess(path)
    assert not [f for f in a.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert a.score() >= 75
    # a modern gateway with no PQ key exchange should still be flagged
    assert "IKE-007" in {f.rule_id for f in a.findings}


def test_esp_findings_are_marked_inferred(tmp_path):
    """An inferred finding must never be presented as an observation."""
    path = str(tmp_path / "backbone.pcap")
    pcapgen.scenario_mixed_backbone(path)
    a = _assess(path)
    for f in a.findings:
        if f.rule_id.startswith("ESP-"):
            assert f.inferred, f"{f.rule_id} lost its inferred marker"
        if f.rule_id.startswith("IKE-"):
            assert not f.inferred


def test_ambiguous_suites_are_reported_as_a_set(tmp_path):
    """3DES and DES are framing-identical. Naming just one as fact would be a
    claim the data cannot support."""
    path = str(tmp_path / "legacy.pcap")
    pcapgen.scenario_legacy(path)
    a = _assess(path)
    esp = [f for f in a.findings if f.rule_id == "ESP-001"]
    assert esp
    assert len(esp[0].evidence["candidates"]) == 2
    assert "not separable" in esp[0].detail


def test_score_is_monotonic_in_severity():
    def score_with(findings):
        a = Assessment(capture="x", started="now")
        a.findings = findings
        return a.score()

    def mk(sev, n):
        return [
            Finding(rule_id="T", title="t", severity=sev, subject=str(i),
                    detail="", reference="", remediation="")
            for i in range(n)
        ]

    assert score_with([]) == 100
    assert score_with(mk(Severity.CRITICAL, 1)) < score_with(mk(Severity.HIGH, 1))
    assert score_with(mk(Severity.CRITICAL, 4)) < score_with(mk(Severity.CRITICAL, 1))
    assert score_with(mk(Severity.CRITICAL, 40)) > 0  # regression: never floors flat


def test_disabled_rules_are_skipped(tmp_path):
    path = str(tmp_path / "legacy.pcap")
    pcapgen.scenario_legacy(path)
    a = _assess(path, disabled_rules={"IKE-001", "IKE-002"})
    assert not {"IKE-001", "IKE-002"} & {f.rule_id for f in a.findings}


def test_rule_exception_does_not_abort_the_audit(monkeypatch):
    import cipherguard.audit.engine as eng

    def boom(_sess):
        raise ValueError("synthetic")

    a = Assessment(capture="x", started="now")
    a.sessions = [
        ike_mod.IkeSession(b"\x01" * 8, b"\x02" * 8, "IKEv2", "10.0.0.1", "10.0.0.2")
    ]
    monkeypatch.setattr(eng, "IKE_RULES", [("BOOM", boom)])
    out = evaluate(a)
    assert out.findings and out.findings[0].rule_id == "BOOM"


# ---------------------------------------------------------------------------
# Policy consistency
# ---------------------------------------------------------------------------


def test_every_suite_belongs_to_exactly_one_framing_class():
    seen = [m for spec in P.FRAMING_CLASSES.values() for m in spec["members"]]
    assert sorted(seen) == sorted(C.ESP_SUITES)
    assert len(seen) == len(set(seen))


def test_framing_class_members_share_a_signature():
    """The whole point of a class is that its verdict holds for every member."""
    for name, spec in P.FRAMING_CLASSES.items():
        sigs = {
            (C.ESP_SUITES[m]["block"], C.ESP_SUITES[m]["iv"], C.ESP_SUITES[m]["icv"])
            for m in spec["members"]
        }
        assert len(sigs) == 1, f"{name} mixes distinguishable framings"


def test_prohibited_algorithms_are_known_transform_names():
    """Policy must name transforms the dissector can actually emit, in both the
    IKEv2 and IKEv1 vocabularies. A prohibition spelled only one way silently
    stops applying to half the traffic."""
    known = set(C.ENCR.values()) | set(C.INTEG.values()) | set(C.PRF.values())
    known |= set(C.V1_ENCR.values())
    # IKEv1 integrity and PRF names are synthesised from the Hash attribute
    known |= {f"AUTH_HMAC_{h}" for h in C.V1_HASH.values()}
    known |= {f"PRF_HMAC_{h}" for h in C.V1_HASH.values()}
    for name in list(P.ENCR_PROHIBITED) + list(P.INTEG_PROHIBITED) + list(P.PRF_PROHIBITED):
        assert name in known, f"policy names a transform the dissector never emits: {name}"


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("platform", sorted(GENERATORS))
def test_remediation_renders_for_every_platform(platform, tmp_path):
    path = str(tmp_path / "backbone.pcap")
    pcapgen.scenario_mixed_backbone(path)
    config = synthesize(_assess(path), platform)
    assert "CipherGuard" in config
    assert len(config.splitlines()) > 15

    # Only active lines matter. Comments legitimately name weak algorithms,
    # because they cite the finding each block is there to fix.
    active = [
        l for l in config.splitlines()
        if l.strip() and not l.lstrip().startswith(("#", "!"))
    ]
    body = "\n".join(active).lower()
    assert active, "generated a config with no executable lines"
    for weak in ("3des", "md5", "sha1", "des-cbc", "group2 ", "dh-group group2\n"):
        assert weak not in body, f"remediation emits weak crypto: {weak}"
    assert "gcm" in body


def test_remediation_rejects_unknown_platform(tmp_path):
    path = str(tmp_path / "hardened.pcap")
    pcapgen.scenario_hardened(path)
    with pytest.raises(ValueError):
        synthesize(_assess(path), "nonexistent-vendor")


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_full_pipeline_is_serialisable(tmp_path):
    import json

    path = str(tmp_path / "backbone.pcap")
    pcapgen.scenario_mixed_backbone(path)
    payload = json.loads(json.dumps(_assess(path).to_dict()))
    assert payload["sessions"] and payload["flows"] and payload["findings"]
    assert 0 <= payload["score"] <= 100


def test_analysis_is_deterministic(tmp_path):
    path = str(tmp_path / "backbone.pcap")
    pcapgen.scenario_mixed_backbone(path)
    a, b = _assess(path), _assess(path)
    assert a.digest() == b.digest()
    assert a.score() == b.score()


@pytest.mark.no_model
def test_missing_capture_raises():
    with pytest.raises(FileNotFoundError):
        analyze("/nonexistent/capture.pcap")


# ---------------------------------------------------------------------------
# Security strength quantification
# ---------------------------------------------------------------------------


def test_suite_scored_at_weakest_link_not_strongest():
    """AES-256 with DH Group 2 is an 80-bit association, not a 256-bit one.
    Averaging or taking the max would flatter the commonest real misconfiguration."""
    from cipherguard.core.models import Transform
    from cipherguard.core.strength import score_proposal

    mixed = [
        Transform(1, "ENCR", 12, "ENCR_AES_CBC", key_length=256),
        Transform(2, "PRF", 5, "PRF_HMAC_SHA2_256"),
        Transform(3, "INTEG", 12, "AUTH_HMAC_SHA2_256_128"),
        Transform(4, "DH", 2, "1024-bit MODP"),
    ]
    s = score_proposal(mixed)
    assert s.classical_bits == 80
    assert s.detail["encryption"] == 256
    assert s.classical_grade == "deprecated"


def test_every_classical_key_exchange_has_zero_quantum_strength():
    """Shor breaks finite-field and elliptic-curve DH regardless of modulus, so
    a bigger classical group must never read as quantum progress."""
    from cipherguard.core.strength import DH_STRENGTH

    for gid, (classical, quantum, family) in DH_STRENGTH.items():
        if family in ("modp", "ecp"):
            assert quantum == 0, f"group {gid} claims quantum strength"
        if family == "ml-kem":
            assert quantum >= 128


def test_quantum_strength_bounded_by_key_exchange():
    from cipherguard.core.models import Transform
    from cipherguard.core.strength import score_proposal

    # AES-256 gives 128 bits under Grover, but a classical KEX zeroes it out
    s = score_proposal([
        Transform(1, "ENCR", 20, "ENCR_AES_GCM_16", key_length=256),
        Transform(4, "DH", 31, "Curve25519"),
    ])
    assert s.quantum_bits == 0
    assert not s.quantum_safe

    pq = score_proposal([
        Transform(1, "ENCR", 20, "ENCR_AES_GCM_16", key_length=256),
        Transform(4, "DH", 36, "ML-KEM-768"),
    ])
    assert pq.quantum_safe


def test_sweet32_scales_with_observed_volume():
    from cipherguard.core.strength import sweet32_exposure

    assert sweet32_exposure(128, 10**12, 100, 86400) is None  # AES is unaffected
    quiet = sweet32_exposure(64, 10**6, 3600, 86400)
    busy = sweet32_exposure(64, 10**11, 3600, 86400)
    assert quiet is not None and busy is not None
    assert quiet["ratio_to_threshold"] < busy["ratio_to_threshold"]
    assert busy["exceeds"] and not quiet["exceeds"]


# ---------------------------------------------------------------------------
# Temporal baseline
# ---------------------------------------------------------------------------


def test_downgrade_is_detected_only_across_observations(tmp_path):
    """The core claim of the temporal module: this failure is invisible to any
    single capture, and visible the moment there are two."""
    from cipherguard.intel.baseline import BaselineStore

    strong = str(tmp_path / "hardened.pcap")
    weak = str(tmp_path / "downgrade.pcap")
    pcapgen.scenario_hardened(strong)
    pcapgen.scenario_downgrade(weak)

    db = str(tmp_path / "b.db")
    with BaselineStore(db) as store:
        first = store.record(_assess(strong))
        assert [d.kind for d in first] == ["new"]
        assert not [d for d in first if d.kind == "downgrade"]

        second = store.record(_assess(weak))
        downgrades = [d for d in second if d.kind == "downgrade"]
        assert len(downgrades) == 1
        assert downgrades[0].previous_bits > downgrades[0].current_bits
        assert downgrades[0].delta < 0


def test_peer_key_is_direction_independent(tmp_path):
    """An initiator/responder role swap must not reset the link's baseline."""
    from cipherguard.core.models import IkeSession
    from cipherguard.intel.baseline import peer_key

    a = IkeSession(b"\x01" * 8, b"\x02" * 8, "IKEv2", "10.0.0.1", "10.0.0.2")
    b = IkeSession(b"\x03" * 8, b"\x04" * 8, "IKEv2", "10.0.0.2", "10.0.0.1")
    assert peer_key(a) == peer_key(b)


def test_baseline_retains_best_not_latest(tmp_path):
    """Baseline must be the strongest state ever seen, or a downgrade would
    silently become the new normal on the next observation."""
    from cipherguard.intel.baseline import BaselineStore

    strong = str(tmp_path / "h.pcap")
    weak = str(tmp_path / "d.pcap")
    pcapgen.scenario_hardened(strong)
    pcapgen.scenario_downgrade(weak)

    db = str(tmp_path / "b.db")
    with BaselineStore(db) as store:
        store.record(_assess(strong))
        store.record(_assess(weak))
        store.record(_assess(weak))          # repeated weakness
        rows = store.fleet()
    assert rows[0]["best_classical_bits"] > rows[0]["current_bits"]
    assert rows[0]["degraded"]


# ---------------------------------------------------------------------------
# Post-quantum exposure
# ---------------------------------------------------------------------------


def test_mosca_inequality_sign_convention():
    from cipherguard.intel.pqc import mosca_gap

    assert mosca_gap(50, 3, 12) > 0     # strategic data: already late
    assert mosca_gap(1, 1, 12) < 0      # short-lived data: margin remains


def test_roadmap_ranks_weak_links_first(tmp_path):
    from cipherguard.intel.pqc import roadmap

    path = str(tmp_path / "backbone.pcap")
    pcapgen.scenario_mixed_backbone(path)
    plan = roadmap(_assess(path), data_class="strategic")

    indices = [l["exposure_index"] for l in plan["links"]]
    assert indices == sorted(indices, reverse=True)
    assert plan["assumptions"]["already_late"] is True
    assert plan["phases"][0]["phase"] == 1


def test_quantum_safe_links_carry_zero_exposure(tmp_path):
    from cipherguard.core.models import Transform
    from cipherguard.core.strength import score_proposal

    s = score_proposal([
        Transform(1, "ENCR", 20, "ENCR_AES_GCM_16", key_length=256),
        Transform(4, "DH", 37, "ML-KEM-1024"),
    ])
    assert s.quantum_safe and s.quantum_bits >= 128


# ---------------------------------------------------------------------------
# CBOM export
# ---------------------------------------------------------------------------


def test_cbom_is_valid_cyclonedx(tmp_path):
    import json as _json

    from cipherguard.export.cbom import build_cbom

    path = str(tmp_path / "backbone.pcap")
    pcapgen.scenario_mixed_backbone(path)
    doc = build_cbom(_assess(path))

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["components"]
    for c in doc["components"]:
        assert c["type"] == "cryptographic-asset"
        assert c["cryptoProperties"]["assetType"] in ("algorithm", "protocol")
        assert c["bom-ref"]
    _json.dumps(doc)  # must be serialisable


def test_cbom_marks_inferred_assets(tmp_path):
    """An inventory that cannot distinguish measurement from inference is
    misleading exactly where it is most consequential."""
    from cipherguard.export.cbom import build_cbom

    path = str(tmp_path / "backbone.pcap")
    pcapgen.scenario_mixed_backbone(path)
    doc = build_cbom(_assess(path))

    def prov(c):
        return next((p["value"] for p in c.get("properties", [])
                     if p["name"] == "cipherguard:provenance"), None)

    provenances = {prov(c) for c in doc["components"]}
    assert provenances == {"observed", "inferred"}

    inferred = [c for c in doc["components"] if prov(c) == "inferred"]
    assert inferred
    for c in inferred:
        names = {p["name"] for p in c["properties"]}
        assert "cipherguard:confidence" in names
        assert "cipherguard:candidates" in names


def test_cbom_bom_refs_are_unique(tmp_path):
    from cipherguard.export.cbom import build_cbom

    path = str(tmp_path / "backbone.pcap")
    pcapgen.scenario_mixed_backbone(path)
    doc = build_cbom(_assess(path))
    refs = [c["bom-ref"] for c in doc["components"]]
    assert len(refs) == len(set(refs))


# ---------------------------------------------------------------------------
# New audit rules
# ---------------------------------------------------------------------------


def test_sweet32_rule_quantifies_rather_than_asserts(tmp_path):
    path = str(tmp_path / "legacy.pcap")
    pcapgen.scenario_legacy(path)
    a = _assess(path)
    hits = [f for f in a.findings if f.rule_id == "IKE-013"]
    assert hits
    ev = hits[0].evidence
    assert ev["block_bits"] == 64
    assert ev["ratio_to_threshold"] > 0
    assert "GB" in hits[0].detail


def test_sweet32_silent_on_modern_ciphers(tmp_path):
    path = str(tmp_path / "hardened.pcap")
    pcapgen.scenario_hardened(path)
    a = _assess(path)
    assert not [f for f in a.findings if f.rule_id == "IKE-013"]


def test_weakest_link_rule_names_the_binding_component(tmp_path):
    path = str(tmp_path / "legacy.pcap")
    pcapgen.scenario_legacy(path)
    a = _assess(path)
    hits = [f for f in a.findings if f.rule_id == "IKE-012"]
    assert hits
    assert "components" in hits[0].evidence


# ---------------------------------------------------------------------------
# Security regression tests
#
# Every test below corresponds to a vulnerability that was present and is now
# fixed. The analyzer's entire threat model is that it ingests data an attacker
# controls, so these are functional requirements rather than hardening extras.
# ---------------------------------------------------------------------------


def test_flow_table_is_bounded_against_spi_randomisation(tmp_path):
    """A 32-bit attacker-chosen SPI keys the flow table. Unbounded, spoofed ESP
    with randomised SPIs created one record per packet — 60k packets produced
    68 MB — so a few seconds of line-rate traffic blinds the sensor."""
    path = str(tmp_path / "flood.pcap")
    with PcapWriter(path) as w:
        for i in range(5000):
            w.write_esp(i * 1e-6, "10.0.0.1", "10.0.0.2",
                        (i * 2654435761) & 0xFFFFFFFF, 1, b"x" * 64)

    tracker = EspTracker(max_flows=256)
    for pkt in read_packets(path):
        tracker.consume(pkt)

    assert len(tracker.flows) <= 256
    assert tracker.evicted > 0


def test_flood_does_not_evict_established_tunnels(tmp_path):
    """Eviction must drop flood singletons, not the long-lived tunnels that are
    the entire point of the audit."""
    path = str(tmp_path / "mixed.pcap")
    with PcapWriter(path) as w:
        for i in range(400):  # a genuine, busy tunnel
            w.write_esp(i * 1e-4, "10.0.0.1", "10.0.0.2", 0xCAFEBABE, i, b"y" * 128)
        for i in range(3000):  # flood of singletons
            w.write_esp(1.0 + i * 1e-6, "10.0.0.1", "10.0.0.2",
                        (i * 2654435761) & 0xFFFFFFFF, 1, b"x" * 64)

    tracker = EspTracker(max_flows=128)
    for pkt in read_packets(path):
        tracker.consume(pkt)

    survivors = {f.spi for f in tracker.flows.values()}
    assert 0xCAFEBABE in survivors, "the real tunnel was evicted by the flood"


def test_capture_declaring_an_absurd_packet_length_is_rejected(tmp_path):
    """A 140-byte file declaring a 3 GB packet is a 20-million-fold memory
    amplification and costs an attacker nothing to produce."""
    from cipherguard.dissector.pcap import CaptureError

    path = str(tmp_path / "bomb.pcap")
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        f.write(struct.pack("<IIII", 0, 0, 3_000_000_000, 3_000_000_000))
        f.write(b"\x00" * 100)

    with pytest.raises(CaptureError):
        list(read_packets(path))


def test_pcapng_block_length_is_validated(tmp_path):
    from cipherguard.dissector.pcap import CaptureError

    path = str(tmp_path / "bomb.pcapng")
    with open(path, "wb") as f:
        f.write(struct.pack("<IIIHHq", 0x0A0D0D0A, 0x7FFFFFFF, 0x1A2B3C4D, 1, 0, -1))
        f.write(b"\x00" * 64)

    with pytest.raises(CaptureError):
        list(read_packets(path))


def test_remediation_output_cannot_be_injected_via_capture_name():
    """Generated config is pasted into a router by an operator. A newline in an
    untrusted value ends the comment and the rest becomes a live directive."""
    from cipherguard.remediation.synth import synthesize

    hostile = "x.pcap\n crypto ikev2 policy ATTACKER\n set peer 203.0.113.66"
    a = Assessment(capture=hostile, started="now")
    for platform in GENERATORS:
        config = synthesize(a, platform)
        active = [
            l for l in config.splitlines()
            if l.strip() and not l.lstrip().startswith(("#", "!"))
        ]
        assert not any("ATTACKER" in l for l in active), platform
        assert not any("203.0.113.66" in l for l in active), platform


def test_finding_text_cannot_escape_the_comment_block():
    from cipherguard.remediation.synth import synthesize

    a = Assessment(capture="ok.pcap", started="now")
    a.findings = [
        Finding(rule_id="X-1", title="bad\n set peer 198.51.100.9\n", severity=Severity.HIGH,
                subject="s", detail="d", reference="r", remediation="fix")
    ]
    for platform in GENERATORS:
        active = [
            l for l in synthesize(a, platform).splitlines()
            if l.strip() and not l.lstrip().startswith(("#", "!"))
        ]
        assert not any("198.51.100.9" in l for l in active), platform


@pytest.mark.no_model
def test_fleet_endpoint_takes_no_caller_supplied_path():
    """The baseline store opens its path as SQLite and creates parent
    directories. Accepting that path per-request was an unauthenticated
    arbitrary-directory-creation and file-probing primitive."""
    import inspect

    from cipherguard.api.server import create_app

    app = create_app()
    route = next(r for r in app.routes if getattr(r, "path", "") == "/api/fleet")
    params = inspect.signature(getattr(route, "endpoint")).parameters
    assert "db" not in params
    assert not params, "no request-controlled parameters may reach the store path"


@pytest.mark.no_model
def test_upload_rejects_traversal_and_control_characters(tmp_path):
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app

    client = TestClient(create_app(capture_dir=str(tmp_path)))

    # Reachable over the wire. A raw control character is not in this list
    # because the multipart encoder percent-encodes it before transmission, so
    # it cannot be exercised end-to-end; the server-side check remains as
    # defence against a client that does not.
    for name in ("../../etc/passwd.pcap", "..\\win.pcap", ".hidden.pcap", "x.exe", ""):
        r = client.post("/api/upload", files={"file": (name, b"\x00" * 32)})
        assert r.status_code >= 400, f"{name} was accepted"

    assert not list(tmp_path.iterdir()), "a rejected upload still wrote to disk"


@pytest.mark.no_model
def test_stored_capture_names_never_contain_control_characters(tmp_path):
    """The invariant that matters: whatever reaches disk is safe to interpolate
    into a filename, a log line and a generated router configuration."""
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app

    client = TestClient(create_app(capture_dir=str(tmp_path)))
    client.post("/api/upload", files={"file": ("good.pcap", b"\x00" * 32)})
    for child in tmp_path.iterdir():
        assert not any(ord(c) < 32 or ord(c) == 127 for c in child.name)
        assert os.sep not in child.name


@pytest.mark.no_model
def test_upload_refuses_to_overwrite_existing_capture(tmp_path):
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app

    (tmp_path / "existing.pcap").write_bytes(b"original")
    client = TestClient(create_app(capture_dir=str(tmp_path)))
    r = client.post("/api/upload", files={"file": ("existing.pcap", b"replacement")})
    assert r.status_code == 409
    assert (tmp_path / "existing.pcap").read_bytes() == b"original"


# ---------------------------------------------------------------------------
# Cross-model validation
# ---------------------------------------------------------------------------


def test_field_model_respects_rfc_framing(model_dir):
    """The field model must differ from the training model in its traffic
    assumptions and agree with it on protocol arithmetic. If it violated RFC
    4303 framing it would not be modelling IPsec, and the comparison would be
    meaningless rather than independent."""
    from cipherguard.lab.fieldmodel import field_flow

    rng = random.Random(9)
    for suite, spec in C.ESP_SUITES.items():
        flow = field_flow(suite, rng, packets=200, tfc_regime="light")
        modulus = max(spec["block"], 4)
        expected = (spec["iv"] + spec["icv"]) % modulus
        assert all(l % modulus == expected for l in flow.payload_lengths), suite


def test_field_model_differs_from_training_distribution():
    """A control that produced the same distribution would validate nothing."""
    import numpy as np

    from cipherguard.lab.fieldmodel import field_flow
    from cipherguard.ml.synth import synth_flow

    suite = "AES-GCM-256 (ICV 16)"
    train = synth_flow(suite, random.Random(1), packets=800)
    field = field_flow(suite, random.Random(1), packets=800, tfc_regime="none")
    # markedly different shape: the field model's ACK spike dominates
    assert abs(np.mean(train.payload_lengths) - np.mean(field.payload_lengths)) > 50


def test_classifier_transfers_across_generators(model_dir):
    """The number this project is actually claiming."""
    from cipherguard.ml.validate import cross_validate

    result = cross_validate(model_dir=model_dir, samples_per_suite=8)
    assert result["framing_class_accuracy"] >= 0.95
    for name, stat in result["by_condition"].items():
        assert stat["accuracy"] >= 0.90, f"degrades under {name}"


def test_ablation_shows_arithmetic_carries_the_transfer(model_dir):
    """Regression against a misattribution rather than a bug: without this the
    project would claim the ML generalises, when in fact the learned models lose
    a quarter of their accuracy off-distribution and the deterministic RFC
    constraints are what hold the result up."""
    from cipherguard.ml.validate import ablate

    abl = ablate(model_dir, samples_per_suite=8)
    assert abl["with_mask_framing"] > abl["models_only_framing"]
    assert abl["mask_contribution"] > 0.05


# ---------------------------------------------------------------------------
# Model provenance and schema safety
# ---------------------------------------------------------------------------


def test_feature_schema_change_refuses_to_load(model_dir, monkeypatch):
    """The dangerous failure: shapes stay compatible, the model loads, and every
    prediction is silently computed from columns that no longer mean what the
    model was fitted on."""
    from cipherguard.ml import features as Feat
    from cipherguard.ml.classifier import ModelSchemaError, SuiteClassifier

    SuiteClassifier.load(model_dir)  # baseline: loads fine
    monkeypatch.setattr(Feat, "FEATURE_NAMES", ["injected"] + Feat.FEATURE_NAMES)
    with pytest.raises(ModelSchemaError):
        SuiteClassifier.load(model_dir)


def test_model_records_provenance(model_dir):
    import json as _json

    meta = _json.load(open(os.path.join(model_dir, "meta.json")))
    assert meta["schema_version"]
    assert meta["feature_hash"]
    for key in ("trained_at", "python", "sklearn", "corpus"):
        assert key in meta["provenance"]


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------


def test_audit_log_records_capture_digest(tmp_path):
    """A finding is only meaningful against a known input, so the trail has to
    pin down which bytes were assessed."""
    import json as _json

    from cipherguard.core.audit_log import AuditLog

    cap = str(tmp_path / "legacy.pcap")
    pcapgen.scenario_legacy(cap)
    logfile = str(tmp_path / "audit.jsonl")

    a = _assess(cap)
    AuditLog(logfile).assessment(a, cap)

    rec = _json.loads(open(logfile).read().strip())
    assert rec["event"] == "assessment"
    assert len(rec["capture_sha256"]) == 64
    assert rec["score"] == a.score()


def test_audit_log_does_not_duplicate_intelligence(tmp_path):
    """The trail must account for what happened without becoming a second copy
    of the traffic analysis it exists to account for."""
    import json as _json

    from cipherguard.core.audit_log import AuditLog

    cap = str(tmp_path / "backbone.pcap")
    pcapgen.scenario_mixed_backbone(cap)
    logfile = str(tmp_path / "audit.jsonl")

    a = _assess(cap)
    AuditLog(logfile).assessment(a, cap)
    blob = open(logfile).read()

    for finding in a.findings:
        assert finding.detail not in blob
        assert finding.remediation not in blob
    rec = _json.loads(blob.strip())
    assert all(":" in f for f in rec["findings"])  # rule id and subject only


def test_audit_log_appends_rather_than_truncates(tmp_path):
    from cipherguard.core.audit_log import AuditLog

    cap = str(tmp_path / "h.pcap")
    pcapgen.scenario_hardened(cap)
    logfile = str(tmp_path / "audit.jsonl")
    log = AuditLog(logfile)
    a = _assess(cap)
    log.assessment(a, cap)
    log.assessment(a, cap)
    assert len(open(logfile).read().strip().splitlines()) == 2


# ---------------------------------------------------------------------------
# API authentication
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_api_requires_bearer_token_when_configured(tmp_path):
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app

    client = TestClient(create_app(capture_dir=str(tmp_path), auth_token="s3cret"))
    for endpoint in ("/api/captures", "/api/rules", "/api/model", "/api/fleet"):
        assert client.get(endpoint).status_code == 401, endpoint
        assert client.get(
            endpoint, headers={"Authorization": "Bearer wrong"}
        ).status_code == 401, endpoint
        assert client.get(
            endpoint, headers={"Authorization": "Bearer s3cret"}
        ).status_code == 200, endpoint


@pytest.mark.no_model
def test_health_endpoint_stays_open(tmp_path):
    """A health probe that needs a credential is useless to a load balancer, and
    it reveals nothing about the traffic."""
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app

    client = TestClient(create_app(capture_dir=str(tmp_path), auth_token="s3cret"))
    body = client.get("/api/health")
    assert body.status_code == 200
    assert body.json()["auth_required"] is True
    assert "capture_dir" not in body.json()  # no path disclosure pre-auth


@pytest.mark.no_model
def test_token_comparison_is_constant_time():
    """A plain == returns early on the first differing byte and leaks the token
    prefix to anyone who can time the responses."""
    import inspect

    from cipherguard.api import server

    src = inspect.getsource(server.create_app)
    assert "compare_digest" in src


# ---------------------------------------------------------------------------
# Policy overlay
# ---------------------------------------------------------------------------


@pytest.fixture
def restore_policy():
    """Overlays mutate the policy module, so every test here must put it back or
    it silently changes the baseline for every test that runs afterwards."""
    import copy

    from cipherguard.audit import policy as pol
    from cipherguard.audit.policy_config import OVERLAYABLE

    saved = {k: copy.deepcopy(getattr(pol, k)) for k in OVERLAYABLE}
    yield
    for k, v in saved.items():
        setattr(pol, k, v)


def test_overlay_extends_rather_than_replaces_by_default(restore_policy):
    from cipherguard.audit import policy as pol
    from cipherguard.audit.policy_config import apply_overlay

    baseline = set(pol.DH_PROHIBITED)
    apply_overlay({"DH_PROHIBITED": {"14": "below national floor"}})
    assert 14 in pol.DH_PROHIBITED
    assert baseline <= set(pol.DH_PROHIBITED), "extending dropped NIST prohibitions"


def test_overlay_replace_mode_is_opt_in(restore_policy):
    from cipherguard.audit import policy as pol
    from cipherguard.audit.policy_config import apply_overlay

    apply_overlay({"DH_PROHIBITED": {"14": "only this"}}, replace=True)
    assert set(pol.DH_PROHIBITED) == {14}


def test_overlay_coerces_integer_keyed_tables(restore_policy):
    """JSON object keys are strings. Left uncoerced, every DH lookup misses and
    the rule silently never fires — a control that stops running without
    telling anyone."""
    from cipherguard.audit import policy as pol
    from cipherguard.audit.policy_config import apply_overlay

    apply_overlay({"DH_PROHIBITED": {"14": "reason"}})
    assert 14 in pol.DH_PROHIBITED
    assert "14" not in pol.DH_PROHIBITED


def test_overlay_rejects_unknown_settings(restore_policy):
    from cipherguard.audit.policy_config import PolicyError, apply_overlay

    with pytest.raises(PolicyError) as exc:
        apply_overlay({"MIN_DH_BTIS": 3072})  # typo
    assert "MIN_DH_BITS" in str(exc.value)  # names the valid settings


def test_overlay_rejects_wrong_types(restore_policy):
    from cipherguard.audit.policy_config import PolicyError, apply_overlay

    with pytest.raises(PolicyError):
        apply_overlay({"MIN_DH_BITS": "3072"})
    with pytest.raises(PolicyError):
        apply_overlay({"DH_PROHIBITED": ["14"]})


def test_stricter_directive_changes_the_verdict(tmp_path, restore_policy):
    """The point of the feature: an agency retargets the tool to its own
    directive without forking it."""
    import json as _json

    from cipherguard.audit.policy_config import EXAMPLE, load_and_apply

    cap = str(tmp_path / "transitional.pcap")
    pcapgen.scenario_transitional(cap)

    before = _assess(cap)
    assert "IKE-006" not in {f.rule_id for f in before.findings}

    path = tmp_path / "directive.json"
    path.write_text(_json.dumps(EXAMPLE))
    record = load_and_apply(str(path))

    after = _assess(cap)
    assert "IKE-006" in {f.rule_id for f in after.findings}
    assert after.score() < before.score()
    assert record["name"] == EXAMPLE["name"]
    assert record["mode"] == "extend"


# ---------------------------------------------------------------------------
# Real-world protocol handling
# ---------------------------------------------------------------------------


def test_nat_keepalive_is_not_counted_as_esp():
    """RFC 3948 s4 keepalives are a single 0xFF byte sent every 20 seconds by
    every peer behind NAT. Counted as ESP they would pollute every flow
    statistic the inference depends on."""
    from cipherguard.dissector.esp import EspTracker

    tracker = EspTracker()
    keepalive = Packet(frame=1, timestamp=1.0, src="10.0.0.1", dst="10.0.0.2",
                       protocol=17, sport=4500, dport=4500, payload=b"\xff")
    assert tracker.consume(keepalive) is False
    assert not tracker.flows


def test_nat_keepalive_is_not_parsed_as_ike():
    from cipherguard.dissector.pcap import Packet

    pkt = Packet(frame=1, timestamp=1.0, src="10.0.0.1", dst="10.0.0.2",
                 protocol=17, sport=4500, dport=4500, payload=b"\xff")
    assert ike_mod.parse_message(pkt) is None


def test_ikev2_fragmentation_is_recognised_not_flagged_malformed():
    """RFC 7383 fragments are routine on certificate-bearing IKE_AUTH. A
    dissector that does not know the payload type reports a valid exchange as
    malformed."""
    body = struct.pack("!HH", 1, 3) + os.urandom(64)
    payload = struct.pack("!BBH", 0, 0, len(body) + 4) + body
    header = (b"\x01" * 8 + b"\x02" * 8
              + struct.pack("!BBBBII", 53, 0x20, 35, 0x08, 1, 28 + len(payload)))
    msg = _parse_single(header + payload)

    assert msg is not None
    assert msg.encrypted
    assert msg.fragment == (1, 3)
    assert not msg.parse_errors


def test_retransmissions_are_counted_not_treated_as_new_negotiations():
    """A repeated IKE_SA_INIT on a lossy path would otherwise inflate every
    per-message statistic on exactly the links that are already unhealthy."""
    suite = dict(encr=12, key_bits=128, prf=2, integ=2, dh=14)
    raw = pcapgen.ikev2_sa_init(b"\x21" * 8, b"\x00" * 8, suite, response=False)
    messages = [_parse_single(raw) for _ in range(4)]
    sessions = ike_mod.group_sessions([m for m in messages if m])

    assert len(sessions) == 1
    assert sessions[0].retransmissions == 3


# ---------------------------------------------------------------------------
# Static assets
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_static_assets_are_served(tmp_path):
    """The page is inert without them, and a missing mount fails silently: the
    HTML still returns 200 and renders unstyled with no behaviour at all."""
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app

    client = TestClient(create_app(capture_dir=str(tmp_path)))
    page = client.get("/")
    assert page.status_code == 200
    assert 'href="/static/css/dashboard.css"' in page.text
    assert 'src="/static/js/dashboard.js"' in page.text

    css = client.get("/static/css/dashboard.css")
    assert css.status_code == 200
    assert "text/css" in css.headers["content-type"]
    assert "--observed" in css.text

    js = client.get("/static/js/dashboard.js")
    assert js.status_code == 200
    assert "renderRibbon" in js.text


@pytest.mark.no_model
def test_markup_carries_no_inline_style_or_script():
    """The point of splitting the page: markup, presentation and behaviour stay
    in separate files rather than drifting back into one."""
    import re

    from cipherguard.api.server import STATIC_DIR

    html = open(os.path.join(STATIC_DIR, "index.html"), encoding="utf-8").read()
    assert not re.search(r"<style[\s>]", html)
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)


@pytest.mark.no_model
def test_static_assets_are_packaged():
    """Missing package-data entries only surface after an install, where the
    dashboard is served from a wheel that never contained the css or js."""
    import tomllib

    with open("pyproject.toml", "rb") as fh:
        data = tomllib.load(fh)
    patterns = data["tool"]["setuptools"]["package-data"]["cipherguard.api"]
    assert any(p.endswith("css/*.css") for p in patterns)
    assert any(p.endswith("js/*.js") for p in patterns)


@pytest.mark.no_model
def test_every_dashboard_element_id_exists_in_the_markup():
    """The script and the markup are now separate files, so a renamed id in one
    breaks the other with nothing but a null dereference at runtime."""
    import re

    from cipherguard.api.server import STATIC_DIR

    html = open(os.path.join(STATIC_DIR, "index.html"), encoding="utf-8").read()
    js = open(os.path.join(STATIC_DIR, "js", "dashboard.js"), encoding="utf-8").read()

    declared = set(re.findall(r'id="([^"]+)"', html))
    referenced = set(re.findall(r'\$\("([^"]+)"\)', js))
    missing = referenced - declared
    assert not missing, f"dashboard.js addresses ids absent from index.html: {missing}"


# ---------------------------------------------------------------------------
# Real-world protocol handling
# ---------------------------------------------------------------------------


def test_nat_keepalive_is_not_mistaken_for_esp():
    """RFC 3948 s4 keepalives are a single 0xFF byte sent every 20 seconds by
    every peer behind NAT. On a real capture they arrive in bulk, and counting
    them as ESP would pollute every flow statistic the inference depends on."""
    from cipherguard.dissector.esp import EspTracker

    tracker = EspTracker()
    keepalive = Packet(frame=1, timestamp=1.0, src="10.0.0.1", dst="10.0.0.2",
                       protocol=17, sport=4500, dport=4500, payload=b"\xff")
    assert tracker.consume(keepalive) is False
    assert not tracker.flows
    assert ike_mod.parse_message(keepalive) is None


def test_ikev2_fragmentation_is_recognised_not_flagged_malformed():
    """RFC 7383. Certificate-bearing IKE_AUTH is routinely fragmented in the
    field; a dissector that does not know the payload type reports a perfectly
    valid exchange as malformed."""
    body = struct.pack("!BBH", 0, 0, 4 + 4 + 64) + struct.pack("!HH", 2, 5) + b"\x00" * 64
    raw = (b"\x11" * 8 + b"\x22" * 8
           + struct.pack("!BBBBII", 53, 0x20, 35, 0x08, 1, 28 + len(body)) + body)
    pkt = Packet(frame=1, timestamp=1.0, src="10.0.0.1", dst="10.0.0.2",
                 protocol=17, sport=500, dport=500, payload=raw)

    msg = ike_mod.parse_message(pkt)
    assert msg is not None
    assert msg.encrypted
    assert msg.fragment == (2, 5)
    assert not msg.parse_errors


def test_retransmissions_counted_not_treated_as_new_negotiations(tmp_path):
    """A repeated IKE_SA_INIT on a lossy path must not read as many distinct
    negotiations, which would inflate per-message statistics on exactly the
    links that are already unhealthy."""
    suite = dict(encr=20, key_bits=256, prf=5, integ=12, dh=31)
    raw = pcapgen.ikev2_sa_init(b"\x31" * 8, b"\x32" * 8, suite, response=False)
    path = str(tmp_path / "retrans.pcap")
    with PcapWriter(path) as w:
        for i in range(5):  # same message, five times
            w.write_udp(1.0 + i, "10.0.0.1", "10.0.0.2", 500, 500, raw)

    msgs = [ike_mod.parse_message(p) for p in read_packets(path)]
    sessions = ike_mod.group_sessions([m for m in msgs if m])
    assert len(sessions) == 1
    assert sessions[0].retransmissions == 4


# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------


def test_live_capture_reports_capability_without_raising():
    from cipherguard.capture.live import available, list_interfaces

    ok, why = available()
    assert isinstance(ok, bool) and isinstance(why, str) and why
    assert isinstance(list_interfaces(), list)


def test_live_capture_fails_gracefully_on_a_bad_interface():
    """An operator typo must produce an explanation, not a traceback."""
    from cipherguard.capture.live import CaptureUnavailable, LiveCapture, available

    if not available()[0]:
        pytest.skip("no capture privilege on this host")
    with pytest.raises(CaptureUnavailable):
        with LiveCapture("definitely-not-an-interface"):
            pass


def test_bpf_filter_jumps_are_all_in_range():
    """A hand-assembled BPF program with an out-of-range jump is rejected by the
    kernel at attach time, or worse, accepts the wrong traffic silently."""
    from cipherguard.capture.live import _ipsec_filter

    prog = _ipsec_filter()
    n = len(prog) // 8
    assert n > 0
    for i in range(n):
        code, jt, jf, _k = struct.unpack_from("HBBI", prog, i * 8)
        if code & 0x07 == 0x05 and code != 0x06:  # BPF_JMP, not a return
            assert i + 1 + jt < n, f"instruction {i} jt jumps past the program"
            assert i + 1 + jf < n, f"instruction {i} jf jumps past the program"
    # the program must terminate in returns
    last_code = struct.unpack_from("HBBI", prog, (n - 1) * 8)[0]
    assert last_code == 0x06


# ---------------------------------------------------------------------------
# Policy overlay
# ---------------------------------------------------------------------------


def test_policy_overlay_extends_rather_than_replaces(tmp_path, monkeypatch):
    """An agency adding one prohibition must not implicitly permit everything
    the baseline prohibits. That failure would be silent and would weaken the
    audit, which is the wrong direction for a mistake to go."""
    import json as _json

    from cipherguard.audit import policy as Pol
    from cipherguard.audit import policy_config as PC

    monkeypatch.setattr(Pol, "DH_PROHIBITED", dict(Pol.DH_PROHIBITED))
    monkeypatch.setattr(Pol, "MIN_DH_BITS", Pol.MIN_DH_BITS)

    overlay = tmp_path / "agency.json"
    overlay.write_text(_json.dumps({
        "name": "test directive",
        "MIN_DH_BITS": 3072,
        "DH_PROHIBITED": {"14": "below the 3072-bit floor"},
    }))

    PC.load_and_apply(str(overlay))
    assert 14 in Pol.DH_PROHIBITED       # the agency's addition
    assert 2 in Pol.DH_PROHIBITED        # baseline prohibitions retained
    assert Pol.MIN_DH_BITS == 3072


def test_policy_overlay_rejects_unknown_settings(tmp_path):
    """A typo must fail loudly. A control that quietly stops running is worse
    than one that was never configured."""
    import json as _json

    from cipherguard.audit.policy_config import PolicyError, load

    bad = tmp_path / "typo.json"
    bad.write_text(_json.dumps({"MIN_DH_BTIS": 3072}))
    with pytest.raises(PolicyError) as exc:
        load(str(bad))
    assert "MIN_DH_BTIS" in str(exc.value)


def test_policy_overlay_changes_the_verdict(tmp_path, monkeypatch):
    """The overlay is only meaningful if it actually moves findings."""
    import json as _json

    from cipherguard.audit import policy as Pol
    from cipherguard.audit import policy_config as PC

    cap = str(tmp_path / "transitional.pcap")
    pcapgen.scenario_transitional(cap)
    before = _assess(cap).score()

    monkeypatch.setattr(Pol, "DH_PROHIBITED", dict(Pol.DH_PROHIBITED))
    overlay = tmp_path / "strict.json"
    overlay.write_text(_json.dumps({"DH_PROHIBITED": {"14": "below agency floor"}}))
    PC.load_and_apply(str(overlay))

    assert _assess(cap).score() < before


# ---------------------------------------------------------------------------
# Dashboard asset separation
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_dashboard_assets_are_separate_files():
    """Markup, styling and behaviour live in their own files.

    Asserted rather than assumed: an inline <style> or <script> block creeping
    back in is easy to add and invisible in review, and it defeats browser
    caching and any future Content-Security-Policy that forbids inline sources.
    """
    from cipherguard.api.server import STATIC_DIR

    html = open(os.path.join(STATIC_DIR, "index.html"), encoding="utf-8").read()
    assert "<style" not in html.lower()
    # the only <script> permitted is an external reference with a src attribute
    for fragment in html.lower().split("<script")[1:]:
        assert "src=" in fragment.split(">")[0]

    for rel in ("css/dashboard.css", "js/dashboard.js"):
        path = os.path.join(STATIC_DIR, *rel.split("/"))
        assert os.path.exists(path), f"{rel} is missing"
        assert os.path.getsize(path) > 500, f"{rel} looks truncated"
        assert rel in html, f"{rel} exists but index.html does not reference it"


@pytest.mark.no_model
def test_dashboard_assets_are_actually_served(tmp_path):
    """A packaged build that omits the CSS or JS serves a broken dashboard and
    fails silently — the page still returns 200."""
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app

    client = TestClient(create_app(capture_dir=str(tmp_path)))
    for url, marker in (
        ("/", "<!DOCTYPE html>"),
        ("/static/css/dashboard.css", "--observed"),
        ("/static/js/dashboard.js", "function"),
    ):
        response = client.get(url)
        assert response.status_code == 200, url
        assert marker in response.text, f"{url} served unexpected content"


@pytest.mark.no_model
def test_packaging_includes_every_static_asset():
    """package-data listing only *.html would install a dashboard with no
    styling or behaviour, and nothing would raise."""
    import re

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pyproject = open(os.path.join(root, "pyproject.toml"), encoding="utf-8").read()
    found = re.search(r"\[tool\.setuptools\.package-data\](.*?)(\n\[|\Z)",
                      pyproject, re.S)
    assert found is not None
    block = found.group(1)
    for pattern in ("static/*.html", "static/css/*.css", "static/js/*.js"):
        assert pattern in block, f"{pattern} is not declared as package data"


# ---------------------------------------------------------------------------
# Sensor evidence retention  (regression)
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_sensor_retention_bounds_disk(tmp_path):
    """Regression: the sensor wrote one capture per window forever.

    At 300-second windows a 50 Mbps link produces roughly 540 GB a day, so the
    host filled within hours and the monitoring died — the same unbounded-growth
    class of bug the flow table and capture parser were already hardened
    against, reintroduced in the feature meant to demonstrate deployability.
    """
    from cipherguard.cli import _prune_evidence

    for i in range(40):
        f = tmp_path / f"window-2026090{i // 10}T{i:04d}00.pcap"
        f.write_bytes(b"\x00" * (1 << 20))
        os.utime(f, (1000 + i, 1000 + i))

    removed, total = _prune_evidence(str(tmp_path), keep=24, max_bytes=10 << 20)
    kept = sorted(p.name for p in tmp_path.iterdir())

    assert removed > 0
    assert len(kept) <= 24
    assert total <= 10 << 20, "disk ceiling not enforced"
    # a count limit alone cannot bound disk, because window size tracks link load
    assert len(kept) == 10


@pytest.mark.no_model
def test_sensor_retention_keeps_the_newest(tmp_path):
    """Pruning must drop the oldest evidence. Discarding the most recent window
    would delete the capture behind the finding an analyst is looking at."""
    from cipherguard.cli import _prune_evidence

    for i in range(10):
        f = tmp_path / f"window-20260901T{i:04d}00.pcap"
        f.write_bytes(b"\x00" * 1024)
        os.utime(f, (5000 + i, 5000 + i))

    _prune_evidence(str(tmp_path), keep=3, max_bytes=1 << 30)
    kept = sorted(p.name for p in tmp_path.iterdir())
    assert kept == [
        "window-20260901T000700.pcap",
        "window-20260901T000800.pcap",
        "window-20260901T000900.pcap",
    ]


@pytest.mark.no_model
def test_retention_ignores_unrelated_files(tmp_path):
    """The output directory may hold an operator's own files. Pruning must not
    delete anything it did not write."""
    from cipherguard.cli import _prune_evidence

    (tmp_path / "notes.txt").write_text("operator notes")
    (tmp_path / "reference.pcap").write_bytes(b"\x00" * 2048)
    for i in range(6):
        f = tmp_path / f"window-20260901T{i:04d}00.pcap"
        f.write_bytes(b"\x00" * 2048)
        os.utime(f, (7000 + i, 7000 + i))

    _prune_evidence(str(tmp_path), keep=1, max_bytes=1 << 30)
    remaining = {p.name for p in tmp_path.iterdir()}
    assert "notes.txt" in remaining
    assert "reference.pcap" in remaining


@pytest.mark.no_model
def test_live_capture_accepts_a_byte_ceiling():
    """A duration bound alone still lets one 300s window reach several GB before
    it returns, so the ceiling has to apply during capture, not after."""
    import inspect

    from cipherguard.capture.live import LiveCapture

    params = inspect.signature(LiveCapture.packets).parameters
    assert "max_bytes" in params


@pytest.mark.no_model
def test_flood_does_not_collapse_throughput(tmp_path):
    """Regression: the memory cap introduced a CPU denial of service.

    Evicting one flow per new key meant that at capacity, every packet of an
    SPI-randomised flood triggered a full linear scan of the table — the table
    never dropped below capacity, so the scan never stopped. Throughput fell
    from ~158,000 packets/second to ~900, a 175x collapse. The memory bound held
    while the sensor stopped keeping up with the link, which is the same denial
    of service the cap existed to prevent.

    Asserted as wall-clock rather than as an implementation detail, because the
    property that matters is that a flood stays cheap however it is achieved.
    """
    import time

    path = str(tmp_path / "flood.pcap")
    with PcapWriter(path) as w:
        for i in range(30000):
            w.write_esp(i * 1e-6, "10.0.0.1", "10.0.0.2",
                        (i * 2654435761) & 0xFFFFFFFF, 1, b"x" * 64)
    packets = list(read_packets(path))

    tracker = EspTracker(max_flows=4096)
    started = time.time()
    for pkt in packets:
        tracker.consume(pkt)
    elapsed = time.time() - started

    rate = len(packets) / max(elapsed, 1e-9)
    assert tracker.evicted > 0, "the flood did not reach capacity; test is vacuous"
    assert len(tracker.flows) <= 4096
    # generous by ~20x against the measured post-fix rate, but ~10x above the
    # broken implementation, so it fails loudly on a regression
    assert rate > 10000, f"flood throughput collapsed to {rate:,.0f} pkt/s"


@pytest.mark.no_model
def test_eviction_is_amortised_not_per_packet(tmp_path):
    """Eviction count should track the flood, not exceed it by a scan per packet."""
    path = str(tmp_path / "flood.pcap")
    with PcapWriter(path) as w:
        for i in range(8000):
            w.write_esp(i * 1e-6, "10.0.0.1", "10.0.0.2",
                        (i * 2654435761) & 0xFFFFFFFF, 1, b"x" * 64)

    tracker = EspTracker(max_flows=1024)
    for pkt in read_packets(path):
        tracker.consume(pkt)

    # batches of 10% mean the table oscillates below capacity rather than
    # sitting exactly at it and scanning on every single insert
    assert len(tracker.flows) < 1024
    assert tracker.evicted >= 1024


@pytest.mark.no_model
def test_flow_reporting_uses_the_framing_class():
    """Regression: the summary printed `predicted_suite` and its exact-suite
    confidence — an arbitrary member of a set the wire cannot distinguish. A
    correctly identified AES-GCM tunnel displayed as 'ChaCha20-Poly1305, 30%'
    directly beneath the parsed IKE proposal saying AES-GCM, which reads as the
    inference engine being wrong."""
    from cipherguard.core.models import EspFlow

    flow = EspFlow(spi=1, src="a", dst="b", packets=400)
    flow.predicted_suite = "ChaCha20-Poly1305"
    flow.confidence = 0.30
    flow.ranked = [
        ("ChaCha20-Poly1305", 0.30), ("AES-GCM-128 (ICV 16)", 0.27),
        ("AES-GCM-256 (ICV 16)", 0.25), ("AES-CTR-128 / HMAC-SHA2-256-128", 0.18),
    ]

    cls_name, members, mass = flow.framing()
    assert cls_name == "AEAD or counter mode"
    assert len(members) == 4
    assert mass == pytest.approx(1.0, abs=0.01), "group confidence must sum the class"

    payload = flow.to_dict()
    assert payload["framing_class"] == "AEAD or counter mode"
    assert payload["ambiguous"] is True
    assert payload["framing_confidence"] > 0.99


@pytest.mark.no_model
def test_unanswered_proposal_cannot_write_the_baseline(tmp_path):
    """Regression: an unanswered IKE_SA_INIT set a peer pair's stored baseline.

    Anyone on a mirrored segment can send one. Set it high and a genuine
    downgrade never fires; set it low across many pairs and the alert flood
    trains operators to ignore exit code 3. The store now records only
    proposals a responder was observed agreeing to.
    """
    from cipherguard.core.models import IkeMessage, IkeSession, Proposal, Transform
    from cipherguard.intel.baseline import BaselineStore

    spoofed = IkeMessage(
        frame=1, timestamp=1.0, src="10.0.0.1", dst="10.0.0.2", sport=500, dport=500,
        version="IKEv2", exchange="IKE_SA_INIT", initiator_spi=b"\x01" * 8,
        responder_spi=b"\x00" * 8, message_id=0, is_initiator=True, is_response=False,
    )
    spoofed.proposals = [Proposal(number=1, protocol_id=1, protocol="IKE", transforms=[
        Transform(1, "ENCR", 20, "ENCR_AES_GCM_16", key_length=256),
        Transform(4, "DH", 31, "Curve25519"),
    ])]
    session = IkeSession(b"\x01" * 8, b"\x00" * 8, "IKEv2", "10.0.0.1", "10.0.0.2")
    session.messages = [spoofed]

    assessment = Assessment(capture="spoof.pcap", started="now")
    assessment.sessions = [session]

    with BaselineStore(str(tmp_path / "b.db")) as store:
        drifts = store.record(assessment)
        assert drifts == []
        assert store.fleet() == []

    assert session.negotiated("IKE") is not None          # still reportable
    assert session.negotiated("IKE", confirmed_only=True) is None
    assert not session.is_confirmed()


@pytest.mark.no_model
def test_baseline_requires_repeat_observation_before_promoting(tmp_path):
    """One anomalous exchange must not become the reference point that every
    later downgrade is measured against."""
    from cipherguard.intel.baseline import BaselineStore
    from cipherguard.lab import pcapgen

    weak = str(tmp_path / "d.pcap")
    strong = str(tmp_path / "h.pcap")
    pcapgen.scenario_downgrade(weak)
    pcapgen.scenario_hardened(strong)

    import cipherguard.pipeline as pipeline

    with BaselineStore(str(tmp_path / "b.db")) as store:
        store.record(pipeline.analyze(weak, model_dir="models"))
        first = store.fleet()[0]["best_classical_bits"]

        store.record(pipeline.analyze(strong, model_dir="models"))
        assert store.fleet()[0]["best_classical_bits"] == first, "promoted on one sighting"

        store.record(pipeline.analyze(strong, model_dir="models"))
        assert store.fleet()[0]["best_classical_bits"] > first, "never promoted"


@pytest.mark.no_model
def test_new_peer_creation_is_rate_limited(tmp_path):
    """Peer keys derive from IP addresses, and spoofing those is free."""
    from cipherguard.core.models import IkeMessage, IkeSession, Proposal, Transform
    from cipherguard.intel.baseline import BaselineStore

    sessions = []
    for i in range(50):
        response = IkeMessage(
            frame=i, timestamp=1.0, src=f"10.9.{i}.2", dst=f"10.9.{i}.1",
            sport=500, dport=500, version="IKEv2", exchange="IKE_SA_INIT",
            initiator_spi=bytes([i]) * 8, responder_spi=b"\x02" * 8,
            message_id=0, is_initiator=False, is_response=True,
        )
        response.proposals = [Proposal(number=1, protocol_id=1, protocol="IKE",
                                       transforms=[Transform(4, "DH", 2, "1024-bit MODP")])]
        s = IkeSession(bytes([i]) * 8, b"\x02" * 8, "IKEv2", f"10.9.{i}.1", f"10.9.{i}.2")
        s.messages = [response]
        sessions.append(s)

    assessment = Assessment(capture="flood.pcap", started="now")
    assessment.sessions = sessions

    with BaselineStore(str(tmp_path / "b.db")) as store:
        store.record(assessment, max_new_peers=10)
        assert len(store.fleet()) <= 10


@pytest.mark.no_model
def test_model_tampering_is_detected_before_unpickling(tmp_path):
    """Regression: `joblib.load` unpickles, so write access to the model
    directory was code execution inside the analyzer. The feature-hash check
    did not help — it reads meta.json from the same directory."""
    import shutil

    from cipherguard.ml.classifier import ModelIntegrityError, SuiteClassifier

    staged = tmp_path / "models"
    shutil.copytree("models", staged)
    assert SuiteClassifier.load(str(staged))

    blob = (staged / "rf.joblib").read_bytes()
    (staged / "rf.joblib").write_bytes(blob[:-1] + bytes([blob[-1] ^ 0x01]))
    with pytest.raises(ModelIntegrityError):
        SuiteClassifier.load(str(staged))

    (staged / "MANIFEST.sha256").unlink()
    with pytest.raises(ModelIntegrityError):
        SuiteClassifier.load(str(staged))


@pytest.mark.no_model
def test_static_export_is_self_contained(tmp_path):
    """The hosted build must not depend on a backend.

    GitHub Pages serves files, not processes. If the exported dashboard still
    reaches for /api/analyze, the deployment looks live and every panel is
    empty — a failure that only shows up after publishing.
    """
    import json as _json

    from cipherguard.export.static_site import export
    from cipherguard.lab import pcapgen

    caps = tmp_path / "caps"
    caps.mkdir()
    pcapgen.scenario_mixed_backbone(str(caps / "backbone.pcap"))

    out = tmp_path / "site"
    manifest = export(capture_dir=str(caps), out_dir=str(out),
                      model_dir="models", verbose=False)

    for rel in ("index.html", "css/dashboard.css", "js/dashboard.js",
                "data/manifest.json", ".nojekyll"):
        assert (out / rel).exists(), f"{rel} missing from the static build"

    # absolute /static/ paths break under a Pages project subpath
    html = (out / "index.html").read_text(encoding="utf-8")
    assert "/static/" not in html

    entry = manifest["captures"][0]
    payload = _json.loads((out / entry["file"]).read_text(encoding="utf-8"))
    for key in ("score", "grade", "findings", "flows", "sessions",
                "platforms", "roadmap", "remediation"):
        assert key in payload, f"exported analysis is missing {key}"
    assert payload["remediation"], "no hardening plan baked into the static build"


@pytest.mark.no_model
def test_static_export_carries_real_analysis(tmp_path):
    """The export must be real pipeline output, not a mock. If it were canned,
    the demo would show numbers the code never produced."""
    import json as _json

    import cipherguard.pipeline as pipeline
    from cipherguard.export.static_site import export
    from cipherguard.lab import pcapgen

    caps = tmp_path / "caps"
    caps.mkdir()
    path = str(caps / "legacy.pcap")
    pcapgen.scenario_legacy(path)

    out = tmp_path / "site"
    manifest = export(capture_dir=str(caps), out_dir=str(out),
                      model_dir="models", verbose=False)
    payload = _json.loads((out / manifest["captures"][0]["file"]).read_text(encoding="utf-8"))

    live = pipeline.analyze(path, model_dir="models")
    assert payload["score"] == live.score()
    assert payload["digest"] == live.digest()
