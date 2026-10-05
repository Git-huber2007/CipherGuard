"""RFC 9370 hybrid key exchange, and RFC 9242 IKE_INTERMEDIATE.

The tool recommends migrating to a hybrid ML-KEM key exchange. Before this it
could not recognise a gateway that had: the exchange that carries the ML-KEM
step was dropped as an unknown type, the transform that negotiates it was
unnamed, and the post-quantum rule looked only at the first key exchange. So
the gateways that had done what the roadmap asks were reported as not having.

Everything checked here is read from cleartext. The additional key exchange
itself is encrypted, and the tests hold the code to saying only that it was
seen, never what it carried.
"""

from __future__ import annotations

import re
import struct

import pytest

from cipherguard.audit import engine
from cipherguard.core import constants as C
from cipherguard.core.models import Assessment, IkeSession, Severity, Transform
from cipherguard.core.strength import DH_STRENGTH, score_proposal
from cipherguard.dissector.ike import group_sessions, parse_message
from cipherguard.dissector.pcap import Packet
from cipherguard.lab import pcapgen
from tests.jsmodules import NODE, dashboard_js, function, run_node

needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")

A, B = "203.0.113.130", "198.51.100.140"
ISPI, RSPI, NO_SPI = b"\x11" * 8, b"\x22" * 8, b"\x00" * 8

CLASSICAL = dict(encr=20, key_bits=256, prf=6, dh=31, esn=1)
HYBRID = dict(CLASSICAL, addke={6: [36]})                 # ADDKE1 = ML-KEM-768


def _session(*messages: tuple[bytes, bool]) -> IkeSession:
    """Dissect raw IKE messages, in order, into the one session they form.
    Each is (bytes, sent_by_initiator)."""
    parsed = []
    for i, (raw, from_initiator) in enumerate(messages):
        src, dst = (A, B) if from_initiator else (B, A)
        msg = parse_message(Packet(frame=i + 1, timestamp=float(i), src=src, dst=dst,
                                   protocol=17, sport=500, dport=500, payload=raw))
        assert msg is not None, f"message {i + 1} was dropped by the dissector"
        parsed.append(msg)
    (sess,) = group_sessions(parsed)
    return sess


def _init(suite: dict, response: bool, notifies: list[int] | None = None) -> tuple[bytes, bool]:
    raw = pcapgen.ikev2_sa_init(ISPI, RSPI if response else NO_SPI, suite, response,
                                extra_notifies=notifies)
    return raw, not response


def _intermediate(response: bool, message_id: int = 1) -> tuple[bytes, bool]:
    return pcapgen.ikev2_intermediate(ISPI, RSPI, response, message_id, 1184), not response


def _hybrid_session(intermediate: bool = True) -> IkeSession:
    msgs = [_init(HYBRID, False, [16438]), _init(HYBRID, True, [16438])]
    if intermediate:
        msgs += [_intermediate(False), _intermediate(True)]
    return _session(*msgs)


def _assess(path: str) -> Assessment:
    """Through the module attribute, so conftest's test model applies."""
    import cipherguard.pipeline as pipeline

    return pipeline.analyze(path)


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------------------
# 1. Dissection
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_registries_cover_the_rfc_9370_and_9242_additions():
    assert C.EXCHANGE_TYPES_V2[43] == "IKE_INTERMEDIATE"
    assert C.EXCHANGE_TYPES_V2[44] == "IKE_FOLLOWUP_KE"
    assert [C.TRANSFORM_TYPE[t] for t in range(6, 13)] == [f"ADDKE{i}" for i in range(1, 8)]
    assert C.KE_TRANSFORM_TYPES == (4, 6, 7, 8, 9, 10, 11, 12)
    # the group numbers the rest of the tool already used, unchanged
    assert {g: C.DH_GROUPS[g]["name"] for g in (35, 36, 37)} == {
        35: "ML-KEM-512", 36: "ML-KEM-768", 37: "ML-KEM-1024"}


@pytest.mark.no_model
@pytest.mark.parametrize("exchange, name", [(43, "IKE_INTERMEDIATE"), (44, "IKE_FOLLOWUP_KE")])
def test_encrypted_key_exchange_messages_are_no_longer_dropped(exchange, name):
    """Regression: parse_message returned None for every IKEv2 exchange type
    outside 34-37, so these messages vanished from the session."""
    sk = pcapgen._generic(C.PAYLOAD_KE_V2, b"\xaa" * 1217)
    raw = pcapgen.ike_header(ISPI, RSPI, 46, C.IKE_VERSION_2, exchange,
                             C.FLAG_INITIATOR, 1, len(sk)) + sk
    msg = parse_message(Packet(frame=1, timestamp=1.0, src=A, dst=B, protocol=17,
                               sport=500, dport=500, payload=raw))
    assert msg is not None
    assert msg.exchange == name and msg.message_id == 1
    # stops at the SK payload: nothing inside is read, and that is not an error
    assert msg.encrypted is True
    assert msg.proposals == [] and msg.ke_group is None and msg.parse_errors == []


@pytest.mark.no_model
def test_generated_intermediate_message_has_the_rfc_layout():
    """The generator is checked against the field layout itself, so the test
    above is not the dissector agreeing with a generator that copied it."""
    raw = pcapgen.ikev2_intermediate(ISPI, RSPI, response=True, message_id=3, ke_data_len=1088)
    nxt, version, exchange, flags, mid, length = struct.unpack_from("!BBBBII", raw, 16)
    assert raw[:8] == ISPI and raw[8:16] == RSPI
    assert (nxt, version, exchange, mid) == (46, 0x20, 43, 3)       # SK, IKEv2, IKE_INTERMEDIATE
    assert flags == C.FLAG_RESPONSE and length == len(raw)
    inner_next, _crit, sk_len = struct.unpack_from("!BBH", raw, 28)
    assert inner_next == 34 and sk_len == len(raw) - 28             # first inner payload: KE
    # IV 8, the KE payload (4 + 4 + data) plus a pad-length byte, ICV 16
    assert sk_len - 4 == 8 + (4 + 4 + 1088 + 1) + 16


@pytest.mark.no_model
def test_additional_key_exchange_transforms_are_named():
    """Regression: types 6-12 were emitted as TYPE6_ID36."""
    offer = dict(CLASSICAL, addke={6: [36, 0], 7: [37], 12: [999]})
    sess = _session(_init(offer, False))
    (prop,) = sess.messages[0].proposals
    named = [(t.type_id, t.type_name, t.value_id, t.name) for t in prop.transforms
             if t.type_id in C.ADDKE_TRANSFORM_TYPES]
    assert named == [
        (6, "ADDKE1", 36, "ML-KEM-768"),
        (6, "ADDKE1", 0, "NONE"),
        (7, "ADDKE2", 37, "ML-KEM-1024"),
        (12, "ADDKE7", 999, "GROUP_999"),
    ]
    assert not any("TYPE" in t.name or "TYPE" in t.type_name for t in prop.transforms)
    assert sess.messages[0].parse_errors == []


@pytest.mark.no_model
def test_generated_addke_transform_has_the_rfc_layout():
    (dh, addke, _esn) = pcapgen._suite_transforms(HYBRID)[2:]
    # last/more(1) reserved(1) length(2) type(1) reserved(1) id(2), RFC 7296 s3.3.2
    assert struct.unpack("!BBHBBH", addke) == (3, 0, 8, 6, 0, 36)
    assert struct.unpack("!BBHBBH", dh) == (3, 0, 8, 4, 0, 31)


@pytest.mark.no_model
def test_session_records_the_intermediate_exchange():
    sess = _hybrid_session()
    assert [m.exchange for m in sess.messages] == [
        "IKE_SA_INIT", "IKE_SA_INIT", "IKE_INTERMEDIATE", "IKE_INTERMEDIATE"]
    # request and response are one exchange
    assert sess.exchanges_seen("IKE_INTERMEDIATE") == 1
    assert sess.retransmissions == 0

    kx = sess.to_dict()["key_exchange"]
    assert kx["confirmed"] is True and kx["hybrid"] is True
    assert kx["method"] == {"slot": "DH", "group": 31, "name": "Curve25519",
                            "post_quantum": False}
    assert kx["additional"] == [{"slot": "ADDKE1", "group": 36, "name": "ML-KEM-768",
                                 "post_quantum": True}]
    assert kx["intermediate_exchanges"] == 1 and kx["followup_ke_exchanges"] == 0
    assert "INTERMEDIATE_EXCHANGE_SUPPORTED" in sess.all_notifies()


def test_hybrid_capture_round_trips_through_the_pipeline(tmp_path):
    path = str(tmp_path / "pqc_hybrid.pcap")
    pcapgen.scenario_pqc_hybrid(path)
    a = _assess(path)
    (sess,) = a.sessions
    assert len(sess.messages) == 6
    assert [m.message_id for m in sess.messages] == [0, 0, 1, 1, 2, 2]   # RFC 9242 s3.2
    assert sess.exchanges_seen("IKE_INTERMEDIATE") == 1
    assert sess.exchanges_seen("IKE_AUTH") == 1
    assert a.stats.get("parse_errors", 0) == 0
    assert not any(m.parse_errors for m in sess.messages)


# ---------------------------------------------------------------------------
# 2. Audit: only what the responder selected counts
# ---------------------------------------------------------------------------


def test_ike_007_is_silent_on_the_hybrid_capture(tmp_path):
    """Regression: a gateway negotiating Curve25519 with ML-KEM-768 was told it
    had no quantum-resistant key establishment."""
    path = str(tmp_path / "pqc_hybrid.pcap")
    pcapgen.scenario_pqc_hybrid(path)
    a = _assess(path)
    fired = _rule_ids(a.findings)
    assert "IKE-007" not in fired and "IKE-014" not in fired
    assert not [f for f in a.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]


def test_ike_007_still_fires_on_a_classical_capture(tmp_path):
    path = str(tmp_path / "hardened.pcap")
    pcapgen.scenario_hardened(path)
    (finding,) = [f for f in _assess(path).findings if f.rule_id == "IKE-007"]
    assert finding.evidence["responder_confirmed"] is True
    assert finding.evidence["pq_offered"] == [] and finding.evidence["addke_selected"] == []
    assert finding.evidence["groups"] == [31]
    assert "offered" not in finding.detail


def test_ike_007_fires_when_the_hybrid_is_offered_but_not_selected(tmp_path):
    path = str(tmp_path / "pqc_declined.pcap")
    pcapgen.scenario_pqc_declined(path)
    a = _assess(path)
    (sess,) = a.sessions
    # the offer really does contain it, in proposal 1; the responder took proposal 2
    assert [p.number for p in sess.messages[0].proposals] == [1, 2]
    confirmed = sess.negotiated("IKE", confirmed_only=True)
    assert confirmed is not None and confirmed.number == 2

    (finding,) = [f for f in a.findings if f.rule_id == "IKE-007"]
    assert finding.severity is Severity.MEDIUM and finding.inferred is False
    assert finding.evidence == {
        "groups": [31], "ppk": False, "responder_confirmed": True,
        "addke_selected": [], "pq_offered": ["ML-KEM-768 (ADDKE1)"],
        "intermediate_exchanges_seen": 0,
    }
    assert "did not select it" in finding.detail
    assert "on the responder" in finding.remediation

    strength = sess.strength()
    assert strength.quantum_bits == 0 and not strength.quantum_safe and not strength.hybrid
    assert sess.key_exchange()["additional_offered"][0]["name"] == "ML-KEM-768"


@pytest.mark.no_model
@pytest.mark.parametrize("selected", [
    dict(CLASSICAL, addke={6: [0]}),     # responder returns ADDKE1 = NONE
    CLASSICAL,                           # responder omits the transform type
])
def test_both_ways_of_declining_an_optional_exchange_are_a_decline(selected):
    """RFC 9370 lets the initiator make the exchange optional by listing NONE.
    A responder may answer with NONE or leave the type out; either way no
    additional exchange was negotiated."""
    offer = dict(CLASSICAL, addke={6: [36, 0]})
    sess = _session(_init(offer, False, [16438]), _init(selected, True))
    (finding,) = engine.rule_post_quantum(sess)
    assert finding.evidence["addke_selected"] == []
    assert finding.evidence["pq_offered"] == ["ML-KEM-768 (ADDKE1)"]
    assert sess.key_exchange()["hybrid"] is False
    assert engine.rule_additional_exchange_not_observed(sess) == []
    assert sess.strength().quantum_bits == 0


@pytest.mark.no_model
def test_an_unanswered_hybrid_offer_is_not_credited():
    """Anyone on the mirrored segment can send an IKE_SA_INIT. One that nobody
    was seen to answer must not make a link read as quantum-safe, in the
    finding, the strength, or the roadmap."""
    from cipherguard.intel.pqc import roadmap

    sess = _session(_init(HYBRID, False, [16438]))
    assert sess.is_confirmed("IKE") is False

    (finding,) = engine.rule_post_quantum(sess)
    assert finding.evidence["responder_confirmed"] is False
    assert finding.evidence["pq_offered"] == ["ML-KEM-768 (ADDKE1)"]
    assert "no response was observed" in finding.detail

    strength = sess.strength()
    assert strength.quantum_bits == 0 and strength.kex_quantum_bits == 0
    assert not strength.quantum_safe
    assert strength.classical_bits == 192          # the rest of the offer is still scored

    plan = roadmap(Assessment(capture="x", started="now", sessions=[sess]))
    (link,) = plan["links"]
    assert link["quantum_safe"] is False and "not credited" in link["rationale"]
    assert "Shor" not in link["rationale"]


@pytest.mark.no_model
def test_a_post_quantum_group_as_the_only_key_exchange_still_counts():
    """ML-KEM negotiated directly in type 4, the case the rule already handled."""
    suite = dict(CLASSICAL, dh=36)
    sess = _session(_init(suite, False), _init(suite, True))
    assert engine.rule_post_quantum(sess) == []
    assert sess.strength().quantum_safe and not sess.strength().hybrid


@pytest.mark.no_model
def test_ppk_counts_only_when_the_responder_agrees_to_it():
    """RFC 8784: USE_PPK from the initiator is an offer, like any other."""
    use_ppk = [16435]
    offered = _session(_init(CLASSICAL, False, use_ppk), _init(CLASSICAL, True))
    agreed = _session(_init(CLASSICAL, False, use_ppk), _init(CLASSICAL, True, use_ppk))
    assert _rule_ids(engine.rule_post_quantum(offered)) == {"IKE-007"}
    assert engine.rule_post_quantum(agreed) == []


@pytest.mark.no_model
def test_negotiated_exchange_that_was_not_observed_is_reported_as_such():
    """The selection is cleartext; the exchange that carries it out is an
    encrypted IKE_INTERMEDIATE. Seeing one without the other is said plainly,
    at a severity that changes no score."""
    sess = _hybrid_session(intermediate=False)
    assert engine.rule_post_quantum(sess) == []          # the negotiation is what is credited
    (note,) = engine.rule_additional_exchange_not_observed(sess)
    assert note.rule_id == "IKE-014" and note.severity is Severity.INFO
    assert note.inferred is False and Severity.INFO.weight == 0
    assert note.evidence == {"addke_selected": ["ADDKE1=ML-KEM-768"],
                             "intermediate_exchanges_seen": 0, "messages_seen": 2}

    assert engine.rule_additional_exchange_not_observed(_hybrid_session()) == []


# ---------------------------------------------------------------------------
# 3. Strength: a hybrid is as strong as its strongest component
# ---------------------------------------------------------------------------

AES256 = Transform(1, "ENCR", 20, "ENCR_AES_GCM_16", key_length=256)
SHA384 = Transform(2, "PRF", 6, "PRF_HMAC_SHA2_384")


def _ke(type_id: int, group: int) -> Transform:
    return Transform(type_id, C.TRANSFORM_TYPE[type_id], group,
                     str(C.DH_GROUPS.get(group, {}).get("name", f"GROUP_{group}")))


@pytest.mark.no_model
def test_hybrid_takes_the_stronger_component_against_each_adversary():
    s = score_proposal([AES256, SHA384, _ke(4, 31), _ke(6, 36)])
    assert s.hybrid and s.kex_family == "ecp+ml-kem"
    assert s.detail["key_exchange"] == 192          # ML-KEM-768, not Curve25519's 128
    assert s.kex_quantum_bits == 192
    assert s.classical_bits == 192                  # bounded by the PRF, the next link
    assert s.quantum_bits == 128 and s.quantum_safe  # AES-256 under Grover
    assert [(c["slot"], c["name"], c["classical_bits"], c["quantum_bits"])
            for c in s.kex_components] == [
        ("DH", "Curve25519", 128, 0), ("ADDKE1", "ML-KEM-768", 192, 192)]
    assert s.to_dict()["hybrid"] is True


@pytest.mark.no_model
def test_a_broken_first_exchange_does_not_cap_the_hybrid():
    """Both shared secrets go into the keys, so the attacker has to break both."""
    s = score_proposal([AES256, SHA384, _ke(4, 2), _ke(6, 37)])
    assert s.detail["key_exchange"] == 256 and s.kex_quantum_bits == 256
    assert s.classical_bits == 192


@pytest.mark.no_model
def test_every_classical_key_exchange_has_zero_quantum_strength_in_any_combination():
    """The invariant that makes the roadmap honest: no number of classical
    groups, in any slot, adds up to quantum strength. Shor breaks each."""
    classical = [g for g, (_c, _q, fam) in DH_STRENGTH.items() if fam in ("modp", "ecp")]
    assert classical and all(DH_STRENGTH[g][1] == 0 for g in classical)

    for base in classical:
        for extra in classical:
            s = score_proposal([AES256, _ke(4, base), _ke(6, extra), _ke(7, extra)])
            assert s.quantum_bits == 0 and s.kex_quantum_bits == 0, (base, extra)
            assert not s.quantum_safe
            assert s.detail["key_exchange"] == max(DH_STRENGTH[base][0], DH_STRENGTH[extra][0])


@pytest.mark.no_model
def test_an_unused_or_unknown_additional_slot_earns_nothing():
    alone = score_proposal([AES256, _ke(4, 31)])
    for extra in ([_ke(6, 0)],                       # NONE selected
                  [_ke(6, 36), _ke(6, 0)],           # optional in an offer: NONE may be chosen
                  [_ke(6, 999)]):                    # a group this tool does not know
        s = score_proposal([AES256, _ke(4, 31), *extra])
        assert (s.classical_bits, s.quantum_bits, s.kex_family, s.hybrid) == (
            alone.classical_bits, 0, "ecp", False), extra
    # and the single-exchange scoring is what it always was
    assert alone.kex_family == "ecp" and len(alone.kex_components) == 1
    assert score_proposal([AES256]).kex_components == []


# ---------------------------------------------------------------------------
# 4. Downstream: roadmap, CBOM, dashboard, glossary
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_roadmap_ranks_the_hybrid_link_as_safe_and_leaves_it_out_of_the_phases():
    from cipherguard.intel.pqc import roadmap

    hybrid = _hybrid_session()
    declined = _session(_init(dict(HYBRID, classical_fallback=True), False),
                        _init(dict(CLASSICAL, proposal_num=2), True))
    declined.peer_a, declined.peer_b = "10.9.9.1", "10.9.9.2"
    plan = roadmap(Assessment(capture="x", started="now", sessions=[hybrid, declined]))

    by_peer = {l["peer"]: l for l in plan["links"]}
    safe, exposed = by_peer[f"{A} <-> {B}"], by_peer["10.9.9.1 <-> 10.9.9.2"]
    assert safe["quantum_safe"] and safe["exposure_index"] == 0.0 and safe["hybrid"]
    assert safe["kex_family"] == "ecp+ml-kem"
    assert "hybrid of Curve25519 and ML-KEM-768" in safe["rationale"]
    assert not exposed["quantum_safe"] and exposed["exposure_index"] > 0
    assert plan["summary"]["quantum_safe"] == 1 and plan["summary"]["quantum_exposed"] == 1
    assert exposed["priority"] < safe["priority"]

    phased = [peer for ph in plan["phases"] for peer in ph["links"]]
    assert phased == ["10.9.9.1 <-> 10.9.9.2"]


@pytest.mark.no_model
def test_roadmap_does_not_tell_a_hybrid_link_to_fix_its_key_exchange():
    """A hybrid on a 128-bit cipher is short on the cipher. Blaming Shor, or
    filing it under "enable ML-KEM", would be advice it has already taken."""
    from cipherguard.intel.pqc import roadmap

    suite = dict(HYBRID, key_bits=128)
    sess = _session(_init(suite, False), _init(suite, True),
                    _intermediate(False), _intermediate(True))
    plan = roadmap(Assessment(capture="x", started="now", sessions=[sess]))
    (link,) = plan["links"]
    assert link["quantum_safe"] is False and link["kex_quantum_bits"] == 192
    assert "cipher is the limit" in link["rationale"] and "recoverable by Shor" not in link["rationale"]
    (phase,) = plan["phases"]
    assert phase["phase"] == 4 and "256-bit" in phase["action"]


@pytest.mark.no_model
def test_cbom_inventories_ml_kem_as_a_kem_and_no_empty_slot():
    from cipherguard.export.cbom import build_cbom

    selected = dict(HYBRID, addke={6: [36], 7: [0]})          # ADDKE2 explicitly NONE
    sess = _session(_init(selected, False), _init(selected, True),
                    _intermediate(False), _intermediate(True))
    bom = build_cbom(Assessment(capture="x", started="now", sessions=[sess]))
    algs = {c["name"]: c for c in bom["components"]
            if c["cryptoProperties"]["assetType"] == "algorithm"}

    assert "NONE" not in algs
    kem = algs["ML-KEM-768"]
    props = kem["cryptoProperties"]["algorithmProperties"]
    assert props["primitive"] == "kem"
    assert props["cryptoFunctions"] == ["keygen", "encapsulate", "decapsulate"]
    assert props["nistQuantumSecurityLevel"] == 3 and props["classicalSecurityLevel"] == 192
    tags = {p["name"]: p["value"] for p in kem["properties"]}
    assert tags["cipherguard:provenance"] == "observed"
    assert tags["cipherguard:transformType"] == "ADDKE1"
    assert algs["Curve25519"]["cryptoProperties"]["algorithmProperties"]["primitive"] == "key-agree"

    (proto,) = [c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "protocol"]
    ptags = {p["name"]: p["value"] for p in proto["properties"]}
    assert ptags["cipherguard:quantumSafe"] == "true"
    assert ptags["cipherguard:hybridKeyExchange"] == "Curve25519 + ML-KEM-768"
    assert ptags["cipherguard:intermediateExchangesObserved"] == "1"
    refs = proto["cryptoProperties"]["protocolProperties"]["cryptoRefArray"]
    assert kem["bom-ref"] in refs and len(refs) == len(set(refs)) == len(algs)


@needs_node
@pytest.mark.no_model
def test_dashboard_shows_the_additional_exchange_as_part_of_a_hybrid():
    js = dashboard_js()
    consts = "\n".join(re.findall(r"^const (?:BAD|BAD_HASH|WEAK_HASH|PQ_GROUPS) = .*$", js, re.M))
    got = run_node(
        consts + "\n" + "\n".join(function(n, js) for n in
                                  ("isAddKe", "pretty", "algClass", "keyExchangeLabel", "hybridNote"))
        + r"""
        const t = (type_id, type_name, value_id, name) => ({type_id, type_name, value_id, name});
        const dh = t(4, "DH", 31, "Curve25519"), kem = t(6, "ADDKE1", 36, "ML-KEM-768");
        const none = t(7, "ADDKE2", 0, "NONE"), weak = t(6, "ADDKE1", 2, "1024-bit MODP");
        process.stdout.write(JSON.stringify({
          pretty: [dh, kem, none].map(pretty),
          cls: [dh, kem, none, weak, t(4, "DH", 36, "ML-KEM-768")].map(algClass),
          label: keyExchangeLabel({transforms: [dh, kem, none]}),
          classical: keyExchangeLabel({transforms: [dh]}),
          note: hybridNote({key_exchange: {hybrid: true, intermediate_exchanges: 1}}),
          none: [hybridNote({key_exchange: {hybrid: false, intermediate_exchanges: 0}}),
                 hybridNote({})],
        }));
    """)
    assert got["pretty"] == ["Curve25519", "ADDKE1: ML-KEM-768", "ADDKE2: none"]
    assert got["cls"] == ["good", "good", "", "bad", "good"]
    assert got["label"] == "Curve25519 + ML-KEM-768" and got["classical"] == "Curve25519"
    assert got["note"] == " · hybrid key exchange, 1 IKE_INTERMEDIATE exchange observed"
    assert got["none"] == ["", ""]


@pytest.mark.no_model
def test_glossary_defines_the_new_terms():
    import json
    import os

    from tests.jsmodules import STATIC

    with open(os.path.join(STATIC, "glossary.json"), encoding="utf-8") as fh:
        terms = json.load(fh)["terms"]
    assert terms["ml-kem"]["term"] == "ML-KEM"
    assert terms["hybrid-kex"]["term"] == "Hybrid key exchange"
    assert terms["ike-intermediate"]["term"] == "IKE_INTERMEDIATE"
    # and the page marks them
    js = dashboard_js()
    for key in ("ml-kem", "hybrid-kex", "ike-intermediate"):
        assert f'"{key}"]' in js, key


# ---------------------------------------------------------------------------
# 5. Lab scenarios
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_lab_writes_both_post_quantum_scenarios(tmp_path):
    assert {"pqc_hybrid", "pqc_declined"} <= set(pcapgen.SCENARIOS)
    written = pcapgen.generate_all(str(tmp_path))
    names = sorted(p.replace("\\", "/").rsplit("/", 1)[1] for p in written)
    assert "pqc_hybrid.pcap" in names and "pqc_declined.pcap" in names
    assert len(names) == len(pcapgen.SCENARIOS)


def test_the_two_scenarios_differ_only_in_what_the_responder_selected(tmp_path):
    """Same offer on the wire, opposite verdicts: the verdict follows the
    selection, which is the point of the pair."""
    paths = {}
    for name in ("pqc_hybrid", "pqc_declined"):
        paths[name] = str(tmp_path / f"{name}.pcap")
        pcapgen.SCENARIOS[name][0](paths[name])
    hybrid, declined = (_assess(paths[n]) for n in ("pqc_hybrid", "pqc_declined"))

    def offered_addke(a):
        return [(t.type_name, t.name) for p in a.sessions[0].offered("IKE")
                for t in p.transforms if t.type_id in C.ADDKE_TRANSFORM_TYPES]

    assert offered_addke(hybrid) == offered_addke(declined) == [("ADDKE1", "ML-KEM-768")]
    assert hybrid.sessions[0].strength().quantum_safe
    assert not declined.sessions[0].strength().quantum_safe
    assert "IKE-007" not in _rule_ids(hybrid.findings)
    assert "IKE-007" in _rule_ids(declined.findings)
    assert hybrid.score() > declined.score()
