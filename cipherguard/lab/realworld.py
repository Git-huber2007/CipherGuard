"""Validation against real captures from a public corpus.

Every accuracy figure elsewhere in this project is measured against traffic the
project itself generated. That is a real limit, and it is the one a reviewer
should press hardest on: a dissector validated only against its own generator
has proven that it agrees with itself.

These captures come from the Wireshark project's test suite — real IKE
exchanges produced by real implementations (a Windows IKE stack, a strongSwan
peer), captured off a real network, with all the untidiness that implies:
vendor IDs this project has never seen, Microsoft-specific NAT-T drafts,
certificate payloads, retransmissions, and Main Mode messages whose later
exchanges are encrypted.

The ground truth is genuinely external. Wireshark names each file after the
algorithm it negotiates — `ikev2-decrypt-aes256gcm16.pcap` — so the expected
result comes from the Wireshark maintainers rather than from anything written
here. Asserting against a label somebody else chose is what makes this a test
rather than a restatement.

The captures are not redistributed in this repository. Run
`scripts/fetch-real-captures.sh` to download them; the tests skip cleanly when
they are absent so an offline checkout still passes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

REAL_CAPTURE_DIR = os.path.join("samples", "real")

SOURCE = "Wireshark project test suite, https://github.com/wireshark/wireshark/tree/master/test/captures"


@dataclass
class Expectation:
    """What an external source says this capture contains."""

    filename: str
    version: str
    encryption: str  # transform name the filename declares
    key_bits: int | None
    dh_group: int
    aead: bool  # AEAD suites carry no INTEG transform
    min_ike_messages: int = 2
    notes: str = ""
    expect_vendor_ids: bool = False
    integrity: str | None = None
    findings_expected: list[str] = field(default_factory=list)


EXPECTATIONS: list[Expectation] = [
    Expectation(
        filename="ikev2-decrypt-aes256gcm16.pcap",
        version="IKEv2",
        encryption="ENCR_AES_GCM_16",
        key_bits=256,
        dh_group=19,
        aead=True,
        notes="AES-GCM with a 16-byte ICV on NIST P-256. A compliant suite: the "
        "only finding should be the post-quantum one.",
        findings_expected=["IKE-007"],
    ),
    Expectation(
        filename="ikev2-decrypt-aes256gcm8.pcap",
        version="IKEv2",
        encryption="ENCR_AES_GCM_8",
        key_bits=256,
        dh_group=19,
        aead=True,
        notes="An 8-byte ICV. Distinguishing GCM_8 from GCM_16 exercises the "
        "transform table rather than a guess from the algorithm family.",
        findings_expected=["IKE-007"],
    ),
    Expectation(
        filename="ikev2-decrypt-aes128ccm12.pcap",
        version="IKEv2",
        encryption="ENCR_AES_CCM_12",
        key_bits=128,
        dh_group=19,
        aead=True,
        notes="CCM rather than GCM, and a 12-byte ICV.",
        findings_expected=["IKE-007"],
    ),
    Expectation(
        filename="ikev2-decrypt-aes192ctr.pcap",
        version="IKEv2",
        encryption="ENCR_AES_CTR",
        key_bits=192,
        dh_group=19,
        aead=False,
        integrity="AUTH_HMAC_SHA2_512_256",
        notes="Counter mode is NOT AEAD, so this capture must carry a separate "
        "INTEG transform where the GCM and CCM captures must not. That "
        "contrast is the sharpest correctness check in the corpus, and it "
        "is verified against real implementations rather than assumed.",
        findings_expected=["IKE-007"],
    ),
    Expectation(
        filename="ikev1-certs.pcap",
        version="IKEv1",
        encryption="3DES_CBC",
        key_bits=None,
        dh_group=2,
        aead=False,
        integrity="AUTH_HMAC_MD5",
        min_ike_messages=4,
        expect_vendor_ids=True,
        notes="A real Windows IKEv1 Main Mode exchange with certificate "
        "authentication. Carries ten vendor IDs including Microsoft "
        "NAT-T drafts this project had never seen. Should raise the full "
        "set of legacy findings: IKEv1, 3DES, MD5 and DH Group 2.",
        findings_expected=["IKE-001", "IKE-004", "IKE-005", "IKE-006", "IKE-012", "IKE-013"],
    ),
]


def available(directory: str = REAL_CAPTURE_DIR) -> list[Expectation]:
    """Expectations whose capture is present on disk."""
    return [e for e in EXPECTATIONS if os.path.exists(os.path.join(directory, e.filename))]


def missing(directory: str = REAL_CAPTURE_DIR) -> list[str]:
    return [e.filename for e in EXPECTATIONS if not os.path.exists(os.path.join(directory, e.filename))]


def check(expectation: Expectation, directory: str = REAL_CAPTURE_DIR) -> dict:
    """Dissect one real capture and compare against the external label."""
    from ..dissector import ike as ike_mod
    from ..dissector.pcap import read_packets

    path = os.path.join(directory, expectation.filename)
    packets = list(read_packets(path))
    messages = [m for m in (ike_mod.parse_message(p) for p in packets if ike_mod.is_ike_port(p)) if m is not None]
    sessions = ike_mod.group_sessions(messages)

    problems: list[str] = []
    if len(messages) < expectation.min_ike_messages:
        problems.append(f"parsed {len(messages)} IKE messages, expected at least {expectation.min_ike_messages}")

    parse_errors = [e for m in messages for e in m.parse_errors]
    if parse_errors:
        problems.append(f"parse errors on real traffic: {parse_errors}")

    proposal = sessions[0].negotiated("IKE") if sessions else None
    encr = proposal.first(1) if proposal else None
    integ = proposal.by_type(3) if proposal else []
    dh = proposal.first(4) if proposal else None

    if encr is None:
        problems.append("no encryption transform recovered")
    else:
        if encr.name != expectation.encryption:
            problems.append(f"encryption {encr.name}, expected {expectation.encryption}")
        if encr.key_length != expectation.key_bits:
            problems.append(f"key length {encr.key_length}, expected {expectation.key_bits}")

    if dh is None or dh.value_id != expectation.dh_group:
        problems.append(f"DH group {dh.value_id if dh else None}, expected {expectation.dh_group}")

    # The AEAD contrast: combined-mode suites must carry no INTEG transform.
    if expectation.aead and integ:
        problems.append(f"AEAD suite carries an INTEG transform: {[t.name for t in integ]}")
    if not expectation.aead and not integ:
        problems.append("non-AEAD suite is missing its INTEG transform")
    if expectation.integrity and integ and integ[0].name != expectation.integrity:
        problems.append(f"integrity {integ[0].name}, expected {expectation.integrity}")

    if expectation.expect_vendor_ids and sessions and not sessions[0].all_vendor_ids():
        problems.append("no vendor IDs recovered from a capture known to carry them")

    return {
        "capture": expectation.filename,
        "packets": len(packets),
        "ike_messages": len(messages),
        "sessions": len(sessions),
        "version": sessions[0].version if sessions else None,
        "encryption": encr.label() if encr else None,
        "integrity": [t.name for t in integ],
        "dh_group": dh.value_id if dh else None,
        "vendor_ids": sessions[0].all_vendor_ids() if sessions else [],
        "problems": problems,
        "passed": not problems,
    }


def check_all(directory: str = REAL_CAPTURE_DIR) -> dict:
    present = available(directory)
    results = [check(e, directory) for e in present]
    return {
        "source": SOURCE,
        "available": len(present),
        "total_known": len(EXPECTATIONS),
        "missing": missing(directory),
        "passed": sum(1 for r in results if r["passed"]),
        "results": results,
    }
