"""Cryptographic Bill of Materials (CBOM) export, CycloneDX 1.6.

A finding is a message to a human. A CBOM is an artefact a fleet can be queried
against: "which of our four hundred links still use a 64-bit block cipher" should
be a database question, not a re-scan.

CycloneDX 1.6 added first-class cryptographic assets precisely because the PQC
migration mandates require organisations to inventory their cryptography. Every
existing CBOM generator derives that inventory from *source code or binaries* —
it tells you what a device is capable of. This one derives it from observed
traffic, which tells you what a device is actually doing. Those differ constantly
in practice: a gateway compiled with AES-GCM support that negotiates 3DES because
of a stale peer policy is invisible to a source-derived CBOM and obvious here.

Each asset carries its provenance, because the distinction matters downstream as
much as it does in the dashboard: assets parsed from cleartext headers are
asserted, assets inferred from ESP framing carry a confidence and a candidate
set.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .. import __version__
from ..audit.policy import framing_class_of
from ..core import constants as C
from ..core.models import Assessment
from ..core.strength import DH_STRENGTH

SPEC_VERSION = "1.6"


# NIST PQC security categories, used for the quantumSecurityLevel field.
def _nist_level(classical_bits: int, quantum_bits: int) -> int:
    if quantum_bits >= 256:
        return 5
    if quantum_bits >= 192:
        return 3
    if quantum_bits >= 128:
        return 1
    return 0


PRIMITIVE = {
    1: "block-cipher",
    2: "prf",
    3: "mac",
    4: "key-agree",
}

CRYPTO_FUNCTIONS = {
    1: ["encrypt", "decrypt"],
    2: ["generate"],
    3: ["tag", "verify"],
    4: ["keygen", "key-derive"],
}

# ML-KEM is a key-encapsulation mechanism, which CycloneDX inventories as its
# own primitive with its own functions, whichever transform type carried it.
KEM_FUNCTIONS = ["keygen", "encapsulate", "decapsulate"]


def _in_use(transforms) -> list:
    """Transforms that name an algorithm actually in use.

    An RFC 9370 additional key exchange set to NONE is an empty slot, and an
    inventory entry for "NONE" would be an asset that does not exist.
    """
    return [t for t in transforms if not (t.type_id in C.ADDKE_TRANSFORM_TYPES and t.value_id == 0)]


def _bom_ref(*parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
    return f"crypto:{digest}"


def _algorithm_component(name: str, transform, peer: str, sess) -> dict:
    """One cryptographic-asset component for a negotiated transform."""
    tid = transform.type_id
    param = str(transform.key_length) if transform.key_length else None
    # type 4 and the RFC 9370 additional key exchanges (6-12) are all key
    # establishment, drawn from one registry
    is_kex = tid in C.KE_TRANSFORM_TYPES
    if is_kex:
        classical, quantum, family = DH_STRENGTH.get(transform.value_id, (0, 0, "unknown"))
        param = C.DH_GROUPS.get(transform.value_id, {}).get("name")
    else:
        classical = quantum = 0
        family = None
    is_kem = family == "ml-kem"

    props: dict[str, Any] = {
        "primitive": "kem" if is_kem else PRIMITIVE.get(4 if is_kex else tid, "other"),
        "executionEnvironment": "hardware" if sess.vendor_family() in ("cisco", "juniper", "fortinet") else "software",
        "implementationPlatform": "generic",
        "cryptoFunctions": KEM_FUNCTIONS if is_kem else CRYPTO_FUNCTIONS.get(4 if is_kex else tid, ["other"]),
    }
    if param:
        props["parameterSetIdentifier"] = param
    if is_kex:
        props["nistQuantumSecurityLevel"] = _nist_level(classical, quantum)
        props["classicalSecurityLevel"] = classical

    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref("alg", name, peer),
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": props,
            "oid": _OIDS.get(name),
        },
        "properties": [
            {"name": "cipherguard:provenance", "value": "observed"},
            {"name": "cipherguard:source", "value": "IKE cleartext header"},
            {"name": "cipherguard:peer", "value": peer},
            {"name": "cipherguard:transformType", "value": transform.type_name},
        ],
    }


# A small set of the OIDs that actually appear in IPsec negotiation. Absent
# entries are emitted as null rather than guessed, since a wrong OID in an
# inventory is worse than a missing one.
_OIDS = {
    "ENCR_AES_CBC": "2.16.840.1.101.3.4.1.2",
    "ENCR_AES_GCM_16": "2.16.840.1.101.3.4.1.6",
    "ENCR_3DES": "1.2.840.113549.3.7",
    "ENCR_DES": "1.3.14.3.2.7",
    "PRF_HMAC_SHA2_256": "1.2.840.113549.2.9",
    "PRF_HMAC_SHA1": "1.2.840.113549.2.7",
    "AUTH_HMAC_SHA2_256_128": "1.2.840.113549.2.9",
    "AUTH_HMAC_SHA1_96": "1.2.840.113549.2.7",
    "AUTH_HMAC_MD5_96": "1.2.840.113549.2.6",
}


def _protocol_component(sess, assessment: Assessment) -> dict:
    prop = sess.negotiated("IKE")
    # the session's figure, which gives an unanswered offer no post-quantum credit
    strength = sess.strength() if prop else None
    peer = f"{sess.peer_a} <-> {sess.peer_b}"

    props = [
        {"name": "cipherguard:provenance", "value": "observed"},
        {"name": "cipherguard:vendorFamily", "value": sess.vendor_family()},
        {"name": "cipherguard:peer", "value": peer},
    ]
    if strength:
        props += [
            {"name": "cipherguard:classicalSecurityBits", "value": str(strength.classical_bits)},
            {"name": "cipherguard:quantumSecurityBits", "value": str(strength.quantum_bits)},
            {"name": "cipherguard:quantumSafe", "value": "true" if strength.quantum_safe else "false"},
            {"name": "cipherguard:responderConfirmed", "value": "true" if sess.is_confirmed("IKE") else "false"},
        ]
        if strength.hybrid:
            kex = sess.key_exchange()
            props += [
                {
                    "name": "cipherguard:hybridKeyExchange",
                    "value": " + ".join(c["name"] for c in strength.kex_components),
                },
                # the additional exchanges are encrypted; this is how many of
                # the exchanges that carry them were seen, and nothing more
                {"name": "cipherguard:intermediateExchangesObserved", "value": str(kex["intermediate_exchanges"])},
            ]

    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref("proto", peer, sess.version),
        "name": f"IPsec {sess.version} — {peer}",
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": {
                "type": "ipsec",
                "version": "2.0" if sess.version == "IKEv2" else "1.0",
                "cryptoRefArray": [_bom_ref("alg", t.label(), peer) for t in _in_use(prop.transforms if prop else [])],
            },
        },
        "properties": props,
    }


def _esp_component(flow) -> dict:
    """An inferred asset. Provenance and confidence are mandatory here — an
    inventory that cannot distinguish measurement from inference is misleading
    exactly where it is most consequential."""
    cls_name, spec = framing_class_of(flow.predicted_suite or "")
    candidates = spec["members"] if spec else [flow.predicted_suite or "unknown"]

    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref("esp", flow.key),
        "name": f"ESP SA {flow.spi:#010x} — {cls_name or 'unclassified'}",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "ae",
                "executionEnvironment": "unknown",
                "implementationPlatform": "generic",
                "cryptoFunctions": ["encrypt", "decrypt"],
            },
        },
        "properties": [
            {"name": "cipherguard:provenance", "value": "inferred"},
            {"name": "cipherguard:source", "value": "RFC 4303 framing analysis"},
            {"name": "cipherguard:confidence", "value": f"{flow.confidence:.3f}"},
            {"name": "cipherguard:candidates", "value": ", ".join(candidates)},
            {"name": "cipherguard:framingSignature", "value": spec["signature"] if spec else "unknown"},
            {"name": "cipherguard:packetsObserved", "value": str(flow.packets)},
            {"name": "cipherguard:peer", "value": f"{flow.src} -> {flow.dst}"},
        ],
    }


def build_cbom(assessment: Assessment, serial: str | None = None) -> dict:
    """Assemble a CycloneDX 1.6 CBOM from an assessment."""
    components: list[dict] = []
    seen: set[str] = set()

    for sess in assessment.sessions:
        peer = f"{sess.peer_a} <-> {sess.peer_b}"
        components.append(_protocol_component(sess, assessment))
        prop = sess.negotiated("IKE")
        for transform in _in_use(prop.transforms if prop else []):
            ref = _bom_ref("alg", transform.label(), peer)
            if ref in seen:
                continue
            seen.add(ref)
            components.append(_algorithm_component(transform.label(), transform, peer, sess))

    for flow in assessment.flows:
        if flow.predicted_suite:
            components.append(_esp_component(flow))

    vulnerabilities = []
    for f in assessment.findings:
        if f.severity.value in ("critical", "high"):
            vulnerabilities.append(
                {
                    "bom-ref": _bom_ref("vuln", f.rule_id, f.subject),
                    "id": f.rule_id,
                    "source": {"name": "CipherGuard"},
                    "ratings": [{"severity": f.severity.value, "method": "other"}],
                    "description": f.title,
                    "detail": f.detail,
                    "recommendation": f.remediation,
                    "properties": [
                        {"name": "cipherguard:provenance", "value": "inferred" if f.inferred else "observed"},
                        {"name": "cipherguard:reference", "value": f.reference},
                    ],
                }
            )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "CipherGuard",
                        "version": __version__,
                        "description": ("Passive IPsec cryptographic inventory derived from observed network traffic"),
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": _bom_ref("capture", assessment.capture),
                "name": f"IPsec deployment observed in {assessment.capture}",
            },
            "properties": [
                {"name": "cipherguard:postureScore", "value": str(assessment.score())},
                {"name": "cipherguard:grade", "value": assessment.grade()},
                {"name": "cipherguard:derivation", "value": "passive-traffic"},
            ],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def to_json(assessment: Assessment, indent: int = 2) -> str:
    return json.dumps(build_cbom(assessment), indent=indent)
