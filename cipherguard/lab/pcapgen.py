"""Reference testbed capture generator.

Builds byte-accurate IKEv1 and IKEv2 exchanges to the wire formats in RFC 2408
and RFC 7296, then writes them to pcap alongside ESP traffic. Two purposes:

  1. The dissector is validated against packets built independently from the RFC
     field layouts rather than against its own output, so a misread field shows
     up as a round-trip failure.
  2. Demonstration and grading do not require the Docker strongSwan lab, which
     needs privileged networking that a judging laptop may not have.

Scenarios mirror what these captures look like in the field: a legacy gateway
still running IKEv1 Aggressive Mode with 3DES and DH Group 2, a partially
modernised IKEv2 gateway on AES-CBC and SHA-1, and a hardened IKEv2 gateway on
AES-GCM with Curve25519.
"""

from __future__ import annotations

import os
import random
import struct

from ..core import constants as C
from ..dissector.pcap import PcapWriter
from ..ml.synth import synth_flow

BASE_TS = 1767225600.0  # 2026-01-01T00:00:00Z


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def _generic(next_payload: int, body: bytes, critical: bool = False) -> bytes:
    return struct.pack("!BBH", next_payload, 0x80 if critical else 0, len(body) + 4) + body


def _attr_tv(attr_type: int, value: int) -> bytes:
    return struct.pack("!HH", 0x8000 | attr_type, value)


def _attr_tlv(attr_type: int, value: bytes) -> bytes:
    return struct.pack("!HH", attr_type, len(value)) + value


def v2_transform(ttype: int, tid: int, last: bool, key_bits: int | None = None) -> bytes:
    attrs = _attr_tv(C.ATTR_KEY_LENGTH, key_bits) if key_bits else b""
    body = struct.pack("!BH", 0, tid) + attrs  # reserved(1) + id(2)
    return struct.pack("!BBHB", 0 if last else 3, 0, 8 + len(attrs), ttype) + body


def v2_proposal(
    num: int,
    protocol: int,
    transforms: list[bytes],
    last: bool,
    spi: bytes = b"",
) -> bytes:
    body = b"".join(transforms)
    header = struct.pack(
        "!BBHBBBB",
        0 if last else 2,
        0,
        8 + len(spi) + len(body),
        num,
        protocol,
        len(spi),
        len(transforms),
    )
    return header + spi + body


def v2_sa_payload(next_payload: int, proposals: list[bytes]) -> bytes:
    return _generic(next_payload, b"".join(proposals))


def v2_ke_payload(next_payload: int, group: int, keylen: int = 256) -> bytes:
    body = struct.pack("!HH", group, 0) + bytes(random.Random(group).getrandbits(8) for _ in range(keylen))
    return _generic(next_payload, body)


def v2_nonce(next_payload: int, size: int = 32) -> bytes:
    return _generic(next_payload, os.urandom(size))


def v2_notify(next_payload: int, ntype: int, data: bytes = b"") -> bytes:
    return _generic(next_payload, struct.pack("!BBH", 0, 0, ntype) + data)


def v2_vid(next_payload: int, vid: bytes) -> bytes:
    return _generic(next_payload, vid)


def ike_header(
    ispi: bytes,
    rspi: bytes,
    next_payload: int,
    version: int,
    exchange: int,
    flags: int,
    message_id: int,
    body_len: int,
) -> bytes:
    return (
        ispi
        + rspi
        + struct.pack(
            "!BBBBII",
            next_payload,
            version,
            exchange,
            flags,
            message_id,
            C.IKE_HEADER_LEN + body_len,
        )
    )


# ---------------------------------------------------------------------------
# IKEv2 exchanges
# ---------------------------------------------------------------------------

# transform type ids
T_ENCR, T_PRF, T_INTEG, T_DH, T_ESN = 1, 2, 3, 4, 5


# RFC 9370 s2: Additional Key Exchange 1..7 are transform types 6..12, and take
# their transform IDs from the key exchange registry that type 4 uses.
T_ADDKE1 = 6
KE_ML_KEM_768 = 36
KE_NONE = 0

# FIPS 203 sizes for ML-KEM-768: the initiator sends an encapsulation key, the
# responder answers with a ciphertext. They set the size of the encrypted
# IKE_INTERMEDIATE messages, which is all a passive observer sees of them.
ML_KEM_768_ENCAPSULATION_KEY = 1184
ML_KEM_768_CIPHERTEXT = 1088


def _suite_transforms(suite: dict, with_addke: bool = True) -> list[bytes]:
    """The transform substructures of one IKE proposal, in registry order.

    `suite["addke"]` maps an additional key exchange transform type (6-12) to
    the transform IDs listed for it. An initiator that makes the additional
    exchange optional lists the method and NONE (0); a responder lists the one
    it selected.
    """
    aead = suite["encr"] in {18, 19, 20, 28, 14, 15, 16}
    items: list[tuple[int, int, int | None]] = [(T_ENCR, suite["encr"], suite.get("key_bits"))]
    items.append((T_PRF, suite["prf"], None))
    if not aead:
        items.append((T_INTEG, suite["integ"], None))
    items.append((T_DH, suite["dh"], None))
    if with_addke:
        for ttype in sorted(suite.get("addke", {})):
            items.extend((ttype, tid, None) for tid in suite["addke"][ttype])
    items.append((T_ESN, suite.get("esn", 0), None))

    return [
        v2_transform(ttype, tid, last=(i == len(items) - 1), key_bits=bits)
        for i, (ttype, tid, bits) in enumerate(items)
    ]


def ikev2_sa_init(
    ispi: bytes,
    rspi: bytes,
    suite: dict,
    response: bool,
    extra_notifies: list[int] | None = None,
    vendor: bytes | None = None,
) -> bytes:
    """Build one IKE_SA_INIT message carrying the IKE SA proposal in the clear."""
    transforms = _suite_transforms(suite)

    # a responder echoes the number of the proposal it selected
    proposals = [v2_proposal(suite.get("proposal_num", 1), 1, transforms, last=True)]

    # RFC 9370 s2.2.2: a responder that predates the additional key exchange
    # transform types has to reject a proposal containing them, so an initiator
    # that wants to interoperate also sends the same suite without them.
    if suite.get("classical_fallback"):
        proposals = [
            v2_proposal(1, 1, transforms, last=False),
            v2_proposal(2, 1, _suite_transforms(suite, with_addke=False), last=True),
        ]

    # a legacy gateway also advertises a broken fallback proposal
    if suite.get("legacy_fallback"):
        fallback = [
            v2_transform(T_ENCR, 3, False),  # 3DES
            v2_transform(T_PRF, 1, False),  # MD5
            v2_transform(T_INTEG, 1, False),  # HMAC-MD5-96
            v2_transform(T_DH, 2, False),  # 1024-bit MODP
            v2_transform(T_ESN, 0, True),
        ]
        proposals = [
            v2_proposal(1, 1, transforms, last=False),
            v2_proposal(2, 1, fallback, last=True),
        ]

    payloads = [v2_sa_payload(C.PAYLOAD_KE_V2, proposals)]
    payloads.append(v2_ke_payload(40, suite["dh"]))  # next = NONCE

    notifies = list(extra_notifies or [])
    next_after_nonce = 41 if notifies else (43 if vendor else 0)
    payloads.append(_generic(next_after_nonce, os.urandom(32)))  # NONCE

    for i, ntype in enumerate(notifies):
        last = i == len(notifies) - 1
        nxt = 43 if (last and vendor) else (0 if last else 41)
        payloads.append(v2_notify(nxt, ntype))

    if vendor:
        payloads.append(v2_vid(0, vendor))

    body = b"".join(payloads)
    flags = C.FLAG_RESPONSE if response else C.FLAG_INITIATOR
    return ike_header(ispi, rspi, C.PAYLOAD_SA_V2, C.IKE_VERSION_2, 34, flags, 0, len(body)) + body


def ikev2_auth(ispi: bytes, rspi: bytes, response: bool, message_id: int = 1) -> bytes:
    """IKE_AUTH: everything of interest is inside the encrypted SK payload.

    This is the message that carries the Child/ESP SA proposal, and it is exactly
    why passive ESP inference is necessary — the analyzer can see that IKE_AUTH
    happened and nothing about what it agreed.

    `message_id` is 1 unless IKE_INTERMEDIATE exchanges came first, each of
    which takes the next ID (RFC 9242 s3.2).
    """
    sk_body = struct.pack("!8s", os.urandom(8)) + os.urandom(220)
    body = _generic(0, sk_body)  # payload type 46 = SK
    flags = C.FLAG_RESPONSE if response else C.FLAG_INITIATOR
    return ike_header(ispi, rspi, 46, C.IKE_VERSION_2, 35, flags, message_id, len(body)) + body


def ikev2_intermediate(ispi: bytes, rspi: bytes, response: bool, message_id: int, ke_data_len: int) -> bytes:
    """IKE_INTERMEDIATE (RFC 9242, exchange type 43) carrying one additional
    key exchange (RFC 9370 s2.2.2).

    The header is followed by a single Encrypted (SK) payload, protected with
    the keys from the first key exchange. Inside it is a KE payload holding
    `ke_data_len` bytes of key exchange data. None of that is readable without
    keys: what crosses the wire in the clear is the header, the exchange type
    and the size. The SK payload's Next Payload field names the first payload
    inside it (RFC 7296 s3.14), which is KE.
    """
    inner = 4 + 4 + ke_data_len + 1  # KE payload, then the pad-length byte
    sk_body = os.urandom(8) + os.urandom(inner) + os.urandom(16)  # IV, ciphertext, ICV
    body = _generic(C.PAYLOAD_KE_V2, sk_body)
    flags = C.FLAG_RESPONSE if response else C.FLAG_INITIATOR
    return ike_header(ispi, rspi, 46, C.IKE_VERSION_2, 43, flags, message_id, len(body)) + body


# ---------------------------------------------------------------------------
# IKEv1 exchanges
# ---------------------------------------------------------------------------


def ikev1_sa_payload(
    next_payload: int,
    encr: int,
    hash_alg: int,
    auth: int,
    group: int,
    lifetime: int,
    key_bits: int | None = None,
) -> bytes:
    attrs = (
        _attr_tv(1, encr)
        + _attr_tv(2, hash_alg)
        + _attr_tv(3, auth)
        + _attr_tv(4, group)
        + _attr_tv(11, 1)
        + _attr_tlv(12, struct.pack("!I", lifetime))
    )
    if key_bits:
        attrs += _attr_tv(14, key_bits)

    transform = struct.pack("!BBHBBH", 0, 0, 8 + len(attrs), 1, 1, 0) + attrs
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    sa_body = struct.pack("!II", 1, 1) + proposal  # DOI=IPSEC, SIT=IDENTITY_ONLY
    return _generic(next_payload, sa_body)


def ikev1_message(
    ispi: bytes,
    rspi: bytes,
    exchange: int,
    payloads: list[tuple[int, bytes]],
) -> bytes:
    """payloads is a list of (payload_type, generic-encoded bytes) in order."""
    body = b"".join(p for _, p in payloads)
    first = payloads[0][0] if payloads else 0
    return ike_header(ispi, rspi, first, C.IKE_VERSION_1, exchange, 0, 0, len(body)) + body


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

SUITE_HARDENED = dict(encr=20, key_bits=256, prf=5, integ=12, dh=31, esn=1)
SUITE_TRANSITIONAL = dict(encr=12, key_bits=128, prf=2, integ=2, dh=14, esn=0, legacy_fallback=True)
SUITE_WEAK = dict(encr=3, prf=1, integ=1, dh=2, esn=0)
# AES-GCM-256 / SHA2-384 on Curve25519, with ML-KEM-768 as Additional Key
# Exchange 1: the hybrid the roadmap recommends.
SUITE_HYBRID = dict(encr=20, key_bits=256, prf=6, dh=31, esn=1, addke={T_ADDKE1: [KE_ML_KEM_768]})
# The same suite with no additional key exchange.
SUITE_CLASSICAL_384 = dict(encr=20, key_bits=256, prf=6, dh=31, esn=1)


def _write_ike_pair(
    w: PcapWriter, t: float, a: str, b: str, req: bytes, resp: bytes, port: int = 500, ident: int = 0
) -> float:
    w.write_udp(t, a, b, port, port, req, ident)
    w.write_udp(t + 0.018, b, a, port, port, resp, ident + 1)
    return t + 0.036


# Structured filler standing in for the inner packets of an ESP-NULL tunnel:
# IP and TCP headers plus protocol text, which is what actually crosses an
# integrity-only SA. Byte entropy lands near 5.6, well under the ciphertext
# floor, which is the signal that separates ESP-NULL from a real cipher.
_PLAINTEXT_POOL = (
    b"GET /api/v2/status HTTP/1.1\r\nHost: gw-node-04.internal\r\n"
    b"User-Agent: telemetry-agent/2.1\r\nAccept: application/json\r\n"
    b"Connection: keep-alive\r\nX-Request-Id: 8f2ac41b\r\n\r\n"
    b'{"node":"gw-04","uptime":184023,"sessions":417,"queue":12,'
    b'"iface":"ge-0/0/3","rx_bytes":88123441,"tx_bytes":71220398}'
) * 24


def _esp_payload(rng: random.Random, length: int, suite: str) -> bytes:
    """Bytes with statistics faithful to the suite.

    A capture whose ESP-NULL flows are filled with random bytes is not a capture
    of an ESP-NULL flow: it silently removes the only observable that separates
    integrity-only traffic from a real cipher, and any model trained or tested
    against it learns the wrong thing.
    """
    if suite.startswith("NULL"):
        start = rng.randrange(0, max(1, len(_PLAINTEXT_POOL) - length - 1))
        body = bytearray(_PLAINTEXT_POOL[start : start + length])
        while len(body) < length:
            body += _PLAINTEXT_POOL[: length - len(body)]
        # inner IP/TCP header bytes and a sprinkle of binary fields
        for _ in range(max(1, length // 40)):
            body[rng.randrange(len(body))] = rng.getrandbits(8)
        return bytes(body)
    return bytes(rng.getrandbits(8) for _ in range(length))


def _write_esp_flow(
    w: PcapWriter,
    t: float,
    a: str,
    b: str,
    suite: str,
    rng: random.Random,
    packets: int = 400,
    profile: str | None = None,
    udp_encap: bool = False,
) -> float:
    """Write one ESP SA to the capture, returning the new clock position."""
    flow = synth_flow(suite, rng, packets=packets, src=a, dst=b, profile_name=profile)
    for i, (clen, seq) in enumerate(zip(flow.payload_lengths, flow.sequence_numbers)):
        if i:
            t += flow.inter_arrivals[i - 1]
        body = _esp_payload(rng, clen, suite)
        if udp_encap:
            w.write_udp(t, a, b, 4500, 4500, struct.pack("!II", flow.spi, seq) + body, i)
        else:
            w.write_esp(t, a, b, flow.spi, seq, body, ident=i)
    return t


def scenario_legacy(path: str) -> str:
    """IKEv1 Aggressive Mode, 3DES/MD5/PSK on Group 2, then a 3DES ESP tunnel."""
    a, b = "203.0.113.7", "198.51.100.4"
    ispi, rspi = os.urandom(8), os.urandom(8)
    rng = random.Random(11)

    sa = ikev1_sa_payload(4, encr=5, hash_alg=1, auth=1, group=2, lifetime=172800)
    ke = _generic(10, os.urandom(128))
    nonce = _generic(13, os.urandom(20))
    vid = _generic(0, bytes.fromhex("12f5f28c457168a9702d9fe274cc0100"))  # Cisco Unity

    req = ikev1_message(ispi, b"\x00" * 8, 4, [(1, sa), (4, ke), (10, nonce), (13, vid)])
    resp = ikev1_message(ispi, rspi, 4, [(1, sa), (4, ke), (10, nonce), (13, vid)])

    with PcapWriter(path) as w:
        t = _write_ike_pair(w, BASE_TS, a, b, req, resp)
        _write_esp_flow(w, t, a, b, "3DES-CBC / HMAC-MD5-96", rng, packets=520, profile="mixed")
    return path


def scenario_transitional(path: str) -> str:
    """IKEv2, AES-CBC-128/SHA-1 on Group 14, with a 3DES fallback still advertised."""
    a, b = "203.0.113.21", "198.51.100.33"
    ispi, rspi = os.urandom(8), os.urandom(8)
    rng = random.Random(23)

    req = ikev2_sa_init(
        ispi,
        b"\x00" * 8,
        SUITE_TRANSITIONAL,
        response=False,
        extra_notifies=[16388, 16389],
        vendor=bytes.fromhex("8404ad0330a7e4a41325229166d0cfff"),
    )
    resp = ikev2_sa_init(ispi, rspi, SUITE_TRANSITIONAL, response=True, extra_notifies=[16389])

    with PcapWriter(path) as w:
        t = _write_ike_pair(w, BASE_TS, a, b, req, resp)
        w.write_udp(t, a, b, 500, 500, ikev2_auth(ispi, rspi, False), 10)
        w.write_udp(t + 0.02, b, a, 500, 500, ikev2_auth(ispi, rspi, True), 11)
        t += 0.05
        _write_esp_flow(w, t, a, b, "AES-CBC-128 / HMAC-SHA1-96", rng, packets=680, profile="bulk")
    return path


def scenario_hardened(path: str) -> str:
    """IKEv2, AES-GCM-256 on Curve25519 with fragmentation, over NAT-T."""
    a, b = "203.0.113.55", "198.51.100.77"
    ispi, rspi = os.urandom(8), os.urandom(8)
    rng = random.Random(37)

    req = ikev2_sa_init(
        ispi, b"\x00" * 8, SUITE_HARDENED, response=False, extra_notifies=[16430, 16388, 16389], vendor=b"strongSwan"
    )
    resp = ikev2_sa_init(ispi, rspi, SUITE_HARDENED, response=True, extra_notifies=[16430, 16389])

    marker = b"\x00\x00\x00\x00"
    with PcapWriter(path) as w:
        t = BASE_TS
        w.write_udp(t, a, b, 4500, 4500, marker + req, 0)
        w.write_udp(t + 0.014, b, a, 4500, 4500, marker + resp, 1)
        t += 0.04
        _write_esp_flow(w, t, a, b, "AES-GCM-256 (ICV 16)", rng, packets=740, profile="mixed", udp_encap=True)
    return path


def scenario_mixed_backbone(path: str) -> str:
    """Several gateways on one mirror port, which is what a real sensor sees."""
    rng = random.Random(101)
    peers = [
        ("203.0.113.7", "198.51.100.4", "legacy"),
        ("203.0.113.21", "198.51.100.33", "transitional"),
        ("203.0.113.55", "198.51.100.77", "hardened"),
        ("203.0.113.90", "198.51.100.12", "null"),
    ]

    with PcapWriter(path) as w:
        t = BASE_TS
        for a, b, kind in peers:
            ispi, rspi = os.urandom(8), os.urandom(8)
            if kind == "legacy":
                sa = ikev1_sa_payload(4, 5, 1, 1, 2, 172800)
                ke = _generic(10, os.urandom(128))
                nonce = _generic(13, os.urandom(20))
                vid = _generic(0, bytes.fromhex("cbe7943665ff6c2cd39a11f56aad86a0"))
                req = ikev1_message(ispi, b"\x00" * 8, 4, [(1, sa), (4, ke), (10, nonce), (13, vid)])
                resp = ikev1_message(ispi, rspi, 4, [(1, sa), (4, ke), (10, nonce), (13, vid)])
                suite = "3DES-CBC / HMAC-MD5-96"
            elif kind == "transitional":
                req = ikev2_sa_init(
                    ispi,
                    b"\x00" * 8,
                    SUITE_TRANSITIONAL,
                    False,
                    [16388, 16389],
                    bytes.fromhex("0d33611a5d521b5e3c9c03d2fc107e12"),
                )
                resp = ikev2_sa_init(ispi, rspi, SUITE_TRANSITIONAL, True, [14])
                suite = "AES-CBC-128 / HMAC-SHA1-96"
            elif kind == "hardened":
                req = ikev2_sa_init(ispi, b"\x00" * 8, SUITE_HARDENED, False, [16430, 16388], b"strongSwan")
                resp = ikev2_sa_init(ispi, rspi, SUITE_HARDENED, True, [16430])
                suite = "AES-GCM-256 (ICV 16)"
            else:
                weak = dict(SUITE_WEAK)
                req = ikev2_sa_init(ispi, b"\x00" * 8, weak, False, [16388])
                resp = ikev2_sa_init(ispi, rspi, weak, True, [])
                suite = "NULL encryption / HMAC-SHA1-96"

            t = _write_ike_pair(w, t, a, b, req, resp, ident=rng.getrandbits(12))
            t = _write_esp_flow(w, t, a, b, suite, rng, packets=380)
            t += 0.5
    return path


def scenario_downgrade(path: str) -> str:
    """The same peer pair, later, negotiating markedly weaker parameters.

    This is the capture that only makes sense in sequence. On its own it looks
    like an ordinary weak gateway. Compared against a baseline that recorded the
    same pair at AES-GCM-256 / Curve25519, it is a downgrade — an on-path
    attacker stripping strong proposals, a failover onto a legacy standby, or a
    botched firmware rollback. No single-capture analysis and no configuration
    review can tell those apart from "it was always like this".

    Addresses deliberately match scenario_hardened so the pair correlates.
    """
    a, b = "203.0.113.55", "198.51.100.77"
    ispi, rspi = os.urandom(8), os.urandom(8)
    rng = random.Random(71)

    downgraded = dict(encr=12, key_bits=128, prf=2, integ=2, dh=2, esn=0)
    req = ikev2_sa_init(ispi, b"\x00" * 8, downgraded, response=False, extra_notifies=[16388], vendor=b"strongSwan")
    resp = ikev2_sa_init(ispi, rspi, downgraded, response=True, extra_notifies=[14])

    with PcapWriter(path) as w:
        t = _write_ike_pair(w, BASE_TS + 86400, a, b, req, resp)
        _write_esp_flow(w, t, a, b, "AES-CBC-128 / HMAC-SHA1-96", rng, packets=420, profile="mixed")
    return path


def scenario_pqc_hybrid(path: str) -> str:
    """IKEv2 with an RFC 9370 hybrid key exchange: Curve25519, then ML-KEM-768.

    The proposal, and the responder's selection of ML-KEM-768 as Additional Key
    Exchange 1, are in the clear in IKE_SA_INIT. The ML-KEM exchange itself runs
    in an IKE_INTERMEDIATE exchange, encrypted under the Curve25519 keys, so the
    capture shows that it took place and how large it was, and nothing else.
    IKE_AUTH follows with the next message ID.
    """
    a, b = "203.0.113.130", "198.51.100.140"
    ispi, rspi = os.urandom(8), os.urandom(8)
    rng = random.Random(53)

    # 16438 = INTERMEDIATE_EXCHANGE_SUPPORTED (RFC 9242), sent by both ends
    req = ikev2_sa_init(
        ispi,
        b"\x00" * 8,
        SUITE_HYBRID,
        response=False,
        extra_notifies=[16430, 16438, 16388, 16389],
        vendor=b"strongSwan",
    )
    resp = ikev2_sa_init(ispi, rspi, SUITE_HYBRID, response=True, extra_notifies=[16430, 16438, 16389])

    with PcapWriter(path) as w:
        t = _write_ike_pair(w, BASE_TS, a, b, req, resp)
        t = _write_ike_pair(
            w,
            t,
            a,
            b,
            ikev2_intermediate(ispi, rspi, False, 1, ML_KEM_768_ENCAPSULATION_KEY),
            ikev2_intermediate(ispi, rspi, True, 1, ML_KEM_768_CIPHERTEXT),
            ident=2,
        )
        t = _write_ike_pair(
            w, t, a, b, ikev2_auth(ispi, rspi, False, message_id=2), ikev2_auth(ispi, rspi, True, message_id=2), ident=4
        )
        _write_esp_flow(w, t + 0.02, a, b, "AES-GCM-256 (ICV 16)", rng, packets=700, profile="mixed")
    return path


def scenario_pqc_declined(path: str) -> str:
    """The same hybrid offer, to a responder that selects the classical proposal.

    The initiator sends two proposals, the hybrid and the same suite without
    the additional key exchange, as RFC 9370 s2.2.2 describes for reaching a
    responder that does not implement it. The responder picks the second. No
    IKE_INTERMEDIATE follows and the association is classical, whatever was
    offered. An analyzer that credits the offer reads this link as
    quantum-resistant; it is not.
    """
    a, b = "203.0.113.131", "198.51.100.141"
    ispi, rspi = os.urandom(8), os.urandom(8)
    rng = random.Random(59)

    offer = dict(SUITE_HYBRID, classical_fallback=True)
    selected = dict(SUITE_CLASSICAL_384, proposal_num=2)
    req = ikev2_sa_init(
        ispi, b"\x00" * 8, offer, response=False, extra_notifies=[16430, 16438, 16388, 16389], vendor=b"strongSwan"
    )
    resp = ikev2_sa_init(ispi, rspi, selected, response=True, extra_notifies=[16430, 16389])

    with PcapWriter(path) as w:
        t = _write_ike_pair(w, BASE_TS, a, b, req, resp)
        t = _write_ike_pair(w, t, a, b, ikev2_auth(ispi, rspi, False), ikev2_auth(ispi, rspi, True), ident=2)
        _write_esp_flow(w, t + 0.02, a, b, "AES-GCM-256 (ICV 16)", rng, packets=640, profile="mixed")
    return path


SCENARIOS = {
    "legacy": (scenario_legacy, "IKEv1 Aggressive Mode, 3DES/MD5/PSK, DH Group 2"),
    "transitional": (scenario_transitional, "IKEv2 AES-CBC-128/SHA-1, DH 14, 3DES fallback"),
    "hardened": (scenario_hardened, "IKEv2 AES-GCM-256, Curve25519, NAT-T"),
    "downgrade": (scenario_downgrade, "The hardened peer pair, later, renegotiated weaker"),
    "backbone": (scenario_mixed_backbone, "Four gateways on one mirror port"),
    "pqc_hybrid": (scenario_pqc_hybrid, "IKEv2 AES-GCM-256, Curve25519 + ML-KEM-768 hybrid (RFC 9370)"),
    "pqc_declined": (scenario_pqc_declined, "The same hybrid offer; the responder selects the classical proposal"),
}


def generate_all(directory: str = "samples") -> list[str]:
    os.makedirs(directory, exist_ok=True)
    written = []
    for name, (fn, _desc) in SCENARIOS.items():
        path = os.path.join(directory, f"{name}.pcap")
        fn(path)
        written.append(path)
    return written
