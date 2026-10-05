"""IKEv1 / IKEv2 dissector.

Parses only what travels in the clear: the ISAKMP header, SA proposals and their
transform substructures, KE group, notify payloads and vendor IDs. Encrypted
payloads (IKEv2 SK, IKEv1 phase-2 after the HASH) are counted, never decrypted —
the analyzer holds no keys and requests none.

  RFC 7296 s3.1-3.3  IKEv2 header, generic payload header, SA payload
  RFC 7296 s3.4/3.9  KE and Nonce payloads, reduced to digests on the way in
  RFC 9242           IKE_INTERMEDIATE exchange (recognised; its body is encrypted)
  RFC 9370 s2        additional key exchange transforms (types 6-12), IKE_FOLLOWUP_KE
  RFC 2408 s3        ISAKMP payload formats used by IKEv1
  RFC 2409 App. A    IKEv1 phase-1 SA attribute classes
  RFC 3947           UDP encapsulation and the non-ESP marker on port 4500
"""

from __future__ import annotations

import hashlib
import struct

from ..core import constants as C
from ..core.models import IkeMessage, IkeSession, Proposal, Transform
from .pcap import Packet

FLAG_V1_ENCRYPTION = 0x01  # RFC 2408 s3.1: payloads after the header are encrypted
FLAG_V1_COMMIT = 0x02
FLAG_V1_AUTH_ONLY = 0x04

NON_ESP_MARKER = b"\x00\x00\x00\x00"

# RFC 3948 s4: a NAT keepalive is a single 0xFF byte on UDP 4500. It is not IKE
# and it is not ESP, and gateways behind NAT send one every 20 seconds — on a
# real capture they are among the most numerous packets on the port.
NAT_KEEPALIVE = b"\xff"

PAYLOAD_SKF = 53  # RFC 7383 Encrypted Fragment

# IKEv2 notify types worth surfacing to the audit engine
NOTIFY_TYPES = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD",
    4: "INVALID_SYNTAX",
    7: "INVALID_KE_PAYLOAD",
    14: "NO_PROPOSAL_CHOSEN",
    17: "AUTHENTICATION_FAILED",
    24: "AUTHENTICATION_FAILED",
    34: "INVALID_SELECTORS",
    16384: "INITIAL_CONTACT",
    16385: "SET_WINDOW_SIZE",
    16386: "ADDITIONAL_TS_POSSIBLE",
    16387: "IPCOMP_SUPPORTED",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE",
    16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED",
    16393: "REKEY_SA",
    16394: "ESP_TFC_PADDING_NOT_SUPPORTED",
    16395: "NON_FIRST_FRAGMENTS_ALSO",
    16404: "MOBIKE_SUPPORTED",
    16406: "REDIRECT",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED",
    16431: "SIGNATURE_HASH_ALGORITHMS",
    16435: "USE_PPK",
    16436: "PPK_IDENTITY",
    16437: "NO_PPK_AUTH",
    16438: "INTERMEDIATE_EXCHANGE_SUPPORTED",
}


class DissectError(Exception):
    pass


# ---------------------------------------------------------------------------
# Attribute helpers
# ---------------------------------------------------------------------------


def _parse_attributes(data: bytes) -> list[tuple[int, int, bytes]]:
    """Parse a run of ISAKMP TV/TLV attributes.

    Returns (type, integer value, raw value). The top bit of the type field
    selects the short (Type/Value) form; otherwise the second field is a length.
    """
    out: list[tuple[int, int, bytes]] = []
    off = 0
    while off + 4 <= len(data):
        raw_type, second = struct.unpack_from("!HH", data, off)
        attr_type = raw_type & 0x7FFF
        if raw_type & 0x8000:
            out.append((attr_type, second, struct.pack("!H", second)))
            off += 4
        else:
            val = data[off + 4 : off + 4 + second]
            if len(val) < second:
                break
            out.append((attr_type, int.from_bytes(val, "big") if val else 0, val))
            off += 4 + second
    return out


def _fingerprint_vendor(payload: bytes) -> str:
    hexed = payload.hex().lower()
    for prefix, name in C.VENDOR_IDS.items():
        if hexed.startswith(prefix[:32]):
            return name
    # strongSwan and several open-source stacks send a printable string
    try:
        text = payload.decode("ascii")
        if text.isprintable() and 3 <= len(text) <= 40:
            return text.strip()
    except UnicodeDecodeError:
        pass
    return f"unknown:{hexed[:16]}"


def _digest(value: bytes) -> str:
    """SHA-256 of a public value or nonce. The hygiene rules only need to know
    whether two values are equal, so the bytes themselves are never kept."""
    return hashlib.sha256(value).hexdigest()


def _record_ke(value: bytes, msg: IkeMessage) -> None:
    # first KE payload only; an empty one is not a public value to compare
    if msg.ke_digest is None and value:
        msg.ke_digest = _digest(value)


def _record_nonce(value: bytes, msg: IkeMessage) -> None:
    # a zero-length nonce is recorded as length 0 (short) but has no digest,
    # so two empty payloads cannot also read as one nonce reused
    if msg.nonce_len is None:
        msg.nonce_len = len(value)
        if value:
            msg.nonce_digest = _digest(value)


# ---------------------------------------------------------------------------
# IKEv2
# ---------------------------------------------------------------------------


def _parse_v2_transforms(data: bytes, count: int, msg: IkeMessage) -> list[Transform]:
    transforms: list[Transform] = []
    off = 0
    for _ in range(count):
        if off + 8 > len(data):
            msg.parse_errors.append("truncated transform substructure")
            break
        _last, _res, tlen, ttype, _res2, tid = struct.unpack_from("!BBHBBH", data, off)
        if tlen < 8 or off + tlen > len(data):
            msg.parse_errors.append(f"bad transform length {tlen}")
            break
        attrs = _parse_attributes(data[off + 8 : off + tlen])
        key_len = next((v for t, v, _ in attrs if t == C.ATTR_KEY_LENGTH), None)

        if ttype in C.KE_TRANSFORM_TYPES:
            # the additional key exchanges of RFC 9370 (types 6-12) share the
            # key exchange registry with type 4
            name = str(C.DH_GROUPS.get(tid, {}).get("name", f"GROUP_{tid}"))
        else:
            table = C.TRANSFORM_TABLES.get(ttype)
            name = (table or {}).get(tid, f"TYPE{ttype}_ID{tid}")

        transforms.append(
            Transform(
                type_id=ttype,
                type_name=C.TRANSFORM_TYPE.get(ttype, f"TYPE_{ttype}"),
                value_id=tid,
                name=name,
                key_length=key_len,
            )
        )
        off += tlen
    return transforms


def _parse_v2_sa(data: bytes, msg: IkeMessage) -> list[Proposal]:
    proposals: list[Proposal] = []
    off = 0
    while off + 8 <= len(data):
        last, _res, plen, pnum, proto, spi_size, ntrans = struct.unpack_from(
            "!BBHBBBB", data, off
        )
        if plen < 8 or off + plen > len(data):
            msg.parse_errors.append(f"bad proposal length {plen}")
            break
        spi = data[off + 8 : off + 8 + spi_size]
        body = data[off + 8 + spi_size : off + plen]
        prop = Proposal(
            number=pnum,
            protocol_id=proto,
            protocol=C.PROTOCOL_IDS.get(proto, f"PROTO_{proto}"),
            spi=spi,
            transforms=_parse_v2_transforms(body, ntrans, msg),
        )
        proposals.append(prop)
        off += plen
        if last == 0:
            break
    return proposals


def _parse_v2_payloads(data: bytes, first: int, msg: IkeMessage) -> None:
    next_payload = first
    off = 0
    guard = 0
    while next_payload != 0 and off + 4 <= len(data) and guard < 64:
        guard += 1
        nxt, _crit, plen = struct.unpack_from("!BBH", data, off)
        if plen < 4 or off + plen > len(data):
            msg.parse_errors.append(f"truncated {C.PAYLOAD_V2.get(next_payload, next_payload)}")
            break
        body = data[off + 4 : off + plen]

        if next_payload == C.PAYLOAD_SA_V2:
            msg.proposals.extend(_parse_v2_sa(body, msg))
        elif next_payload == C.PAYLOAD_KE_V2 and len(body) >= 4:
            msg.ke_group = struct.unpack_from("!H", body, 0)[0]
            # RFC 7296 s3.4: group (2), reserved (2), then the public value
            _record_ke(body[4:], msg)
        elif next_payload == C.PAYLOAD_NONCE_V2:
            _record_nonce(body, msg)
        elif next_payload == C.PAYLOAD_NOTIFY_V2 and len(body) >= 4:
            _proto, spi_size, ntype = struct.unpack_from("!BBH", body, 0)
            label = NOTIFY_TYPES.get(ntype, f"NOTIFY_{ntype}")
            if label not in msg.notifies:
                msg.notifies.append(label)
            if ntype in (16388, 16389):
                msg.natt = True
        elif next_payload == C.PAYLOAD_VID_V2:
            vid = _fingerprint_vendor(body)
            if vid not in msg.vendor_ids:
                msg.vendor_ids.append(vid)
        elif next_payload == 46:  # SK — encrypted, stop here by design
            msg.encrypted = True
            break
        elif next_payload == PAYLOAD_SKF and len(body) >= 4:
            # RFC 7383 fragmentation. Certificate-bearing IKE_AUTH exchanges are
            # routinely fragmented in the field, and a dissector that does not
            # recognise the payload type reports the message as malformed. The
            # content is encrypted either way, so there is nothing to reassemble
            # without keys — what matters is recording that it happened rather
            # than logging a parse error against a perfectly valid exchange.
            frag_num, total = struct.unpack_from("!HH", body, 0)
            msg.encrypted = True
            msg.fragment = (frag_num, total)
            break

        off += plen
        next_payload = nxt


# ---------------------------------------------------------------------------
# IKEv1
# ---------------------------------------------------------------------------


def _parse_v1_transform(data: bytes, msg: IkeMessage) -> tuple[Transform, ...] | None:
    """IKEv1 bundles the whole phase-1 suite into attributes of one transform."""
    if len(data) < 4:
        return None
    attrs = _parse_attributes(data[4:])
    lookup = {t: v for t, v, _ in attrs}

    encr = C.V1_ENCR.get(lookup.get(1, -1), f"ENCR_{lookup.get(1)}")
    key_len = lookup.get(14)
    hash_alg = C.V1_HASH.get(lookup.get(2, -1), f"HASH_{lookup.get(2)}")
    auth = C.V1_AUTH.get(lookup.get(3, -1), f"AUTH_{lookup.get(3)}")
    group = lookup.get(4)

    msg.auth_method = auth
    if lookup.get(11) == 1 and 12 in lookup:
        msg.lifetime_seconds = lookup[12]
    if group is not None:
        msg.ke_group = group

    return Transform(
        type_id=1,
        type_name="ENCR",
        value_id=lookup.get(1, 0),
        name=encr,
        key_length=key_len,
    ), Transform(
        type_id=2,
        type_name="PRF",
        value_id=lookup.get(2, 0),
        name=f"PRF_HMAC_{hash_alg}",
    ), Transform(
        type_id=3,
        type_name="INTEG",
        value_id=lookup.get(2, 0),
        name=f"AUTH_HMAC_{hash_alg}",
    ), Transform(
        type_id=4,
        type_name="DH",
        value_id=group or 0,
        name=str(C.DH_GROUPS.get(group or 0, {}).get("name", f"GROUP_{group}")),
    )


def _parse_v1_sa(data: bytes, msg: IkeMessage) -> list[Proposal]:
    if len(data) < 8:
        return []
    proposals: list[Proposal] = []
    off = 8  # DOI (4) + Situation (4)
    guard = 0
    while off + 8 <= len(data) and guard < 32:
        guard += 1
        _nxt, _res, plen, pnum, proto, spi_size, ntrans = struct.unpack_from(
            "!BBHBBBB", data, off
        )
        if plen < 8 or off + plen > len(data):
            msg.parse_errors.append("truncated IKEv1 proposal")
            break
        spi = data[off + 8 : off + 8 + spi_size]
        body = data[off + 8 + spi_size : off + plen]
        prop = Proposal(
            number=pnum,
            protocol_id=proto,
            protocol=C.PROTOCOL_IDS.get(proto, f"PROTO_{proto}"),
            spi=spi,
        )
        toff = 0
        for _ in range(ntrans):
            if toff + 8 > len(body):
                break
            _tn, _tr, tlen = struct.unpack_from("!BBH", body, toff)
            if tlen < 8 or toff + tlen > len(body):
                break
            parsed = _parse_v1_transform(body[toff + 4 : toff + tlen], msg)
            if parsed:
                prop.transforms.extend(parsed)
            toff += tlen
        proposals.append(prop)
        off += plen
    return proposals


def _parse_v1_payloads(data: bytes, first: int, msg: IkeMessage) -> None:
    next_payload = first
    off = 0
    guard = 0
    while next_payload != 0 and off + 4 <= len(data) and guard < 64:
        guard += 1
        nxt, _res, plen = struct.unpack_from("!BBH", data, off)
        if plen < 4 or off + plen > len(data):
            msg.parse_errors.append("truncated IKEv1 payload")
            break
        body = data[off + 4 : off + plen]

        if next_payload == C.PAYLOAD_SA_V1:
            msg.proposals.extend(_parse_v1_sa(body, msg))
        elif next_payload == C.PAYLOAD_VID_V1:
            vid = _fingerprint_vendor(body)
            if vid not in msg.vendor_ids:
                msg.vendor_ids.append(vid)
        elif next_payload == C.PAYLOAD_KE_V1:
            # IKEv1 carries the group in the SA attributes, not the KE payload;
            # the KE body is the public value alone (RFC 2408 s3.7)
            _record_ke(body, msg)
        elif next_payload == C.PAYLOAD_NONCE_V1:
            _record_nonce(body, msg)

        off += plen
        next_payload = nxt


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def parse_message(pkt: Packet) -> IkeMessage | None:
    """Dissect one UDP datagram as IKE. Returns None if it is not IKE."""
    data = pkt.payload

    # RFC 3947: on port 4500 a four-zero-byte marker distinguishes IKE from ESP
    if pkt.dport == 4500 or pkt.sport == 4500:
        if data == NAT_KEEPALIVE:
            return None
        if data[:4] == NON_ESP_MARKER:
            data = data[4:]
        else:
            return None

    if len(data) < C.IKE_HEADER_LEN:
        return None

    ispi = data[0:8]
    rspi = data[8:16]
    next_payload, version, exch, flags, msgid, length = struct.unpack_from(
        "!BBBBII", data, 16
    )

    if version not in (C.IKE_VERSION_1, C.IKE_VERSION_2):
        return None
    if length < C.IKE_HEADER_LEN or length > 0x40000:
        return None
    if ispi == b"\x00" * 8:
        return None

    is_v2 = version == C.IKE_VERSION_2
    exch_name = (C.EXCHANGE_TYPES_V2 if is_v2 else C.EXCHANGE_TYPES_V1).get(
        exch, f"EXCHANGE_{exch}"
    )
    if is_v2 and exch not in C.EXCHANGE_TYPES_V2:
        return None

    msg = IkeMessage(
        frame=pkt.frame,
        timestamp=pkt.timestamp,
        src=pkt.src,
        dst=pkt.dst,
        sport=pkt.sport,
        dport=pkt.dport,
        version="IKEv2" if is_v2 else "IKEv1",
        exchange=exch_name,
        initiator_spi=ispi,
        responder_spi=rspi,
        message_id=msgid,
        is_initiator=bool(flags & C.FLAG_INITIATOR) if is_v2 else rspi == b"\x00" * 8,
        is_response=bool(flags & C.FLAG_RESPONSE) if is_v2 else rspi != b"\x00" * 8,
        natt=pkt.dport == 4500 or pkt.sport == 4500,
    )

    body = data[C.IKE_HEADER_LEN : min(length, len(data))]
    if pkt.truncated:
        msg.parse_errors.append("snaplen-truncated frame")

    # IKEv1 Main Mode encrypts everything after the header from message five
    # onward, signalled by the Encryption bit rather than by a distinct payload
    # type as IKEv2 does with SK. Without this check the walker treats
    # ciphertext as a payload chain and reports a parse error against a
    # perfectly valid exchange — which is exactly what real Windows and
    # strongSwan captures produced, while synthetic ones never could, because
    # the generator only ever emitted cleartext Main Mode.
    if not is_v2 and (flags & FLAG_V1_ENCRYPTION):
        msg.encrypted = True
        return msg

    try:
        if is_v2:
            _parse_v2_payloads(body, next_payload, msg)
        else:
            _parse_v1_payloads(body, next_payload, msg)
    except (struct.error, IndexError) as exc:
        msg.parse_errors.append(f"payload walk aborted: {exc}")

    return msg


def is_ike_port(pkt: Packet) -> bool:
    return pkt.protocol == 17 and (
        pkt.sport in (500, 4500) or pkt.dport in (500, 4500)
    )


def group_sessions(messages: list[IkeMessage]) -> list[IkeSession]:
    """Correlate messages into IKE SAs keyed on the initiator SPI."""
    sessions: dict[bytes, IkeSession] = {}
    seen: dict[bytes, set[tuple[int, bool, str]]] = {}
    for msg in messages:
        sess = sessions.get(msg.initiator_spi)
        if sess is None:
            sess = IkeSession(
                initiator_spi=msg.initiator_spi,
                responder_spi=msg.responder_spi,
                version=msg.version,
                peer_a=msg.src,
                peer_b=msg.dst,
            )
            sessions[msg.initiator_spi] = sess
        if sess.responder_spi == b"\x00" * 8 and msg.responder_spi != b"\x00" * 8:
            sess.responder_spi = msg.responder_spi
        # Retransmissions are normal on a lossy path and pathological in volume.
        # Counting them separately keeps a repeated IKE_SA_INIT from being read
        # as many distinct negotiations, which would inflate every per-message
        # statistic on exactly the links that are already unhealthy.
        fingerprint = (msg.message_id, msg.is_response, msg.exchange)
        bucket = seen.setdefault(msg.initiator_spi, set())
        if fingerprint in bucket:
            sess.retransmissions += 1
        else:
            bucket.add(fingerprint)
        sess.messages.append(msg)
        for prop in msg.proposals:
            if prop.protocol == "ESP" and prop.spi:
                spi_hex = prop.spi.hex()
                if spi_hex not in sess.child_sa_spis:
                    sess.child_sa_spis.append(spi_hex)
    for sess in sessions.values():
        sess.messages.sort(key=lambda m: (m.timestamp, m.frame))
    return list(sessions.values())
