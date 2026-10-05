"""Robustness fuzzing.

The dissector's input is chosen by an attacker. That is not a hypothetical: the
sensor sits on a mirror port and parses whatever arrives, so anyone who can put
a packet on the segment supplies input directly to this code. A crash is a
denial of service on the monitoring itself.

Real captures also contain malformed packets for entirely innocent reasons —
snaplen truncation, mid-transfer capture start, hardware offload artefacts,
vendors that pad payloads inconsistently. A parser that raises on those is
useless in the field regardless of security.

The contract asserted here is narrow and absolute: `parse_message` either
returns a message or returns None, and records difficulties in `parse_errors`.
It never raises, never hangs, and never allocates without bound.
"""

from __future__ import annotations

import random
import struct
import time

import pytest

from cipherguard.dissector.ike import parse_message
from cipherguard.dissector.pcap import Packet
from cipherguard.lab import pcapgen

SEEDS = [
    lambda: pcapgen.ikev2_sa_init(
        b"\x01" * 8, b"\x02" * 8,
        dict(encr=20, key_bits=256, prf=5, integ=12, dh=31, esn=1), True,
        extra_notifies=[16430, 16388], vendor=b"strongSwan"),
    lambda: pcapgen.ikev2_sa_init(
        b"\x03" * 8, b"\x00" * 8,
        dict(encr=12, key_bits=128, prf=2, integ=2, dh=14, legacy_fallback=True), False),
    lambda: pcapgen.ikev2_auth(b"\x05" * 8, b"\x06" * 8, False),
    lambda: pcapgen.ikev1_message(
        b"\x07" * 8, b"\x00" * 8, 4,
        [(1, pcapgen.ikev1_sa_payload(0, 5, 1, 1, 2, 172800))]),
    # RFC 9370: additional key exchange transforms, two proposals, and the
    # encrypted IKE_INTERMEDIATE exchange that carries the extra key exchange
    lambda: pcapgen.ikev2_sa_init(
        b"\x08" * 8, b"\x00" * 8,
        dict(encr=20, key_bits=256, prf=6, dh=31, esn=1,
             addke={6: [36, 0], 7: [37]}, classical_fallback=True), False,
        extra_notifies=[16430, 16438]),
    lambda: pcapgen.ikev2_intermediate(b"\x09" * 8, b"\x0a" * 8, True, 1, 1088),
]


def _packet(payload: bytes, sport: int = 500, dport: int = 500) -> Packet:
    return Packet(frame=1, timestamp=1.0, src="10.0.0.1", dst="10.0.0.2",
                  protocol=17, sport=sport, dport=dport, payload=payload)


def _mutate(data: bytes, rng: random.Random) -> bytes:
    b = bytearray(data)
    if not b:
        return bytes(b)
    for _ in range(rng.randint(1, 6)):
        op = rng.randrange(5)
        if op == 0:                                    # flip a byte
            b[rng.randrange(len(b))] = rng.getrandbits(8)
        elif op == 1:                                  # truncate
            b = b[: rng.randrange(1, len(b) + 1)]
        elif op == 2 and len(b) > 4:                   # corrupt a length field
            off = rng.randrange(len(b) - 2)
            struct.pack_into("!H", b, off, rng.choice([0, 1, 0xFFFF, 0x7FFF]))
        elif op == 3:                                  # extend with junk
            b += bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64)))
        else:                                          # zero a run
            off = rng.randrange(len(b))
            for i in range(off, min(off + rng.randint(1, 16), len(b))):
                b[i] = 0
        if not b:
            b = bytearray(b"\x00")
    return bytes(b)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_dissector_never_raises_on_mutated_input(seed):
    rng = random.Random(seed)
    started = time.time()
    parsed = errored = 0

    for _ in range(2500):
        base = SEEDS[rng.randrange(len(SEEDS))]()
        payload = _mutate(base, rng)
        port = rng.choice([500, 4500])
        if port == 4500 and rng.random() < 0.5:
            payload = b"\x00\x00\x00\x00" + payload
        try:
            msg = parse_message(_packet(payload, port, port))
        except Exception as exc:  # the contract this file exists to enforce
            raise AssertionError(
                f"parse_message raised {type(exc).__name__}: {exc}\n"
                f"input: {payload[:96].hex()}"
            ) from exc
        if msg is not None:
            parsed += 1
            errored += bool(msg.parse_errors)

    elapsed = time.time() - started
    assert elapsed < 30, f"fuzzing 2500 inputs took {elapsed:.1f}s — possible hang"
    # A run where nothing parses would pass vacuously without exercising the
    # payload walk, which is where the interesting failures live.
    assert parsed > 100, f"only {parsed} inputs reached the parser"


def test_random_bytes_are_rejected_not_misparsed():
    """Structureless input must be refused rather than yielding a confident
    reading of fields that are not there."""
    rng = random.Random(99)
    accepted = 0
    for _ in range(4000):
        payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200)))
        msg = parse_message(_packet(payload))
        if msg is not None:
            accepted += 1
            assert msg.version in ("IKEv1", "IKEv2")
    assert accepted < 40, f"{accepted}/4000 random inputs accepted as valid IKE"


def test_esp_tracker_survives_malformed_packets():
    from cipherguard.dissector.esp import EspTracker

    rng = random.Random(7)
    tracker = EspTracker(max_flows=64)
    for _ in range(3000):
        payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 40)))
        pkt = Packet(frame=1, timestamp=rng.random(), src="10.0.0.1", dst="10.0.0.2",
                     protocol=rng.choice([50, 17]), sport=4500, dport=4500,
                     payload=payload)
        tracker.consume(pkt)
    assert len(tracker.flows) <= 64


def test_deeply_nested_payload_chain_terminates():
    """A self-referential payload chain must hit the walk guard rather than loop
    until the process is killed."""
    body = b""
    for _ in range(300):                       # 300 chained zero-progress payloads
        body += struct.pack("!BBH", 41, 0, 4)  # NOTIFY, length 4, no content
    header = (b"\x01" * 8 + b"\x02" * 8
              + struct.pack("!BBBBII", 41, 0x20, 34, 0x20, 0, 28 + len(body)))

    started = time.time()
    msg = parse_message(_packet(header + body))
    assert time.time() - started < 1.0
    assert msg is None or len(msg.notifies) < 100
