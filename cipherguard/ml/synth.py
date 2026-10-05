"""Reference testbed: generates labelled ESP flows for training and calibration.

Packet geometry follows RFC 4303 s2 exactly rather than being invented, so a
model trained here transfers to real captures:

    ciphertext = IV || Enc(payload || TFC pad || pad || padlen || next-header) || ICV

with the encrypted region padded up to the cipher block size, and to a 4-byte
boundary at minimum. Inner packet sizes are drawn from a three-mode mixture
(bare ACKs, interactive traffic, MTU-filling bulk) that matches what site-to-site
tunnels on a government backbone actually carry.

The timing model gives each suite a small, honest performance difference. It is
not enough to separate suites with identical framing — AES-CTR and AES-GCM-16
share IV 8 / ICV 16 / 4-byte alignment and are genuinely near-indistinguishable
on the wire. The classifier is expected to confuse them, and the audit engine
treats that ambiguity explicitly rather than papering over it.
"""

from __future__ import annotations

import random

from ..core.constants import ESP_SUITES
from ..core.models import EspFlow
from ..dissector.pcap import PcapWriter

# relative cost per byte, used only to shape inter-arrival jitter
SUITE_COST = {
    "AES-CBC-128 / HMAC-SHA1-96": 1.00,
    "AES-CBC-256 / HMAC-SHA2-256-128": 1.25,
    "AES-CTR-128 / HMAC-SHA2-256-128": 0.95,
    "AES-GCM-128 (ICV 16)": 0.55,
    "AES-GCM-256 (ICV 16)": 0.70,
    "ChaCha20-Poly1305": 0.62,
    "3DES-CBC / HMAC-MD5-96": 3.10,
    "DES-CBC / HMAC-SHA1-96": 1.45,
    "NULL encryption / HMAC-SHA1-96": 0.30,
}

PROFILES = {
    "bulk": (0.15, 0.10, 0.75),  # backup / replication link
    "interactive": (0.55, 0.35, 0.10),  # terminal, VoIP signalling
    "mixed": (0.35, 0.30, 0.35),  # ordinary branch office tunnel
}


def esp_ciphertext_length(inner: int, block: int, iv: int, icv: int, tfc_pad: int = 0) -> int:
    """Length of the ESP payload after the 8-byte SPI/sequence header."""
    alignment = max(block, 4)
    body = inner + tfc_pad + 2  # pad length byte + next header byte
    padded = -(-body // alignment) * alignment
    return iv + padded + icv


def _draw_inner(rng: random.Random, profile: tuple[float, float, float]) -> int:
    p_small, p_mid, _ = profile
    r = rng.random()
    if r < p_small:
        return rng.randint(40, 64)
    if r < p_small + p_mid:
        return rng.randint(80, 700)
    return rng.randint(1280, 1420)


def synth_flow(
    suite: str,
    rng: random.Random,
    packets: int = 600,
    profile_name: str | None = None,
    src: str = "10.10.0.1",
    dst: str = "10.20.0.1",
    spi: int | None = None,
    tfc: bool = False,
) -> EspFlow:
    """Generate one labelled ESP flow."""
    spec = ESP_SUITES[suite]
    profile = PROFILES[profile_name or rng.choice(list(PROFILES))]
    cost = SUITE_COST[suite]

    flow = EspFlow(
        spi=spi if spi is not None else rng.getrandbits(32),
        src=src,
        dst=dst,
        first_seen=0.0,
    )

    # NULL encryption leaves plaintext byte structure intact: markedly lower
    # entropy than any real cipher, which is the one thing entropy is good for.
    # Values match what the Miller-Madow estimator in dissector.esp actually
    # reports on 256-512 byte samples, not the asymptotic 8.0 / 5.5.
    base_entropy = 5.62 if spec["block"] == 1 and spec["iv"] == 0 else 7.83

    t = 0.0
    line_rate = rng.uniform(2e6, 9e7)  # bytes/sec available to this tunnel
    for i in range(packets):
        inner = _draw_inner(rng, profile)
        pad = rng.choice([0, 0, 0, 8, 16, 32]) if tfc else 0
        clen = esp_ciphertext_length(inner, spec["block"], spec["iv"], spec["icv"], pad)

        service = (clen * cost) / line_rate
        gap = max(rng.expovariate(1.0 / max(service * 4 + 2e-5, 1e-6)), 1e-6)
        t += gap

        if i:
            flow.inter_arrivals.append(gap)
        flow.payload_lengths.append(clen)
        flow.sequence_numbers.append(i + 1)
        if len(flow.entropy_samples) < 256:
            flow.entropy_samples.append(min(8.0, max(0.0, rng.gauss(base_entropy, 0.08))))
        flow.packets += 1

    flow.last_seen = t
    return flow


def build_corpus(
    samples_per_suite: int = 90,
    seed: int = 20260101,
    min_packets: int = 200,
    max_packets: int = 900,
) -> tuple[list[EspFlow], list[str]]:
    """Return (flows, labels) spanning every suite and traffic profile."""
    rng = random.Random(seed)
    flows: list[EspFlow] = []
    labels: list[str] = []
    for suite in ESP_SUITES:
        for _ in range(samples_per_suite):
            flow = synth_flow(
                suite,
                rng,
                packets=rng.randint(min_packets, max_packets),
                tfc=rng.random() < 0.15,
            )
            flows.append(flow)
            labels.append(suite)
    order = list(range(len(flows)))
    rng.shuffle(order)
    return [flows[i] for i in order], [labels[i] for i in order]


# ---------------------------------------------------------------------------
# pcap emission — the containerised strongSwan lab writes real captures, this
# writes equivalent ones offline so the pipeline is demonstrable without Docker.
# ---------------------------------------------------------------------------


def write_esp_pcap(
    path: str, suite: str, packets: int = 400, seed: int = 7, src: str = "203.0.113.10", dst: str = "198.51.100.20"
) -> str:
    rng = random.Random(seed)
    flow = synth_flow(suite, rng, packets=packets, src=src, dst=dst)
    with PcapWriter(path) as w:
        t = 1767225600.0
        for i, (clen, seq) in enumerate(zip(flow.payload_lengths, flow.sequence_numbers)):
            if i:
                t += flow.inter_arrivals[i - 1]
            w.write_esp(t, src, dst, flow.spi, seq, bytes(rng.getrandbits(8) for _ in range(clen)), ident=i)
    return path
