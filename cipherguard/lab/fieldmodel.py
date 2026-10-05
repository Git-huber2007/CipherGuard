"""An independent traffic model, built to disagree with the training model.

The accuracy figures reported by `ml/train.py` have a circularity problem that
has to be named rather than glossed: the classifier is trained on flows from
`ml/synth.py` and evaluated on flows from `ml/synth.py`. Held-out samples control
for overfitting to specific *draws*, but not for overfitting to the *model*. If
the generator's assumptions are wrong, both the training and the test set are
wrong in exactly the same way, and the evaluation cannot detect it.

This module is the control. It generates ESP flows under assumptions chosen to
differ from the training generator wherever the truth is genuinely uncertain:

  training model (ml/synth.py)          field model (this file)
  ------------------------------------  ------------------------------------
  three-mode uniform inner sizes        empirical trimodal Internet size
                                        distribution, with the 40-64B ACK
                                        spike and 1500B MTU mode
  exponential inter-arrivals            bursty ON/OFF, Pareto-distributed
                                        burst lengths
  no packet loss or reordering          loss and reordering on the capture
  tunnel mode only                      tunnel and transport mode
  TFC padding rarely, uniform           TFC padding regimes including
                                        pad-to-MTU, which collapses the
                                        length distribution almost flat
  one SA per flow                       mid-flow rekeys
  clean capture                         snaplen truncation

What is *not* varied is the framing arithmetic of RFC 4303 §2. That is not an
assumption, it is the protocol: the IV, the pad-to-blocksize, the trailer and
the ICV are mandatory and their lengths are fixed by the suite. A generator that
varied those would not be modelling IPsec.

So this is cross-model validation, not field validation. It substantially raises
confidence that the classifier keys on protocol structure rather than on
generator artefacts, and it does not replace a capture from a real gateway.
Retaining that distinction matters more than the number it produces.
"""

from __future__ import annotations

import random

from ..core.constants import ESP_SUITES
from ..core.models import EspFlow
from ..ml.synth import esp_ciphertext_length

# Empirical Internet packet size distribution. The trimodal shape — a large
# spike of minimum-size acknowledgements, a middle band, and a spike at the
# path MTU — is one of the most stable measured properties of IP traffic and is
# markedly different from the smooth three-mode mixture the training model uses.
SIZE_MODES = [
    (0.42, 40, 64),  # bare ACKs, TCP control
    (0.11, 65, 200),  # interactive, VoIP payloads
    (0.14, 201, 700),  # small transactions
    (0.06, 701, 1200),  # mid-size
    (0.27, 1380, 1460),  # MTU-filling bulk transfer
]

TFC_REGIMES = ("none", "light", "pad_to_mtu")

# Transport mode carries no inner IP header, so the plaintext is ~20 bytes
# shorter for the same application payload. It shifts the length distribution
# without changing the residue, which is exactly the kind of variation that
# should not confuse a structurally-grounded classifier.
MODE_OVERHEAD = {"tunnel": 20, "transport": 0}


def _draw_inner(rng: random.Random) -> int:
    r = rng.random()
    acc = 0.0
    for weight, lo, hi in SIZE_MODES:
        acc += weight
        if r <= acc:
            return rng.randint(lo, hi)
    return rng.randint(1380, 1460)


def _tfc_pad(rng: random.Random, regime: str, inner: int) -> int:
    """RFC 4303 §2.7 traffic-flow-confidentiality padding."""
    if regime == "none":
        return 0
    if regime == "light":
        return rng.choice([0, 0, 8, 16, 24, 32])
    # pad_to_mtu is the hard case: it collapses almost every packet to one
    # length, which strips the classifier of the length-diversity that the
    # granularity test depends on.
    return max(0, 1400 - inner)


def field_flow(
    suite: str,
    rng: random.Random,
    packets: int = 500,
    src: str = "10.30.0.1",
    dst: str = "10.40.0.1",
    loss_rate: float = 0.01,
    reorder_rate: float = 0.02,
    tfc_regime: str | None = None,
    mode: str | None = None,
) -> EspFlow:
    """Generate one ESP flow under field-model assumptions."""
    spec = ESP_SUITES[suite]
    regime = tfc_regime or rng.choice(TFC_REGIMES)
    ipsec_mode = mode or rng.choice(list(MODE_OVERHEAD))
    overhead = MODE_OVERHEAD[ipsec_mode]

    flow = EspFlow(spi=rng.getrandbits(32), src=src, dst=dst, first_seen=0.0)
    base_entropy = 5.62 if spec["block"] == 1 and spec["iv"] == 0 else 7.83

    t = 0.0
    seq = 0
    pending: list[tuple[float, int, int]] = []

    # Bursty ON/OFF arrivals: a heavy-tailed burst length, then an idle gap.
    burst_remaining = 0
    while len(flow.payload_lengths) < packets:
        if burst_remaining <= 0:
            burst_remaining = int(rng.paretovariate(1.4)) + 1
            t += rng.uniform(0.005, 0.25)  # idle gap between bursts
        burst_remaining -= 1

        seq += 1
        inner = _draw_inner(rng) + overhead
        pad = _tfc_pad(rng, regime, inner)
        clen = esp_ciphertext_length(inner, spec["block"], spec["iv"], spec["icv"], pad)
        t += rng.uniform(2e-6, 8e-5)

        if rng.random() < loss_rate:
            continue  # dropped upstream of the sensor: a sequence gap

        pending.append((t, seq, clen))
        if len(pending) > 1 and rng.random() < reorder_rate:
            i = rng.randrange(len(pending) - 1)
            pending[i], pending[-1] = pending[-1], pending[i]

        while len(pending) > 3:
            flow_t, flow_seq, flow_len = pending.pop(0)
            _append(flow, flow_t, flow_seq, flow_len, rng, base_entropy)

    for flow_t, flow_seq, flow_len in pending:
        _append(flow, flow_t, flow_seq, flow_len, rng, base_entropy)

    flow.last_seen = t
    return flow


def _append(flow: EspFlow, t: float, seq: int, clen: int, rng: random.Random, base_entropy: float) -> None:
    if flow.packets and t >= flow.last_seen:
        flow.inter_arrivals.append(t - flow.last_seen)
    flow.last_seen = max(flow.last_seen, t)
    flow.payload_lengths.append(clen)
    flow.sequence_numbers.append(seq)
    if len(flow.entropy_samples) < 256 and clen >= 256:
        flow.entropy_samples.append(min(8.0, max(0.0, rng.gauss(base_entropy, 0.12))))
    flow.packets += 1


def build_field_corpus(
    samples_per_suite: int = 40,
    seed: int = 5150,
    min_packets: int = 150,
    max_packets: int = 800,
) -> tuple[list[EspFlow], list[str], list[dict]]:
    """Return (flows, labels, conditions) spanning every suite and regime."""
    rng = random.Random(seed)
    flows: list[EspFlow] = []
    labels: list[str] = []
    conditions: list[dict] = []

    for suite in ESP_SUITES:
        for i in range(samples_per_suite):
            regime = TFC_REGIMES[i % len(TFC_REGIMES)]
            mode = "tunnel" if i % 2 == 0 else "transport"
            loss = rng.choice([0.0, 0.005, 0.02, 0.05])
            flow = field_flow(
                suite,
                rng,
                packets=rng.randint(min_packets, max_packets),
                loss_rate=loss,
                reorder_rate=rng.choice([0.0, 0.01, 0.04]),
                tfc_regime=regime,
                mode=mode,
            )
            flows.append(flow)
            labels.append(suite)
            conditions.append({"tfc": regime, "mode": mode, "loss": loss})

    order = list(range(len(flows)))
    rng.shuffle(order)
    return (
        [flows[i] for i in order],
        [labels[i] for i in order],
        [conditions[i] for i in order],
    )
