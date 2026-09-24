"""RFC 4303 framing arithmetic, with every step recorded.

This is the deterministic half of ESP inference: hard constraints that follow
from how ESP pads and frames ciphertext, applied to lengths a reviewer can read
straight off the capture. It needs no model and no training data, and it is
kept apart from the learned models so that its output can be checked by hand.

`evaluate` returns the whole working rather than a verdict: the residue
histograms the constraints read, the padding granularity, which constraint
eliminated each catalogued suite and in what order, and which tests could not
run. `ml.classifier.plausibility` derives its mask from the same trace, so the
arithmetic the dashboard shows is the arithmetic that was actually applied.

Pure Python on purpose. It runs inside `EspFlow.to_dict`, which must work
whether or not a model is loaded.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

from .constants import ESP_SUITES

if TYPE_CHECKING:
    from .models import EspFlow

MIN_CIPHERTEXT_ENTROPY = 6.8  # below this, the payload is not cipher output
MAX_PLAINTEXT_ENTROPY = 7.2   # above this, the payload is not plaintext
MIN_ENTROPY_SAMPLES = 12
MIN_DISTINCT_FOR_GRANULARITY = 8
RESIDUE_AGREEMENT = 0.90
RESIDUE_MODULI = (4, 8, 16)

# In the order they are applied. The first constraint a suite fails is the one
# that eliminates it; later constraints are not evaluated for that suite.
CONSTRAINTS = [
    {
        "id": "granularity",
        "step": 1,
        "title": "Padding boundary",
        "rule": "The GCD of the gaps between distinct ciphertext lengths is the "
                "padding boundary, and it must equal the suite's max(block, 4).",
    },
    {
        "id": "residue",
        "step": 2,
        "title": "Length residue",
        "rule": "Every ciphertext length satisfies len mod boundary == "
                f"(IV + ICV) mod boundary; at least {RESIDUE_AGREEMENT:.0%} must agree.",
    },
    {
        "id": "overhead",
        "step": 3,
        "title": "Minimum size",
        "rule": "The shortest ciphertext must hold the suite's IV and ICV plus "
                "4 bytes of padding, pad length and next header.",
    },
    {
        "id": "entropy",
        "step": 4,
        "title": "Payload entropy",
        "rule": f"Encrypting suites need mean entropy of at least "
                f"{MIN_CIPHERTEXT_ENTROPY} bits/byte; ESP-NULL must not exceed "
                f"{MAX_PLAINTEXT_ENTROPY}.",
    },
]
_STEP = {c["id"]: c["step"] for c in CONSTRAINTS}


def boundary(suite: str) -> int:
    """The padding boundary RFC 4303 imposes: the block size, 4 at minimum."""
    return max(ESP_SUITES[suite]["block"], 4)


def expected_residue(suite: str) -> int:
    spec = ESP_SUITES[suite]
    return (spec["iv"] + spec["icv"]) % boundary(suite)


def residue_histogram(lengths: list[int], modulus: int) -> list[int]:
    counts = [0] * modulus
    for n in lengths:
        counts[n % modulus] += 1
    return counts


def length_granularity(lengths: list[int]) -> tuple[int, int]:
    """(granularity, distinct lengths): the GCD of gaps between distinct lengths."""
    distinct = sorted(set(lengths))
    g = 0
    for a, b in zip(distinct, distinct[1:]):
        g = math.gcd(g, b - a)
    return g, len(distinct)


def mean_entropy(samples: list[float]) -> float | None:
    if len(samples) < MIN_ENTROPY_SAMPLES:
        return None
    return sum(samples) / len(samples)


def _note(kind: str, test: str | None, text: str) -> dict:
    return {"kind": kind, "test": test, "text": text}


def evaluate(flow: "EspFlow") -> dict:
    """Apply every framing constraint to every catalogued suite, and show the work."""
    lengths = list(flow.payload_lengths)
    granularity, distinct = length_granularity(lengths)
    granularity_usable = distinct >= MIN_DISTINCT_FOR_GRANULARITY and granularity > 0
    entropy = mean_entropy(flow.entropy_samples)
    notes: list[dict] = []

    base = {
        "method": "RFC 4303 framing arithmetic",
        "lengths_observed": len(lengths),
        "distinct_lengths": distinct,
        "granularity": granularity,
        "granularity_usable": granularity_usable,
        "mean_entropy": round(entropy, 3) if entropy is not None else None,
        "entropy_samples": len(flow.entropy_samples),
        "residues": {str(m): residue_histogram(lengths, m) for m in RESIDUE_MODULI},
        "constraints": CONSTRAINTS,
    }

    if not lengths:
        notes.append(_note(
            "skipped", None,
            "No ESP ciphertext lengths were observed, so no framing constraint "
            "could run and every suite remains possible.",
        ))
        records = [_record(s, None, None, None) for s in ESP_SUITES]
        return {**base, "suites": records, "survivors": list(ESP_SUITES),
                "fallback": False, "classes": surviving_classes(list(ESP_SUITES)),
                "notes": notes}

    if not granularity_usable:
        # The strongest tie-breaker switches off exactly where inference is
        # weakest, so the caller is told rather than left to assume it ran.
        notes.append(_note(
            "skipped", "granularity",
            f"Only {distinct} distinct ciphertext lengths observed, so the "
            "padding-boundary test could not run and suites differing only by "
            "block size cannot be separated. Treat this attribution as weaker "
            "than its confidence suggests.",
        ))
    if entropy is None:
        notes.append(_note(
            "skipped", "entropy",
            f"Only {len(flow.entropy_samples)} packets were long enough to sample "
            f"entropy (at least {MIN_ENTROPY_SAMPLES} are needed), so the entropy "
            "test did not run. ESP-NULL cannot be told apart from an encrypting "
            "suite with the same framing without it.",
        ))

    shortest = min(lengths)
    records = []
    for suite, spec in ESP_SUITES.items():
        modulus = boundary(suite)
        expected = expected_residue(suite)
        agree = sum(1 for n in lengths if n % modulus == expected) / len(lengths)
        overhead = spec["iv"] + spec["icv"]

        failed, reason = None, None
        if granularity_usable and granularity != modulus:
            failed = "granularity"
            reason = (f"length granularity is {granularity}B, so the padding "
                      f"boundary is not this suite's {modulus}B")
        elif agree < RESIDUE_AGREEMENT:
            failed = "residue"
            reason = (f"framing mismatch: {agree:.0%} of lengths match the "
                      f"required len mod {modulus} == {expected}")
        elif shortest < overhead + 4:
            failed = "overhead"
            reason = (f"shortest packet ({shortest}B) cannot hold this "
                      f"suite's {overhead}B IV+ICV overhead")
        elif entropy is not None:
            encrypts = not suite.startswith("NULL")
            if encrypts and entropy < MIN_CIPHERTEXT_ENTROPY:
                failed = "entropy"
                reason = (f"payload entropy {entropy:.2f} is below the "
                          f"ciphertext floor of {MIN_CIPHERTEXT_ENTROPY}")
            elif not encrypts and entropy > MAX_PLAINTEXT_ENTROPY:
                failed = "entropy"
                reason = (f"payload entropy {entropy:.2f} exceeds the plaintext "
                          f"ceiling of {MAX_PLAINTEXT_ENTROPY}; payload is encrypted")
        records.append(_record(suite, failed, reason, agree))

    survivors = [r["suite"] for r in records if r["eliminated_by"] is None]
    fallback = not survivors
    if fallback:
        notes.append(_note(
            "fallback", None,
            "No catalogued suite satisfies the observed framing. The SA may use a "
            "transform outside the catalogue, TFC padding, or nested encapsulation. "
            "Any suite reported for this flow comes from the learned models alone, "
            "with no support from the arithmetic.",
        ))
    classes = surviving_classes(survivors)
    if len(classes) > 1:
        notes.append(_note(
            "unresolved", None,
            f"The arithmetic leaves {len(classes)} framing classes standing, so it "
            "does not decide this flow on its own. The choice between them was "
            "made by the learned models.",
        ))

    return {**base, "suites": records, "survivors": survivors,
            "fallback": fallback, "classes": classes, "notes": notes}


def _record(suite: str, failed: str | None, reason: str | None,
            agree: float | None) -> dict:
    spec = ESP_SUITES[suite]
    return {
        "suite": suite,
        "boundary": boundary(suite),
        "expected_residue": expected_residue(suite),
        "iv": spec["iv"],
        "icv": spec["icv"],
        "residue_agreement": round(agree, 4) if agree is not None else None,
        "eliminated_by": failed,
        "step": _STEP[failed] if failed else None,
        "reason": reason,
    }


def surviving_classes(survivors: list[str]) -> list[dict]:
    """Group surviving suites by framing class and say why members are inseparable."""
    from ..audit.policy import FRAMING_CLASSES

    out = []
    for name, spec in FRAMING_CLASSES.items():
        alive = [m for m in spec["members"] if m in survivors]
        if not alive:
            continue
        out.append({
            "name": name,
            "signature": spec["signature"],
            "verdict": spec["verdict"],
            "members": alive,
            "all_members": spec["members"],
            "why_inseparable": _why_inseparable(spec["members"]),
        })
    return out


def _a(n: int) -> str:
    """'a 16', 'an 8', 'an 11', 'an 18': the article follows the spoken number."""
    return f"an {n}" if str(n).startswith("8") or n in (11, 18) else f"a {n}"


def _why_inseparable(members: list[str]) -> str:
    if len(members) == 1:
        return ("This class has a single member, so the framing identifies the "
                "suite exactly.")
    specs = [ESP_SUITES[m] for m in members]
    ivs = {s["iv"] for s in specs}
    icvs = {s["icv"] for s in specs}
    bounds = {boundary(m) for m in members}
    if len(ivs) == len(icvs) == len(bounds) == 1:
        return (f"All {len(members)} members use {_a(ivs.pop())}-byte IV, "
                f"{_a(icvs.pop())}-byte ICV and {_a(bounds.pop())}-byte padding "
                "boundary, so the same plaintext produces the same ciphertext "
                "length under each of them. They differ only in the keyed "
                "transform, which never appears on the wire, so no length-based "
                "test can separate them.")
    return ("The members' framing parameters produce the same length residues, "
            "so no length-based test can separate them.")
