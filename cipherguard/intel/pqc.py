"""Harvest-now-decrypt-later exposure and PQC migration sequencing.

"Enable post-quantum crypto" is not a plan. An agency with hundreds of links,
a fixed engineering budget and vendors at different firmware levels needs to
know which link to migrate first — and the honest answer is not simply the one
with the weakest cipher.

The distinguishing feature of the quantum threat is that it is retroactive.
Traffic recorded today is decrypted later, so exposure depends on three things
a passive analyzer can actually measure or be told:

  volume       how much traffic crosses the link, which is how much an
               adversary can harvest per unit time
  key exchange whether the session key is recoverable by Shor at all, which for
               every classical DH group is simply yes
  secrecy life how long the data stays sensitive, which is the one input the
               tool cannot observe and must take from the operator

Mosca's inequality frames the deadline: if the time data must stay secret plus
the time needed to migrate exceeds the time until a capable quantum computer
exists, you are already late. This module makes that arithmetic explicit per
link rather than leaving it as a slogan.

The exposure index is a transparent weighted product, not a learned or
calibrated risk score. It is stated here in full so a reviewer can disagree with
the weights rather than having to reverse-engineer them.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.models import Assessment, IkeSession
from ..core.strength import score_proposal

# Default assumption for when a cryptanalytically relevant quantum computer
# arrives. Deliberately a parameter, not a constant belief: expert estimates
# span a wide range and an agency should substitute its own planning figure.
DEFAULT_CRQC_YEARS = 12.0

# Data classes and how long each must remain confidential, in years.
SECRECY_LIFETIME = {
    "routine": 3.0,
    "official": 10.0,
    "confidential": 25.0,
    "strategic": 50.0,
}


@dataclass
class LinkExposure:
    peer: str
    classical_bits: int
    quantum_bits: int
    kex_family: str
    quantum_safe: bool
    bytes_observed: int
    harvest_rate_mbps: float
    exposure_index: float
    priority: int
    mosca_gap_years: float
    rationale: str
    # Key establishment alone. A link whose key exchange is post-quantum but
    # whose cipher key is short is exposed for a different reason, and needs a
    # different fix, from one whose key exchange is classical.
    kex_quantum_bits: int = 0
    hybrid: bool = False

    def to_dict(self) -> dict:
        return {
            "peer": self.peer,
            "classical_bits": self.classical_bits,
            "quantum_bits": self.quantum_bits,
            "kex_family": self.kex_family,
            "quantum_safe": self.quantum_safe,
            "bytes_observed": self.bytes_observed,
            "harvest_rate_mbps": self.harvest_rate_mbps,
            "exposure_index": self.exposure_index,
            "priority": self.priority,
            "mosca_gap_years": self.mosca_gap_years,
            "rationale": self.rationale,
            "kex_quantum_bits": self.kex_quantum_bits,
            "hybrid": self.hybrid,
        }


def mosca_gap(secrecy_years: float, migration_years: float,
              crqc_years: float = DEFAULT_CRQC_YEARS) -> float:
    """Mosca's inequality as a signed number of years.

    Positive means the data will still be sensitive when it becomes decryptable,
    so migration is already overdue. Negative is the margin remaining.

    The dashboard's harvest clock recomputes this in the browser when the data
    classification is changed (`HarvestClock.moscaGap` in dashboard.js), with
    the same operands in the same order so both produce the same double. A test
    runs both over a table of inputs; change them together.
    """
    return (secrecy_years + migration_years) - crqc_years


def _link_bytes(assessment: Assessment, sess: IkeSession) -> tuple[int, float]:
    """Total ESP bytes and duration attributable to this peer pair."""
    peers = {sess.peer_a, sess.peer_b}
    total = 0
    duration = 0.0
    for flow in assessment.flows:
        if {flow.src, flow.dst} & peers:
            total += sum(flow.payload_lengths)
            duration = max(duration, flow.duration)
    return total, duration


def assess_links(
    assessment: Assessment,
    data_class: str = "official",
    migration_years: float = 3.0,
    crqc_years: float = DEFAULT_CRQC_YEARS,
) -> list[LinkExposure]:
    """Rank every observed link by harvest-now-decrypt-later exposure."""
    secrecy = SECRECY_LIFETIME.get(data_class, SECRECY_LIFETIME["official"])
    gap = mosca_gap(secrecy, migration_years, crqc_years)

    results: list[LinkExposure] = []
    for sess in assessment.sessions:
        prop = sess.negotiated("IKE")
        if not prop:
            continue
        # the session's own figure: an offer no responder was seen to accept
        # earns no post-quantum credit
        strength = sess.strength()
        uncredited = score_proposal(prop.transforms).kex_quantum_bits > strength.kex_quantum_bits
        nbytes, duration = _link_bytes(assessment, sess)
        rate_mbps = (nbytes * 8 / 1e6 / duration) if duration > 0 else 0.0

        if strength.quantum_safe:
            index = 0.0
            how = ("a hybrid of " + " and ".join(c["name"] for c in strength.kex_components)
                   if strength.hybrid else strength.kex_family.upper())
            # quantum_bits is the association's figure, capped by the cipher's
            # Grover margin, so it is stated of the association, not the exchange
            rationale = (
                f"Key exchange is {how}, and the association keeps "
                f"{strength.quantum_bits} bits against a quantum attacker. Recorded "
                "traffic on this link is not retroactively decryptable."
            )
        else:
            # Volume term is logarithmic: a link carrying ten times the traffic
            # is more exposed, but not ten times more — the adversary only needs
            # to capture the handshake and enough ciphertext, not everything.
            volume_term = 1.0 + (nbytes / 1e9) ** 0.5
            # Weakness term: a classically weak link is exposed to a conventional
            # attacker too, which brings the deadline forward.
            weakness_term = max(1.0, 128 / max(strength.classical_bits, 8))
            urgency_term = max(0.5, 1.0 + gap / 10.0)
            index = round(volume_term * weakness_term * urgency_term, 2)
            if uncredited:
                rationale = (
                    "A post-quantum key exchange was offered on this link, but no "
                    "response was observed, so it is not confirmed as negotiated and "
                    "is not credited. Capture the full handshake to confirm it."
                )
            elif strength.kex_quantum_bits >= 128:
                # Shor is not the problem here, and saying it was would send
                # the operator to fix a key exchange that is already fixed.
                rationale = (
                    f"Key exchange is {strength.kex_family.upper()} and resists "
                    f"Shor's algorithm at {strength.kex_quantum_bits} bits, but the "
                    f"cipher key leaves {strength.quantum_bits} bits against Grover's "
                    "search, below the 128-bit level. The cipher is the limit on "
                    "this link, not key establishment."
                )
            else:
                rationale = (
                    f"{strength.kex_family.upper()} key exchange at "
                    f"{strength.classical_bits} classical bits and zero quantum bits. "
                    f"Every session key on this link is recoverable by Shor's algorithm "
                    f"from recorded traffic."
                )

        results.append(
            LinkExposure(
                peer=f"{sess.peer_a} <-> {sess.peer_b}",
                classical_bits=strength.classical_bits,
                quantum_bits=strength.quantum_bits,
                kex_family=strength.kex_family,
                quantum_safe=strength.quantum_safe,
                bytes_observed=nbytes,
                harvest_rate_mbps=round(rate_mbps, 2),
                exposure_index=index,
                priority=0,
                mosca_gap_years=round(gap, 1),
                rationale=rationale,
                kex_quantum_bits=strength.kex_quantum_bits,
                hybrid=strength.hybrid,
            )
        )

    results.sort(key=lambda r: (-r.exposure_index, r.classical_bits))
    for i, r in enumerate(results, start=1):
        r.priority = i
    return results


def roadmap(
    assessment: Assessment,
    data_class: str = "official",
    migration_years: float = 3.0,
    crqc_years: float = DEFAULT_CRQC_YEARS,
) -> dict:
    """A sequenced migration plan with the assumptions stated alongside it."""
    links = assess_links(assessment, data_class, migration_years, crqc_years)
    exposed = [l for l in links if not l.quantum_safe]
    secrecy = SECRECY_LIFETIME.get(data_class, SECRECY_LIFETIME["official"])
    gap = mosca_gap(secrecy, migration_years, crqc_years)

    phases = []
    if exposed:
        immediate = [l for l in exposed if l.classical_bits < 112]
        # Past the classical floor, a link whose key exchange is already
        # post-quantum does not belong in the key-exchange phases: telling it to
        # deploy a PPK or enable ML-KEM would be advice it has already taken.
        rest = [l for l in exposed if l.classical_bits >= 112]
        cipher_limited = [l for l in rest if l.kex_quantum_bits >= 128]
        rest = [l for l in rest if l.kex_quantum_bits < 128]
        near = [l for l in rest if l.classical_bits < 128]
        planned = [l for l in rest if l.classical_bits >= 128]

        if immediate:
            phases.append({
                "phase": 1,
                "window": "immediate",
                "links": [l.peer for l in immediate],
                "action": (
                    "Replace broken classical cryptography first. These links are "
                    "exposed to a conventional attacker today, so the quantum "
                    "timeline is not the binding constraint — fix them regardless "
                    "of PQC readiness."
                ),
                "target": "AES-GCM-256, DH Group 19 or 31, IKEv2, certificate auth",
            })
        if near:
            phases.append({
                "phase": 2,
                "window": "next change window",
                "links": [l.peer for l in near],
                "action": (
                    "Deploy RFC 8784 post-quantum pre-shared keys. This works on "
                    "existing IKEv2 firmware and mixes a PPK into the key schedule, "
                    "so it defeats harvest-now-decrypt-later without waiting for "
                    "ML-KEM support to ship."
                ),
                "target": "RFC 8784 PPK layered over the current suite",
            })
        if planned:
            phases.append({
                "phase": 3,
                "window": "as firmware allows",
                "links": [l.peer for l in planned],
                "action": (
                    "Enable hybrid key establishment: ML-KEM alongside the existing "
                    "elliptic-curve group under RFC 9370, so the link stays secure "
                    "if either primitive fails."
                ),
                "target": "Hybrid ML-KEM-768 (Group 36) + Curve25519 (Group 31)",
            })
        if cipher_limited:
            phases.append({
                "phase": 4,
                "window": "next change window",
                "links": [l.peer for l in cipher_limited],
                "action": (
                    "Key establishment on these links is already post-quantum. "
                    "What remains is the cipher: raise it to a 256-bit key, so that "
                    "Grover's search leaves a 128-bit margin."
                ),
                "target": "AES-GCM-256 or ChaCha20-Poly1305",
            })

    return {
        "assumptions": {
            "data_class": data_class,
            "secrecy_lifetime_years": secrecy,
            "migration_years": migration_years,
            "crqc_years": crqc_years,
            "mosca_gap_years": round(gap, 1),
            "already_late": gap > 0,
            # Published so a client can recompute the deadline for another
            # class without keeping its own copy of the table to drift.
            "secrecy_lifetimes": dict(SECRECY_LIFETIME),
            "note": (
                "The CRQC arrival estimate is a planning assumption, not a "
                "prediction. Substitute the agency's own figure; the ranking of "
                "links is unchanged by it, only the urgency framing."
            ),
        },
        "summary": {
            "links_assessed": len(links),
            "quantum_exposed": len(exposed),
            "quantum_safe": len(links) - len(exposed),
            "total_bytes_harvestable": sum(l.bytes_observed for l in exposed),
            # The rate at which that total grows while the links keep carrying
            # traffic as observed: the harvest clock's tick rate.
            "harvest_rate_mbps": round(sum(l.harvest_rate_mbps for l in exposed), 2),
        },
        "links": [l.to_dict() for l in links],
        "phases": phases,
    }
