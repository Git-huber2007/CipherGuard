"""Data model shared by the dissector, audit engine, inference engine and API."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 40, "high": 25, "medium": 12, "low": 4, "info": 0}[self.value]

    @property
    def rank(self) -> int:
        return ["critical", "high", "medium", "low", "info"].index(self.value)


@dataclass
class Transform:
    """One IKEv2 transform substructure, or one IKEv1 phase-1 attribute group."""

    type_id: int
    type_name: str
    value_id: int
    name: str
    key_length: int | None = None

    def label(self) -> str:
        if self.key_length:
            return f"{self.name}-{self.key_length}"
        return self.name

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Proposal:
    number: int
    protocol_id: int
    protocol: str
    spi: bytes = b""
    transforms: list[Transform] = field(default_factory=list)

    def by_type(self, type_id: int) -> list[Transform]:
        return [t for t in self.transforms if t.type_id == type_id]

    def first(self, type_id: int) -> Transform | None:
        got = self.by_type(type_id)
        return got[0] if got else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "protocol_id": self.protocol_id,
            "protocol": self.protocol,
            "spi": self.spi.hex(),
            "transforms": [t.to_dict() for t in self.transforms],
        }


@dataclass
class IkeMessage:
    """A single dissected IKE message from the cleartext outer headers."""

    frame: int
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    version: str  # "IKEv1" | "IKEv2"
    exchange: str
    initiator_spi: bytes
    responder_spi: bytes
    message_id: int
    is_initiator: bool
    is_response: bool
    encrypted: bool = False
    proposals: list[Proposal] = field(default_factory=list)
    ke_group: int | None = None
    notifies: list[str] = field(default_factory=list)
    vendor_ids: list[str] = field(default_factory=list)
    lifetime_seconds: int | None = None
    auth_method: str | None = None
    natt: bool = False
    parse_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["initiator_spi"] = self.initiator_spi.hex()
        d["responder_spi"] = self.responder_spi.hex()
        d["proposals"] = [p.to_dict() for p in self.proposals]
        return d


@dataclass
class IkeSession:
    """All messages sharing one initiator SPI — a single negotiated IKE SA."""

    initiator_spi: bytes
    responder_spi: bytes
    version: str
    peer_a: str
    peer_b: str
    messages: list[IkeMessage] = field(default_factory=list)
    child_sa_spis: list[str] = field(default_factory=list)

    # ESP volume attributed to this peer pair. Populated by the pipeline so
    # volume-dependent rules (Sweet32 birthday bounds, harvest exposure) can
    # quantify risk instead of asserting it.
    observed_bytes: int = 0
    observed_seconds: float = 0.0
    retransmissions: int = 0

    @property
    def sid(self) -> str:
        return self.initiator_spi.hex()

    def negotiated(self, protocol: str, confirmed_only: bool = False) -> Proposal | None:
        """The proposal the responder selected.

        By default this falls back to the initiator's offer when no response was
        observed, because a capture that starts mid-exchange or misses the
        return path is common and reporting nothing would be less useful than
        reporting what was proposed.

        `confirmed_only` disables that fallback, and callers that persist state
        must set it. An unanswered IKE_SA_INIT proves only that somebody sent a
        packet — anyone on the mirrored segment can send one — so treating an
        offer as an agreement lets a single spoofed datagram write a peer pair's
        stored baseline.
        """
        for msg in self.messages:
            if not msg.is_response:
                continue
            for prop in msg.proposals:
                if prop.protocol == protocol:
                    return prop
        if confirmed_only:
            return None
        for msg in self.messages:
            for prop in msg.proposals:
                if prop.protocol == protocol:
                    return prop
        return None

    def is_confirmed(self, protocol: str = "IKE") -> bool:
        """Whether a responder was actually observed agreeing to a proposal."""
        return self.negotiated(protocol, confirmed_only=True) is not None

    def offered(self, protocol: str) -> list[Proposal]:
        out = []
        for msg in self.messages:
            if msg.is_response:
                continue
            out.extend(p for p in msg.proposals if p.protocol == protocol)
        return out

    def all_vendor_ids(self) -> list[str]:
        seen: list[str] = []
        for msg in self.messages:
            for vid in msg.vendor_ids:
                if vid not in seen:
                    seen.append(vid)
        return seen

    def all_notifies(self) -> list[str]:
        seen: list[str] = []
        for msg in self.messages:
            for n in msg.notifies:
                if n not in seen:
                    seen.append(n)
        return seen

    def vendor_family(self) -> str:
        from .constants import VENDOR_FAMILY

        for vid in self.all_vendor_ids():
            if vid in VENDOR_FAMILY:
                return VENDOR_FAMILY[vid]
        return "generic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sid": self.sid,
            "initiator_spi": self.initiator_spi.hex(),
            "responder_spi": self.responder_spi.hex(),
            "version": self.version,
            "peer_a": self.peer_a,
            "peer_b": self.peer_b,
            "vendor_ids": self.all_vendor_ids(),
            "vendor_family": self.vendor_family(),
            "notifies": self.all_notifies(),
            "messages": [m.to_dict() for m in self.messages],
            "child_sa_spis": self.child_sa_spis,
            "retransmissions": self.retransmissions,
            "observed_bytes": self.observed_bytes,
            "observed_seconds": round(self.observed_seconds, 3),
            "strength": self.strength().to_dict(),
        }

    def strength(self):
        from .strength import score_proposal

        prop = self.negotiated("IKE")
        return score_proposal(prop.transforms if prop else [])


@dataclass
class EspFlow:
    """An ESP security association observed on the wire, payload never decrypted."""

    spi: int
    src: str
    dst: str
    packets: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    payload_lengths: list[int] = field(default_factory=list)
    inter_arrivals: list[float] = field(default_factory=list)
    sequence_numbers: list[int] = field(default_factory=list)
    entropy_samples: list[float] = field(default_factory=list)
    encapsulated: bool = False  # UDP-encapsulated (NAT-T) rather than IP proto 50

    # populated by the inference engine
    predicted_suite: str | None = None
    confidence: float = 0.0
    ranked: list[tuple[str, float]] = field(default_factory=list)
    exclusions: list[tuple[str, str]] = field(default_factory=list)  # (suite, reason)
    inference_notes: list[dict[str, Any]] = field(default_factory=list)
    framing_trace: dict[str, Any] | None = None  # core.framing.evaluate() output

    @property
    def key(self) -> str:
        return f"{self.src}->{self.dst}:0x{self.spi:08x}"

    def framing_arithmetic(self) -> dict[str, Any]:
        """The RFC 4303 working for this flow: persisted by the classifier when
        one ran, otherwise computed here, since the arithmetic needs no model."""
        if self.framing_trace is None:
            from .framing import evaluate

            self.framing_trace = evaluate(self)
        return self.framing_trace

    @property
    def duration(self) -> float:
        return max(self.last_seen - self.first_seen, 0.0)

    def replay_gaps(self) -> int:
        """Sequence discontinuities — a proxy for loss or replay-window pressure."""
        gaps = 0
        for prev, cur in zip(self.sequence_numbers, self.sequence_numbers[1:]):
            if cur != prev + 1:
                gaps += 1
        return gaps

    def framing(self) -> tuple[str | None, list[str], float]:
        """The claim the evidence actually supports: the framing class, its
        candidate members, and the probability mass across all of them.

        `predicted_suite` alone names one member of a set the wire cannot
        distinguish, at its exact-suite probability. Reporting that as the
        result makes a correctly identified AES-GCM tunnel read as
        "ChaCha20-Poly1305, 30%". Computed here so the CLI, the API and the
        dashboard cannot drift apart on it.
        """
        from ..audit.policy import framing_class_of

        if not self.predicted_suite:
            return None, [], 0.0
        name, spec = framing_class_of(self.predicted_suite)
        if not spec:
            return None, [self.predicted_suite], self.confidence
        members = spec["members"]
        mass = sum(p for suite, p in self.ranked if suite in members)
        return name, members, mass

    def to_dict(self) -> dict[str, Any]:
        cls_name, members, mass = self.framing()
        trace = self.framing_arithmetic()
        exclusions = self.exclusions or [
            (r["suite"], r["reason"]) for r in trace["suites"] if r["eliminated_by"]
        ]
        return {
            "key": self.key,
            "spi": f"0x{self.spi:08x}",
            "src": self.src,
            "dst": self.dst,
            "packets": self.packets,
            "duration": round(self.duration, 3),
            "encapsulated": self.encapsulated,
            "mean_payload": round(sum(self.payload_lengths) / len(self.payload_lengths), 1)
            if self.payload_lengths
            else 0,
            "replay_gaps": self.replay_gaps(),
            "predicted_suite": self.predicted_suite,
            "confidence": round(self.confidence, 4),
            "framing_class": cls_name,
            "framing_candidates": members,
            "framing_confidence": round(mass, 4),
            "ambiguous": len(members) > 1,
            "ranked": [(n, round(p, 4)) for n, p in self.ranked[:3]],
            # The deterministic evidence, in a form a reviewer can recompute.
            "exclusions": [{"suite": s, "reason": r} for s, r in exclusions],
            "inference_notes": self.inference_notes or trace["notes"],
            "residues": trace["residues"],
            "length_granularity": trace["granularity"],
            "granularity_usable": trace["granularity_usable"],
            "distinct_lengths": trace["distinct_lengths"],
            "mean_entropy": trace["mean_entropy"],
            "framing_arithmetic": {
                k: trace[k] for k in (
                    "method", "lengths_observed", "entropy_samples", "constraints",
                    "suites", "survivors", "classes", "fallback",
                )
            },
        }


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    subject: str
    detail: str
    reference: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    inferred: bool = False  # True when raised off an ML prediction, not parsed bytes

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Assessment:
    capture: str
    started: str
    sessions: list[IkeSession] = field(default_factory=list)
    flows: list[EspFlow] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def score(self) -> int:
        """Posture score out of 100.

        Linear deduction is wrong for this: a capture with six critical findings
        and one with twelve both floor at zero, so the score stops distinguishing
        bad from catastrophic exactly where an analyst most needs it to. Instead
        severity weights accumulate into a penalty and the score decays
        exponentially, which is strictly monotonic, never saturates, and keeps
        the top of the range sensitive to a single serious finding.

        Repeat findings of the same severity are discounted, because twenty
        gateways sharing one misconfiguration is one problem to fix, not twenty.
        """
        penalty = 0.0
        for sev in Severity:
            hits = [f for f in self.findings if f.severity is sev]
            if not hits:
                continue
            # first hit full weight, each repeat worth a third, capped at 3x
            penalty += sev.weight * min(1 + (len(hits) - 1) / 3.0, 3.0)
        return int(round(100 * math.exp(-penalty / 75.0)))

    def grade(self) -> str:
        s = self.score()
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 40:
            return "D"
        return "E"

    def counts(self) -> dict[str, int]:
        return {
            sev.value: sum(1 for f in self.findings if f.severity is sev) for sev in Severity
        }

    def digest(self) -> str:
        raw = "|".join(sorted(f"{f.rule_id}:{f.subject}" for f in self.findings))
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        from .grouping import review_index

        return {
            "capture": self.capture,
            "started": self.started,
            "score": self.score(),
            "grade": self.grade(),
            "counts": self.counts(),
            "digest": self.digest(),
            "stats": self.stats,
            "sessions": [s.to_dict() for s in self.sessions],
            "flows": [f.to_dict() for f in self.flows],
            "findings": [f.to_dict() for f in self.findings],
            # finding_groups, links, unlinked_findings: indexes into the lists
            # above, so the grouping is computed once, here, for every client
            **review_index(self),
        }
