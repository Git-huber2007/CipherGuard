"""Audit engine.

Each rule is a small function over one IKE session or one ESP flow, returning
zero or more Findings. Rules are registered rather than hard-wired so an agency
can disable individual checks without forking the engine.

An important structural note about what can be audited from a passive capture:

  * The IKE SA proposal travels in the clear in IKE_SA_INIT (IKEv2) and in Main
    or Aggressive Mode (IKEv1). It is parsed directly, so IKE findings are
    assertions about observed bytes.
  * The Child/ESP SA proposal does NOT. In IKEv2 it is inside the encrypted SK
    payload of IKE_AUTH; in IKEv1 it is inside Quick Mode. No passive analyzer
    without keys can read it.

That gap is exactly why the inference engine exists. ESP findings are marked
``inferred=True`` and carry their confidence, and they are phrased as the
framing class rather than a specific suite wherever framing cannot separate the
members. A finding is never silently upgraded from inferred to observed.
"""

from __future__ import annotations

from typing import Callable

from ..core import constants as C
from ..core.grouping import pair_key
from ..core.models import (
    Assessment,
    EspFlow,
    Finding,
    IkeMessage,
    IkeSession,
    Proposal,
    Severity,
)
from ..core.strength import score_proposal, sweet32_exposure
from . import policy as P

IkeRule = Callable[[IkeSession], list[Finding]]
EspRule = Callable[[EspFlow], list[Finding]]
# A capture rule sees every IKE session in one capture at once, for checks that
# only mean something across sessions. Its scope is that one capture: nothing
# is carried between captures.
CaptureRule = Callable[[list[IkeSession]], list[Finding]]

IKE_RULES: list[tuple[str, IkeRule]] = []
ESP_RULES: list[tuple[str, EspRule]] = []
CAPTURE_RULES: list[tuple[str, CaptureRule]] = []


def ike_rule(rule_id: str):
    def wrap(fn: IkeRule) -> IkeRule:
        IKE_RULES.append((rule_id, fn))
        return fn

    return wrap


def esp_rule(rule_id: str):
    def wrap(fn: EspRule) -> EspRule:
        ESP_RULES.append((rule_id, fn))
        return fn

    return wrap


def capture_rule(rule_id: str):
    def wrap(fn: CaptureRule) -> CaptureRule:
        CAPTURE_RULES.append((rule_id, fn))
        return fn

    return wrap


def _peer(sess: IkeSession) -> str:
    return f"{sess.peer_a} <-> {sess.peer_b}"


def _ike_proposal(sess: IkeSession) -> Proposal | None:
    return sess.negotiated("IKE")


# ---------------------------------------------------------------------------
# IKE protocol-level rules
# ---------------------------------------------------------------------------


@ike_rule("IKE-001")
def rule_ikev1(sess: IkeSession) -> list[Finding]:
    if sess.version != "IKEv1":
        return []
    return [
        Finding(
            rule_id="IKE-001",
            title="IKEv1 in use",
            severity=Severity.HIGH,
            subject=_peer(sess),
            detail=(
                "The gateway negotiated IKEv1, which has been formally deprecated. "
                "It has no built-in DoS cookie mechanism, no reliable fragmentation, "
                "and no path to the RFC 8784 post-quantum pre-shared key extension."
            ),
            reference="RFC 9395 (IKEv1 deprecation); NIST SP 800-77 Rev. 1 s3.2",
            remediation="Migrate the tunnel to IKEv2 and disable IKEv1 on the gateway.",
            evidence={"version": sess.version, "spi": sess.sid},
        )
    ]


@ike_rule("IKE-002")
def rule_aggressive_mode(sess: IkeSession) -> list[Finding]:
    hits = [m for m in sess.messages if "Aggressive" in m.exchange]
    if not hits:
        return []
    return [
        Finding(
            rule_id="IKE-002",
            title="IKEv1 Aggressive Mode",
            severity=Severity.CRITICAL,
            subject=_peer(sess),
            detail=(
                "Aggressive Mode transmits the responder's identity and a hash "
                "derived from the pre-shared key in the clear, in the first two "
                "messages. Anyone who can capture the handshake can mount an "
                "offline dictionary attack against the PSK without touching the "
                "gateway."
            ),
            reference="NIST SP 800-77 Rev. 1 s3.2.1; RFC 2409 s5.4",
            remediation=(
                "Disable Aggressive Mode. Use IKEv2 with certificate authentication, "
                "or at minimum IKEv1 Main Mode with a high-entropy PSK."
            ),
            evidence={"frames": [m.frame for m in hits]},
        )
    ]


@ike_rule("IKE-003")
def rule_weak_auth(sess: IkeSession) -> list[Finding]:
    out = []
    for msg in sess.messages:
        if msg.auth_method and msg.auth_method in P.WEAK_AUTH:
            out.append(
                Finding(
                    rule_id="IKE-003",
                    title=f"Pre-shared key authentication ({msg.auth_method})",
                    severity=Severity.MEDIUM,
                    subject=_peer(sess),
                    detail=P.WEAK_AUTH[msg.auth_method]
                    + ". On a backbone link this is a credential-management liability: "
                    "the same secret is typically shared across peers and rarely rotated.",
                    reference="NIST SP 800-77 Rev. 1 s3.4",
                    remediation=(
                        "Move to certificate-based authentication (RSA or ECDSA) "
                        "backed by the agency PKI."
                    ),
                    evidence={"auth_method": msg.auth_method, "frame": msg.frame},
                )
            )
            break
    return out


@ike_rule("IKE-004")
def rule_encryption(sess: IkeSession) -> list[Finding]:
    prop = _ike_proposal(sess)
    if not prop:
        return []
    out = []
    for tr in prop.by_type(1):
        if tr.name in P.ENCR_PROHIBITED:
            out.append(
                Finding(
                    rule_id="IKE-004",
                    title=f"Prohibited IKE encryption algorithm: {tr.label()}",
                    severity=Severity.CRITICAL,
                    subject=_peer(sess),
                    detail=P.ENCR_PROHIBITED[tr.name]
                    + ". This protects the IKE control channel itself, so a break "
                    "exposes the negotiated child SA keys.",
                    reference="RFC 8247 s2.1; NIST SP 800-131A Rev. 2",
                    remediation="Configure AES-GCM-256, or AES-CBC-256 where AEAD is unavailable.",
                    evidence={"transform": tr.label(), "transform_id": tr.value_id},
                )
            )
        elif tr.key_length and tr.key_length < P.MIN_KEY_BITS:
            out.append(
                Finding(
                    rule_id="IKE-004",
                    title=f"Undersized key length: {tr.label()}",
                    severity=Severity.HIGH,
                    subject=_peer(sess),
                    detail=f"{tr.name} negotiated with a {tr.key_length}-bit key, "
                    f"below the {P.MIN_KEY_BITS}-bit floor.",
                    reference="NIST SP 800-131A Rev. 2",
                    remediation="Raise the negotiated key length to 256 bits.",
                    evidence={"key_length": tr.key_length},
                )
            )
    return out


@ike_rule("IKE-005")
def rule_integrity(sess: IkeSession) -> list[Finding]:
    prop = _ike_proposal(sess)
    if not prop:
        return []
    out = []
    for tr in prop.by_type(3):
        if tr.name in P.INTEG_PROHIBITED:
            out.append(
                Finding(
                    rule_id="IKE-005",
                    title=f"Prohibited integrity algorithm: {tr.name}",
                    severity=Severity.HIGH,
                    subject=_peer(sess),
                    detail=P.INTEG_PROHIBITED[tr.name],
                    reference="RFC 8247 s2.2",
                    remediation="Configure AUTH_HMAC_SHA2_256_128 or stronger.",
                    evidence={"transform": tr.name},
                )
            )
        elif tr.name in P.INTEG_LEGACY:
            out.append(
                Finding(
                    rule_id="IKE-005",
                    title=f"Deprecated integrity algorithm: {tr.name}",
                    severity=Severity.MEDIUM,
                    subject=_peer(sess),
                    detail=P.INTEG_LEGACY[tr.name],
                    reference="NIST SP 800-131A Rev. 2",
                    remediation="Migrate to AUTH_HMAC_SHA2_256_128.",
                    evidence={"transform": tr.name},
                )
            )
    for tr in prop.by_type(2):
        if tr.name in P.PRF_PROHIBITED:
            out.append(
                Finding(
                    rule_id="IKE-005",
                    title=f"Prohibited PRF: {tr.name}",
                    severity=Severity.HIGH,
                    subject=_peer(sess),
                    detail=P.PRF_PROHIBITED[tr.name],
                    reference="RFC 8247 s2.3",
                    remediation="Configure PRF_HMAC_SHA2_256 or stronger.",
                    evidence={"transform": tr.name},
                )
            )
        elif tr.name in P.PRF_LEGACY:
            out.append(
                Finding(
                    rule_id="IKE-005",
                    title=f"Deprecated PRF: {tr.name}",
                    severity=Severity.LOW,
                    subject=_peer(sess),
                    detail=P.PRF_LEGACY[tr.name],
                    reference="NIST SP 800-131A Rev. 2",
                    remediation="Configure PRF_HMAC_SHA2_256.",
                    evidence={"transform": tr.name},
                )
            )
    return out


@ike_rule("IKE-006")
def rule_dh_group(sess: IkeSession) -> list[Finding]:
    prop = _ike_proposal(sess)
    groups: list[int] = []
    if prop:
        groups += [t.value_id for t in prop.by_type(4)]
    groups += [m.ke_group for m in sess.messages if m.ke_group is not None]

    out = []
    seen: set[int] = set()
    for gid in groups:
        if gid in seen or gid == 0:
            continue
        seen.add(gid)
        meta = C.DH_GROUPS.get(gid, {"name": f"GROUP_{gid}", "bits": 0})
        if gid in P.DH_PROHIBITED:
            out.append(
                Finding(
                    rule_id="IKE-006",
                    title=f"Prohibited Diffie-Hellman group {gid} ({meta['name']})",
                    severity=Severity.CRITICAL,
                    subject=_peer(sess),
                    detail=P.DH_PROHIBITED[gid]
                    + ". A single precomputation against a standard modulus breaks "
                    "every session that ever used it, including traffic already recorded.",
                    reference="RFC 8247 s2.4; NIST SP 800-77 Rev. 1 s3.3",
                    remediation="Configure Group 19 (256-bit ECP) or Group 14 at minimum.",
                    evidence={"group": gid, "bits": meta.get("bits")},
                )
            )
        elif gid in P.DH_LEGACY:
            out.append(
                Finding(
                    rule_id="IKE-006",
                    title=f"Deprecated Diffie-Hellman group {gid} ({meta['name']})",
                    severity=Severity.HIGH,
                    subject=_peer(sess),
                    detail=P.DH_LEGACY[gid],
                    reference="NIST SP 800-77 Rev. 1 s3.3",
                    remediation="Configure Group 19 or Group 14.",
                    evidence={"group": gid, "bits": meta.get("bits")},
                )
            )
    return out


def _key_exchanges(prop: Proposal | None) -> list:
    """The key exchange transforms of a proposal that are actually in use: type
    4, and any RFC 9370 additional key exchange that is not NONE."""
    if not prop:
        return []
    return [t for t in prop.transforms
            if t.type_id in C.KE_TRANSFORM_TYPES and t.value_id != 0]


def _addke_labels(prop: Proposal | None) -> list[str]:
    return [f"{t.type_name}={t.name}" for t in _key_exchanges(prop)
            if t.type_id in C.ADDKE_TRANSFORM_TYPES]


@ike_rule("IKE-007")
def rule_post_quantum(sess: IkeSession) -> list[Finding]:
    """Harvest-now-decrypt-later exposure on long-lived government links.

    A link counts as quantum-resistant only on what a responder was seen to
    agree to: a post-quantum group as the key exchange, or as one of the RFC
    9370 additional key exchanges, in the selected proposal; or USE_PPK in a
    response. What an initiator merely offered does not count. Anyone on the
    mirrored segment can send an offer, and a responder that declines it has
    negotiated a classical exchange whatever was on the table. The same rule,
    for the same reason, governs what the baseline store will record.
    """
    confirmed = sess.negotiated("IKE", confirmed_only=True)
    selected = _key_exchanges(confirmed)
    pq_selected = [t for t in selected if t.value_id in P.DH_PQ_GROUPS]
    has_ppk = any("USE_PPK" in m.notifies for m in sess.messages if m.is_response)
    if pq_selected or has_ppk:
        return []

    offered_pq = sorted({
        f"{t.name} ({t.type_name})"
        for prop in sess.offered("IKE")
        for t in _key_exchanges(prop)
        if t.value_id in P.DH_PQ_GROUPS
    })
    # what the finding is about: the selection if one was seen, else the offer
    basis = confirmed or _ike_proposal(sess)
    groups = {t.value_id for t in _key_exchanges(basis)}
    groups |= {m.ke_group for m in sess.messages if m.is_response and m.ke_group}

    detail = (
        "The SA relies entirely on classical Diffie-Hellman. Traffic "
        "recorded today can be decrypted once a cryptanalytically relevant "
        "quantum computer exists, which matters for material whose "
        "sensitivity outlives the hardware."
    )
    remediation = (
        "Deploy an RFC 8784 post-quantum pre-shared key now, and enable a "
        "hybrid ML-KEM key exchange (Group 35-37) as gateway firmware allows."
    )
    if offered_pq and confirmed:
        detail += (
            " The initiator offered " + ", ".join(offered_pq) + " and the responder "
            "did not select it, so the association was negotiated without it. "
            "That usually means the responder does not support RFC 9370 or is not "
            "configured for it."
        )
        remediation = (
            "The initiator already offers a post-quantum exchange: enable RFC 9370 "
            "hybrid key exchange with ML-KEM on the responder so it is selected. "
            "An RFC 8784 post-quantum pre-shared key covers the link until then."
        )
    elif offered_pq:
        detail += (
            " A post-quantum exchange was offered (" + ", ".join(offered_pq) + "), "
            "but no response was observed in this capture, so it is not confirmed "
            "as negotiated and is not credited."
        )

    return [
        Finding(
            rule_id="IKE-007",
            title="No quantum-resistant key establishment",
            severity=Severity.MEDIUM,
            subject=_peer(sess),
            detail=detail,
            reference="NIST FIPS 203 (ML-KEM); RFC 8784; RFC 9370",
            remediation=remediation,
            evidence={
                "groups": sorted(groups),
                "ppk": has_ppk,
                "responder_confirmed": confirmed is not None,
                "addke_selected": _addke_labels(confirmed),
                "pq_offered": offered_pq,
                "intermediate_exchanges_seen": sess.exchanges_seen("IKE_INTERMEDIATE"),
            },
        )
    ]


@ike_rule("IKE-008")
def rule_downgrade_surface(sess: IkeSession) -> list[Finding]:
    """A responder that still advertises broken transforms can be downgraded into
    them, whether or not this particular session selected one."""
    offered = sess.offered("IKE")
    weak: set[str] = set()
    weak_groups: set[int] = set()
    for prop in offered:
        for tr in prop.by_type(1):
            if tr.name in P.ENCR_PROHIBITED:
                weak.add(tr.label())
        for tr in prop.by_type(3):
            if tr.name in P.INTEG_PROHIBITED:
                weak.add(tr.name)
        for tr in prop.by_type(4):
            if tr.value_id in P.DH_PROHIBITED:
                weak_groups.add(tr.value_id)

    negotiated = _ike_proposal(sess)
    selected = {t.label() for t in negotiated.transforms} if negotiated else set()
    residual = weak - selected
    if not residual and not weak_groups:
        return []

    return [
        Finding(
            rule_id="IKE-008",
            title="Broken transforms remain in the proposal set",
            severity=Severity.MEDIUM,
            subject=_peer(sess),
            detail=(
                "The initiator advertised transforms that policy prohibits: "
                + ", ".join(sorted(residual | {f"DH group {g}" for g in weak_groups}))
                + ". Even unselected, they widen the downgrade surface — an on-path "
                "attacker who can drop the strong proposals may force a fallback."
            ),
            reference="NIST SP 800-77 Rev. 1 s3.2",
            remediation=(
                "Prune the gateway's transform set to approved algorithms only, "
                "so a downgrade has nothing to fall back to."
            ),
            evidence={"residual": sorted(residual), "groups": sorted(weak_groups)},
        )
    ]


@ike_rule("IKE-009")
def rule_lifetime(sess: IkeSession) -> list[Finding]:
    out = []
    for msg in sess.messages:
        if msg.lifetime_seconds and msg.lifetime_seconds > P.MAX_IKE_SA_LIFETIME:
            hours = msg.lifetime_seconds / 3600
            out.append(
                Finding(
                    rule_id="IKE-009",
                    title=f"Excessive SA lifetime ({hours:.1f} hours)",
                    severity=Severity.MEDIUM,
                    subject=_peer(sess),
                    detail=(
                        f"The SA is configured to live {hours:.1f} hours before rekey. "
                        "Long lifetimes increase the volume of traffic under a single "
                        "key and lengthen the window in which a compromised key stays "
                        "useful."
                    ),
                    reference="NIST SP 800-77 Rev. 1 s5.2",
                    remediation="Reduce the IKE SA lifetime to 24 hours or less, and the child SA to 8 hours.",
                    evidence={"lifetime_seconds": msg.lifetime_seconds},
                )
            )
            break
    return out


@ike_rule("IKE-010")
def rule_negotiation_failures(sess: IkeSession) -> list[Finding]:
    notifies = sess.all_notifies()
    alarming = [
        n for n in notifies
        if n in {"NO_PROPOSAL_CHOSEN", "AUTHENTICATION_FAILED", "INVALID_SYNTAX",
                 "INVALID_KE_PAYLOAD"}
    ]
    if not alarming:
        return []
    return [
        Finding(
            rule_id="IKE-010",
            title="Repeated negotiation failures observed",
            severity=Severity.MEDIUM,
            subject=_peer(sess),
            detail=(
                "The exchange carried " + ", ".join(alarming) + ". In isolation this "
                "is a misconfiguration; in volume it is the signature of an attacker "
                "probing which proposals a gateway will accept, or brute-forcing "
                "authentication."
            ),
            reference="RFC 7296 s3.10.1",
            remediation=(
                "Correlate against the gateway's own logs and rate-limit IKE from "
                "untrusted sources. If unexplained, treat as reconnaissance."
            ),
            evidence={"notifies": alarming},
        )
    ]


@ike_rule("IKE-011")
def rule_fragmentation(sess: IkeSession) -> list[Finding]:
    if sess.version != "IKEv2":
        return []
    if "IKEV2_FRAGMENTATION_SUPPORTED" in sess.all_notifies():
        return []
    return [
        Finding(
            rule_id="IKE-011",
            title="IKEv2 fragmentation not negotiated",
            severity=Severity.LOW,
            subject=_peer(sess),
            detail=(
                "Neither peer advertised RFC 7383 fragmentation. Certificate-bearing "
                "IKE_AUTH messages then rely on IP fragmentation, which middleboxes on "
                "carrier paths routinely drop — a common cause of tunnels that "
                "establish with PSK but fail with certificates."
            ),
            reference="RFC 7383",
            remediation="Enable IKEv2 fragmentation on both peers before migrating to certificate auth.",
            evidence={"notifies": sess.all_notifies()},
        )
    ]


@ike_rule("IKE-012")
def rule_weakest_link(sess: IkeSession) -> list[Finding]:
    """Score the association at its weakest component rather than its strongest.

    Mixed suites are the common real-world failure: AES-256 paired with SHA-1
    and DH Group 2 reads as "AES-256" on a configuration screen and is in fact
    an 80-bit association. Naming the number makes that undeniable.
    """
    prop = _ike_proposal(sess)
    if not prop:
        return []
    strength = score_proposal(prop.transforms)
    if strength.classical_bits >= 112:
        return []

    weakest = min(strength.detail, key=lambda k: strength.detail[k])
    severity = Severity.CRITICAL if strength.classical_bits < 80 else Severity.HIGH
    return [
        Finding(
            rule_id="IKE-012",
            title=f"Association provides only {strength.classical_bits}-bit security",
            severity=severity,
            subject=_peer(sess),
            detail=(
                f"Component strengths: "
                + ", ".join(f"{k} {v} bits" for k, v in strength.detail.items())
                + f". The association is bounded by its {weakest} at "
                f"{strength.classical_bits} bits, which is graded "
                f"'{strength.classical_grade}'. A strong cipher does not "
                "compensate for a weak key exchange: an attacker who recovers "
                "the session key never has to attack the cipher at all."
            ),
            reference="NIST SP 800-57 Part 1 Rev. 5, Table 2",
            remediation=(
                f"Raise the {weakest} to at least the 128-bit level. The whole "
                "suite should be re-specified together rather than patched "
                "component by component."
            ),
            evidence=strength.to_dict(),
        )
    ]


@ike_rule("IKE-013")
def rule_sweet32(sess: IkeSession) -> list[Finding]:
    """64-bit block ciphers, quantified against this link's observed throughput.

    'Do not use 3DES' is advice. 'This SA processes 4.2x the Sweet32 birthday
    bound between rekeys, and will reach it 41 minutes after each rekey' is a
    change request, because it survives contact with an operations team that
    wants to know why the outage window is justified.
    """
    prop = _ike_proposal(sess)
    if not prop:
        return []
    strength = score_proposal(prop.transforms)
    if strength.block_bits == 0 or strength.block_bits >= 128:
        return []

    lifetime = next(
        (m.lifetime_seconds for m in sess.messages if m.lifetime_seconds),
        P.MAX_IKE_SA_LIFETIME,
    )
    volume = getattr(sess, "observed_bytes", 0)
    duration = getattr(sess, "observed_seconds", 0.0)
    exposure = sweet32_exposure(strength.block_bits, volume, duration, lifetime)
    if exposure is None:
        return []

    if exposure["exceeds"]:
        severity, verdict = Severity.CRITICAL, "already exceeds"
    elif exposure["ratio_to_threshold"] > 0.1:
        severity, verdict = Severity.HIGH, "approaches"
    else:
        severity, verdict = Severity.MEDIUM, "remains below"

    to_threshold = exposure["seconds_to_threshold"]
    timing = (
        f"At the observed {exposure['observed_rate_mbps']} Mbps this SA reaches "
        f"the bound {to_threshold / 60:.0f} minutes after each rekey."
        if to_threshold and to_threshold > 0
        else "Observed throughput is too low to project a crossing time."
    )

    return [
        Finding(
            rule_id="IKE-013",
            title=f"64-bit block cipher {verdict} the Sweet32 birthday bound",
            severity=severity,
            subject=_peer(sess),
            detail=(
                f"The negotiated cipher has a {exposure['block_bits']}-bit block, so "
                f"ciphertext blocks begin colliding after roughly "
                f"{exposure['threshold_gb']} GB under a single key. With a "
                f"{lifetime / 3600:.0f}-hour rekey interval this SA processes about "
                f"{exposure['bytes_per_rekey_gb']} GB per key, which is "
                f"{exposure['ratio_to_threshold']}x the bound. {timing}"
            ),
            reference="Bhargavan & Leurent, Sweet32 (CCS 2016); RFC 8247 s2.1",
            remediation=(
                "Move to a 128-bit block cipher (AES-GCM-256). If that cannot be "
                "scheduled immediately, cut the rekey interval so that less than "
                f"{exposure['threshold_gb']} GB passes under any single key — that "
                "is mitigation, not a fix."
            ),
            evidence=exposure,
        )
    ]


@ike_rule("IKE-014")
def rule_additional_exchange_not_observed(sess: IkeSession) -> list[Finding]:
    """An additional key exchange was negotiated but none was seen to run.

    The selection is cleartext; the exchange that carries it out is an
    encrypted IKE_INTERMEDIATE. When the responder selects an additional key
    exchange and no IKE_INTERMEDIATE appears on the session, the capture shows
    the agreement and not its execution. That is usually a capture that ended
    between the two, so this is informational: it says what was and was not
    observed, and changes no score.
    """
    confirmed = sess.negotiated("IKE", confirmed_only=True)
    addke = _addke_labels(confirmed)
    seen = sess.exchanges_seen("IKE_INTERMEDIATE")
    if not addke or seen:
        return []
    return [
        Finding(
            rule_id="IKE-014",
            title="Additional key exchange negotiated but not observed",
            severity=Severity.INFO,
            subject=_peer(sess),
            detail=(
                "The responder selected " + ", ".join(addke) + ", which RFC 9370 "
                "carries out in IKE_INTERMEDIATE exchanges between IKE_SA_INIT and "
                "IKE_AUTH. None was observed on this session. The negotiated "
                "selection is reported as negotiated; that the additional exchange "
                "completed is not something this capture shows."
            ),
            reference="RFC 9370 s2.2.2; RFC 9242",
            remediation=(
                "Extend the capture window to cover the whole handshake. If the "
                "tunnel carries traffic and still shows no IKE_INTERMEDIATE, check "
                "the gateway's own log for the negotiated key exchange methods."
            ),
            evidence={
                "addke_selected": addke,
                "intermediate_exchanges_seen": seen,
                "messages_seen": len(sess.messages),
            },
        )
    ]


# ---------------------------------------------------------------------------
# Key exchange hygiene — capture scope
# ---------------------------------------------------------------------------

# RFC 7296 s2.10: at least 128 bits; s3.9: Nonce Data between 16 and 256 octets.
MIN_NONCE_BYTES = 16


def _by_distinct_sa(
    sessions: list[IkeSession], key: Callable[[IkeMessage], tuple | None]
) -> dict[tuple, dict[str, tuple[IkeSession, IkeMessage]]]:
    """Group sightings of a value by the distinct IKE SAs that carried it.

    An SA is its initiator SPI. A retransmission, and an IKE_SA_INIT retried
    after a COOKIE or INVALID_KE_PAYLOAD response, keep the same SPI (RFC 7296
    s2.6, s2.6.1), so they collapse into one SA here and can never count as
    reuse on their own.
    """
    out: dict[tuple, dict[str, tuple[IkeSession, IkeMessage]]] = {}
    for sess in sessions:
        for msg in sess.messages:
            k = key(msg)
            if k is not None:
                out.setdefault(k, {}).setdefault(sess.sid, (sess, msg))
    return out


def _one_per_link(sightings: list[tuple[IkeSession, IkeMessage]]) -> list[IkeSession]:
    """One session per peer pair, so a reuse spanning several links is reported
    on each of them rather than only on whichever came first."""
    first: dict[tuple[str, str], IkeSession] = {}
    for sess, _ in sightings:
        first.setdefault(pair_key(sess.peer_a, sess.peer_b), sess)
    return list(first.values())


@capture_rule("IKE-015")
def rule_ke_reuse(sessions: list[IkeSession]) -> list[Finding]:
    """The same key exchange public value from one peer in two or more IKE SAs.

    RFC 7296 s2.12 allows an endpoint to reuse its Diffie-Hellman exponential,
    so this is not a protocol violation and is medium, not high. It is still a
    forward secrecy cost worth knowing about: whoever recovers that one private
    value can recompute the key exchange of every SA that used it. Distinct
    SAs are distinct initiator SPIs, so retransmissions and COOKIE retries,
    which resend the same KE payload on the same SPI, never trigger it.
    """
    reused = _by_distinct_sa(
        sessions, lambda m: (m.src, m.ke_digest) if m.ke_digest else None)
    out = []
    for (peer, digest), by_sa in reused.items():
        if len(by_sa) < 2:
            continue
        sightings = list(by_sa.values())
        spis = sorted(by_sa)
        groups = sorted({m.ke_group for _, m in sightings if m.ke_group})
        for sess in _one_per_link(sightings):
            out.append(
                Finding(
                    rule_id="IKE-015",
                    title="Key exchange public value reused across IKE SAs",
                    severity=Severity.MEDIUM,
                    subject=_peer(sess),
                    detail=(
                        f"{peer} sent the same key exchange public value in "
                        f"{len(by_sa)} distinct IKE SAs in this capture. RFC 7296 "
                        "s2.12 permits an endpoint to reuse its Diffie-Hellman "
                        "exponential, so this is not a protocol violation, but it "
                        "weakens forward secrecy: anyone who later recovers that "
                        "one private value can recompute the key exchange of every "
                        "SA that used it, not just one. The same symptom can also "
                        "come from a random number generator that repeats itself."
                    ),
                    reference="RFC 7296 s2.12",
                    remediation=(
                        f"Configure {peer} to generate a fresh key exchange value "
                        "for every IKE SA, or confirm that its reuse window is "
                        "short and deliberate. If reuse is not configured, check "
                        "the device's random number source."
                    ),
                    evidence={
                        "peer": peer,
                        "ke_sha256": digest,
                        "groups": groups,
                        "distinct_sas": len(by_sa),
                        "initiator_spis": spis,
                        "frames": sorted(m.frame for _, m in sightings),
                        "scope": "this capture",
                    },
                )
            )
    return out


@capture_rule("IKE-016")
def rule_nonce_hygiene(sessions: list[IkeSession]) -> list[Finding]:
    """A nonce shorter than 16 bytes, or the same nonce in two different SAs.

    RFC 7296 s2.10 requires IKEv2 nonces of at least 128 bits and s3.9 says
    nonce values MUST NOT be reused. The length floor is applied to IKEv2
    only, because it is an IKEv2 requirement; IKEv1 is held to the reuse
    check. Reuse is counted across distinct initiator SPIs for the same reason
    as IKE-015, and across all senders, since two devices producing one nonce
    is as much a failure as one device repeating it.
    """
    out = []
    for sess in sessions:
        if sess.version != "IKEv2":
            continue
        short: dict[str, int] = {}
        frames = []
        for msg in sess.messages:
            if msg.nonce_len is not None and msg.nonce_len < MIN_NONCE_BYTES:
                short[msg.src] = min(msg.nonce_len, short.get(msg.src, msg.nonce_len))
                frames.append(msg.frame)
        if not short:
            continue
        who = ", ".join(f"{src} sent {n} bytes" for src, n in sorted(short.items()))
        out.append(
            Finding(
                rule_id="IKE-016",
                title="Nonce shorter than 128 bits",
                severity=Severity.HIGH,
                subject=_peer(sess),
                detail=(
                    f"A nonce below the {MIN_NONCE_BYTES}-byte minimum was observed "
                    f"({who}). RFC 7296 s2.10 requires IKEv2 nonces to be randomly "
                    "chosen and at least 128 bits long. They feed the key derivation "
                    "and make each exchange fresh, so a short one weakens both, and "
                    "it marks an implementation that is not following the standard."
                ),
                reference="RFC 7296 s2.10, s3.9",
                remediation=(
                    "Update or reconfigure the sending device so it emits nonces of "
                    "at least 32 bytes, which also covers the s2.10 rule that a nonce "
                    "be at least half the key size of the negotiated PRF."
                ),
                evidence={
                    "short_nonces": short,
                    "minimum_bytes": MIN_NONCE_BYTES,
                    "frames": frames,
                    "spi": sess.sid,
                },
            )
        )

    reused = _by_distinct_sa(
        sessions, lambda m: (m.nonce_digest,) if m.nonce_digest else None)
    for (digest,), by_sa in reused.items():
        if len(by_sa) < 2:
            continue
        sightings = list(by_sa.values())
        senders = sorted({m.src for _, m in sightings})
        for sess in _one_per_link(sightings):
            out.append(
                Finding(
                    rule_id="IKE-016",
                    title="Nonce reused across IKE SAs",
                    severity=Severity.HIGH,
                    subject=_peer(sess),
                    detail=(
                        f"The same nonce appeared in {len(by_sa)} distinct IKE SAs "
                        f"in this capture, sent by {', '.join(senders)}. RFC 7296 "
                        "s3.9 says nonce values MUST NOT be reused. Nonces are what "
                        "make each SA's keys unique; a repeat points to a broken "
                        "random number generator, which also puts the key exchange "
                        "values from the same device in doubt, or to replayed "
                        "handshake messages."
                    ),
                    reference="RFC 7296 s2.10, s3.9",
                    remediation=(
                        "Treat the sending device's random number source as suspect: "
                        "check for a firmware fix and for adequate entropy at boot, "
                        "and rule out replay by checking whether the device logged "
                        "these SAs itself."
                    ),
                    evidence={
                        "nonce_sha256": digest,
                        "senders": senders,
                        "distinct_sas": len(by_sa),
                        "initiator_spis": sorted(by_sa),
                        "frames": sorted(m.frame for _, m in sightings),
                        "scope": "this capture",
                    },
                )
            )
    return out


# ---------------------------------------------------------------------------
# ESP rules — every finding below is inference, not observation
# ---------------------------------------------------------------------------

CONFIDENCE_FLOOR = 0.35


@esp_rule("ESP-001")
def rule_esp_framing(flow: EspFlow) -> list[Finding]:
    if not flow.predicted_suite:
        return []
    cls_name, spec = P.framing_class_of(flow.predicted_suite)
    if not spec:
        return []

    # confidence in the framing class, not the individual suite
    group_conf = sum(p for name, p in flow.ranked if name in spec["members"])
    if group_conf < CONFIDENCE_FLOOR:
        return []

    verdict = spec["verdict"]
    if verdict == "acceptable":
        return []

    severity = Severity.CRITICAL if verdict == "prohibited" else Severity.MEDIUM
    members = spec["members"]
    if len(members) == 1:
        naming = members[0]
    else:
        naming = " or ".join(members) + " (framing-identical, not separable passively)"

    return [
        Finding(
            rule_id="ESP-001",
            title=f"ESP tunnel using {cls_name}",
            severity=severity,
            subject=flow.key,
            detail=(
                f"Packet framing on this SA matches {spec['signature']}, which "
                f"identifies {naming}. {spec['reason']} "
                f"Inferred from {flow.packets} packets at {group_conf:.0%} confidence "
                "in the framing class."
            ),
            reference="RFC 4303 s2; RFC 8221; NIST SP 800-77 Rev. 1 s4.1",
            remediation=(
                "Reconfigure the child SA proposal to AES-GCM-256 and confirm from "
                "the gateway's own SA table."
            ),
            evidence={
                "framing_class": cls_name,
                "signature": spec["signature"],
                "candidates": members,
                "group_confidence": round(group_conf, 4),
                "top_suite": flow.predicted_suite,
                "packets": flow.packets,
                "distinct_lengths": len(set(flow.payload_lengths)),
                "granularity_test": "applied"
                if len(set(flow.payload_lengths)) >= 8
                else "unavailable (too few distinct lengths)",
            },
            inferred=True,
        )
    ]


@esp_rule("ESP-002")
def rule_low_entropy(flow: EspFlow) -> list[Finding]:
    # Fewer than a dozen usable samples cannot distinguish a cipher from a
    # short-packet artefact, so the rule abstains rather than guessing.
    if len(flow.entropy_samples) < 12:
        return []
    mean_entropy = sum(flow.entropy_samples) / len(flow.entropy_samples)
    if mean_entropy >= 7.0:
        return []
    return [
        Finding(
            rule_id="ESP-002",
            title="ESP payload entropy below the ciphertext floor",
            severity=Severity.HIGH,
            subject=flow.key,
            detail=(
                f"Mean payload entropy is {mean_entropy:.2f} bits/byte. Output of any "
                "sound cipher is statistically indistinguishable from random and sits "
                "above 7.9. This SA is carrying structured data, which points to "
                "ESP-NULL, a compression layer, or a misconfigured transform."
            ),
            reference="RFC 4303 s2.4; RFC 8221 s5",
            remediation="Verify the SA's encryption transform on the gateway; ESP-NULL must not be used on transit links.",
            evidence={"mean_entropy": round(mean_entropy, 3), "packets": flow.packets},
            inferred=True,
        )
    ]


@esp_rule("ESP-003")
def rule_replay_gaps(flow: EspFlow) -> list[Finding]:
    gaps = flow.replay_gaps()
    if flow.packets < 50 or gaps < flow.packets * 0.02:
        return []
    return [
        Finding(
            rule_id="ESP-003",
            title="Anti-replay sequence discontinuities",
            severity=Severity.LOW,
            subject=flow.key,
            detail=(
                f"{gaps} sequence gaps across {flow.packets} packets. Ordinary loss on "
                "a congested path looks like this, but so does replay-window pressure "
                "and out-of-order delivery that will cause the receiver to silently "
                "drop valid traffic."
            ),
            reference="RFC 4303 s3.4.3",
            remediation="Check gateway replay-window size and interface error counters, and enable extended sequence numbers on high-rate SAs.",
            evidence={"gaps": gaps, "packets": flow.packets},
            inferred=True,
        )
    ]


@esp_rule("ESP-004")
def rule_low_confidence(flow: EspFlow) -> list[Finding]:
    if not flow.predicted_suite or flow.packets >= 60:
        return []
    return [
        Finding(
            rule_id="ESP-004",
            title="Insufficient sample for reliable inference",
            severity=Severity.INFO,
            subject=flow.key,
            detail=(
                f"Only {flow.packets} packets observed. The framing signature needs a "
                "few hundred packets before the length-residue distribution is stable, "
                "so treat any suite attribution on this SA as provisional."
            ),
            reference="Internal: inference confidence policy",
            remediation="Extend the capture window on this SA before acting on its result.",
            evidence={"packets": flow.packets},
            inferred=True,
        )
    ]


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def evaluate(assessment: Assessment, disabled: set[str] | None = None) -> Assessment:
    disabled = disabled or set()
    findings: list[Finding] = []

    for sess in assessment.sessions:
        for rule_id, fn in IKE_RULES:
            if rule_id in disabled:
                continue
            try:
                findings.extend(fn(sess))
            except Exception as exc:  # a bad rule must not abort the audit
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        title=f"Rule {rule_id} failed to evaluate",
                        severity=Severity.INFO,
                        subject=_peer(sess),
                        detail=f"{type(exc).__name__}: {exc}",
                        reference="internal",
                        remediation="Report with the capture that triggered it.",
                    )
                )

    for rule_id, fn in CAPTURE_RULES:
        if rule_id in disabled:
            continue
        try:
            findings.extend(fn(assessment.sessions))
        except Exception as exc:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=f"Rule {rule_id} failed to evaluate",
                    severity=Severity.INFO,
                    subject=assessment.capture,
                    detail=f"{type(exc).__name__}: {exc}",
                    reference="internal",
                    remediation="Report with the capture that triggered it.",
                )
            )

    for flow in assessment.flows:
        for rule_id, fn in ESP_RULES:
            if rule_id in disabled:
                continue
            try:
                findings.extend(fn(flow))
            except Exception as exc:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        title=f"Rule {rule_id} failed to evaluate",
                        severity=Severity.INFO,
                        subject=flow.key,
                        detail=f"{type(exc).__name__}: {exc}",
                        reference="internal",
                        remediation="Report with the capture that triggered it.",
                    )
                )

    findings.sort(key=lambda f: (f.severity.rank, f.rule_id, f.subject))
    assessment.findings = findings
    return assessment


def rule_catalogue() -> list[dict]:
    out = []
    for rule_id, fn in IKE_RULES + CAPTURE_RULES + ESP_RULES:
        out.append(
            {
                "id": rule_id,
                "scope": "esp" if (rule_id, fn) in ESP_RULES else "ike",
                "per": ("capture" if (rule_id, fn) in CAPTURE_RULES
                        else "flow" if (rule_id, fn) in ESP_RULES else "session"),
                "function": fn.__name__,
                "doc": (fn.__doc__ or "").strip(),
            }
        )
    return out
