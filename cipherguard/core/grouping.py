"""Assessment structure for review: findings grouped by rule, and per-link views.

A backbone capture raises the same rule once per gateway that trips it, so the
flat findings list repeats itself: 33 entries for what is, in review terms, a
dozen problems spread over four links. Two indexes fix that without discarding
anything:

  finding_groups   one entry per (rule, title), with the highest severity in
                   the group, how many times it fired, and where
  links            one entry per peer pair, holding that pair's IKE sessions,
                   ESP flows and findings, so a reviewer can look at one gateway
                   pair's handshake, tunnel and problems together

Both reference findings, sessions and flows by index into the lists
`Assessment.to_dict()` already emits, so nothing is duplicated and every client
(CLI, API, static build) gets the same grouping from the same code.
"""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .models import Assessment, EspFlow, Finding, IkeSession

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# ESP findings use EspFlow.key, "src->dst:0xSPI"; IKE findings "a <-> b".
_ESP_SUBJECT = re.compile(r"^(?P<src>.+?)->(?P<dst>.+):0x[0-9a-fA-F]+$")
_IKE_SEP = " <-> "


def _addr_sort_key(addr: str) -> tuple:
    try:
        ip = ipaddress.ip_address(addr)
        return (0, ip.version, int(ip))
    except ValueError:
        return (1, 0, addr)


def pair_key(a: str, b: str) -> tuple[str, str]:
    """The canonical, direction-free key for a peer pair: addresses sorted numerically."""
    first, second = sorted((a, b), key=_addr_sort_key)
    return first, second


def link_id(pair: tuple[str, str]) -> str:
    # "~" is unreserved in URLs, so the id survives a round trip through the
    # location hash unescaped; it never occurs in an IPv4 or IPv6 address.
    return f"{pair[0]}~{pair[1]}"


def subject_pair(subject: str) -> tuple[str, str] | None:
    """The peer pair a finding subject names, or None if it names no pair."""
    if _IKE_SEP in subject:
        a, b = subject.split(_IKE_SEP, 1)
        return pair_key(a.strip(), b.strip())
    m = _ESP_SUBJECT.match(subject.strip())
    if m:
        return pair_key(m.group("src"), m.group("dst"))
    return None


def _worst(severities: list[str]) -> str | None:
    return min(severities, key=_RANK.__getitem__) if severities else None


def group_findings(findings: list["Finding"]) -> list[dict[str, Any]]:
    """Collapse repeated findings into one entry per (rule_id, title)."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for i, f in enumerate(findings):
        key = (f.rule_id, f.title)
        g: dict[str, Any] | None = groups.get(key)
        if g is None:
            g = groups[key] = {
                "key": f"{f.rule_id}|{f.title}",
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "count": 0,
                "subjects": [],
                "inferred": False,
                "findings": [],
            }
        g["count"] += 1
        g["findings"].append(i)
        if f.subject not in g["subjects"]:
            g["subjects"].append(f.subject)
        g["inferred"] = g["inferred"] or f.inferred
        if _RANK[f.severity.value] < _RANK[g["severity"]]:
            g["severity"] = f.severity.value

    return sorted(
        groups.values(),
        key=lambda g: (_RANK[g["severity"]], -g["count"], g["rule_id"], g["title"]),
    )


def _strength(sessions: list["IkeSession"]) -> dict[str, Any] | None:
    """The weakest negotiated IKE suite on the link, or None when no IKE was seen.

    Strength comes from the handshake only. The ESP suite is inferred, and a
    framing class spans suites of different strength, so putting a bit count
    on it would state more than the evidence supports.
    """
    scored = [s.strength() for s in sessions]
    scored = [s for s in scored if s.kex_family != "unknown"]
    if not scored:
        return None
    weakest = min(scored, key=lambda s: (s.classical_bits, s.quantum_bits))
    return {
        "classical_bits": weakest.classical_bits,
        "quantum_bits": weakest.quantum_bits,
        "classical_grade": weakest.classical_grade,
        "quantum_safe": weakest.quantum_safe,
        "kex_family": weakest.kex_family,
        "source": "negotiated IKE proposal",
    }


def build_links(
    sessions: list["IkeSession"], flows: list["EspFlow"], findings: list["Finding"]
) -> tuple[list[dict[str, Any]], list[int]]:
    """One entry per peer pair, worst first, plus findings that belong to none.

    ESP flows are attached to IKE sessions by address pair, not by SPI. The
    child SA's SPI is negotiated inside IKE_AUTH, which is encrypted, so a
    passive observer can never link an ESP SPI to the IKE SA that created it
    cryptographically; the address pair is the only correlation available.
    The consequence is stated rather than hidden: two tunnels between the same
    pair of gateways are pooled into one link, and a link reports how many
    tunnels it holds.
    """
    links: dict[tuple[str, str], dict[str, Any]] = {}

    def link(pair: tuple[str, str]) -> dict[str, Any]:
        if pair not in links:
            links[pair] = {
                "id": link_id(pair),
                "peers": list(pair),
                "sessions": [],
                "flows": [],
                "findings": [],
            }
        return links[pair]

    for i, s in enumerate(sessions):
        link(pair_key(s.peer_a, s.peer_b))["sessions"].append(i)
    for i, f in enumerate(flows):
        link(pair_key(f.src, f.dst))["flows"].append(i)

    unlinked: list[int] = []
    for i, finding in enumerate(findings):
        pair = subject_pair(finding.subject)
        if pair is not None and pair in links:
            links[pair]["findings"].append(i)
        else:
            unlinked.append(i)

    out = []
    for pair, entry in links.items():
        entry["findings"].sort(key=lambda i: (_RANK[findings[i].severity.value], i))
        sevs = [findings[i].severity.value for i in entry["findings"]]
        entry["worst_severity"] = _worst(sevs)
        entry["counts"] = {s: sevs.count(s) for s in SEVERITY_ORDER if s in sevs}
        entry["strength"] = _strength([sessions[i] for i in entry["sessions"]])
        entry["tunnels"] = len(entry["flows"])
        entry["pooled"] = len(entry["flows"]) > 1
        out.append(entry)

    def order(e: dict[str, Any]) -> tuple:
        strength = e["strength"]
        return (
            _RANK.get(e["worst_severity"], len(SEVERITY_ORDER)),
            -len(e["findings"]),
            strength["classical_bits"] if strength else 10_000,
            [_addr_sort_key(p) for p in e["peers"]],
        )

    out.sort(key=order)
    return out, unlinked


def review_index(assessment: "Assessment") -> dict[str, Any]:
    links, unlinked = build_links(assessment.sessions, assessment.flows, assessment.findings)
    return {
        "finding_groups": group_findings(assessment.findings),
        "links": links,
        "unlinked_findings": unlinked,
    }
