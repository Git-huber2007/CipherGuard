"""User-labelled real captures: ground truth for the ESP inference model.

The public Wireshark corpus in `realworld` validates the IKE dissector, but it
contains handshakes only — no sustained ESP — so until now the inference model
had never been scored against a real tunnel. This module closes that gap.

The difficulty is where the ground truth lives. The ESP suite is negotiated
inside IKE_AUTH, which is encrypted, so nothing on the wire can label an ESP
flow. The only authoritative source is the endpoint's own configuration or SA
table. The label therefore has to be supplied by whoever captured the traffic,
and it has to say where it came from, because a label is only as good as its
source.

Sidecar format
--------------
A capture `site-a.pcap` is labelled by `site-a.pcap.label.json` beside it::

    {
      "source": "swanctl --list-sas on the responder",
      "notes": "optional free text",
      "flows": [
        {"spi": "0xc3a1f00d", "suite": "AES-GCM-256 (ICV 16)"},
        {"peers": ["203.0.113.10", "198.51.100.20"],
         "suite": "AES-CBC-128 / HMAC-SHA1-96",
         "source": "ipsec statusall on the initiator"}
      ]
    }

Each entry declares one catalogued suite (see `core.constants.ESP_SUITES`) and
selects flows either by SPI (optionally narrowed with `dst`) or by an
unordered peer pair, which covers both directions of the tunnel. A per-entry
`source` overrides the top-level one; every entry must end up with a source.
When both an SPI entry and a peer entry match a flow, the SPI entry wins, since
it is the more specific claim.

Comparison is at framing-class level. Suites inside a class share IV, ICV and
block size, so they are not separable from the wire by construction; scoring
the exact suite would measure a coin toss and call it accuracy.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from ..core.constants import ESP_SUITES
from ..core.models import EspFlow

LABEL_SUFFIX = ".label.json"
CAPTURE_EXTENSIONS = (".pcap", ".pcapng", ".cap")


class LabelError(ValueError):
    """A label sidecar is malformed or makes a claim that cannot be checked."""


@dataclass
class LabelEntry:
    suite: str
    source: str
    spi: int | None = None
    dst: str | None = None
    peers: tuple[str, str] | None = None

    def selector(self) -> str:
        if self.spi is not None:
            where = f" to {self.dst}" if self.dst else ""
            return f"SPI 0x{self.spi:08x}{where}"
        assert self.peers is not None
        return f"peers {self.peers[0]} <-> {self.peers[1]}"

    def matches(self, flow: EspFlow) -> bool:
        if self.spi is not None:
            return flow.spi == self.spi and (self.dst is None or flow.dst == self.dst)
        assert self.peers is not None
        return {flow.src, flow.dst} == set(self.peers)


@dataclass
class CaptureLabel:
    capture: str
    path: str
    source: str
    entries: list[LabelEntry]
    notes: str = ""

    def entry_for(self, flow: EspFlow) -> LabelEntry | None:
        """The most specific entry that claims this flow, SPI before peer pair."""
        by_spi = [e for e in self.entries if e.spi is not None and e.matches(flow)]
        if by_spi:
            return by_spi[0]
        by_peer = [e for e in self.entries if e.peers is not None and e.matches(flow)]
        return by_peer[0] if by_peer else None


@dataclass
class RealSample:
    """One labelled real ESP flow, with the capture it came from."""

    capture: str
    flow: EspFlow
    suite: str
    source: str
    selector: str = ""


@dataclass
class RealCorpus:
    samples: list[RealSample] = field(default_factory=list)
    captures: list[str] = field(default_factory=list)      # labelled, contributed flows
    unlabelled: list[str] = field(default_factory=list)    # no sidecar at all
    empty: list[dict] = field(default_factory=list)        # labelled, no usable flow
    unlabelled_flows: list[dict] = field(default_factory=list)
    unmatched_entries: list[dict] = field(default_factory=list)


def label_path(capture: str) -> str:
    return capture + LABEL_SUFFIX


def _parse_spi(value) -> int:
    if isinstance(value, bool):
        raise LabelError(f"SPI must be an integer or hex string, got {value!r}")
    if isinstance(value, int):
        spi = value
    elif isinstance(value, str):
        # swanctl and `ip xfrm` print SPIs as bare hex, so a string is always hex
        try:
            spi = int(value, 16)
        except ValueError:
            raise LabelError(f"SPI {value!r} is not a hex number") from None
    else:
        raise LabelError(f"SPI must be an integer or hex string, got {value!r}")
    if not 0 < spi <= 0xFFFFFFFF:
        raise LabelError(f"SPI {value!r} is outside the 32-bit range (0 is reserved)")
    return spi


def parse_label(data: dict, capture: str, path: str = "") -> CaptureLabel:
    """Validate a decoded sidecar. Every rejection names the offending entry."""
    if not isinstance(data, dict):
        raise LabelError(f"{path or capture}: label must be a JSON object")

    top_source = data.get("source") or ""
    raw = data.get("flows")
    if not isinstance(raw, list) or not raw:
        raise LabelError(f"{path or capture}: 'flows' must be a non-empty list")

    entries: list[LabelEntry] = []
    seen_spi: set[tuple[int, str | None]] = set()
    for i, item in enumerate(raw):
        where = f"{path or capture}: flows[{i}]"
        if not isinstance(item, dict):
            raise LabelError(f"{where} must be an object")

        suite = item.get("suite")
        if suite not in ESP_SUITES:
            raise LabelError(
                f"{where}: suite {suite!r} is not in the catalogue. Known suites: "
                + "; ".join(ESP_SUITES)
            )

        source = item.get("source") or top_source
        if not isinstance(source, str) or not source.strip():
            raise LabelError(
                f"{where}: no 'source'. A label must say where the ground truth "
                "came from (e.g. \"swanctl --list-sas on the responder\"), because "
                "the wire cannot vouch for it."
            )

        has_spi, has_peers = "spi" in item, "peers" in item
        if has_spi == has_peers:
            raise LabelError(f"{where}: give exactly one of 'spi' or 'peers'")

        if has_spi:
            spi = _parse_spi(item["spi"])
            dst = item.get("dst")
            key = (spi, dst)
            if key in seen_spi:
                raise LabelError(f"{where}: SPI 0x{spi:08x} is labelled twice")
            seen_spi.add(key)
            entries.append(LabelEntry(suite=suite, source=source.strip(), spi=spi, dst=dst))
        else:
            peers = item["peers"]
            if (not isinstance(peers, list) or len(peers) != 2
                    or not all(isinstance(p, str) and p for p in peers)
                    or peers[0] == peers[1]):
                raise LabelError(f"{where}: 'peers' must be two distinct addresses")
            entries.append(
                LabelEntry(suite=suite, source=source.strip(), peers=(peers[0], peers[1]))
            )

    return CaptureLabel(
        capture=os.path.basename(capture),
        path=path,
        source=top_source,
        entries=entries,
        notes=data.get("notes", "") or "",
    )


def load_label(capture: str) -> CaptureLabel | None:
    """The capture's sidecar label, or None when it has none."""
    path = label_path(capture)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise LabelError(f"{path}: not valid JSON ({exc})") from None
    return parse_label(data, capture, path)


def extract_esp_flows(capture: str, min_packets: int = 8) -> tuple[list[EspFlow], list[EspFlow]]:
    """(assessable, too_short) ESP flows, tracked exactly as the pipeline does."""
    from ..dissector import ike as ike_mod
    from ..dissector.esp import EspTracker
    from ..dissector.pcap import read_packets

    tracker = EspTracker()
    for pkt in read_packets(capture):
        if ike_mod.is_ike_port(pkt) and ike_mod.parse_message(pkt) is not None:
            continue
        tracker.consume(pkt)
    every = tracker.all_flows()
    kept = [f for f in every if f.packets >= min_packets]
    short = [f for f in every if f.packets < min_packets]
    return kept, short


def _flow_ref(flow: EspFlow) -> dict:
    return {"flow": flow.key, "spi": f"0x{flow.spi:08x}", "src": flow.src,
            "dst": flow.dst, "packets": flow.packets}


def match_flows(label: CaptureLabel, flows: list[EspFlow], short: list[EspFlow] | None = None):
    """Pair flows with label entries. Nothing is dropped without a record.

    Returns (matched, unlabelled_flows, unmatched_entries, short_labelled), where
    matched is a list of (flow, entry).
    """
    matched: list[tuple[EspFlow, LabelEntry]] = []
    unlabelled: list[dict] = []
    used: set[int] = set()
    for flow in flows:
        entry = label.entry_for(flow)
        if entry is None:
            unlabelled.append(_flow_ref(flow))
            continue
        matched.append((flow, entry))
        used.add(id(entry))

    short_labelled: list[dict] = []
    for flow in short or []:
        entry = label.entry_for(flow)
        if entry is not None:
            used.add(id(entry))
            short_labelled.append({**_flow_ref(flow), "label": entry.selector(),
                                   "suite": entry.suite})

    unmatched = [
        {"label": e.selector(), "suite": e.suite}
        for e in label.entries if id(e) not in used
    ]
    return matched, unlabelled, unmatched, short_labelled


def collect(directory: str, min_packets: int = 8) -> RealCorpus:
    """Every labelled real ESP flow in a directory, with a full accounting.

    Captures without a sidecar are listed as unlabelled rather than skipped
    quietly: a corpus that shrinks without saying so looks exactly like one that
    was never bigger.
    """
    corpus = RealCorpus()
    if not os.path.isdir(directory):
        raise FileNotFoundError(directory)

    for name in sorted(os.listdir(directory)):
        if not name.lower().endswith(CAPTURE_EXTENSIONS):
            continue
        path = os.path.join(directory, name)
        label = load_label(path)
        if label is None:
            corpus.unlabelled.append(name)
            continue

        flows, short = extract_esp_flows(path, min_packets)
        matched, unlabelled, unmatched, short_labelled = match_flows(label, flows, short)
        corpus.unlabelled_flows += [{"capture": name, **u} for u in unlabelled]
        corpus.unmatched_entries += [{"capture": name, **u} for u in unmatched]

        if not matched:
            if short_labelled:
                reason = f"labelled flows have fewer than {min_packets} packets"
            elif flows:
                reason = "no label entry matches any ESP flow in the capture"
            else:
                reason = "no ESP traffic in capture"
            corpus.empty.append({"capture": name, "reason": reason})
            continue

        corpus.captures.append(name)
        for flow, entry in matched:
            corpus.samples.append(RealSample(
                capture=name, flow=flow, suite=entry.suite,
                source=entry.source, selector=entry.selector(),
            ))
    return corpus


# ---------------------------------------------------------------------------
# label-check
# ---------------------------------------------------------------------------


def _explain_miss(pred, truth: str, truth_class: str | None) -> dict:
    """Why the model's answer differs from the label, in stated reasons."""
    from ..audit.policy import FRAMING_CLASSES

    members = set(FRAMING_CLASSES[truth_class]["members"]) if truth_class else {truth}
    excluded = pred.excluded or []
    truth_excluded = [
        {"suite": s, "reason": r} for s, r in excluded if s in members
    ]
    truth_prob = sum(p for s, p in pred.ranked if s in members)
    if truth_excluded and len(truth_excluded) == len(members):
        verdict = ("the plausibility mask ruled out every member of the labelled "
                   "class; either the label is wrong or the flow violates the "
                   "framing model (TFC padding, nesting, an uncatalogued transform)")
    elif truth_excluded:
        verdict = ("the mask ruled out part of the labelled class; the surviving "
                   "members were outranked by the learned models")
    else:
        verdict = ("the labelled class survived the mask and was outranked by the "
                   "learned models")
    return {
        "truth_class_probability": round(float(truth_prob), 4),
        "truth_excluded": truth_excluded,
        "all_exclusions": [{"suite": s, "reason": r} for s, r in excluded],
        "diagnosis": verdict,
    }


def score_flow(model, flow: EspFlow, truth: str) -> dict:
    """Run inference on one flow and compare against the labelled suite."""
    from ..audit.policy import framing_class_of

    pred = model.predict_one(flow)
    truth_class, _ = framing_class_of(truth)
    pred_class, pred_spec = framing_class_of(pred.label)
    members = pred_spec["members"] if pred_spec else [pred.label]
    class_conf = sum(p for s, p in pred.ranked if s in members)
    hit = truth_class is not None and truth_class == pred_class

    row = {
        **_flow_ref(flow),
        "label_suite": truth,
        "label_class": truth_class,
        "predicted_suite": pred.label,
        "predicted_class": pred_class,
        "class_confidence": round(float(class_conf), 4),
        "hit": hit,
        "exact_suite_match": pred.label == truth,
    }
    if not hit:
        row["miss"] = _explain_miss(pred, truth, truth_class)
    return row


def check_capture(capture: str, model, min_packets: int = 8) -> dict:
    """Score one capture's ESP flows against its sidecar label."""
    name = os.path.basename(capture)
    label = load_label(capture)
    if label is None:
        return {
            "capture": name,
            "labelled": False,
            "label_path": label_path(capture),
            "results": [], "hits": 0, "misses": 0,
            "passed": False,
        }

    flows, short = extract_esp_flows(capture, min_packets)
    matched, unlabelled, unmatched, short_labelled = match_flows(label, flows, short)

    results = []
    for flow, entry in matched:
        row = score_flow(model, flow, entry.suite)
        row["label"] = entry.selector()
        row["label_source"] = entry.source
        results.append(row)

    hits = sum(1 for r in results if r["hit"])
    return {
        "capture": name,
        "labelled": True,
        "label_path": label.path,
        "label_source": label.source,
        "notes": label.notes,
        "results": results,
        "hits": hits,
        "misses": len(results) - hits,
        "unlabelled_flows": unlabelled,
        "unmatched_entries": unmatched,
        "too_short": short_labelled,
        "min_packets": min_packets,
        # A labelled capture that scores nothing has not passed; it has not
        # been tested.
        "passed": bool(results) and hits == len(results),
    }


def find_captures(directory: str) -> list[str]:
    if not os.path.isdir(directory):
        return []
    return sorted(
        n for n in os.listdir(directory) if n.lower().endswith(CAPTURE_EXTENSIONS)
    )


def check_directory(directory: str, model, min_packets: int = 8) -> dict:
    """label-check every labelled capture in a directory; list the rest."""
    labelled, unlabelled, errors = [], [], []
    for name in find_captures(directory):
        path = os.path.join(directory, name)
        if not os.path.exists(label_path(path)):
            unlabelled.append(name)
            continue
        try:
            labelled.append(check_capture(path, model, min_packets))
        except LabelError as exc:
            errors.append({"capture": name, "error": str(exc)})

    rows = [r for c in labelled for r in c["results"]]
    return {
        "labelled": len(labelled),
        "unlabelled": unlabelled,
        "label_errors": errors,
        "flows": len(rows),
        "hits": sum(1 for r in rows if r["hit"]),
        "captures": labelled,
        "passed": not errors and all(c["passed"] for c in labelled),
    }
