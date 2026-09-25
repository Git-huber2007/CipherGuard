"""Continuous sensor mode.

Everything else in the project is a tool an analyst runs. This is the deployed
form: capture a window of live traffic, assess it, compare against the baseline,
record the trail, alert on regression, repeat. Cryptographic posture is not a
property you establish once — links fail over, firmware is rolled back, peers
change policy — so the assessment has to be a standing process rather than an
annual audit.

Windowing matters for a reason beyond tidiness. An IKE negotiation happens once
and then the SA carries traffic for hours, so a window that is too short sees
ESP with no handshake to attribute it to, and one that is too long delays
detection of the downgrade it exists to catch. The default is a compromise, and
it is a parameter because the right value depends on the link's rekey interval.

Memory is bounded per window by construction: each window builds its own
tracker, the assessment is emitted, and the packet state is discarded. A sensor
that accumulates across windows is a sensor that eventually dies on a busy link.
Disk is bounded the same way `cipherguard sensor` bounds it: evidence, baseline
observations and the audit log all have ceilings, with the same defaults.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from ..audit.engine import evaluate
from ..core.audit_log import DEFAULT_BACKUPS, DEFAULT_MAX_BYTES, AuditLog
from ..core.health import write_sensor_state
from ..core.models import Assessment
from ..core.retention import EVIDENCE_PREFIX, prune_evidence
from ..dissector import ike as ike_mod
from ..dissector.esp import EspTracker
from ..intel.baseline import DEFAULT_RETAIN_DAYS, DEFAULT_RETAIN_PER_PEER
from ..ml.classifier import SuiteClassifier
from ..pipeline import _attribute_volume
from .live import CaptureUnavailable, LiveCapture


@dataclass
class SensorConfig:
    interface: str
    window_seconds: float = 300.0
    max_windows: int | None = None
    min_esp_packets: int = 8
    model_dir: str = "models"
    baseline_db: str | None = "cipherguard-baseline.db"
    audit_log: str | None = "cipherguard-audit.jsonl"
    evidence_dir: str | None = None
    max_packets_per_window: int = 2_000_000
    # retention: the same ceilings and defaults as `cipherguard sensor`
    retain_windows: int = 24
    max_evidence_bytes: int = 4096 << 20
    retain_per_peer: int | None = DEFAULT_RETAIN_PER_PEER
    retain_days: float | None = DEFAULT_RETAIN_DAYS
    audit_max_bytes: int = DEFAULT_MAX_BYTES
    audit_backups: int = DEFAULT_BACKUPS


def _evidence_name(interface: str, index: int) -> str:
    """`window-<iface>-<n>-<epoch>.pcap`: the prefix is what retention prunes.

    The interface name is flattened because on Windows it is a display name
    ("Local Area Connection* 2") that can hold characters no path may contain.
    """
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", interface).strip("_") or "if"
    return f"{EVIDENCE_PREFIX}{safe}-{index}-{int(time.time())}.pcap"


@dataclass
class WindowResult:
    index: int
    started: str
    assessment: Assessment
    downgrades: list = field(default_factory=list)
    capture_stats: dict = field(default_factory=dict)
    evidence_path: str | None = None


def _assess_window(packets, model, min_esp_packets: int, capture_name: str) -> Assessment:
    messages = []
    tracker = EspTracker()
    counts = {"ike": 0, "esp": 0, "other": 0, "total": 0}

    for pkt in packets:
        counts["total"] += 1
        if ike_mod.is_ike_port(pkt):
            msg = ike_mod.parse_message(pkt)
            if msg is not None:
                messages.append(msg)
                counts["ike"] += 1
                continue
        if tracker.consume(pkt):
            counts["esp"] += 1
        else:
            counts["other"] += 1

    sessions = ike_mod.group_sessions(messages)
    flows = tracker.results(min_packets=min_esp_packets)
    _attribute_volume(sessions, flows)
    if model is not None:
        model.annotate(flows)

    assessment = Assessment(
        capture=capture_name,
        started=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sessions=sessions,
        flows=flows,
        stats={
            "packets_read": counts["total"],
            "ike_messages": counts["ike"],
            "esp_packets": counts["esp"],
            "other_packets": counts["other"],
            "ike_sessions": len(sessions),
            "esp_flows_assessed": len(flows),
            "esp_flows_evicted": tracker.evicted,
            "model_loaded": model is not None,
            "parse_errors": sum(len(m.parse_errors) for m in messages),
            "retransmissions": sum(s.retransmissions for s in sessions),
        },
    )
    return evaluate(assessment)


def run(
    config: SensorConfig,
    on_window: Callable[[WindowResult], None] | None = None,
) -> list[WindowResult]:
    """Capture and assess in windows until the window budget is exhausted."""
    model = (
        SuiteClassifier.load(config.model_dir)
        if SuiteClassifier.is_trained(config.model_dir)
        else None
    )
    store = None
    if config.baseline_db:
        from ..intel.baseline import BaselineStore

        store = BaselineStore(config.baseline_db, retain_per_peer=config.retain_per_peer,
                              retain_days=config.retain_days)
    log = AuditLog(config.audit_log, actor="sensor", max_bytes=config.audit_max_bytes,
                   backups=config.audit_backups)

    results: list[WindowResult] = []
    index = 0

    try:
        with LiveCapture(config.interface) as cap:
            while config.max_windows is None or index < config.max_windows:
                index += 1
                started = datetime.now(timezone.utc).isoformat(timespec="seconds")
                name = f"{config.interface}-window-{index}"

                evidence = None
                if config.evidence_dir:
                    os.makedirs(config.evidence_dir, exist_ok=True)
                    evidence = os.path.join(
                        config.evidence_dir, _evidence_name(config.interface, index)
                    )

                before = cap.stats.packets
                packets = cap.packets(
                    max_seconds=config.window_seconds,
                    max_packets=before + config.max_packets_per_window,
                    pcap_path=evidence,
                )
                assessment = _assess_window(
                    packets, model, config.min_esp_packets, name
                )

                drifts = store.record(assessment) if store else []
                downgrades = [d for d in drifts if d.kind == "downgrade"]

                if assessment.sessions or assessment.flows:
                    if evidence:
                        log.assessment(assessment, evidence, source="sensor")
                    else:
                        log._write(
                            {
                                "event": "assessment",
                                "source": "sensor",
                                "capture": name,
                                "score": assessment.score(),
                                "grade": assessment.grade(),
                                "counts": assessment.counts(),
                            }
                        )

                if config.evidence_dir:
                    # after the assessment is recorded, and never the window it
                    # was made from
                    prune_evidence(config.evidence_dir, config.retain_windows,
                                   config.max_evidence_bytes, protect=evidence)
                    write_sensor_state(
                        config.evidence_dir, window=index,
                        window_seconds=config.window_seconds,
                        packets=cap.stats.packets - before,
                        score=assessment.score(),
                        evidence=os.path.basename(evidence) if evidence else None,
                    )

                result = WindowResult(
                    index=index,
                    started=started,
                    assessment=assessment,
                    downgrades=downgrades,
                    capture_stats=cap.stats.to_dict(),
                    evidence_path=evidence,
                )
                results.append(result)
                if on_window:
                    on_window(result)
    except CaptureUnavailable:
        raise
    finally:
        if store:
            store.close()

    return results
