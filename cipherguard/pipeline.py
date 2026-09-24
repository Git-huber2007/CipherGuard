"""Analysis pipeline: capture file in, scored assessment out.

Single pass over the capture. Each packet is offered to the IKE dissector and
the ESP tracker; neither holds more than flow-level metadata, so memory is
bounded by the number of distinct SAs rather than by capture size.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from .audit.engine import evaluate
from .core.models import Assessment, IkeMessage
from .dissector import ike as ike_mod
from .dissector.esp import EspTracker
from .dissector.pcap import read_packets
from .ml.classifier import SuiteClassifier

DEFAULT_MODEL_DIR = "models"


def analyze(
    capture: str,
    model_dir: str = DEFAULT_MODEL_DIR,
    min_esp_packets: int = 8,
    max_packets: int | None = None,
    disabled_rules: set[str] | None = None,
) -> Assessment:
    if not os.path.exists(capture):
        raise FileNotFoundError(capture)

    started = time.perf_counter()
    messages: list[IkeMessage] = []
    tracker = EspTracker()

    total = ike_seen = esp_seen = other = 0
    first_ts = last_ts = None

    for pkt in read_packets(capture):
        total += 1
        if max_packets and total > max_packets:
            break
        if first_ts is None:
            first_ts = pkt.timestamp
        last_ts = pkt.timestamp

        if ike_mod.is_ike_port(pkt):
            msg = ike_mod.parse_message(pkt)
            if msg is not None:
                messages.append(msg)
                ike_seen += 1
                continue
        if tracker.consume(pkt):
            esp_seen += 1
        else:
            other += 1

    sessions = ike_mod.group_sessions(messages)
    flows = tracker.results(min_packets=min_esp_packets)
    _attribute_volume(sessions, flows)

    # Model loading is timed apart from packet processing. It is a fixed cost
    # (unpickling a forest, reading CNN weights, hashing both against the
    # manifest) that dominates any small capture: on the demo captures it was
    # most of the wall time, so dividing packets by total time reported a rate
    # some 25x below the pipeline's real steady state.
    model_loaded = False
    model_metrics: dict = {}
    model_load_seconds = 0.0
    if SuiteClassifier.is_trained(model_dir):
        load_started = time.perf_counter()
        model = SuiteClassifier.load(model_dir)
        model_load_seconds = time.perf_counter() - load_started
        model.annotate(flows)
        model_loaded = True
        model_metrics = model.metrics

    elapsed = time.perf_counter() - started
    assessment = Assessment(
        capture=os.path.basename(capture),
        started=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sessions=sessions,
        flows=flows,
        stats={
            "packets_read": total,
            "ike_messages": ike_seen,
            "esp_packets": esp_seen,
            "other_packets": other,
            "ike_sessions": len(sessions),
            "esp_flows_tracked": len(tracker.all_flows()),
            "esp_flows_assessed": len(flows),
            "capture_seconds": round((last_ts or 0) - (first_ts or 0), 3),
            "analysis_seconds": round(elapsed, 3),
            "model_load_seconds": round(model_load_seconds, 3),
            # everything except the model load: reading, dissection, flow
            # tracking and inference. This is what throughput is measured on.
            "processing_seconds": round(max(elapsed - model_load_seconds, 0.0), 4),
            "model_loaded": model_loaded,
            "model_metrics": model_metrics,
            "parse_errors": sum(len(m.parse_errors) for m in messages),
        },
    )

    return evaluate(assessment, disabled=disabled_rules)


def _attribute_volume(sessions, flows) -> None:
    """Attach each ESP flow's byte volume to the IKE session for its peer pair.

    The association is by address pair rather than by SPI: the child SA's SPI is
    negotiated inside the encrypted IKE_AUTH exchange, so a passive observer can
    never link an ESP SPI to its parent IKE SA cryptographically. Matching on
    peers is the only correlation available, and it is stated here rather than
    hidden because it is an approximation — two tunnels between the same pair of
    gateways will be pooled together.
    """
    for sess in sessions:
        peers = {sess.peer_a, sess.peer_b}
        total = 0
        duration = 0.0
        for flow in flows:
            if {flow.src, flow.dst} & peers:
                total += sum(flow.payload_lengths)
                duration = max(duration, flow.duration)
        sess.observed_bytes = total
        sess.observed_seconds = duration


MIN_PACKETS_FOR_RATE = 10_000


def throughput_estimate(assessment: Assessment) -> dict:
    """Packet-processing rate on this host, or an honest refusal to state one.

    The rate is packets over processing time, which excludes the fixed cost of
    loading the model. Below MIN_PACKETS_FOR_RATE packets no rate is given at
    all: on a capture of a few thousand packets the run is over in
    milliseconds, dominated by interpreter warm-up and cache effects, and any
    packets/sec figure derived from it is noise that contradicts the measured
    steady state. A misleading number is worse than no number, so the caller
    gets the timings and the reason instead.
    """
    stats = assessment.stats
    packets = stats.get("packets_read", 0)
    processing = stats.get("processing_seconds", stats.get("analysis_seconds", 0))
    measurable = packets >= MIN_PACKETS_FOR_RATE and processing > 0
    return {
        "measurable": measurable,
        "packets_per_second": round(packets / processing, 1) if measurable else None,
        "packets_read": packets,
        "min_packets_for_rate": MIN_PACKETS_FOR_RATE,
        "processing_seconds": processing,
        "model_load_seconds": stats.get("model_load_seconds", 0.0),
        "analysis_seconds": stats.get("analysis_seconds"),
        "note": (
            "Measured single-threaded in the pure-Python reference reader, "
            "excluding model load. The C++/DPDK ingestion path is a separate "
            "component; this is the portable path's real rate, not a line-rate claim."
            if measurable else
            f"Capture too small to measure throughput: {packets:,} packets, fewer "
            f"than the {MIN_PACKETS_FOR_RATE:,} needed for a stable rate. Run "
            "`cipherguard bench` for a reproducible figure."
        ),
    }
