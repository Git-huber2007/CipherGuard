"""Tests for Live Network Interface Packet Sniffer & Telemetry Streamer."""

from __future__ import annotations

import os
import queue
import time
import pytest

from cipherguard.capture.live_sniffer import LiveSniffer
from cipherguard.dissector.pcap import read_packets

pytestmark = pytest.mark.no_model


def test_sniffer_lifecycle_simulated():
    sniffer = LiveSniffer()
    assert not sniffer.running

    st = sniffer.start(force_simulation=True)
    assert st["running"] is True
    assert st["mode"] == "simulated_wire"

    # Let sniffer generate a few packets
    time.sleep(0.35)

    status = sniffer.get_status()
    assert status["packets_captured"] > 0
    assert status["bytes_captured"] > 0
    assert isinstance(status["active_spis"], list)

    stopped = sniffer.stop()
    assert stopped["running"] is False
    assert stopped["mode"] == "idle"


def test_sniffer_subscriber_queue():
    sniffer = LiveSniffer()
    q = sniffer.subscribe()
    assert q in sniffer.subscribers

    sniffer.start(force_simulation=True)
    time.sleep(0.35)
    sniffer.stop()

    # Verify events arrived in queue
    events = []
    while not q.empty():
        events.append(q.get_nowait())

    sniffer.unsubscribe(q)
    assert q not in sniffer.subscribers
    assert len(events) > 0
    first = events[0]
    assert "timestamp" in first
    assert "type" in first
    assert "src" in first
    assert "dst" in first


def test_sniffer_snapshot_to_pcap(tmp_path):
    sniffer = LiveSniffer()
    sniffer.start(force_simulation=True)
    time.sleep(0.4)
    sniffer.stop()

    snapshot_file = str(tmp_path / "test_snapshot.pcap")
    res = sniffer.snapshot_to_pcap(snapshot_file)
    assert res["success"] is True
    assert res["packets_written"] > 0
    assert os.path.exists(snapshot_file)
    assert os.path.getsize(snapshot_file) > 24

    # Validate exported pcap with standard parser
    pkts = list(read_packets(snapshot_file))
    assert len(pkts) == res["packets_written"]


def test_sniffer_idempotent():
    sniffer = LiveSniffer()
    s1 = sniffer.start(force_simulation=True)
    s2 = sniffer.start(force_simulation=True)
    assert s1["running"] is True
    assert s2["running"] is True

    time.sleep(0.1)
    sniffer.stop()
    sniffer.stop()  # Second stop should not error
    assert sniffer.running is False
