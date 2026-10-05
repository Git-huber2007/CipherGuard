"""Tests for Live Network Interface Packet Sniffer & Telemetry Streamer.

These drive the sniffer through its explicit replay source, because a raw
socket needs privileges a test run does not have. What happens when the live
source cannot start, and what the live path keeps, is in test_guarantees.py.
"""

from __future__ import annotations

import os
import time
import pytest

from cipherguard.capture import live_sniffer
from cipherguard.capture.live_sniffer import LiveSniffer
from cipherguard.dissector.pcap import read_packets

pytestmark = pytest.mark.no_model


@pytest.fixture(autouse=True)
def _samples(tmp_path, monkeypatch):
    """Replay from a generated capture, not from whatever is in samples/."""
    from cipherguard.lab import pcapgen

    samples = tmp_path / "samples"
    samples.mkdir()
    pcapgen.scenario_hardened(str(samples / "hardened.pcap"))
    monkeypatch.setattr(live_sniffer, "_samples_dir", lambda: str(samples))


def test_sniffer_lifecycle_replay():
    sniffer = LiveSniffer()
    assert not sniffer.running

    st = sniffer.start(replay=True)
    assert st["running"] is True
    assert st["mode"] == "replay"

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

    sniffer.start(replay=True)
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
    sniffer.start(replay=True)
    time.sleep(0.4)
    sniffer.stop()

    snapshot_file = str(tmp_path / "test_snapshot.pcap")
    res = sniffer.snapshot_to_pcap(snapshot_file)
    assert res["success"] is True
    assert res["packets_written"] > 0
    assert res["source"] == "replay"
    assert os.path.exists(snapshot_file)
    assert os.path.getsize(snapshot_file) > 24

    # Validate exported pcap with standard parser
    pkts = list(read_packets(snapshot_file))
    assert len(pkts) == res["packets_written"]


def test_sniffer_idempotent():
    sniffer = LiveSniffer()
    s1 = sniffer.start(replay=True)
    s2 = sniffer.start(replay=True)
    assert s1["running"] is True
    assert s2["running"] is True

    time.sleep(0.1)
    sniffer.stop()
    sniffer.stop()  # Second stop should not error
    assert sniffer.running is False
