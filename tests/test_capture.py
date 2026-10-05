"""Live capture and sensor mode.

These tests skip rather than fail when the host cannot capture, because
CAP_NET_RAW is a deployment property and a developer laptop legitimately lacks
it. What must never be skipped is the BPF program's validity — a filter with an
out-of-range jump is rejected by the kernel verifier at attach time and takes
the whole sensor down, and that is checkable without any privilege at all.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

from cipherguard.capture.live import (
    LiveCapture,
    _ipsec_filter,
    available,
    list_interfaces,
)
from cipherguard.lab import pcapgen

live_ok, live_why = available()
requires_capture = pytest.mark.skipif(not live_ok, reason=f"live capture: {live_why}")


# ---------------------------------------------------------------------------
# BPF program validity — checkable without privilege
# ---------------------------------------------------------------------------


def test_bpf_jump_targets_are_in_range():
    """Regression: the first version branched past the end of the program. The
    kernel verifier rejected it with EINVAL at attach time, which surfaced as a
    total capture failure rather than as a filtering problem."""
    prog = _ipsec_filter()
    assert len(prog) % 8 == 0
    instructions = [struct.unpack_from("HBBI", prog, i) for i in range(0, len(prog), 8)]
    for i, (op, jt, jf, _k) in enumerate(instructions):
        if op & 0x07 != 0x05:  # only BPF_JMP carries branch targets
            continue
        assert 0 <= i + 1 + jt < len(instructions), f"instruction {i} jt escapes"
        assert 0 <= i + 1 + jf < len(instructions), f"instruction {i} jf escapes"


def test_bpf_program_terminates_in_returns():
    prog = _ipsec_filter()
    instructions = [struct.unpack_from("HBBI", prog, i) for i in range(0, len(prog), 8)]
    assert instructions[-2][0] & 0x07 == 0x06  # ret accept
    assert instructions[-1][0] & 0x07 == 0x06  # ret drop
    assert instructions[-2][3] > 0  # accept returns a snaplen
    assert instructions[-1][3] == 0  # drop returns zero


def test_capture_availability_reports_a_reason():
    ok, why = available()
    assert isinstance(ok, bool)
    assert why and isinstance(why, str)


def test_interface_enumeration_does_not_raise():
    assert isinstance(list_interfaces(), list)


# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------


def _emit(port: int, payload: bytes, count: int = 30, delay: float = 0.02) -> None:
    time.sleep(0.8)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(count):
        sock.sendto(payload, ("127.0.0.1", port))
        time.sleep(delay)


@requires_capture
def test_kernel_filter_excludes_non_ipsec_traffic():
    """The filter is what lets the sensor keep up on a link carrying mostly
    non-IPsec traffic, so it has to actually exclude things."""
    threading.Thread(target=_emit, args=(500, b"\x00" * 4 + b"\x11" * 28), daemon=True).start()
    threading.Thread(target=_emit, args=(9999, b"X" * 120), daemon=True).start()

    with LiveCapture("lo") as cap:
        packets = list(cap.packets(max_seconds=3.0))
        assert cap.kernel_filter, "filter was rejected and silently disabled"

    ports = {p.dport for p in packets} | {p.sport for p in packets}
    assert 500 in ports
    assert 9999 not in ports, "non-IPsec traffic reached userspace"


@requires_capture
def test_capture_honours_its_time_bound():
    """An unbounded capture loop on a busy link is an outage on the sensor."""
    with LiveCapture("lo") as cap:
        started = time.time()
        list(cap.packets(max_seconds=1.5))
        assert 1.0 < time.time() - started < 4.0


@requires_capture
def test_capture_honours_its_packet_bound():
    threading.Thread(target=_emit, args=(500, b"\x00" * 4 + b"\x11" * 28, 200, 0.001), daemon=True).start()
    with LiveCapture("lo") as cap:
        list(cap.packets(max_packets=10, max_seconds=5))
        assert cap.stats.packets <= 10


@requires_capture
def test_capture_writes_replayable_evidence(tmp_path):
    """A finding from live traffic is unfalsifiable without the packets it came
    from, so the evidence file has to be readable by the ordinary file path."""
    from cipherguard.dissector.pcap import read_packets

    threading.Thread(target=_emit, args=(500, b"\x00" * 4 + b"\x11" * 28), daemon=True).start()
    evidence = str(tmp_path / "window.pcap")
    with LiveCapture("lo") as cap:
        list(cap.packets(max_seconds=2.5, pcap_path=evidence))

    replayed = list(read_packets(evidence))
    assert replayed, "evidence file contained no readable packets"


# ---------------------------------------------------------------------------
# Sensor mode
# ---------------------------------------------------------------------------


@requires_capture
def test_sensor_assesses_live_negotiation(tmp_path):
    """End to end: a weak IKEv1 negotiation on the wire becomes a graded
    assessment with findings, without a capture file in between."""
    from cipherguard.capture.sensor import SensorConfig, run

    weak = pcapgen.ikev1_message(
        b"\x11" * 8,
        b"\x00" * 8,
        4,
        [(1, pcapgen.ikev1_sa_payload(0, 5, 1, 1, 2, 172800))],
    )
    threading.Thread(target=_emit, args=(500, weak, 40, 0.03), daemon=True).start()

    results = run(
        SensorConfig(
            interface="lo",
            window_seconds=3.0,
            max_windows=1,
            baseline_db=None,
            audit_log=None,
            model_dir="models",
        )
    )
    assert len(results) == 1
    a = results[0].assessment
    assert a.sessions, "no IKE session recovered from live traffic"
    fired = {f.rule_id for f in a.findings}
    assert "IKE-001" in fired  # IKEv1
    assert "IKE-002" in fired  # Aggressive Mode
    assert a.score() < 60


@requires_capture
def test_sensor_window_state_does_not_accumulate(tmp_path):
    """Each window must build and discard its own state; a sensor that
    accumulates across windows eventually dies on a busy link."""
    from cipherguard.capture.sensor import SensorConfig, run

    threading.Thread(target=_emit, args=(500, b"\x00" * 4 + b"\x11" * 28, 60, 0.02), daemon=True).start()
    results = run(
        SensorConfig(
            interface="lo", window_seconds=1.5, max_windows=3, baseline_db=None, audit_log=None, model_dir="models"
        )
    )
    assert len(results) == 3
    for r in results:
        assert r.assessment.capture.endswith(f"window-{r.index}")


def test_sensor_reports_a_clear_error_without_privilege(monkeypatch):
    """Without CAP_NET_RAW the failure must name the capability and the narrow
    fix, not surface a bare PermissionError."""
    import cipherguard.capture.live as live

    def deny(*a, **k):
        raise PermissionError(13, "Operation not permitted")

    monkeypatch.setattr(live.socket, "socket", deny)
    with pytest.raises(live.CaptureUnavailable) as exc:
        live.LiveCapture("eth0").open()
    assert "CAP_NET_RAW" in str(exc.value)
    assert "setcap" in str(exc.value)
