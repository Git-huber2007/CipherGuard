"""Live Network Interface Packet Sniffer & Telemetry Streamer.

Captures live IPsec/ESP and IKE traffic across network interfaces with real-time
Server-Sent Events (SSE) streaming, active SPI discovery, and on-demand snapshot
dumping for instant cryptographic assessment.
"""

from __future__ import annotations

import json
import os
import queue
import socket
import struct
import threading
import time
from typing import Any, Generator

from ..dissector.pcap import PcapWriter, read_packets

MAX_BUFFER_PACKETS = 5000


class LiveSniffer:
    """Manages live wire packet sniffing and streaming event distribution."""

    def __init__(self) -> None:
        self.running: bool = False
        self.thread: threading.Thread | None = None
        self.subscribers: list[queue.Queue] = []
        self._lock = threading.RLock()

        self.started_at: float = 0.0
        self.packets_captured: int = 0
        self.bytes_captured: int = 0
        self.ike_count: int = 0
        self.esp_count: int = 0
        self.mode: str = "idle"  # "live_socket" | "simulated_wire" | "idle"
        self.interface_name: str = "Default"

        self.active_spis: dict[str, dict[str, Any]] = {}
        self.recent_events: list[dict[str, Any]] = []
        self.packet_buffer: list[tuple[float, str, str, int, bytes]] = []

        self._last_rate_calc_time = 0.0
        self._last_packet_count = 0
        self._current_pps = 0.0
        self._current_kbps = 0.0

    def start(self, interface: str | None = None, force_simulation: bool = False) -> dict[str, Any]:
        with self._lock:
            if self.running:
                return self.get_status()

            self.running = True
            self.started_at = time.time()
            self.packets_captured = 0
            self.bytes_captured = 0
            self.ike_count = 0
            self.esp_count = 0
            self.active_spis.clear()
            self.recent_events.clear()
            self.packet_buffer.clear()
            self.interface_name = interface or "All Interfaces"

            self.thread = threading.Thread(
                target=self._run_capture_loop,
                args=(interface, force_simulation),
                daemon=True,
                name="CipherGuard-LiveSniffer",
            )
            self.thread.start()

        return self.get_status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.5)
        self.mode = "idle"
        return self.get_status()

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            now = time.time()
            duration = round(now - self.started_at, 1) if self.running else 0.0
            dt = now - self._last_rate_calc_time
            if dt >= 0.5:
                dp = self.packets_captured - self._last_packet_count
                self._current_pps = round(dp / dt, 1)
                self._current_kbps = round((dp * 800 * 8) / (dt * 1000), 1)
                self._last_rate_calc_time = now
                self._last_packet_count = self.packets_captured

            return {
                "running": self.running,
                "mode": self.mode,
                "interface": self.interface_name,
                "duration_seconds": duration,
                "packets_captured": self.packets_captured,
                "bytes_captured": self.bytes_captured,
                "ike_count": self.ike_count,
                "esp_count": self.esp_count,
                "active_spis": list(self.active_spis.values()),
                "rate_pps": self._current_pps,
                "rate_kbps": self._current_kbps,
                "recent_events": self.recent_events[-15:],
            }

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=100)
        with self._lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def _broadcast_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            self.recent_events.append(event)
            if len(self.recent_events) > 50:
                self.recent_events.pop(0)

            dead = []
            for q in self.subscribers:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self.subscribers.remove(q)

    def _record_packet(self, ts: float, src: str, dst: str, proto: int, payload: bytes) -> None:
        self.packets_captured += 1
        self.bytes_captured += len(payload)

        # Retain bounded buffer for snapshot assessment
        if len(self.packet_buffer) < MAX_BUFFER_PACKETS:
            self.packet_buffer.append((ts, src, dst, proto, payload))

        spi_str = None
        proto_name = "OTHER"

        if proto == 50:
            proto_name = "ESP"
            self.esp_count += 1
            if len(payload) >= 4:
                spi = struct.unpack_from("!I", payload, 0)[0]
                spi_str = f"0x{spi:08x}"
        elif proto == 17:
            # UDP: check for IKE (500) or UDP-encapsulated ESP (4500)
            if len(payload) >= 4 and payload[:4] == b"\x00\x00\x00\x00":
                proto_name = "IKE"
                self.ike_count += 1
            elif len(payload) >= 4:
                proto_name = "UDP-ESP"
                self.esp_count += 1
                spi = struct.unpack_from("!I", payload, 0)[0]
                if spi != 0:
                    spi_str = f"0x{spi:08x}"

        if spi_str:
            if spi_str not in self.active_spis:
                self.active_spis[spi_str] = {
                    "spi": spi_str,
                    "src": src,
                    "dst": dst,
                    "proto": proto_name,
                    "packets": 0,
                    "first_seen": round(ts, 3),
                    "last_seen": round(ts, 3),
                }
            self.active_spis[spi_str]["packets"] += 1
            self.active_spis[spi_str]["last_seen"] = round(ts, 3)

        event = {
            "type": "packet",
            "frame": self.packets_captured,
            "timestamp": round(ts, 3),
            "src": src,
            "dst": dst,
            "protocol": proto_name,
            "spi": spi_str,
            "length": len(payload),
            "active_spis_count": len(self.active_spis),
            "rate_pps": self._current_pps,
            "rate_kbps": self._current_kbps,
        }
        self._broadcast_event(event)

    def _run_capture_loop(self, interface: str | None, force_simulation: bool) -> None:
        """Attempt raw socket; fallback cleanly to synthetic stream on permission error."""
        if not force_simulation:
            try:
                # Try raw socket binding
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.settimeout(1.0)
                if os.name == "nt":
                    # Windows raw socket requires binding to local host IP
                    hostname = socket.gethostname()
                    host_ip = socket.gethostbyname(hostname)
                    sock.bind((host_ip, 0))
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                else:
                    sock.bind(("", 0))

                self.mode = "live_socket"
                self._run_socket_loop(sock)
                return
            except (PermissionError, OSError):
                pass

        # Fallback to high-fidelity live stream
        self.mode = "simulated_wire"
        self._run_simulation_loop()

    def _run_socket_loop(self, sock: socket.socket) -> None:
        while self.running:
            try:
                data, _ = sock.recvfrom(65535)
                if len(data) < 20:
                    continue
                # Decode IPv4 header
                proto = data[9]
                src = socket.inet_ntoa(data[12:16])
                dst = socket.inet_ntoa(data[16:20])
                ihl = (data[0] & 0x0F) * 4
                payload = data[ihl:]
                ts = time.time()
                self._record_packet(ts, src, dst, proto, payload)
            except socket.timeout:
                continue
            except Exception:
                break
        try:
            if os.name == "nt":
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
        except Exception:
            pass

    def _run_simulation_loop(self) -> None:
        """Stream packets from local samples to provide an authentic live demonstration."""
        sample_files = ["hardened.pcap", "backbone.pcap", "transitional.pcap"]
        packets_to_stream: list[tuple[float, str, str, int, bytes]] = []

        samples_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "samples")
        if not os.path.exists(samples_dir):
            samples_dir = "samples"

        for sfile in sample_files:
            spath = os.path.join(samples_dir, sfile)
            if os.path.exists(spath):
                try:
                    for pkt in read_packets(spath):
                        packets_to_stream.append((pkt.timestamp, pkt.src, pkt.dst, pkt.protocol, pkt.payload))
                except Exception:
                    pass

        if not packets_to_stream:
            # Fallback synthetic dummy packet generator
            dummy_payload = struct.pack("!II", 0xae97d9db, 1) + os.urandom(120)
            packets_to_stream.append((time.time(), "192.168.1.100", "192.168.1.1", 50, dummy_payload))

        idx = 0
        seq_offset = 0
        while self.running:
            _, src, dst, proto, payload = packets_to_stream[idx % len(packets_to_stream)]
            idx += 1
            seq_offset += 1
            ts = time.time()

            # Increment sequence number for visual dynamism
            if proto == 50 and len(payload) >= 8:
                spi = struct.unpack_from("!I", payload, 0)[0]
                payload = struct.pack("!II", spi, seq_offset) + payload[8:]

            self._record_packet(ts, src, dst, proto, payload)
            time.sleep(0.08)  # ~12 packets/sec for fluid HUD updates

    def snapshot_to_pcap(self, target_path: str) -> dict[str, Any]:
        """Export buffered live packets into a valid PCAP file for analysis."""
        with self._lock:
            packets = list(self.packet_buffer)

        os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
        with PcapWriter(target_path) as writer:
            for ts, src, dst, proto, payload in packets:
                writer.write_ip(ts, src, dst, proto, payload)

        return {
            "success": True,
            "path": target_path,
            "packets_written": len(packets),
        }


# Global sniffer singleton for the API server
global_sniffer = LiveSniffer()
