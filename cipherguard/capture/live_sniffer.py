"""Live Network Interface Packet Sniffer & Telemetry Streamer.

Captures live IPsec/ESP and IKE traffic across network interfaces with real-time
Server-Sent Events (SSE) streaming, active SPI discovery, and on-demand snapshot
dumping for instant cryptographic assessment.

Two sources, and the status always says which one is running:

  live_socket  a receive-only raw socket on this machine
  replay       the bundled sample captures, played back on request

Replay is only ever started by an explicit request. An earlier version fell
back to it silently whenever the raw socket could not be opened, which on an
unprivileged workstation is every time, so the page showed sample traffic under
a "live" label. A capture that cannot start now reports that it failed and why.
"""

from __future__ import annotations

import os
import queue
import socket
import struct
import threading
import time
from typing import Any

from ..dissector.pcap import PcapWriter, read_packets

MAX_BUFFER_PACKETS = 5000

IPPROTO_UDP = 17
IPPROTO_ESP = 50
IKE_PORTS = (500, 4500)

REPLAY_SAMPLES = ("hardened.pcap", "backbone.pcap", "transitional.pcap")

# (timestamp, src, dst, protocol, sport, dport, transport payload)
BufferedPacket = tuple[float, str, str, int, int, int, bytes]


def _samples_dir() -> str:
    packaged = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "samples")
    return packaged if os.path.exists(packaged) else "samples"


def _explain_socket_error(exc: OSError) -> str:
    """One sentence an operator can act on, for a raw socket that would not open."""
    denied = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 10013
    if denied:
        need = ("an Administrator terminal" if os.name == "nt"
                else "CAP_NET_RAW (or root)")
        return f"Live capture needs {need}: the raw socket was refused ({exc})."
    return f"Live capture could not open a raw socket on this machine ({exc})."


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
        self.mode: str = "idle"  # "live_socket" | "replay" | "failed" | "idle"
        self.error: str | None = None
        # Where the packets now in the buffer came from. Kept after stop(), so
        # a snapshot taken later is still labelled with its real source.
        self.buffer_source: str | None = None  # "live" | "replay" | None
        self.interface_name: str = "Default"

        self.active_spis: dict[str, dict[str, Any]] = {}
        self.recent_events: list[dict[str, Any]] = []
        self.packet_buffer: list[BufferedPacket] = []

        self._last_rate_calc_time = 0.0
        self._last_packet_count = 0
        self._last_byte_count = 0
        self._current_pps = 0.0
        self._current_kbps = 0.0

    def start(self, interface: str | None = None, replay: bool = False) -> dict[str, Any]:
        """Start capturing, or start a replay when `replay` is true.

        Opening the source happens here, before the thread starts, so a failure
        is in the status this call returns. Nothing is substituted for a source
        that could not be opened.
        """
        with self._lock:
            if self.running:
                return self.get_status()

            self.started_at = time.time()
            self.packets_captured = 0
            self.bytes_captured = 0
            self.ike_count = 0
            self.esp_count = 0
            self._last_packet_count = 0
            self._last_byte_count = 0
            self.active_spis.clear()
            self.recent_events.clear()
            self.packet_buffer.clear()
            self.buffer_source = None
            self.error = None
            self.interface_name = interface or "All Interfaces"

            if replay:
                packets = self._load_replay_packets()
                if not packets:
                    self.mode = "failed"
                    self.error = "No sample captures to replay. Generate them with: cipherguard lab"
                    return self.get_status()
                self.mode = "replay"
                self.buffer_source = "replay"
                self.interface_name = "Sample captures (replay)"
                target, args = self._run_replay_loop, (packets,)
            else:
                try:
                    sock = self._open_socket()
                except OSError as exc:
                    self.mode = "failed"
                    self.error = _explain_socket_error(exc)
                    return self.get_status()
                self.mode = "live_socket"
                self.buffer_source = "live"
                target, args = self._run_socket_loop, (sock,)

            self.running = True
            self.thread = threading.Thread(
                target=target,
                args=args,
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
                db = self.bytes_captured - self._last_byte_count
                self._current_pps = round(dp / dt, 1)
                # from the bytes actually seen, not an assumed packet size
                self._current_kbps = round((db * 8) / (dt * 1000), 1)
                self._last_rate_calc_time = now
                self._last_packet_count = self.packets_captured
                self._last_byte_count = self.bytes_captured

            return {
                "running": self.running,
                "mode": self.mode,
                "source": self.buffer_source,
                "error": self.error,
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

    def _record_packet(self, ts: float, src: str, dst: str, proto: int,
                       sport: int, dport: int, payload: bytes) -> None:
        """Count, buffer and announce one IKE or ESP packet.

        `payload` is the transport payload: the ESP packet for protocol 50, the
        UDP payload for protocol 17. Anything that is not IKE or ESP is dropped
        here, uncounted and unbuffered, so the snapshot never holds other
        traffic from the host.
        """
        spi_str = None

        if proto == IPPROTO_ESP:
            if len(payload) < 8:
                return
            proto_name = "ESP"
            spi_str = f"0x{struct.unpack_from('!I', payload, 0)[0]:08x}"
        elif proto == IPPROTO_UDP and (sport in IKE_PORTS or dport in IKE_PORTS):
            natt = sport == 4500 or dport == 4500
            if not natt:
                proto_name = "IKE"
            elif payload[:4] == b"\x00\x00\x00\x00" and len(payload) > 4:
                proto_name = "IKE"  # RFC 3948 non-ESP marker
            elif len(payload) >= 8:
                proto_name = "UDP-ESP"
                spi_str = f"0x{struct.unpack_from('!I', payload, 0)[0]:08x}"
            else:
                return  # NAT keepalive (a single 0xFF byte) or a runt
        else:
            return

        if spi_str:
            self.esp_count += 1
        else:
            self.ike_count += 1
        self.packets_captured += 1
        self.bytes_captured += len(payload)

        # Retain bounded buffer for snapshot assessment
        if len(self.packet_buffer) < MAX_BUFFER_PACKETS:
            self.packet_buffer.append((ts, src, dst, proto, sport, dport, payload))

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

    # -- live ----------------------------------------------------------------

    def _open_socket(self) -> socket.socket:
        """A receive-only raw IPv4 socket. Raises OSError if it cannot be opened."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        try:
            sock.settimeout(1.0)
            if os.name == "nt":
                # Windows raw socket requires binding to local host IP
                host_ip = socket.gethostbyname(socket.gethostname())
                sock.bind((host_ip, 0))
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                sock.bind(("", 0))
        except OSError:
            sock.close()
            raise
        return sock

    def _handle_datagram(self, data: bytes, ts: float) -> None:
        """Decode one raw IPv4 datagram and record it if it is IKE or ESP."""
        if len(data) < 20 or data[0] >> 4 != 4:
            return
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return
        # A non-first fragment has no transport header to read.
        if struct.unpack_from("!H", data, 6)[0] & 0x1FFF:
            return
        proto = data[9]
        src = socket.inet_ntoa(data[12:16])
        dst = socket.inet_ntoa(data[16:20])
        body = data[ihl:]
        if proto == IPPROTO_ESP:
            self._record_packet(ts, src, dst, proto, 0, 0, body)
        elif proto == IPPROTO_UDP and len(body) >= 8:
            sport, dport = struct.unpack_from("!HH", body, 0)
            self._record_packet(ts, src, dst, proto, sport, dport, body[8:])

    def _run_socket_loop(self, sock: socket.socket) -> None:
        try:
            while self.running:
                try:
                    data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError as exc:
                    self.error = f"Live capture stopped: {exc}"
                    break
                self._handle_datagram(data, time.time())
        finally:
            self.running = False
            try:
                if os.name == "nt":
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                sock.close()
            except OSError:
                pass

    # -- replay --------------------------------------------------------------

    def _load_replay_packets(self) -> list[BufferedPacket]:
        """The IPv4 IKE and ESP packets of the bundled sample captures."""
        packets: list[BufferedPacket] = []
        samples_dir = _samples_dir()
        for name in REPLAY_SAMPLES:
            path = os.path.join(samples_dir, name)
            if not os.path.exists(path):
                continue
            try:
                for pkt in read_packets(path):
                    if pkt.ip_version == 4:
                        packets.append((pkt.timestamp, pkt.src, pkt.dst, pkt.protocol,
                                        pkt.sport, pkt.dport, pkt.payload))
            except Exception:
                continue
        return packets

    def _run_replay_loop(self, packets: list[BufferedPacket]) -> None:
        """Play the sample packets back, unmodified, at a readable pace."""
        idx = 0
        while self.running:
            _, src, dst, proto, sport, dport, payload = packets[idx % len(packets)]
            idx += 1
            self._record_packet(time.time(), src, dst, proto, sport, dport, payload)
            time.sleep(0.08)  # ~12 packets/sec

    def snapshot_to_pcap(self, target_path: str) -> dict[str, Any]:
        """Export the buffered packets into a valid PCAP file for analysis."""
        with self._lock:
            packets = list(self.packet_buffer)
            source = self.buffer_source

        os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
        with PcapWriter(target_path) as writer:
            for ts, src, dst, proto, sport, dport, payload in packets:
                if proto == IPPROTO_UDP:
                    writer.write_udp(ts, src, dst, sport, dport, payload)
                else:
                    writer.write_ip(ts, src, dst, proto, payload)

        return {
            "success": True,
            "path": target_path,
            "packets_written": len(packets),
            "source": source,
        }


# Global sniffer singleton for the API server
global_sniffer = LiveSniffer()
