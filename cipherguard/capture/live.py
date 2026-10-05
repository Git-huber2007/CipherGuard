"""Live capture from a network interface.

Until now the analyzer could only read files, which meant the "passive sensor"
it describes did not exist: someone still had to run tcpdump, move a file, and
run an assessment by hand. Continuous assurance is not a scheduled batch job.

This is AF_PACKET on Linux with no third-party dependency, because the sensor
host is expected to be a hardened, minimal, possibly air-gapped machine where
installing a libpcap binding is a procurement question rather than a pip
command. The same `decode()` used for capture files handles the frames, so
there is exactly one packet-decoding path and live traffic cannot diverge from
file behaviour.

Two properties matter more than throughput:

  It is receive-only. The socket is never bound for transmission and nothing in
  this module writes to it. A monitoring device that can inject onto the
  segment it monitors is a liability, and on a defence backbone it is
  disqualifying.

  It cannot grow without bound. A capture loop with no ceiling on time, packets
  or bytes turns a busy link into an outage on the sensor.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Iterator

from ..dissector.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW, Packet, PcapWriter, decode

logger = logging.getLogger(__name__)

ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
SO_RCVBUF = 8
SOL_PACKET = 263

DEFAULT_SNAPLEN = 2048


class CaptureUnavailable(RuntimeError):
    """Live capture cannot start — wrong platform, or missing privilege."""


@dataclass
class CaptureStats:
    packets: int = 0
    bytes: int = 0
    dropped: int = 0
    started: float = 0.0

    @property
    def elapsed(self) -> float:
        return time.time() - self.started

    def to_dict(self) -> dict:
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "dropped": self.dropped,
            "elapsed_seconds": round(self.elapsed, 1),
            "packets_per_second": round(self.packets / max(self.elapsed, 1e-6), 1),
        }


def _ipsec_filter() -> bytes:
    """A classic-BPF program selecting IKE (UDP 500/4500) and ESP (proto 50).

    Filtering in the kernel rather than in Python is the difference between a
    sensor that keeps up on a busy link and one that does not: on a backbone
    carrying mostly non-IPsec traffic, userspace would otherwise copy and
    discard every frame. Assembled by hand because compiling a filter
    expression would mean depending on libpcap, which is what this module
    exists to avoid.

    Jump operands are offsets *relative to the next instruction*, and the kernel
    verifier rejects the whole program if any of them lands past the end — so
    the indices below are stated explicitly and the two return instructions are
    kept last, at fixed positions 14 (accept) and 15 (drop).
    """
    A, D = 14, 15  # accept and drop instruction indices

    def jmp(idx: int, target: int) -> int:
        return target - idx - 1

    # fmt: off
    prog = [
        (0x28, 0,           0,           0x0000000C),  # 0  ldh  [12] ethertype
        (0x15, 0,           jmp(1, D),   0x00000800),  # 1  jeq  #IPv4 else drop
        (0x30, 0,           0,           0x00000017),  # 2  ldb  [23] protocol
        (0x15, jmp(3, A),   0,           0x00000032),  # 3  jeq  #ESP -> accept
        (0x15, 0,           jmp(4, D),   0x00000011),  # 4  jeq  #UDP else drop
        (0x28, 0,           0,           0x00000014),  # 5  ldh  [20] frag field
        (0x45, jmp(6, D),   0,           0x00001FFF),  # 6  jset #frag -> drop
        (0xB1, 0,           0,           0x0000000E),  # 7  ldxb 4*([14]&0xf)
        (0x48, 0,           0,           0x0000000E),  # 8  ldh  [x+14] sport
        (0x15, jmp(9, A),   0,           0x000001F4),  # 9  jeq  #500  -> accept
        (0x15, jmp(10, A),  0,           0x00001194),  # 10 jeq  #4500 -> accept
        (0x48, 0,           0,           0x00000010),  # 11 ldh  [x+16] dport
        (0x15, jmp(12, A),  0,           0x000001F4),  # 12 jeq  #500  -> accept
        (0x15, jmp(13, A),  jmp(13, D),  0x00001194),  # 13 jeq  #4500 else drop
        (0x06, 0,           0,           0x00040000),  # 14 ret  #snaplen
        (0x06, 0,           0,           0x00000000),  # 15 ret  #0
    ]
    # fmt: on
    assert len(prog) == 16
    # Only jump-class instructions carry branch targets; a `ret` leaves jt/jf
    # zero and must not be range-checked as though it branched.
    for i, (op, jt, jf, _k) in enumerate(prog):
        if op & 0x07 != 0x05:  # BPF_JMP
            continue
        assert 0 <= i + 1 + jt < len(prog), f"instruction {i} jt out of range"
        assert 0 <= i + 1 + jf < len(prog), f"instruction {i} jf out of range"
    return b"".join(struct.pack("HBBI", *ins) for ins in prog)


class LiveCapture:
    """Receive-only capture from one interface."""

    def __init__(
        self,
        interface: str,
        snaplen: int = DEFAULT_SNAPLEN,
        rcvbuf: int = 16 << 20,
        kernel_filter: bool = True,
    ):
        self.interface = interface
        self.snaplen = snaplen
        self.rcvbuf = rcvbuf
        self.kernel_filter = kernel_filter
        self.sock: socket.socket | None = None
        self.stats = CaptureStats()
        self.truncated = False  # a window ended on its byte ceiling, not its clock
        self.linktype = LINKTYPE_RAW if sys.platform.startswith("win") else LINKTYPE_ETHERNET
        self.promiscuous = True

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        if sys.platform.startswith("win"):
            try:
                host_ip = "0.0.0.0"
                try:
                    host_name = socket.gethostname()
                    host_ip = socket.gethostbyname(host_name)
                except Exception:
                    logger.debug("could not look up the local address; using the default", exc_info=True)
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((host_ip, 0))
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                except Exception:
                    self.promiscuous = False
                self.sock = sock
                self.stats = CaptureStats(started=time.time())
                return
            except PermissionError as exc:
                raise CaptureUnavailable(
                    "live capture needs CAP_NET_RAW (see: setcap cap_net_raw+eip) on Linux "
                    "or Administrator privileges on Windows."
                ) from exc
            except OSError as exc:
                raise CaptureUnavailable(f"Could not open Windows raw socket: {exc}") from exc

        if not sys.platform.startswith("linux"):
            raise CaptureUnavailable(
                f"live capture needs Linux AF_PACKET or Windows raw socket; this host is {sys.platform}. "
                "Capture with tcpdump and analyse the file instead."
            )
        self._open_packet_socket()

    def _open_packet_socket(self) -> None:
        af_packet = getattr(socket, "AF_PACKET", None)
        if af_packet is None:
            raise CaptureUnavailable("this Python build has no AF_PACKET support")

        try:
            sock = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except PermissionError as exc:
            raise CaptureUnavailable(
                "live capture needs CAP_NET_RAW. Grant it narrowly rather than "
                "running the whole analyzer as root:\n"
                f"    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f {sys.executable})"
            ) from exc
        except OSError as exc:
            raise CaptureUnavailable(f"could not open a packet socket: {exc}") from exc

        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUF, self.rcvbuf)
            sock.bind((self.interface, ETH_P_ALL))
        except OSError as exc:
            sock.close()
            raise CaptureUnavailable(f"could not bind interface {self.interface!r}: {exc}") from exc

        if self.kernel_filter:
            try:
                prog = _ipsec_filter()
                # The kernel keeps a pointer to this buffer while the filter is
                # attached, so it has to outlive the setsockopt call — hence the
                # instance attribute rather than a local.
                self._filter_buf = bytearray(prog)
                fprog = struct.pack("H6xP", len(prog) // 8, _buffer_address(self._filter_buf))
                sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
            except OSError:
                # A rejected filter must not stop the capture: falling back to
                # userspace filtering costs throughput, while failing outright
                # costs the whole assessment.
                self.kernel_filter = False

        self.sock = sock
        self.stats = CaptureStats(started=time.time())

    def close(self) -> None:
        if self.sock is not None:
            self._read_kernel_drops()
            self.sock.close()
            self.sock = None

    def __enter__(self) -> "LiveCapture":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _read_kernel_drops(self) -> None:
        """Packets the kernel discarded because userspace fell behind.

        Reported rather than ignored: an assessment made from a capture that
        silently lost 40% of its packets is not a weaker assessment, it is a
        misleading one, and the operator has to be told.
        """
        if self.sock is None:
            return
        try:
            raw = self.sock.getsockopt(SOL_PACKET, 6, 16)  # PACKET_STATISTICS
            _received, dropped = struct.unpack("II", raw[:8])
            self.stats.dropped = dropped
        except (OSError, AttributeError, struct.error):
            pass

    # -- reading -----------------------------------------------------------

    def packets(
        self,
        max_packets: int | None = None,
        max_seconds: float | None = None,
        max_bytes: int | None = None,
        pcap_path: str | None = None,
    ) -> Iterator[Packet]:
        """Yield decoded packets until a bound is reached or the caller stops.

        The byte bound is not redundant with the time bound. A 300-second window
        on a 200 Mbps link is 7.5 GB, so a duration limit alone still lets one
        window fill the sensor's disk before it ever returns. Whichever ceiling
        is reached first ends the window.
        """
        if self.sock is None:
            raise RuntimeError("capture is not open")

        deadline = time.time() + max_seconds if max_seconds else None
        writer = PcapWriter(pcap_path, self.linktype) if pcap_path else None
        self.sock.settimeout(0.5)
        self.truncated = False

        try:
            while True:
                if max_packets and self.stats.packets >= max_packets:
                    return
                if max_bytes and self.stats.bytes >= max_bytes:
                    self.truncated = True
                    return
                if deadline and time.time() >= deadline:
                    return
                try:
                    frame = self.sock.recv(self.snaplen)
                except socket.timeout:
                    continue  # let the loop re-check its bounds
                except OSError:
                    return
                if not frame:
                    continue

                ts = time.time()
                self.stats.packets += 1
                self.stats.bytes += len(frame)
                if writer:
                    writer.write_frame(ts, frame)

                pkt = decode(self.stats.packets, ts, frame, self.linktype)
                if pkt is not None:
                    yield pkt
        finally:
            if writer:
                writer.close()
            self._read_kernel_drops()


def _buffer_address(buf: bytearray) -> int:
    import ctypes

    return ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))


def list_interfaces() -> list[str]:
    """Interfaces the host can capture on, best effort."""
    if sys.platform.startswith("win"):
        try:
            import subprocess

            out = subprocess.check_output(
                ["netsh", "interface", "show", "interface"],
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            ifaces = []
            for line in out.splitlines()[3:]:
                parts = line.split(None, 3)
                if len(parts) == 4:
                    ifaces.append(parts[3].strip())
            return ifaces or ["Wi-Fi", "Ethernet"]
        except Exception:
            return ["Wi-Fi", "Ethernet"]
    try:
        return sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []


def available() -> tuple[bool, str]:
    """Whether live capture can run here, and why not if it cannot."""
    if sys.platform.startswith("win"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.close()
            return True, "ready (Windows raw socket)"
        except PermissionError:
            return False, "needs Administrator privileges on Windows for raw packet capture"
        except OSError as exc:
            return False, str(exc)
    if not sys.platform.startswith("linux"):
        return False, f"needs Linux AF_PACKET or Windows raw socket; this host is {sys.platform}"
    return _packet_socket_available()


def _packet_socket_available() -> tuple[bool, str]:
    af_packet = getattr(socket, "AF_PACKET", None)
    if af_packet is None:
        return False, "this Python build has no AF_PACKET support"
    try:
        s = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.close()
        return True, "ready"
    except PermissionError:
        return False, "needs CAP_NET_RAW (see: setcap cap_net_raw+eip)"
    except OSError as exc:
        return False, str(exc)
