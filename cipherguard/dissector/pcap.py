"""Capture file I/O and L2/L3/L4 decoding.

Deliberately dependency-free: the analyzer must run on an air-gapped sensor host
where installing scapy or a libpcap Python binding is not an option. Supports
classic pcap (both endiannesses, microsecond and nanosecond) and the subset of
pcapng that tcpdump and Wireshark actually emit.
"""

from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass
from typing import Iterator

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_NULL = 0

IPPROTO_UDP = 17
IPPROTO_ESP = 50
IPPROTO_AH = 51

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_MAGIC = 0x0A0D0D0A


# Hard ceilings on anything derived from a length field inside the file.
# A capture is untrusted input: it may be a hostile artefact handed to an
# analyst, or written by a sensor that was itself under attack. Every read
# sized by an in-file integer is validated against these before allocating,
# because a 140-byte file declaring a 3 GB packet is a 20-million-fold memory
# amplification and costs an attacker nothing to produce.
MAX_SNAPLEN = 262_144  # a jumbo frame is 9 KB; this is generous already
MAX_BLOCK_LEN = 16 << 20  # pcapng block ceiling


class CaptureError(Exception):
    pass


def _file_size(fh) -> int:
    """Total size, read once.

    The previous implementation asked per packet, and each answer cost a tell,
    a seek to the end and a seek back — which discards the BufferedReader's
    read-ahead every time and made validation cost more than parsing.
    """
    return os.fstat(fh.fileno()).st_size


@dataclass
class Packet:
    """One decoded frame, trimmed to the transport payload."""

    frame: int
    timestamp: float
    src: str
    dst: str
    protocol: int
    sport: int = 0
    dport: int = 0
    payload: bytes = b""
    ip_version: int = 4
    truncated: bool = False


# ---------------------------------------------------------------------------
# Address formatting
# ---------------------------------------------------------------------------


# Precomputed decimal strings. ipv4() is called twice per packet and showed up
# 305,600 times in a profile of a 30k-packet capture; building four strings and
# joining them each time is pure overhead when there are only 256 possibilities.
_OCTET = [str(i) for i in range(256)]


def ipv4(raw: bytes) -> str:
    return f"{_OCTET[raw[0]]}.{_OCTET[raw[1]]}.{_OCTET[raw[2]]}.{_OCTET[raw[3]]}"


def ipv6(raw: bytes) -> str:
    parts = [f"{raw[i] << 8 | raw[i + 1]:x}" for i in range(0, 16, 2)]
    # RFC 5952 zero-run compression
    best_start = best_len = cur_start = cur_len = -1
    for i, p in enumerate(parts):
        if p == "0":
            if cur_len <= 0:
                cur_start, cur_len = i, 1
            else:
                cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
        else:
            cur_len = 0
    if best_len > 1:
        return ":".join(parts[:best_start]) + "::" + ":".join(parts[best_start + best_len :])
    return ":".join(parts)


# ---------------------------------------------------------------------------
# Link / network / transport decoding
# ---------------------------------------------------------------------------


def _strip_link(data: bytes, linktype: int) -> tuple[bytes, int] | None:
    """Return (network-layer bytes, ethertype-ish protocol hint)."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        etype = struct.unpack_from("!H", data, 12)[0]
        off = 14
        # walk 802.1Q / 802.1ad tags
        while etype in (0x8100, 0x88A8, 0x9100) and len(data) >= off + 4:
            etype = struct.unpack_from("!H", data, off + 2)[0]
            off += 4
        return data[off:], etype
    if linktype == LINKTYPE_RAW:
        if not data:
            return None
        version = data[0] >> 4
        return data, 0x0800 if version == 4 else 0x86DD
    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        return data[16:], struct.unpack_from("!H", data, 14)[0]
    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return None
        fam = struct.unpack_from("<I", data, 0)[0]
        return data[4:], 0x0800 if fam == 2 else 0x86DD
    return None


def decode(frame_no: int, ts: float, data: bytes, linktype: int) -> Packet | None:
    stripped = _strip_link(data, linktype)
    if stripped is None:
        return None
    net, etype = stripped

    if etype == 0x0800:
        if len(net) < 20:
            return None
        ihl = (net[0] & 0x0F) * 4
        if ihl < 20 or len(net) < ihl:
            return None
        total_len = struct.unpack_from("!H", net, 2)[0]
        frag = struct.unpack_from("!H", net, 6)[0]
        proto = net[9]
        src, dst = ipv4(net[12:16]), ipv4(net[16:20])
        body = net[ihl:total_len] if 0 < total_len <= len(net) else net[ihl:]
        truncated = total_len > len(net)
        if frag & 0x1FFF:  # non-first fragment carries no usable header
            return None
        version = 4
    elif etype == 0x86DD:
        if len(net) < 40:
            return None
        proto = net[6]
        src, dst = ipv6(net[8:24]), ipv6(net[24:40])
        body = net[40:]
        truncated = False
        version = 6
        # skip well-known extension headers to reach ESP/UDP
        for _ in range(8):
            if proto in (0, 43, 60) and len(body) >= 8:
                nxt, hlen = body[0], (body[1] + 1) * 8
                if len(body) < hlen:
                    break
                proto, body = nxt, body[hlen:]
            else:
                break
    else:
        return None

    pkt = Packet(
        frame=frame_no,
        timestamp=ts,
        src=src,
        dst=dst,
        protocol=proto,
        payload=body,
        ip_version=version,
        truncated=truncated,
    )

    if proto == IPPROTO_UDP:
        if len(body) < 8:
            return None
        pkt.sport, pkt.dport, ulen, _ = struct.unpack_from("!HHHH", body, 0)
        end = ulen if 8 <= ulen <= len(body) else len(body)
        pkt.payload = body[8:end]
    return pkt


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------


def _read_pcap(fh: io.BufferedReader) -> Iterator[Packet]:
    head = fh.read(24)
    if len(head) < 24:
        raise CaptureError("truncated pcap file header")
    magic = struct.unpack("<I", head[:4])[0]
    if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
        endian = "<"
    else:
        magic = struct.unpack(">I", head[:4])[0]
        if magic not in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            raise CaptureError(f"not a pcap file (magic 0x{magic:08x})")
        endian = ">"
    divisor = 1e9 if magic == PCAP_MAGIC_NS else 1e6
    linktype = struct.unpack(endian + "I", head[20:24])[0]
    size = _file_size(fh)

    n = 0
    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            return
        sec, sub, caplen, _origlen = struct.unpack(endian + "IIII", rec)
        if caplen > MAX_SNAPLEN or caplen > size - fh.tell():
            raise CaptureError(
                f"packet {n + 1} declares {caplen} captured bytes, which exceeds "
                f"the {MAX_SNAPLEN}-byte limit or the bytes left in the file"
            )
        data = fh.read(caplen)
        if len(data) < caplen:
            return
        n += 1
        pkt = decode(n, sec + sub / divisor, data, linktype)
        if pkt is not None:
            yield pkt


def _read_pcapng(fh: io.BufferedReader) -> Iterator[Packet]:
    fh.seek(0)
    size = _file_size(fh)
    endian = "<"
    linktypes: dict[int, int] = {}
    resolutions: dict[int, float] = {}
    iface = 0
    n = 0

    while True:
        header = fh.read(8)
        if len(header) < 8:
            return
        btype = struct.unpack(endian + "I", header[:4])[0]
        if btype == PCAPNG_MAGIC:
            rest = fh.read(4)
            bom = struct.unpack("<I", rest)[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
            blen = struct.unpack(endian + "I", header[4:8])[0]
            if blen < 12 or blen - 12 > MAX_BLOCK_LEN or blen - 12 > size - fh.tell():
                raise CaptureError(f"section header block declares {blen} bytes")
            fh.read(blen - 12)
            continue
        blen = struct.unpack(endian + "I", header[4:8])[0]
        if blen < 12:
            raise CaptureError("malformed pcapng block length")
        if blen - 12 > MAX_BLOCK_LEN or blen - 12 > size - fh.tell():
            raise CaptureError(
                f"pcapng block declares {blen} bytes, which exceeds the "
                f"{MAX_BLOCK_LEN}-byte limit or the bytes left in the file"
            )
        body = fh.read(blen - 12)
        fh.read(4)  # trailing block length

        if btype == 0x00000001:  # Interface Description Block
            lt = struct.unpack_from(endian + "H", body, 0)[0]
            res = 1e6
            off = 8
            while off + 4 <= len(body):  # walk options for if_tsresol (code 9)
                code, olen = struct.unpack_from(endian + "HH", body, off)
                val = body[off + 4 : off + 4 + olen]
                if code == 0 or olen == 0 and code == 0:
                    break
                if code == 9 and val:
                    exp = val[0]
                    res = float(2 ** (exp & 0x7F)) if exp & 0x80 else float(10**exp)
                off += 4 + ((olen + 3) & ~3)
                if code == 0:
                    break
            linktypes[iface] = lt
            resolutions[iface] = res
            iface += 1
        elif btype == 0x00000006:  # Enhanced Packet Block
            if len(body) < 20:
                continue
            ifid, hi, lo, caplen, _orig = struct.unpack_from(endian + "IIIII", body, 0)
            if caplen > MAX_SNAPLEN or 20 + caplen > len(body):
                continue  # inconsistent block, skip rather than trust the length
            res = resolutions.get(ifid, 1e6)
            ts = ((hi << 32) | lo) / res
            data = body[20 : 20 + caplen]
            n += 1
            pkt = decode(n, ts, data, linktypes.get(ifid, LINKTYPE_ETHERNET))
            if pkt is not None:
                yield pkt
        elif btype == 0x00000003:  # Simple Packet Block
            data = body[4:]
            n += 1
            pkt = decode(n, 0.0, data, linktypes.get(0, LINKTYPE_ETHERNET))
            if pkt is not None:
                yield pkt


def read_packets(path: str) -> Iterator[Packet]:
    """Yield decoded packets from a pcap or pcapng capture."""
    with open(path, "rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        if len(magic) < 4:
            raise CaptureError("empty capture file")
        if struct.unpack("<I", magic)[0] == PCAPNG_MAGIC:
            yield from _read_pcapng(fh)
        else:
            yield from _read_pcap(fh)


# ---------------------------------------------------------------------------
# Writer — used by the lab corpus generator
# ---------------------------------------------------------------------------


class PcapWriter:
    """Minimal Ethernet/IPv4 pcap writer."""

    def __init__(self, path: str, linktype: int = LINKTYPE_ETHERNET):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, 262144, linktype))

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if not self.fh.closed:
            self.fh.close()

    def write_frame(self, ts: float, frame: bytes) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self.fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.fh.write(frame)

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) | data[i + 1]
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    def write_ip(self, ts: float, src: str, dst: str, proto: int, payload: bytes, ident: int = 0) -> None:
        total = 20 + len(payload)
        hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0x00,
            total,
            ident & 0xFFFF,
            0x4000,
            64,
            proto,
            0,
            bytes(int(x) for x in src.split(".")),
            bytes(int(x) for x in dst.split(".")),
        )
        hdr = hdr[:10] + struct.pack("!H", self._checksum(hdr)) + hdr[12:]
        eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
        self.write_frame(ts, eth + hdr + payload)

    def write_udp(self, ts: float, src: str, dst: str, sport: int, dport: int, payload: bytes, ident: int = 0) -> None:
        udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        self.write_ip(ts, src, dst, IPPROTO_UDP, udp, ident)

    def write_esp(self, ts: float, src: str, dst: str, spi: int, seq: int, body: bytes, ident: int = 0) -> None:
        esp = struct.pack("!II", spi, seq) + body
        self.write_ip(ts, src, dst, IPPROTO_ESP, esp, ident)
