"""ESP flow tracking.

Builds one record per (source, destination, SPI) triple. Only metadata that is
visible without keys is retained: ciphertext length, sequence number, arrival
time and a byte-entropy sample. Payload bytes are read to compute entropy and
are never stored, logged or written to disk.
"""

from __future__ import annotations

import heapq
import math
import struct
from collections import Counter

from ..core.models import EspFlow
from .pcap import Packet

ESP_HEADER_LEN = 8  # SPI (4) + Sequence (4)
ENTROPY_SAMPLE_BYTES = 512
MIN_ENTROPY_SAMPLE = 256


def shannon_entropy(data: bytes, correct_bias: bool = True) -> float:
    """Bits per byte, 0.0-8.0, with Miller-Madow bias correction.

    The naive plug-in estimator is badly biased downward over a 256-symbol
    alphabet at realistic packet sizes: 256 bytes of true random data measures
    about 7.26 rather than 8.0, purely because most byte values are unobserved
    in so short a sample. Left uncorrected that bias is larger than the gap
    between real ciphertext and ESP-NULL, so correctly encrypted tunnels get
    reported as unencrypted.

    Miller-Madow adds (m - 1) / (2n ln2), where m is the number of distinct
    symbols actually seen, which removes most of the bias at these sample sizes.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    plugin = -sum((c / n) * math.log2(c / n) for c in counts.values())
    if not correct_bias:
        return plugin
    return min(8.0, plugin + (len(counts) - 1) / (2 * n * math.log(2)))


class EspTracker:
    """Tracks ESP SAs with bounded memory.

    The bound is a security control, not tidiness. A passive sensor ingests
    whatever an attacker chooses to put on the monitored segment, and the SPI is
    a 32-bit attacker-chosen field that keys this table. Without a cap, spoofing
    ESP packets with randomised SPIs creates one flow record per packet — 60k
    packets produced 60k records and 68 MB in testing, so a few seconds of
    line-rate traffic exhausts the sensor. Taking down the monitoring is a
    worthwhile attack in itself: it blinds the auditor before doing something
    else.

    Once at capacity, the tracker evicts the least active flow rather than
    refusing new ones, so a flood cannot pin out the genuine long-lived tunnels
    that matter, and it records that eviction happened so the report can say the
    view was incomplete instead of quietly under-reporting.
    """

    def __init__(self, max_samples: int = 4000, max_flows: int = 8192, evict_fraction: float = 0.10):
        self.flows: dict[tuple[str, str, int], EspFlow] = {}
        self.max_samples = max_samples
        self.max_flows = max_flows
        self.evict_batch = max(1, int(max_flows * evict_fraction))
        self.evicted = 0
        self.rejected = 0

    def _evict_batch(self) -> None:
        """Drop the least active tenth of the table in one pass.

        Evicting a single flow per new key looks cheaper and is catastrophically
        worse. At capacity every packet of an SPI-randomised flood inserts a new
        key, so every packet triggered a full linear scan of 8192 entries: the
        table never dropped below capacity, and throughput collapsed from
        ~158,000 packets/second to ~900. The memory bound held perfectly while
        the sensor stopped keeping up with the link — the same denial of service
        the cap was added to prevent, moved from RAM to CPU.

        Evicting a batch amortises the scan over many insertions, so a flood
        costs one pass per `evict_batch` new keys rather than one per packet.
        Least-active-first still holds, so flood singletons go before
        established tunnels.
        """
        if not self.flows:
            return
        victims = heapq.nsmallest(
            self.evict_batch,
            self.flows.items(),
            key=lambda kv: (kv[1].packets, kv[1].last_seen),
        )
        for key, _flow in victims:
            del self.flows[key]
            self.evicted += 1

    def consume(self, pkt: Packet) -> bool:
        """Record an ESP packet. Returns True if the packet was ESP."""
        encapsulated = False
        data = pkt.payload

        if pkt.protocol == 50:
            pass
        elif pkt.protocol == 17 and (pkt.sport == 4500 or pkt.dport == 4500):
            # UDP-encapsulated ESP: anything on 4500 that is neither the non-ESP
            # marker nor a NAT keepalive. RFC 3948 s4 keepalives are a single
            # 0xFF byte sent every 20 seconds by every peer behind NAT, so on a
            # real capture they arrive in bulk; counting them as ESP packets
            # would pollute every flow statistic the inference depends on.
            if data == b"\xff":
                return False
            if data[:4] == b"\x00\x00\x00\x00":
                return False
            encapsulated = True
        else:
            return False

        if len(data) < ESP_HEADER_LEN:
            return False

        spi, seq = struct.unpack_from("!II", data, 0)
        if spi == 0:
            return False

        key = (pkt.src, pkt.dst, spi)
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.max_flows:
                self._evict_batch()
            flow = EspFlow(
                spi=spi,
                src=pkt.src,
                dst=pkt.dst,
                first_seen=pkt.timestamp,
                encapsulated=encapsulated,
            )
            self.flows[key] = flow

        ciphertext = data[ESP_HEADER_LEN:]
        if flow.packets and pkt.timestamp >= flow.last_seen:
            flow.inter_arrivals.append(pkt.timestamp - flow.last_seen)

        flow.packets += 1
        flow.last_seen = max(flow.last_seen, pkt.timestamp)

        if len(flow.payload_lengths) < self.max_samples:
            flow.payload_lengths.append(len(ciphertext))
            flow.sequence_numbers.append(seq)
            # Short packets cannot support a usable estimate at all, so they are
            # skipped rather than averaged in as spuriously low entropy.
            if len(flow.entropy_samples) < 256 and len(ciphertext) >= MIN_ENTROPY_SAMPLE:
                flow.entropy_samples.append(shannon_entropy(ciphertext[:ENTROPY_SAMPLE_BYTES]))
        return True

    def results(self, min_packets: int = 8) -> list[EspFlow]:
        flows = [f for f in self.flows.values() if f.packets >= min_packets]
        flows.sort(key=lambda f: f.packets, reverse=True)
        return flows

    def all_flows(self) -> list[EspFlow]:
        return sorted(self.flows.values(), key=lambda f: f.packets, reverse=True)
