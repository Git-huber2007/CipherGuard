"""Reproducible throughput benchmark.

The README states a packets-per-second figure. A figure nobody can reproduce is
a claim, not a measurement, so this module generates a large capture on the
machine at hand and times the two paths the figure describes:

  reader     pcap parsing and packet decoding alone, the ceiling for any
             analysis built on the pure-Python reader
  pipeline   the full `analyze()` path — IKE dissection, ESP flow tracking,
             feature extraction, inference, audit rules — excluding the fixed
             cost of loading the model, which does not scale with traffic

The capture mixes several gateway pairs, each with a real IKE_SA_INIT exchange
and a sustained ESP tunnel whose ciphertext lengths follow RFC 4303 framing,
so the pipeline does the same work per packet it does on a real mirror port.
ESP bodies are drawn from os.urandom: generating them byte by byte from a
seeded RNG would make building the capture slower than analysing it, and the
bytes' values do not change the cost of processing them.
"""

from __future__ import annotations

import os
import random
import struct
import tempfile
import time

from ..dissector.pcap import PcapWriter, read_packets
from ..ml.synth import synth_flow
from . import pcapgen

BENCH_SUITES = [
    "AES-GCM-256 (ICV 16)",
    "AES-CBC-128 / HMAC-SHA1-96",
    "3DES-CBC / HMAC-MD5-96",
    "AES-CBC-256 / HMAC-SHA2-256-128",
]


def generate(path: str, packets: int = 200_000, links: int = 8, seed: int = 4303) -> dict:
    """Write a benchmark capture of about `packets` packets across `links` peer pairs."""
    rng = random.Random(seed)
    per_link = max(1, packets // links)
    written = 0
    t = pcapgen.BASE_TS
    with PcapWriter(path) as w:
        for i in range(links):
            a, b = f"203.0.113.{10 + i}", f"198.51.100.{10 + i}"
            ispi, rspi = rng.randbytes(8), rng.randbytes(8)
            req = pcapgen.ikev2_sa_init(ispi, b"\x00" * 8, pcapgen.SUITE_HARDENED, False, [])
            resp = pcapgen.ikev2_sa_init(ispi, rspi, pcapgen.SUITE_HARDENED, True, [])
            t = pcapgen._write_ike_pair(w, t, a, b, req, resp, ident=i)
            written += 2

            suite = BENCH_SUITES[i % len(BENCH_SUITES)]
            flow = synth_flow(suite, rng, packets=per_link - 2, src=a, dst=b)
            for j, (clen, seq) in enumerate(zip(flow.payload_lengths, flow.sequence_numbers)):
                if j:
                    t += flow.inter_arrivals[j - 1]
                w.write_ip(t, a, b, 50, struct.pack("!II", flow.spi, seq) + os.urandom(clen),
                           j & 0xFFFF)
                written += 1
    return {"path": path, "packets": written, "bytes": os.path.getsize(path), "links": links}


def time_reader(path: str) -> dict:
    started = time.perf_counter()
    count = sum(1 for _ in read_packets(path))
    seconds = time.perf_counter() - started
    return {"packets": count, "seconds": round(seconds, 3),
            "packets_per_second": round(count / seconds, 1) if seconds else None}


def time_pipeline(path: str, model_dir: str) -> dict:
    from ..pipeline import analyze, throughput_estimate

    assessment = analyze(path, model_dir=model_dir)
    tp = throughput_estimate(assessment)
    return {
        "packets": tp["packets_read"],
        "processing_seconds": tp["processing_seconds"],
        "model_load_seconds": tp["model_load_seconds"],
        "packets_per_second": tp["packets_per_second"],
        "model_loaded": assessment.stats.get("model_loaded", False),
        "esp_flows": assessment.stats.get("esp_flows_assessed"),
        "ike_sessions": assessment.stats.get("ike_sessions"),
    }


def _summary(runs: list[dict]) -> dict:
    """The median run, with the observed range beside it.

    Median rather than best: on a laptop, clock boost and background load swing
    single runs by a third, and best-of reported the pipeline faster than the
    reader alone, which is impossible because it does strictly more work.
    """
    ordered = sorted(runs, key=lambda r: r["packets_per_second"] or 0)
    median = dict(ordered[len(ordered) // 2])
    rates = [r["packets_per_second"] for r in ordered if r["packets_per_second"]]
    median["range"] = [min(rates), max(rates)] if rates else None
    return median


def run(packets: int = 200_000, model_dir: str = "models", repeat: int = 3,
        keep: str | None = None, seed: int = 4303) -> dict:
    """Generate a capture, then time both paths `repeat` times each.

    A discarded warm-up pass fills the OS file cache and imports everything,
    and the two paths are interleaved so that a slow stretch on the host (CPU
    boost ending, a background job) lands on both rather than on one.
    """
    import platform
    import sys

    directory = tempfile.mkdtemp(prefix="cipherguard-bench-")
    path = keep or os.path.join(directory, "bench.pcap")
    try:
        gen_started = time.perf_counter()
        capture = generate(path, packets=packets, seed=seed)
        capture["generate_seconds"] = round(time.perf_counter() - gen_started, 2)

        time_reader(path)
        time_pipeline(path, model_dir)
        readers, pipelines = [], []
        for _ in range(max(1, repeat)):
            readers.append(time_reader(path))
            pipelines.append(time_pipeline(path, model_dir))
        return {
            "capture": capture,
            "repeat": repeat,
            "reader": _summary(readers),
            "pipeline": _summary(pipelines),
            "host": {"python": sys.version.split()[0], "platform": platform.platform(),
                     "processor": platform.processor() or platform.machine()},
        }
    finally:
        if not keep:
            try:
                os.remove(path)
                os.rmdir(directory)
            except OSError:
                pass
