"""Interactive ESP Wire Framing Dissector & Raw Hex Inspector.

Extracts wire framing layouts and packet byte dumps from passive capture files
without decrypting payloads, demonstrating RFC 4303 modulo framing mathematics
and Shannon entropy verification.
"""

from __future__ import annotations

import os
import struct
from typing import Any

from .esp import shannon_entropy
from .pcap import read_packets, Packet

ESP_HEADER_LEN = 8  # SPI (4) + Sequence (4)


def _infer_framing_specs(framing_class: str | None) -> dict[str, int]:
    """Return typical IV length, ICV length, and block size for a framing class."""
    if not framing_class:
        return {"iv_len": 16, "icv_len": 16, "block_size": 16}

    fc_lower = framing_class.lower()
    if "64-bit" in fc_lower:
        # 3DES or DES: 8-byte IV, 12-byte ICV (HMAC-96), 8-byte block
        return {"iv_len": 8, "icv_len": 12, "block_size": 8}
    elif "96-bit icv" in fc_lower:
        # AES-CBC with 96-bit ICV: 16-byte IV, 12-byte ICV, 16-byte block
        return {"iv_len": 16, "icv_len": 12, "block_size": 16}
    elif "128-bit icv" in fc_lower:
        # AES-CBC with 128-bit ICV: 16-byte IV, 16-byte ICV, 16-byte block
        return {"iv_len": 16, "icv_len": 16, "block_size": 16}
    elif "aead" in fc_lower or "counter" in fc_lower:
        # AES-GCM or ChaCha20-Poly1305: 8-byte IV, 16-byte ICV, 16-byte block
        return {"iv_len": 8, "icv_len": 16, "block_size": 16}
    elif "unencrypted" in fc_lower or "null" in fc_lower:
        return {"iv_len": 0, "icv_len": 12, "block_size": 4}
    else:
        return {"iv_len": 16, "icv_len": 16, "block_size": 16}


def format_hex_dump(raw: bytes, bytes_per_line: int = 16) -> list[dict[str, Any]]:
    """Format raw bytes into hex + ASCII rows with absolute offsets."""
    lines = []
    for offset in range(0, len(raw), bytes_per_line):
        chunk = raw[offset : offset + bytes_per_line]
        hex_bytes = [f"{b:02x}" for b in chunk]
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append({
            "offset": f"{offset:04x}",
            "offset_int": offset,
            "hex": hex_bytes,
            "ascii": ascii_chars,
            "length": len(chunk),
        })
    return lines


def extract_wire_samples(
    capture_path: str,
    target_spi: int | str,
    framing_class: str | None = None,
    max_samples: int = 3,
) -> dict[str, Any]:
    """Inspect raw packet framing matching target_spi in capture_path."""
    if isinstance(target_spi, str):
        if target_spi.startswith("0x") or target_spi.startswith("0X"):
            spi_int = int(target_spi, 16)
        else:
            try:
                spi_int = int(target_spi)
            except ValueError:
                spi_int = int(target_spi, 16)
    else:
        spi_int = target_spi

    if not os.path.exists(capture_path):
        raise FileNotFoundError(f"Capture file not found: {capture_path}")

    specs = _infer_framing_specs(framing_class)
    iv_len = specs["iv_len"]
    icv_len = specs["icv_len"]
    block_size = specs["block_size"]

    samples = []
    packet_count = 0

    for pkt in read_packets(capture_path):
        data = pkt.payload
        encapsulated = False

        if pkt.protocol == 50:
            pass
        elif pkt.protocol == 17 and (pkt.sport == 4500 or pkt.dport == 4500):
            if data == b"\xff" or data[:4] == b"\x00\x00\x00\x00":
                continue
            encapsulated = True
        else:
            continue

        if len(data) < ESP_HEADER_LEN:
            continue

        spi, seq = struct.unpack_from("!II", data, 0)
        if spi != spi_int:
            continue

        packet_count += 1
        if len(samples) >= max_samples:
            continue

        total_len = len(data)
        prot_start = ESP_HEADER_LEN + iv_len
        prot_end = max(prot_start, total_len - icv_len)
        protected_bytes = data[prot_start:prot_end]
        entropy_val = round(shannon_entropy(protected_bytes), 3) if protected_bytes else 0.0

        # Segments breakdown for interactive highlighting
        segments = [
            {
                "id": "spi",
                "label": "ESP SPI",
                "color": "#10b981",
                "start": 0,
                "end": 4,
                "value": f"0x{spi:08x}",
                "desc": "Security Parameters Index identifying the security association.",
            },
            {
                "id": "seq",
                "label": "Sequence No",
                "color": "#06b6d4",
                "start": 4,
                "end": 8,
                "value": str(seq),
                "desc": "Monotonically increasing counter defending against replay attacks.",
            },
        ]

        if iv_len > 0:
            segments.append({
                "id": "iv",
                "label": f"IV / Nonce ({iv_len}B)",
                "color": "#3b82f6",
                "start": 8,
                "end": 8 + iv_len,
                "value": data[8 : 8 + iv_len].hex(),
                "desc": "Initialization Vector / Nonce for cipher mode initialization.",
            })

        if prot_end > prot_start:
            segments.append({
                "id": "ciphertext",
                "label": "Protected Payload & Padding",
                "color": "#64748b",
                "start": prot_start,
                "end": prot_end,
                "value": f"{prot_end - prot_start} bytes (Entropy: {entropy_val:.2f}/8.0)",
                "desc": "Encrypted payload and alignment padding. Zero payload retained.",
            })

        if icv_len > 0 and total_len >= prot_end + icv_len:
            segments.append({
                "id": "icv",
                "label": f"ICV Auth Tag ({icv_len}B)",
                "color": "#a855f7",
                "start": prot_end,
                "end": prot_end + icv_len,
                "value": data[prot_end : prot_end + icv_len].hex(),
                "desc": "Integrity Check Value / MAC tag guaranteeing packet authenticity.",
            })

        # RFC 4303 Modulo Arithmetic Proof
        protected_len = prot_end - prot_start
        remainder = protected_len % block_size

        modulo_proof = {
            "total_bytes": total_len,
            "header_bytes": 8,
            "iv_bytes": iv_len,
            "icv_bytes": icv_len,
            "protected_bytes": protected_len,
            "block_size": block_size,
            "remainder": remainder,
            "formula": f"({protected_len} bytes) mod {block_size} = {remainder}",
            "valid": remainder == 0,
            "entropy": entropy_val,
            "is_encrypted": entropy_val > 7.0,
        }

        samples.append({
            "sample_index": len(samples) + 1,
            "frame": pkt.frame,
            "timestamp": round(pkt.timestamp, 4),
            "src": pkt.src,
            "dst": pkt.dst,
            "encapsulated": encapsulated,
            "total_bytes": total_len,
            "segments": segments,
            "modulo_proof": modulo_proof,
            "hex_dump": format_hex_dump(data),
            "raw_hex": data.hex(),
        })

    return {
        "spi": f"0x{spi_int:08x}",
        "capture": os.path.basename(capture_path),
        "framing_class": framing_class or "Standard ESP",
        "specs": specs,
        "total_packets_observed": packet_count,
        "samples": samples,
    }
