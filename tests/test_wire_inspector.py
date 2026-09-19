"""Tests for the interactive ESP Wire Dissector & Raw Hex Inspector."""

from __future__ import annotations

import os
import pytest

from cipherguard.dissector.wire_inspector import (
    _infer_framing_specs,
    format_hex_dump,
    extract_wire_samples,
)

pytestmark = pytest.mark.no_model

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def test_infer_framing_specs():
    specs_64 = _infer_framing_specs("64-bit block (3DES / DES)")
    assert specs_64["block_size"] == 8
    assert specs_64["iv_len"] == 8
    assert specs_64["icv_len"] == 12

    specs_cbc = _infer_framing_specs("AES-CBC with 96-bit ICV")
    assert specs_cbc["block_size"] == 16
    assert specs_cbc["iv_len"] == 16
    assert specs_cbc["icv_len"] == 12

    specs_gcm = _infer_framing_specs("AEAD (AES-GCM)")
    assert specs_gcm["block_size"] == 16
    assert specs_gcm["iv_len"] == 8
    assert specs_gcm["icv_len"] == 16

    specs_default = _infer_framing_specs(None)
    assert specs_default["block_size"] == 16


def test_format_hex_dump():
    data = b"Hello, World! 1234567890"
    lines = format_hex_dump(data, bytes_per_line=16)
    assert len(lines) == 2
    assert lines[0]["offset"] == "0000"
    assert lines[0]["ascii"] == "Hello, World! 12"
    assert lines[0]["hex"][0] == f"{ord('H'):02x}"
    assert lines[1]["offset"] == "0010"
    assert lines[1]["ascii"] == "34567890"


def test_extract_wire_samples_backbone():
    pcap_path = os.path.join(SAMPLE_DIR, "backbone.pcap")
    if not os.path.exists(pcap_path):
        pytest.skip("backbone.pcap not present")

    # SPI from backbone.pcap: 0x93a339dd
    res = extract_wire_samples(pcap_path, "0x93a339dd", framing_class="AEAD (AES-GCM)")
    assert res["spi"] == "0x93a339dd"
    assert res["total_packets_observed"] > 0
    assert len(res["samples"]) > 0

    s0 = res["samples"][0]
    assert "raw_hex" in s0
    assert "segments" in s0
    assert "modulo_proof" in s0
    assert len(s0["hex_dump"]) > 0

    # Segments must include SPI, Sequence, IV, Protected, and ICV
    seg_ids = [seg["id"] for seg in s0["segments"]]
    assert "spi" in seg_ids
    assert "seq" in seg_ids
    assert "iv" in seg_ids
    assert "ciphertext" in seg_ids
    assert "icv" in seg_ids


def test_extract_wire_samples_legacy():
    pcap_path = os.path.join(SAMPLE_DIR, "legacy.pcap")
    if not os.path.exists(pcap_path):
        pytest.skip("legacy.pcap not present")

    res = extract_wire_samples(pcap_path, "0x73cf256d", framing_class="64-bit block (3DES)")
    assert res["spi"] == "0x73cf256d"
    assert len(res["samples"]) > 0
    s0 = res["samples"][0]
    assert s0["modulo_proof"]["block_size"] == 8


def test_extract_wire_samples_missing_file():
    with pytest.raises(FileNotFoundError):
        extract_wire_samples("non_existent_file.pcap", "0x12345678")


def test_extract_wire_samples_nonexistent_spi():
    pcap_path = os.path.join(SAMPLE_DIR, "backbone.pcap")
    if not os.path.exists(pcap_path):
        pytest.skip("backbone.pcap not present")

    res = extract_wire_samples(pcap_path, "0xdeadbeef")
    assert res["total_packets_observed"] == 0
    assert len(res["samples"]) == 0
