"""One formatter for every number a person reads, and numbers left unformatted
in the data so that formatter is the only place formatting happens.

The dashboard used to format bytes in four ways (1e6 here, a 1024-based KB
there, three decimals in the harvest clock) and packet counts with and without
grouping. Fmt is now the single path; these tests pin its output and check no
ad-hoc formatting has crept back, and that the JSON the static build ships
carries plain numbers with consistent precision for Fmt to format.
"""

from __future__ import annotations

import json
import math
import re

import pytest

from tests.jsmodules import ESC, NODE, dashboard_js, module, run_node

needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")


@pytest.mark.no_model
@needs_node
def test_fmt_outputs():
    got = run_node(ESC + module("Fmt") + r"""
      process.stdout.write(JSON.stringify({
        count: [0, 999, 1000, 1234567, 12.6, -5, NaN, null, undefined].map(Fmt.count),
        bytes: [0, 512, 999, 1000, 1049, 1146388, 999960, 999950000, 2.5e9, 3.2e12, -1, NaN]
                 .map(Fmt.bytes),
        bits: [128, 0, 1024, null].map(Fmt.bits),
        signed: [48, -48, 0, -0.4, 1234, NaN].map(Fmt.signed),
        percent: [0, 0.5, 0.123, 1, 0.9999].map(p => Fmt.percent(p)),
        percent1: Fmt.percent(0.1234, 1),
        duration: [0.0004, 0.2, 0.9994, 1, 2.44, 59.96, 61, 3599, 3600, 7322, -3, NaN]
                    .map(Fmt.duration),
        mbps: [50.55, 0, 225.39, null].map(Fmt.mbps),
      }));
    """)
    assert got["count"] == ["0", "999", "1,000", "1,234,567", "13", "-5", "—", "—", "—"]
    assert got["bytes"] == ["0 B", "512 B", "999 B", "1.0 KB", "1.0 KB", "1.1 MB",
                            "1.0 MB",          # 999.96 KB carries up, never "1000.0 KB"
                            "1.0 GB", "2.5 GB", "3.2 TB", "0 B", "—"]
    assert got["bits"] == ["128 bits", "0 bits", "1,024 bits", "—"]
    assert got["signed"] == ["+48", "−48", "0", "0", "+1,234", "—"]
    assert got["percent"] == ["0%", "50%", "12%", "100%", "100%"]
    assert got["percent1"] == "12.3%"
    assert got["duration"] == ["0 ms", "200 ms", "999 ms", "1.0 s", "2.4 s", "60.0 s",
                               "1 min 01 s", "59 min 59 s", "1 h 00 min", "2 h 02 min",
                               "0 ms", "—"]
    assert got["mbps"] == ["50.5 Mb/s", "0.0 Mb/s", "225.4 Mb/s", "—"]


def _display_code(js: str) -> str:
    """dashboard.js without the Fmt module itself and without SVG geometry,
    which are the two places raw numeric formatting is legitimate."""
    js = js.replace(module("Fmt", js), "")
    # coordinates written into SVG attributes: x=, y=, cx=, d="M..", widths
    return "\n".join(line for line in js.splitlines()
                     if not re.search(r'\b(x|y|x1|x2|y1|y2|cx|cy|r|d|width|height|'
                                      r'stroke-dasharray|transform)=|\.toFixed\(1\)\]|'
                                      r'style="width:|style\.width|'
                                      r'const \[px, py\]|pathD|setAttribute\("stroke-dasharray"',
                                      line))


@pytest.mark.no_model
def test_no_ad_hoc_formatting_left_in_the_dashboard():
    code = _display_code(dashboard_js())
    offences = {
        "bytes divided by 1e6 or 1024 for display": r"/\s*(1e6|1024|1e3)\)\.toFixed",
        "a hand-written KB/MB unit": r"\}\s*(KB|kB|MB)\b",
        "toLocaleString on a number": r"(Number\([^)]*\)|Math\.round\([^)]*\))\.toLocaleString\(",
        "a percentage built by hand": r"Math\.round\([^)]*\*\s*100\)\}%",
        "seconds with a bare 's' suffix": r'_seconds\s*\+\s*"s"',
    }
    found = {name: re.findall(p, code) for name, p in offences.items()}
    assert not any(found.values()), {k: v for k, v in found.items() if v}


def _walk(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")
    else:
        yield path, node


def _decimals(x: float) -> int:
    s = repr(x)
    return len(s.split(".")[1]) if "." in s and "e" not in s else 0


def test_exported_json_numbers_are_consistent(tmp_path):
    """The static build's numbers are data, not display strings, and each
    family carries one precision, so the dashboard's Fmt is the only thing
    deciding how they read."""
    from cipherguard.export.static_site import export
    from cipherguard.lab import pcapgen

    caps = tmp_path / "caps"
    caps.mkdir()
    pcapgen.scenario_mixed_backbone(str(caps / "backbone.pcap"))
    out = tmp_path / "site"
    manifest = export(capture_dir=str(caps), out_dir=str(out), model_dir="models", verbose=False)
    payload = json.loads((out / manifest["captures"][0]["file"]).read_text(encoding="utf-8"))

    problems = []
    integer_keys = re.compile(r"(^|_)(bytes|packets|bits|count|counts|sessions|flows|"
                              r"size_bytes|bytes_observed|packets_read|observations)$")
    for path, v in _walk({"manifest": manifest, "payload": payload}):
        key = re.sub(r"\[\d+\]", "", path).rsplit(".", 1)[-1]
        if isinstance(v, bool) or v is None:
            continue
        if isinstance(v, float) and not math.isfinite(v):
            problems.append(f"{path}: non-finite {v}")
        if isinstance(v, str) and re.fullmatch(r"-?[\d,.]+\s*(B|KB|kB|MB|GB|%|s|ms|bits)", v):
            problems.append(f"{path}: pre-formatted number {v!r}")
        if isinstance(v, (int, float)) and integer_keys.search(key) and not float(v).is_integer():
            problems.append(f"{path}: {key} should be a whole number, got {v}")
        if isinstance(v, float) and key.endswith("_mbps") and _decimals(v) > 2:
            problems.append(f"{path}: rates carry at most 2 decimals, got {v}")
        if isinstance(v, float) and key.endswith("_seconds") and _decimals(v) > 4:
            problems.append(f"{path}: durations carry at most 4 decimals, got {v}")
        if isinstance(v, (int, float)) and re.search(r"(confidence|probability)$", key) \
                and not 0 <= v <= 1:
            problems.append(f"{path}: {key} must be a 0..1 ratio for Fmt.percent, got {v}")
    assert not problems, "\n".join(problems[:20])

    entry = manifest["captures"][0]
    assert isinstance(entry["size_bytes"], int) and entry["size_bytes"] > 0
