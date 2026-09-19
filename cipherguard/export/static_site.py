from __future__ import annotations

import json
import os
import shutil

from ..api.server import STATIC_DIR
from ..intel.pqc import roadmap as pqc_roadmap
from ..pipeline import analyze, throughput_estimate
from ..remediation.synth import PLATFORM_NAMES, detect_platforms, synthesize

def _get_default_demo_wifi() -> dict:
    snapshot_path = os.path.join(os.path.dirname(__file__), "live_wifi_snapshot.json")
    if os.path.exists(snapshot_path):
        try:
            with open(snapshot_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data.get("networks_in_range"):
                    return data
        except Exception:
            pass
    return {
        "interface": {
            "name": "Wi-Fi (Intel Wireless)",
            "ssid": "Svyasa-Staff",
            "bssid": "58:61:63:11:cf:a6",
            "state": "connected",
            "signal_percent": 83,
            "rssi_dbm": -58,
            "channel": 149,
            "band": "5 GHz",
            "authentication": "WPA2-Personal",
            "cipher": "CCMP"
        },
        "networks_in_range": [],
        "score": 85,
        "grade": "B"
    }

DEFAULT_OUT = "docs"


def export(
    capture_dir: str = "samples",
    out_dir: str = DEFAULT_OUT,
    model_dir: str = "models",
    verbose: bool = True,
) -> dict:
    """Render the dashboard plus pre-computed analyses into a static directory."""
    data_dir = os.path.join(out_dir, "data")
    os.makedirs(data_dir, exist_ok=True)

    # Front-end assets, copied verbatim so the hosted page and the served page
    # are the same files rather than two copies that can drift apart.
    for root, dirs, files in os.walk(STATIC_DIR):
        rel_root = os.path.relpath(root, STATIC_DIR)
        for f in files:
            src = os.path.join(root, f)
            dst = os.path.join(out_dir, f) if rel_root == "." else os.path.join(out_dir, rel_root, f)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)

    # Absolute /static/... paths work behind the API but break under a GitHub
    # Pages project subpath, so they are rewritten to be relative across all HTML pages.
    for item in os.listdir(out_dir):
        if item.endswith(".html"):
            hpath = os.path.join(out_dir, item)
            with open(hpath, "r", encoding="utf-8") as fh:
                html = fh.read()
            html = html.replace('/static/', '')
            with open(hpath, "w", encoding="utf-8") as fh:
                fh.write(html)

    captures = sorted(
        n for n in os.listdir(capture_dir)
        if n.endswith((".pcap", ".pcapng", ".cap"))
    )
    if not captures:
        raise FileNotFoundError(
            f"no captures in {capture_dir}/ — run: cipherguard lab"
        )

    entries = []
    for name in captures:
        path = os.path.join(capture_dir, name)
        if verbose:
            print(f"  analysing {name}")
        assessment = analyze(path, model_dir=model_dir)

        payload = assessment.to_dict()
        payload["throughput"] = throughput_estimate(assessment)
        payload["platforms"] = [
            {"id": p, "name": PLATFORM_NAMES[p]} for p in detect_platforms(assessment)
        ]
        payload["roadmap"] = pqc_roadmap(assessment)

        # Remediation is generated per platform here too, because the static
        # page has no backend to ask for it later.
        payload["remediation"] = {
            p["id"]: synthesize(assessment, p["id"]) for p in payload["platforms"]
        }

        slug = name.replace(".", "_")
        with open(os.path.join(data_dir, f"{slug}.json"), "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

        # Pre-extract wire framing inspection samples for all ESP flows
        try:
            from ..dissector.wire_inspector import extract_wire_samples
            wire_dir = os.path.join(data_dir, "wire")
            os.makedirs(wire_dir, exist_ok=True)
            for flow in assessment.flows:
                try:
                    cls_name, _, _ = flow.framing()
                    w_sample = extract_wire_samples(path, flow.spi, framing_class=cls_name)
                    w_slug = f"{slug}_{flow.spi:08x}.json"
                    with open(os.path.join(wire_dir, w_slug), "w", encoding="utf-8") as fh:
                        json.dump(w_sample, fh)
                except Exception:
                    pass
        except Exception:
            pass

        entries.append({
            "name": name,
            "file": f"data/{slug}.json",
            "size_kb": round(os.path.getsize(path) / 1024, 1),
            "score": assessment.score(),
            "grade": assessment.grade(),
        })

    manifest = {
        "mode": "static",
        "generated_from": "real pipeline output, not mock data",
        "captures": entries,
    }
    with open(os.path.join(data_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

# Pre-generate Wi-Fi & VPN posture for static demo deployment
    try:
        from ..wifi.auditor import WifiAuditor
        from ..vpn.detector import VpnDetector
        auditor = WifiAuditor()
        wifi_data = auditor.audit_current().to_dict()
        # If running in cloud CI runner or headless environment without active Wi-Fi hardware, use rich demo dataset
        if not wifi_data.get("networks_in_range") or not wifi_data.get("interface") or wifi_data.get("interface", {}).get("state") != "connected":
            wifi_data = _get_default_demo_wifi()
        else:
            try:
                vpn_det = VpnDetector()
                w_name = wifi_data.get("interface", {}).get("name", "Wi-Fi") if wifi_data.get("interface") else "Wi-Fi"
                w_dns = wifi_data.get("interface", {}).get("dns_servers", []) if wifi_data.get("interface") else []
                vpn_res = vpn_det.detect_current(wifi_iface_name=w_name, wifi_dns=w_dns)
                wifi_data["vpn"] = vpn_res.to_dict()
            except Exception:
                wifi_data["vpn"] = None
        with open(os.path.join(data_dir, "wifi_demo.json"), "w", encoding="utf-8") as fh:
            json.dump(wifi_data, fh, indent=2)
    except Exception as exc:
        if verbose:
            print(f"  Note: wifi demo export fallback ({exc})")
        with open(os.path.join(data_dir, "wifi_demo.json"), "w", encoding="utf-8") as fh:
            json.dump(_get_default_demo_wifi(), fh, indent=2)

    # Tell GitHub Pages not to run the output through Jekyll, which would
    # otherwise ignore any file or directory beginning with an underscore.
    open(os.path.join(out_dir, ".nojekyll"), "w").close()

    if verbose:
        print(f"\n  Wrote {len(entries)} assessments to {out_dir}/")
        print(f"  Preview locally with:  python -m http.server -d {out_dir} 8080")
    return manifest
