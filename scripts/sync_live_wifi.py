"""CipherGuard Live Wi-Fi & VPN Telemetry Synchronizer.

Runs a real-time active RF spectrum audit and VPN routing inspection
of the local machine and saves the result to wifi_scan.local.json, which
git ignores.

It must not write into docs/ or cipherguard/export/: those files are committed
and published, and a real scan holds this machine's adapter address and the
names of every network in range.
"""

from __future__ import annotations

import json
import os
import sys

# Ensure repository root is on sys.path
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

from cipherguard.wifi.auditor import WifiAuditor
from cipherguard.vpn.detector import VpnDetector


def sync_live_wifi(force_scan: bool = True, verbose: bool = True) -> dict:
    """Audit local physical Wi-Fi and VPN overlay, saving telemetry to disk."""
    if verbose:
        print("[*] Running live Wi-Fi hardware audit (active RF scan)...")

    auditor = WifiAuditor()
    assessment = auditor.audit_current(force_scan=force_scan)
    data = assessment.to_dict()

    if verbose:
        print("[*] Detecting active VPN tunnels and public egress routing...")

    vpn_detector = VpnDetector()
    try:
        vpn_info = vpn_detector.detect_current()
        data["vpn"] = vpn_info.to_dict()
    except Exception as exc:
        if verbose:
            print(f"[!] VPN inspection notice: {exc}")

    # Local only: see the module docstring for why this is not a tracked path
    base_dir = _REPO_ROOT
    targets = [
        os.path.join(base_dir, "wifi_scan.local.json"),
    ]

    for target in targets:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        if verbose:
            print(f"  [+] Synchronized: {os.path.relpath(target, base_dir)}")

    if verbose:
        iface = data.get("interface", {})
        ssid = iface.get("ssid", "Unknown")
        ch = iface.get("channel", "N/A")
        score = data.get("score", "N/A")
        grade = data.get("grade", "N/A")
        vpn = data.get("vpn") or {}
        # the public-address lookup is off unless CIPHERGUARD_EGRESS_LOOKUP=1
        egress = vpn.get("egress_isp") or ("no answer" if vpn.get("egress_queried") else "not queried")
        print(f"[OK] Live Wi-Fi posture synchronized: '{ssid}' (Ch {ch}) | Score {score}/100 (Grade {grade}) | Egress: {egress}")

    return data


if __name__ == "__main__":
    sync_live_wifi(force_scan=True, verbose=True)
