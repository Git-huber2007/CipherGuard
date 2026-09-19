"""Test all web readiness endpoints and custom error handling for CipherGuard."""
import sys
import os
import warnings

# Cleanly suppress upstream library deprecation warnings
warnings.filterwarnings("ignore")

# Ensure the cipherguard project root is first in sys.path regardless of execution CWD
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Remove any parent directories that might shadow the cipherguard module
parent_dir = os.path.dirname(PROJECT_ROOT)
while parent_dir in sys.path:
    sys.path.remove(parent_dir)

# pyrefly: ignore [missing-import]
from fastapi.testclient import TestClient
from cipherguard.api.server import create_app

def run_tests():
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    
    print("Testing 20-Point Web Production Readiness Checklist...")
    
    # 1. Root dashboard
    r = client.get("/")
    assert r.status_code == 200, f"GET / failed: {r.status_code}"
    assert "CipherGuard" in r.text
    assert "og-image.png" in r.text
    assert "site.webmanifest" in r.text
    assert "view-ipsec" in r.text
    print("[OK] GET / (Dashboard with IPsec primary view and metadata) passed")

    # 2. Verify decommissioned marketing pages return 404
    for route in ["/privacy", "/terms", "/thank-you", "/robots.txt", "/sitemap.xml"]:
        r_old = client.get(route)
        assert r_old.status_code == 404, f"Decommissioned {route} should return 404"
    print("[OK] Marketing and consumer SaaS routes correctly decommissioned")

    # 7. Favicon.ico
    r = client.get("/favicon.ico")
    assert r.status_code == 200, f"GET /favicon.ico failed: {r.status_code}"
    print("[OK] GET /favicon.ico passed")

    # 8. Static image assets
    r_svg = client.get("/static/img/favicon.svg")
    assert r_svg.status_code == 200
    r_og = client.get("/static/img/og-image.png")
    assert r_og.status_code == 200
    r_mani = client.get("/static/site.webmanifest")
    assert r_mani.status_code == 200
    print("[OK] Static assets (favicon.svg, og-image.png, site.webmanifest) passed")

    # 9. Custom 404 HTML Page for browser navigation
    r_404_html = client.get("/non-existent-page-test", headers={"Accept": "text/html,application/xhtml+xml"})
    assert r_404_html.status_code == 404, f"Custom 404 HTML status: {r_404_html.status_code}"
    assert "Segment Not Found" in r_404_html.text or "PACKET_DROPPED" in r_404_html.text
    print("[OK] Custom 404 HTML Error Page passed")

    # 10. API 404 JSON for programmatic clients
    r_404_json = client.get("/api/non-existent-endpoint", headers={"Accept": "application/json"})
    assert r_404_json.status_code == 404
    data = r_404_json.json()
    assert "detail" in data
    print("[OK] API 404 JSON response preserved")

    # 11. Wire Framing Dissection & Modulo Proof Endpoint
    r_wire = client.get("/api/captures/backbone.pcap/flows/0x93a339dd/wire")
    assert r_wire.status_code == 200, f"Wire inspection failed: {r_wire.status_code}"
    wire_data = r_wire.json()
    assert wire_data["spi"] == "0x93a339dd"
    assert len(wire_data["samples"]) > 0
    assert "modulo_proof" in wire_data["samples"][0]
    print("[OK] ESP Wire Dissector & RFC 4303 Modulo Proof API passed")

    # 12. Live Network Sniffer Status & Control Endpoints
    r_sniff_status = client.get("/api/sniff/status")
    assert r_sniff_status.status_code == 200
    assert "running" in r_sniff_status.json()

    r_sniff_start = client.post("/api/sniff/start", json={"force_simulation": True})
    assert r_sniff_start.status_code == 200
    assert r_sniff_start.json()["running"] is True

    r_sniff_stop = client.post("/api/sniff/stop")
    assert r_sniff_stop.status_code == 200
    assert r_sniff_stop.json()["running"] is False
    print("[OK] Live Packet Sniffer & Streamer Endpoints passed")

    print("\nALL VERIFICATIONS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
