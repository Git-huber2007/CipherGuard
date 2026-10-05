"""Automated tests for VPN tunnel detection, route redirection, and DNS leak auditing."""

from cipherguard.vpn.detector import VpnDetector
from cipherguard.vpn.models import NetworkPostureComposite, VpnTunnelInfo
from cipherguard.wifi.models import SecurityFinding, WifiAssessment


def test_vpn_models_serialization():
    info = VpnTunnelInfo(
        connected=True,
        adapter_name="wg0",
        adapter_description="WireGuard Tunnel",
        vpn_type="WireGuard",
        virtual_ip="10.8.0.2",
        gateway_ip="10.8.0.1",
        route_metric=10,
        is_default_route=True,
        dns_servers=["10.8.0.1"],
        dns_leak_detected=False,
        egress_ip="198.51.100.1",
        egress_isp="SecureVPN Hosting",
        egress_country="Iceland",
        egress_city="Reykjavik",
        findings=[
            SecurityFinding(
                severity="info",
                rule_id="VPN-001",
                title="Active WireGuard Overlay Tunnel Verified",
                subject="wg0",
                detail="Encapsulated",
                remediation="None",
            )
        ],
    )
    d = info.to_dict()
    assert d["connected"] is True
    assert d["vpn_type"] == "WireGuard"
    assert d["dns_leak_detected"] is False
    assert len(d["findings"]) == 1
    assert d["findings"][0]["rule_id"] == "VPN-001"

    from cipherguard.wifi.models import WifiInterfaceInfo

    iface = WifiInterfaceInfo(
        name="Wi-Fi",
        description="Wireless NIC",
        mac_address="50:fe:0c:5d:83:54",
        state="connected",
        ssid="TestSSID",
        bssid="00:11:22:33:44:55",
        band="5 GHz",
        channel=36,
        radio_type="802.11ac",
        authentication="WPA2-Personal",
        cipher="CCMP",
        signal_percent=85,
        rssi_dbm=-50,
    )
    comp = NetworkPostureComposite(
        wifi=WifiAssessment(interface=iface),
        vpn=info,
        posture_status="Protected (VPN Tunnel)",
        summary="Protected",
    )
    cd = comp.to_dict()
    assert cd["posture_status"] == "Protected (VPN Tunnel)"
    assert cd["vpn"]["adapter_name"] == "wg0"


def test_vpn_dns_leak_assessment():
    detector = VpnDetector()
    info = VpnTunnelInfo(
        connected=True,
        adapter_name="wg0",
        vpn_type="WireGuard",
        is_default_route=True,
        dns_leak_detected=True,
        dns_leak_details="192.168.1.1, 103.57.86.8",
    )
    detector._assess_vpn_posture(info, wifi_dns=["192.168.1.1"])
    rule_ids = [f.rule_id for f in info.findings]
    assert "VPN-001" in rule_ids
    assert "VPN-002" in rule_ids  # DNS leak rule


def test_vpn_direct_egress_assessment():
    detector = VpnDetector()
    info = VpnTunnelInfo(connected=False, egress_isp="Local ISP")
    detector._assess_vpn_posture(info, wifi_dns=None)
    rule_ids = [f.rule_id for f in info.findings]
    assert "VPN-010" in rule_ids  # Direct physical egress rule


def test_vpn_detector_live():
    detector = VpnDetector()
    info = detector.detect_current()
    assert isinstance(info, VpnTunnelInfo)
    assert isinstance(info.connected, bool)
    assert isinstance(info.findings, list)
    assert len(info.findings) >= 1
