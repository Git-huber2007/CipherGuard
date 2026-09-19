"""Tests for the live Wi-Fi auditing and wireless posture module."""

from cipherguard.wifi.auditor import WifiAuditor
from cipherguard.wifi.models import SecurityFinding, WifiAssessment, WifiInterfaceInfo, WifiNetwork


def test_wifi_models_serialization():
    f = SecurityFinding(
        severity="high",
        rule_id="WIFI-001",
        title="Test Finding",
        subject="Test AP",
        detail="Test detail",
        remediation="Test fix",
    )
    assert f.to_dict()["rule_id"] == "WIFI-001"

    net = WifiNetwork(
        ssid="TestSSID",
        bssid="00:11:22:33:44:55",
        signal_percent=90,
        rssi_dbm=-45,
        channel=36,
        band="5 GHz",
        radio_type="802.11ac",
        authentication="WPA3-Personal",
        encryption="CCMP",
        security_grade="A+",
    )
    d = net.to_dict()
    assert d["ssid"] == "TestSSID"
    assert d["security_grade"] == "A+"

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
    assessment = WifiAssessment(interface=iface, networks_in_range=[net], score=85, grade="B")
    ad = assessment.to_dict()
    assert ad["score"] == 85
    assert ad["grade"] == "B"
    assert ad["interface"]["ssid"] == "TestSSID"
    assert len(ad["networks_in_range"]) == 1


def test_wifi_auditor_grading():
    auditor = WifiAuditor()
    assert auditor._grade_network("Open", "None") == "F"
    assert auditor._grade_network("WEP", "WEP") == "F"
    assert auditor._grade_network("WPA-Personal", "TKIP") == "D"
    assert auditor._grade_network("WPA2-Personal", "CCMP") == "B"
    assert auditor._grade_network("WPA3-Personal", "CCMP") == "A+"


def test_wifi_auditor_live_or_fallback():
    auditor = WifiAuditor()
    assessment = auditor.audit_current()
    assert isinstance(assessment, WifiAssessment)
    assert isinstance(assessment.score, int)
    assert 0 <= assessment.score <= 100
    assert assessment.grade in ("A+", "A", "B", "C", "D", "F", "—")
    assert isinstance(assessment.findings, list)


def test_is_private_ip():
    from cipherguard.wifi.auditor import _is_private_ip
    assert _is_private_ip("192.168.1.1") is True
    assert _is_private_ip("10.0.0.1") is True
    assert _is_private_ip("172.16.0.1") is True
    assert _is_private_ip("172.31.255.254") is True
    assert _is_private_ip("172.32.0.1") is False
    assert _is_private_ip("8.8.8.8") is False
    assert _is_private_ip("1.1.1.1") is False
    assert _is_private_ip("invalid-ip") is False


def test_live_capture_linktype_attribute():
    import sys
    from cipherguard.capture.live import LiveCapture
    from cipherguard.dissector.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW

    cap = LiveCapture("test-iface")
    if sys.platform.startswith("win"):
        assert cap.linktype == LINKTYPE_RAW
    else:
        assert cap.linktype == LINKTYPE_ETHERNET


def test_connected_bssid_isolation():
    auditor = WifiAuditor()
    raw_output = """
SSID 1 : Campus-Mesh
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP 
    BSSID 1                 : 11:22:33:44:55:01
         Signal             : 90%
         Radio type         : 802.11ax
         Channel            : 36 
         Band               : 5 GHz
    BSSID 2                 : 11:22:33:44:55:02
         Signal             : 80%
         Radio type         : 802.11ax
         Channel            : 44 
         Band               : 5 GHz
    BSSID 3                 : 11:22:33:44:55:03
         Signal             : 70%
         Radio type         : 802.11ax
         Channel            : 149 
         Band               : 5 GHz
"""
    import unittest.mock as mock
    WifiAuditor._bss_cache.clear()
    with mock.patch("subprocess.check_output", return_value=raw_output):
        # Target only BSSID 2
        nets = auditor._get_windows_networks(
            connected_ssid="Campus-Mesh",
            connected_bssid="11:22:33:44:55:02",
            force_scan=False,
        )
        connected_nets = [n for n in nets if n.connected]
        assert len(connected_nets) == 1
        assert connected_nets[0].bssid == "11:22:33:44:55:02"
        # The other 2 BSSIDs should be false
        other_nets = [n for n in nets if not n.connected]
        assert len(other_nets) == 2
    WifiAuditor._bss_cache.clear()


def _net(ssid, bssid, auth, enc="CCMP", signal=70, connected=False):
    return WifiNetwork(
        ssid=ssid,
        bssid=bssid,
        signal_percent=signal,
        rssi_dbm=-100 + signal // 2,
        channel=6,
        band="2.4 GHz",
        radio_type="802.11n",
        authentication=auth,
        encryption=enc,
        connected=connected,
    )


def test_evil_twin_detected_for_connected_network():
    """The network the host is actually on gets a critical finding and a
    score penalty when a weaker clone of it is in range."""
    auditor = WifiAuditor()
    iface = WifiInterfaceInfo(
        name="Wi-Fi", description="", mac_address="", state="connected",
        ssid="Office-WiFi", bssid="AA:AA:AA:AA:AA:01", band="5 GHz", channel=36,
        radio_type="802.11ac", authentication="WPA2-Personal", cipher="CCMP",
        signal_percent=90, rssi_dbm=-40,
    )
    networks = [
        _net("Office-WiFi", "AA:AA:AA:AA:AA:01", "WPA2-Personal", connected=True),
        _net("Office-WiFi", "BB:BB:BB:BB:BB:02", "Open", enc="None", signal=85),
    ]
    findings, rogue_aps, score_delta = auditor._detect_rogue_aps(iface, networks)
    assert score_delta == -35
    assert any(f.rule_id == "WIFI-020" and f.severity == "critical" for f in findings)
    assert len(rogue_aps) == 1
    assert rogue_aps[0]["bssid"] == "BB:BB:BB:BB:BB:02"
    assert rogue_aps[0]["threat_level"] == "critical"
    clone = next(n for n in networks if n.bssid == "BB:BB:BB:BB:BB:02")
    assert clone.is_rogue is True


def test_evil_twin_detected_for_network_host_is_not_connected_to():
    """A clone of a *different* SSID nearby -- one this host never joined --
    is still flagged, since it is seen for every network in range, not only
    the one the host happens to be on."""
    auditor = WifiAuditor()
    iface = WifiInterfaceInfo(
        name="Wi-Fi", description="", mac_address="", state="connected",
        ssid="My-Home-Network", bssid="CC:CC:CC:CC:CC:01", band="5 GHz", channel=36,
        radio_type="802.11ac", authentication="WPA3-Personal", cipher="CCMP",
        signal_percent=90, rssi_dbm=-40,
    )
    networks = [
        _net("My-Home-Network", "CC:CC:CC:CC:CC:01", "WPA3-Personal", connected=True),
        _net("Neighbor-Cafe", "DD:DD:DD:DD:DD:01", "WPA2-Personal", signal=60),
        _net("Neighbor-Cafe", "EE:EE:EE:EE:EE:02", "Open", enc="None", signal=55),
    ]
    findings, rogue_aps, score_delta = auditor._detect_rogue_aps(iface, networks)
    # Not the host's own network, so no score penalty ...
    assert score_delta == 0
    # ... but it is still surfaced as a finding and a flagged network.
    nearby = [f for f in findings if f.rule_id == "WIFI-020" and "Neighbor-Cafe" in f.subject]
    assert len(nearby) == 1
    assert nearby[0].severity == "high"
    assert any(r["ssid"] == "Neighbor-Cafe" and r["threat_level"] == "high" for r in rogue_aps)
    clone = next(n for n in networks if n.bssid == "EE:EE:EE:EE:EE:02")
    assert clone.is_rogue is True
    legit = next(n for n in networks if n.bssid == "DD:DD:DD:DD:DD:01")
    assert legit.is_rogue is False


def test_matching_security_across_bssids_is_not_flagged_as_rogue():
    """Multiple BSSIDs of the same SSID with identical security is a normal
    mesh/roaming deployment, not an Evil Twin."""
    auditor = WifiAuditor()
    iface = WifiInterfaceInfo(
        name="Wi-Fi", description="", mac_address="", state="connected",
        ssid="Campus-Mesh", bssid="11:11:11:11:11:01", band="5 GHz", channel=36,
        radio_type="802.11ax", authentication="WPA2-Personal", cipher="CCMP",
        signal_percent=90, rssi_dbm=-40,
    )
    networks = [
        _net("Campus-Mesh", "11:11:11:11:11:01", "WPA2-Personal", connected=True),
        _net("Campus-Mesh", "11:11:11:11:11:02", "WPA2-Personal", signal=80),
        _net("Campus-Mesh", "11:11:11:11:11:03", "WPA2-Personal", signal=70),
    ]
    findings, rogue_aps, score_delta = auditor._detect_rogue_aps(iface, networks)
    assert score_delta == 0
    assert not rogue_aps
    assert not any(f.rule_id == "WIFI-020" for f in findings)
    assert any(f.rule_id == "WIFI-021" for f in findings)
    assert all(not n.is_rogue for n in networks)


