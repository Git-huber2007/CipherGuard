"""Wi-Fi and Wireless Security Posture Auditor.

Reads live configuration and RF metrics from the host operating system, audits
security posture (WPA/WPA2/WPA3, cipher strength, PMF, channel allocation,
DNS security, and rogue AP detection), and produces structured assessments.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Any

from .models import (
    SecurityFinding,
    WifiAssessment,
    WifiInterfaceInfo,
    WifiNetwork,
)


def _is_private_ip(ip: str) -> bool:
    """Check if an IP string belongs to RFC 1918 / RFC 4193 private ranges."""
    try:
        return ipaddress.ip_address(ip.strip()).is_private
    except ValueError:
        return False


def _security_rank(authentication: str, encryption: str = "") -> int:
    """Rank a network's security posture so BSSIDs sharing an SSID can be
    compared against each other. Higher is stronger.

    Unknown/unparsed values rank as medium (2) rather than an extreme, so an
    auth string this parser doesn't recognise produces a missed clone instead
    of a false Evil Twin alert on every unfamiliar AP.
    """
    auth = (authentication or "").upper()
    enc = (encryption or "").upper()
    if "OPEN" in auth or "NONE" in enc:
        return 0
    if "WEP" in auth or "WEP" in enc:
        return 1
    if "TKIP" in enc or ("WPA-" in auth and "WPA2" not in auth and "WPA3" not in auth):
        return 2
    if "WPA3" in auth:
        return 4
    if "WPA2" in auth:
        return 3
    return 2


class WifiAuditor:
    """Audits local wireless interfaces, connected Wi-Fi AP, and in-range networks."""

    # Persistent BSSID cache across audits (bssid -> (WifiNetwork, timestamp))
    _bss_cache: dict[str, tuple[WifiNetwork, float]] = {}

    def __init__(self):
        self.is_windows = sys.platform.startswith("win")
        self.is_linux = sys.platform.startswith("linux")

    def audit_current(self, force_scan: bool = False) -> WifiAssessment:
        """Run complete live audit of the current Wi-Fi environment."""
        if self.is_windows:
            interface_info = self._get_windows_current_interface()
            conn_ssid = interface_info.ssid if interface_info else ""
            conn_bssid = interface_info.bssid if interface_info else ""
            networks = self._get_windows_networks(
                conn_ssid, conn_bssid, force_scan=force_scan, interface_info=interface_info
            )
            dns_info = self._get_windows_network_config()
            if interface_info and dns_info:
                interface_info.dns_servers = dns_info.get("dns_servers", [])
                interface_info.gateway_ip = dns_info.get("gateway", "")
                interface_info.ipv4_address = dns_info.get("ipv4", "")
        else:
            interface_info = self._get_linux_current_interface()
            networks = self._get_linux_networks()
            dns_info = self._get_linux_dns()

        findings: list[SecurityFinding] = []
        score = 100

        if not interface_info or interface_info.state.lower() != "connected":
            findings.append(
                SecurityFinding(
                    severity="info",
                    rule_id="WIFI-000",
                    title="Wi-Fi Interface Disconnected or Offline",
                    subject="WLAN Adapter",
                    detail="No active Wi-Fi connection was detected on the host adapter.",
                    remediation="Connect to an authorized enterprise or personal Wi-Fi network to assess live cryptographic posture.",
                    reference="IEEE 802.11",
                )
            )
            return WifiAssessment(
                interface=interface_info,
                networks_in_range=networks,
                score=0,
                grade="—",
                findings=findings,
                summary="No active Wi-Fi connection detected.",
                dns_posture=dns_info or {},
            )

        # 1. Evaluate Connected Encryption & Authentication Posture
        auth_upper = interface_info.authentication.upper()
        cipher_upper = interface_info.cipher.upper()

        if "OPEN" in auth_upper or "NONE" in cipher_upper:
            score -= 60
            findings.append(
                SecurityFinding(
                    severity="critical",
                    rule_id="WIFI-001",
                    title="Unencrypted Open Wi-Fi Network",
                    subject=f"SSID: {interface_info.ssid} ({interface_info.bssid})",
                    detail="This network transmits all wireless frames in cleartext without link-layer encryption. Any adversary in radio range can passively sniff credentials, session tokens, and DNS requests.",
                    remediation="Immediately disconnect or tunnel all traffic over an encrypted VPN (IPsec / WireGuard). Reconfigure the AP with WPA3-Personal or WPA2-Enterprise.",
                    reference="RFC 8110 (OWE) / NIST SP 800-153 §3.1",
                )
            )
        elif "WEP" in auth_upper or "WEP" in cipher_upper:
            score -= 50
            findings.append(
                SecurityFinding(
                    severity="critical",
                    rule_id="WIFI-002",
                    title="Obsolete WEP Encryption Detected",
                    subject=f"SSID: {interface_info.ssid}",
                    detail="WEP uses RC4 with small 24-bit IVs and broken CRC-32 integrity. Keys can be cracked passively in under 60 seconds with FMS/PTW attacks.",
                    remediation="Decommission WEP immediately and enforce WPA3-Personal (SAE) or WPA2-Personal (AES-CCMP).",
                    reference="IEEE 802.11i / NIST SP 800-97",
                )
            )
        elif "TKIP" in cipher_upper or "WPA-" in auth_upper and "WPA2" not in auth_upper and "WPA3" not in auth_upper:
            score -= 30
            findings.append(
                SecurityFinding(
                    severity="high",
                    rule_id="WIFI-003",
                    title="Vulnerable WPA/TKIP Encryption",
                    subject=f"SSID: {interface_info.ssid} (Cipher: {interface_info.cipher})",
                    detail="TKIP uses RC4 with known cryptographic weaknesses (Michael MIC attacks, Beck-Tews). Wi-Fi Alliance deprecated TKIP in 2012.",
                    remediation="Upgrade Access Point security policy to AES-CCMP or GCMP-256 exclusively.",
                    reference="Wi-Fi Alliance Technical Directive 2012",
                )
            )
        elif "WPA2" in auth_upper:
            # WPA2-Personal is acceptable but lacks modern WPA3 protection against offline dictionary attacks
            score -= 15
            findings.append(
                SecurityFinding(
                    severity="medium",
                    rule_id="WIFI-004",
                    title="WPA2 Pre-Shared Key (PSK) Vulnerable to Offline Dictionary Attack",
                    subject=f"SSID: {interface_info.ssid} (WPA2-Personal)",
                    detail="WPA2 4-Way Handshake allows passive adversaries recording the handshake to execute offline dictionary and brute-force attacks against the pre-shared key (PMK/PTK).",
                    remediation="Enable WPA3-Personal (SAE - Simultaneous Authentication of Equals) with Protected Management Frames (PMF / 802.11w) on your router.",
                    reference="IEEE 802.11-2020 / NIST SP 800-162",
                )
            )
        elif "WPA3" in auth_upper:
            # WPA3 is top tier
            findings.append(
                SecurityFinding(
                    severity="info",
                    rule_id="WIFI-005",
                    title="WPA3 Modern SAE Authentication Active",
                    subject=f"SSID: {interface_info.ssid}",
                    detail="Network employs Dragonfly handshake (SAE) with forward secrecy, rendering captured handshakes immune to offline dictionary attacks.",
                    remediation="Maintain mandatory PMF (Protected Management Frames) to prevent deauthentication attacks.",
                    reference="IEEE 802.11-2020 §12.4",
                )
            )

        # 2. RF Signal & Quality Posture
        if interface_info.signal_percent < 40:
            score -= 5
            findings.append(
                SecurityFinding(
                    severity="low",
                    rule_id="WIFI-010",
                    title="Weak Wireless Signal Strength",
                    subject=f"Signal: {interface_info.signal_percent}% ({interface_info.rssi_dbm} dBm)",
                    detail=f"Low signal strength increases packet drop rate, leading to frequent TCP/IPsec retransmissions and susceptibility to jamming or deauthentication.",
                    remediation="Move closer to the access point or switch to a 5 GHz band channel with better line-of-sight.",
                    reference="RFC 9000 §13 / IEEE 802.11k",
                )
            )

        # 3. Radio Band & Frequency Inspection
        if "2.4" in interface_info.band:
            findings.append(
                SecurityFinding(
                    severity="info",
                    rule_id="WIFI-011",
                    title="2.4 GHz Band In Use (Crowded Spectrum)",
                    subject=f"Band: {interface_info.band} · Channel {interface_info.channel}",
                    detail="The 2.4 GHz spectrum has only 3 non-overlapping channels (1, 6, 11) and suffers significant co-channel interference from Bluetooth and microwave emitters.",
                    remediation="Migrate clients to 5 GHz or 6 GHz (Wi-Fi 6/6E) for higher bandwidth and isolated DFS channels.",
                    reference="IEEE 802.11ax / 802.11be",
                )
            )

        # 4. Rogue AP / Evil Twin Analysis, across every SSID seen in range --
        # not only the one this host happens to be connected to. A clone of a
        # neighbouring network is just as real a threat to whoever's near it.
        rogue_findings, rogue_aps, rogue_score_delta = self._detect_rogue_aps(
            interface_info, networks
        )
        findings.extend(rogue_findings)
        score += rogue_score_delta

        # 5. DNS Security & Leak Audit
        dns_servers = (dns_info or {}).get("dns_servers", [])
        if dns_servers:
            is_local = any(_is_private_ip(s) for s in dns_servers)
            is_public_secure = any(s in ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9") for s in dns_servers)
            if is_local:
                score -= 5
                findings.append(
                    SecurityFinding(
                        severity="medium",
                        rule_id="WIFI-030",
                        title="Local Gateway Unencrypted DNS Resolver",
                        subject=f"DNS: {', '.join(dns_servers)}",
                        detail="DNS queries are routed through the local router without DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT). Local network eavesdroppers or malicious gateways can inspect visited hostnames and execute DNS spoofing / cache poisoning.",
                        remediation="Configure encrypted DNS (DoH/DoT) using trusted resolvers like Cloudflare (1.1.1.1) or Quad9 (9.9.9.9), or enforce DNSSEC validation.",
                        reference="RFC 8484 (DoH) / RFC 7858 (DoT)",
                    )
                )
            elif not is_public_secure:
                findings.append(
                    SecurityFinding(
                        severity="low",
                        rule_id="WIFI-031",
                        title="Unverified DNS Resolver Configured",
                        subject=f"DNS: {', '.join(dns_servers)}",
                        detail="Configured DNS resolver does not match known secure public DNS providers. Ensure resolution privacy and DNSSEC validation.",
                        remediation="Confirm DNS provider privacy policy regarding request logging.",
                        reference="RFC 7626",
                    )
                )

        # 6. Post-Quantum Cryptography Note on Wi-Fi Handshakes
        findings.append(
            SecurityFinding(
                severity="info",
                rule_id="WIFI-040",
                title="Wi-Fi Key Exchange Post-Quantum Susceptibility",
                subject="WPA2/WPA3 Key Derivation",
                detail="WPA2 (PBKDF2/SHA1) and WPA3 (ECC Dragonfly P-256) rely on classical cryptography. A recorded Wi-Fi capture can eventually be broken if decrypted by a Cryptanalytically Relevant Quantum Computer (CRQC) or via pre-shared key recovery.",
                remediation="Layer IPsec (RFC 9370 post-quantum hybrid KEM) or WireGuard over sensitive Wi-Fi connections.",
                reference="CNSA 2.0 / NIST PQC Standardization",
            )
        )

        score = max(0, min(100, score))
        grade = "A+" if score >= 95 else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 55 else "F"

        summary = (
            f"Connected to '{interface_info.ssid}' on {interface_info.band} (Channel {interface_info.channel}). "
            f"Security: {interface_info.authentication} / {interface_info.cipher} with {interface_info.signal_percent}% signal. "
            f"Score: {score}/100 (Grade {grade})."
        )

        return WifiAssessment(
            interface=interface_info,
            networks_in_range=networks,
            score=score,
            grade=grade,
            findings=findings,
            summary=summary,
            dns_posture=dns_info or {},
            rogue_aps=rogue_aps,
        )

    # -- Windows Native Parsers --------------------------------------------

    def _get_windows_current_interface(self) -> WifiInterfaceInfo | None:
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
        except Exception:
            return None

        fields: dict[str, str] = {}
        for line in out.splitlines():
            line = line.strip()
            if ":" in line:
                k, v = line.split(":", 1)
                fields[k.strip().lower()] = v.strip()

        if not fields.get("name"):
            return None

        # Parse signal and RSSI
        sig_str = fields.get("signal", "0%").replace("%", "").strip()
        signal_pct = int(sig_str) if sig_str.isdigit() else 0

        rssi_str = fields.get("rssi", "")
        rssi_val = -100
        try:
            if rssi_str:
                rssi_val = int(rssi_str)
            else:
                # Estimate RSSI from percentage if missing
                rssi_val = int((signal_pct / 2) - 100)
        except ValueError:
            rssi_val = -100

        # Parse Channel
        ch_str = fields.get("channel", "0").strip()
        channel = int(ch_str) if ch_str.isdigit() else 0

        # Parse rates
        rx_rate = 0.0
        tx_rate = 0.0
        try:
            rx_rate = float(fields.get("receive rate (mbps)", "0").split()[0])
            tx_rate = float(fields.get("transmit rate (mbps)", "0").split()[0])
        except Exception:
            pass

        return WifiInterfaceInfo(
            name=fields.get("name", "Wi-Fi"),
            description=fields.get("description", "Wireless Adapter"),
            mac_address=fields.get("physical address", ""),
            state=fields.get("state", "disconnected"),
            ssid=fields.get("ssid", ""),
            bssid=fields.get("ap bssid", fields.get("bssid", "")),
            band=fields.get("band", "Unknown"),
            channel=channel,
            radio_type=fields.get("radio type", ""),
            authentication=fields.get("authentication", "Open"),
            cipher=fields.get("cipher", "None"),
            signal_percent=signal_pct,
            rssi_dbm=rssi_val,
            rx_rate_mbps=rx_rate,
            tx_rate_mbps=tx_rate,
        )

    def _get_windows_networks(
        self,
        connected_ssid: str = "",
        connected_bssid: str = "",
        force_scan: bool = False,
        interface_info: WifiInterfaceInfo | None = None,
    ) -> list[WifiNetwork]:
        # If explicitly forced or cache is empty/stale, trigger an active 802.11 probe scan
        if force_scan or len(self._bss_cache) <= 1:
            try:
                from .wlan_native import trigger_scan
                trigger_scan(wait_secs=1.5 if force_scan else 0.8)
            except Exception:
                pass

        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
        except Exception:
            return []

        networks: list[WifiNetwork] = []
        current_ssid = ""
        current_auth = ""
        current_enc = ""
        now = time.time()

        for line in out.splitlines():
            line_str = line.strip()
            if not line_str:
                continue

            if line_str.startswith("SSID") and ":" in line_str and "BSSID" not in line_str:
                parts = line_str.split(":", 1)
                current_ssid = parts[1].strip() if len(parts) > 1 else ""
                current_auth = "Unknown"
                current_enc = "Unknown"
            elif "Authentication" in line_str and ":" in line_str:
                current_auth = line_str.split(":", 1)[1].strip()
            elif "Encryption" in line_str and ":" in line_str:
                current_enc = line_str.split(":", 1)[1].strip()
            elif line_str.startswith("BSSID") and ":" in line_str:
                bssid_val = line_str.split(":", 1)[1].strip().lower()
                is_conn = False
                if connected_bssid and bssid_val:
                    is_conn = (bssid_val.lower() == connected_bssid.lower())
                elif connected_ssid and current_ssid and not connected_bssid:
                    is_conn = (current_ssid.lower() == connected_ssid.lower())

                net = WifiNetwork(
                    ssid=current_ssid or "(Hidden SSID)",
                    bssid=bssid_val,
                    signal_percent=0,
                    rssi_dbm=-100,
                    channel=0,
                    band="2.4 GHz",
                    radio_type="802.11",
                    authentication=current_auth,
                    encryption=current_enc,
                    security_grade=self._grade_network(current_auth, current_enc),
                    connected=is_conn,
                )
                networks.append(net)
            elif networks:
                last_net = networks[-1]
                if "Signal" in line_str and ":" in line_str:
                    s_str = line_str.split(":", 1)[1].replace("%", "").strip()
                    if s_str.isdigit():
                        last_net.signal_percent = int(s_str)
                        last_net.rssi_dbm = int((last_net.signal_percent / 2) - 100)
                elif "Band" in line_str and ":" in line_str:
                    last_net.band = line_str.split(":", 1)[1].strip()
                elif "Channel" in line_str and ":" in line_str:
                    ch = line_str.split(":", 1)[1].strip()
                    if ch.isdigit():
                        last_net.channel = int(ch)
                elif "Radio type" in line_str and ":" in line_str:
                    last_net.radio_type = line_str.split(":", 1)[1].strip()

        # Update persistent cache with fresh detections
        current_bssids = set()
        for net in networks:
            current_bssids.add(net.bssid)
            self._bss_cache[net.bssid] = (net, now)

        # Merge in recently seen networks from the last 180 seconds to prevent
        # sudden collapse when driver enters powersave on non-associated channels
        for bssid, (cached_net, ts) in list(self._bss_cache.items()):
            if bssid not in current_bssids:
                if now - ts <= 180.0:
                    cached_net.connected = False
                    networks.append(cached_net)
                else:
                    self._bss_cache.pop(bssid, None)

        # Ensure strict single-AP connection attribution
        found_conn = False
        if connected_bssid:
            norm_conn_bssid = connected_bssid.lower().strip()
            for net in networks:
                if net.bssid.lower().strip() == norm_conn_bssid:
                    net.connected = True
                    found_conn = True
                else:
                    net.connected = False

        if not found_conn and connected_ssid:
            norm_conn_ssid = connected_ssid.lower().strip()
            for net in sorted(networks, key=lambda n: -n.signal_percent):
                if net.ssid.lower().strip() == norm_conn_ssid:
                    net.connected = True
                    found_conn = True
                    break

        # If the active connected AP was missing from scan results, inject it
        if not found_conn and interface_info and interface_info.state.lower() == "connected":
            networks.insert(0, WifiNetwork(
                ssid=interface_info.ssid or "(Connected Network)",
                bssid=interface_info.bssid or "—",
                signal_percent=interface_info.signal_percent or 80,
                rssi_dbm=interface_info.rssi_dbm or -60,
                channel=interface_info.channel or 0,
                band=interface_info.band or "5 GHz",
                radio_type=interface_info.radio_type or "802.11",
                authentication=interface_info.authentication or "WPA2-Personal",
                encryption=interface_info.cipher or "CCMP",
                security_grade=self._grade_network(interface_info.authentication, interface_info.cipher),
                connected=True,
            ))

        # Sort: connected first, then by signal percent descending
        networks.sort(key=lambda n: (not n.connected, -n.signal_percent))
        return networks

    def _grade_network(self, auth: str, enc: str) -> str:
        u_auth = auth.upper()
        u_enc = enc.upper()
        if "OPEN" in u_auth or "NONE" in u_enc:
            return "F"
        if "WEP" in u_auth or "WEP" in u_enc:
            return "F"
        if "TKIP" in u_enc or ("WPA" in u_auth and "WPA2" not in u_auth and "WPA3" not in u_auth):
            return "D"
        if "WPA3" in u_auth:
            return "A+"
        if "WPA2" in u_auth:
            return "B"
        return "C"

    def _detect_rogue_aps(
        self,
        interface_info: WifiInterfaceInfo | None,
        networks: list[WifiNetwork],
    ) -> tuple[list[SecurityFinding], list[dict[str, Any]], int]:
        """Flag Evil Twin / rogue clone APs for every SSID seen in range, not
        just the one this host happens to be connected to.

        Any BSSID broadcasting an SSID that also appears elsewhere in range
        under materially weaker security is a classic Evil Twin indicator: an
        attacker cloning a known network's name while dropping its encryption
        to lure clients into associating with the clone instead. That is a
        real threat to anyone on the segment whether or not it is the network
        this particular host is connected to right now, so every SSID group is
        checked, and `WifiNetwork.is_rogue` is set on every clone found -- the
        dashboard already renders that flag for any entry in
        `networks_in_range`, connected or not.

        Score is only docked for a clone of the network *this host* is
        connected to: that is an active risk to this assessment's own
        posture. A clone of a neighbouring network is still surfaced as a
        finding and in `rogue_aps`, just without affecting this host's score.
        """
        findings: list[SecurityFinding] = []
        rogue_aps: list[dict[str, Any]] = []
        score_delta = 0

        connected_ssid = (
            interface_info.ssid.lower() if interface_info and interface_info.ssid else ""
        )

        groups: dict[str, list[WifiNetwork]] = {}
        for n in networks:
            if n.ssid:
                groups.setdefault(n.ssid.lower(), []).append(n)

        for ssid_lower, group in groups.items():
            if len(group) < 2:
                continue

            ranked = [(_security_rank(n.authentication, n.encryption), n) for n in group]
            best = max(r for r, _ in ranked)
            weak = [n for r, n in ranked if r < best]
            is_current = ssid_lower == connected_ssid

            if not weak:
                # Multiple BSSIDs, identical security -- a legitimate mesh /
                # roaming deployment, not a clone. Only worth a finding when
                # it is the user's own network.
                if is_current:
                    findings.append(
                        SecurityFinding(
                            severity="info",
                            rule_id="WIFI-021",
                            title="Multi-AP Mesh / BSS Roaming Environment",
                            subject=f"SSID: {group[0].ssid} ({len(group)} APs in range)",
                            detail=f"Detected {len(group)} legitimate BSSIDs operating under matching security parameters ({group[0].authentication}).",
                            remediation="Ensure 802.11r (Fast BSS Transition) and 802.11k/v are enabled for seamless roaming.",
                            reference="IEEE 802.11r-2008",
                        )
                    )
                continue

            baseline_auth = next(n.authentication for r, n in ranked if r == best)
            for rog in weak:
                rog.is_rogue = True
                rog.rogue_reason = f"Evil Twin Clone ({rog.authentication} vs {baseline_auth})"
                rogue_aps.append({
                    "ssid": rog.ssid,
                    "bssid": rog.bssid,
                    "band": rog.band,
                    "channel": rog.channel,
                    "signal_percent": rog.signal_percent,
                    "authentication": rog.authentication,
                    "encryption": rog.encryption,
                    "reason": f"Downgraded security clone: operates under {rog.authentication} while the legitimate '{rog.ssid}' network enforces {baseline_auth}",
                    "target_ssid": rog.ssid,
                    "threat_level": "critical" if is_current else "high",
                })

            if is_current:
                score_delta -= 35

            findings.append(
                SecurityFinding(
                    severity="critical" if is_current else "high",
                    rule_id="WIFI-020",
                    title=(
                        "Potential Evil Twin / Rogue AP Detected"
                        if is_current
                        else f"Nearby Evil Twin / Rogue AP Detected ({group[0].ssid})"
                    ),
                    subject=f"SSID: {group[0].ssid}",
                    detail=(
                        f"Detected {len(group)} access points advertising SSID '{group[0].ssid}', "
                        f"with at least one utilizing downgraded security ({weak[0].authentication} vs {baseline_auth}). "
                        + (
                            "This is a classic indicator of an Evil Twin attack attempting to trick "
                            "clients into associating with a malicious clone."
                            if is_current
                            else
                            "This is not the network this host is connected to, but the clone is "
                            "broadcasting in range and can trick other nearby clients into associating "
                            "with it."
                        )
                    ),
                    remediation="Do not connect to open or downgraded clones. Verify the authentic BSSID MAC address with your network administrator.",
                    reference="OWASP Wireless Security Guide §W04",
                )
            )

        return findings, rogue_aps, score_delta

    def _get_windows_network_config(self) -> dict[str, Any]:
        """Fetch IP, Gateway, and DNS server info via ipconfig /all."""
        info: dict[str, Any] = {"dns_servers": [], "gateway": "", "ipv4": ""}
        try:
            raw = subprocess.check_output(["ipconfig", "/all"], text=True, encoding="utf-8", errors="ignore")
            # Parse IPv4
            ip_match = re.search(r"IPv4 Address[ .:]+:\s*([0-9.]+)", raw)
            if ip_match:
                info["ipv4"] = ip_match.group(1)
            # Parse Gateway
            gw_match = re.search(r"Default Gateway[ .:]+:\s*([0-9.]+)", raw)
            if gw_match:
                info["gateway"] = gw_match.group(1)
            # Parse DNS Servers
            dns_matches = re.findall(r"DNS Servers[ .:]+:\s*([0-9.]+)", raw)
            # Also catch additional DNS lines indented directly below
            for block in re.finditer(r"DNS Servers[ .:]+:\s*([0-9.]+)(?:\s*\n\s+([0-9.]+))*", raw):
                for g in block.groups():
                    if g and g not in info["dns_servers"]:
                        info["dns_servers"].append(g)
            if not info["dns_servers"]:
                info["dns_servers"] = list(dict.fromkeys(dns_matches))
        except Exception:
            pass
        return info

    # -- Linux Fallbacks ---------------------------------------------------

    def _get_linux_current_interface(self) -> WifiInterfaceInfo | None:
        # Check iwconfig or nmcli
        try:
            out = subprocess.check_output(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,SIGNAL,SECURITY,DEVICE", "dev", "wifi"], text=True)
            for line in out.splitlines():
                if line.startswith("yes:"):
                    parts = line.split(":")
                    return WifiInterfaceInfo(
                        name=parts[6] if len(parts) > 6 else "wlan0",
                        description="Linux Wireless Device",
                        mac_address="",
                        state="connected",
                        ssid=parts[1] if len(parts) > 1 else "",
                        bssid=parts[2] if len(parts) > 2 else "",
                        band="5 GHz" if int(parts[3] or 0) > 14 else "2.4 GHz",
                        channel=int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0,
                        radio_type="802.11ac",
                        authentication=parts[5] if len(parts) > 5 else "WPA2",
                        cipher="CCMP",
                        signal_percent=int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 80,
                        rssi_dbm=int((int(parts[4] or 80) / 2) - 100),
                    )
        except Exception:
            pass
        return None

    def _get_linux_networks(self) -> list[WifiNetwork]:
        networks: list[WifiNetwork] = []
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi"],
                text=True,
                errors="ignore",
            )
            for line in out.splitlines():
                if not line.strip():
                    continue
                tokens = re.split(r"(?<!\\):", line)
                if len(tokens) >= 5:
                    ssid = tokens[0].replace(r"\:", ":").strip()
                    bssid = tokens[1].replace(r"\:", ":").strip()
                    chan_str = tokens[2].strip()
                    sig_str = tokens[3].strip()
                    sec_str = tokens[4].replace(r"\:", ":").strip()
                    chan = int(chan_str) if chan_str.isdigit() else 0
                    sig = int(sig_str) if sig_str.isdigit() else 50
                    band = "5 GHz" if chan > 14 else "2.4 GHz"
                    enc_val = "CCMP" if "WPA" in sec_str else "None"
                    networks.append(
                        WifiNetwork(
                            ssid=ssid or "[Hidden SSID]",
                            bssid=bssid,
                            signal_percent=sig,
                            rssi_dbm=int((sig / 2) - 100),
                            channel=chan,
                            band=band,
                            radio_type="802.11",
                            authentication=sec_str or "Open",
                            encryption=enc_val,
                            cipher=enc_val,
                            security_grade=self._grade_network(sec_str, enc_val),
                        )
                    )
        except Exception:
            pass
        return networks

    def _get_linux_dns(self) -> dict[str, Any]:
        info: dict[str, Any] = {"dns_servers": [], "gateway": "", "ipv4": ""}
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        info["dns_servers"].append(line.split()[1])
        except Exception:
            pass
        return info
