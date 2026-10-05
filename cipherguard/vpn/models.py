"""Data models for VPN and tunnel overlay detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from ..wifi.models import SecurityFinding, WifiAssessment


@dataclass
class VpnTunnelInfo:
    connected: bool = False
    adapter_name: str = ""
    adapter_description: str = ""
    vpn_type: str = "None"
    virtual_ip: str = ""
    gateway_ip: str = ""
    route_metric: int = 0
    is_default_route: bool = False
    dns_servers: list[str] = field(default_factory=list)
    dns_leak_detected: bool = False
    dns_leak_details: str = ""
    egress_ip: str = ""
    egress_isp: str = ""
    egress_country: str = ""
    egress_city: str = ""
    # False when no outbound lookup was made, so empty egress fields read as
    # "not queried" and never as "nothing found".
    egress_queried: bool = False
    findings: list[SecurityFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "connected": self.connected,
            "adapter_name": self.adapter_name,
            "adapter_description": self.adapter_description,
            "vpn_type": self.vpn_type,
            "virtual_ip": self.virtual_ip,
            "gateway_ip": self.gateway_ip,
            "route_metric": self.route_metric,
            "is_default_route": self.is_default_route,
            "dns_servers": self.dns_servers,
            "dns_leak_detected": self.dns_leak_detected,
            "dns_leak_details": self.dns_leak_details,
            "egress_ip": self.egress_ip,
            "egress_isp": self.egress_isp,
            "egress_country": self.egress_country,
            "egress_city": self.egress_city,
            "egress_queried": self.egress_queried,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class NetworkPostureComposite:
    wifi: WifiAssessment
    vpn: VpnTunnelInfo
    posture_status: str = "Normal (Direct Wi-Fi)"
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "wifi": self.wifi.to_dict(),
            "vpn": self.vpn.to_dict(),
            "posture_status": self.posture_status,
            "summary": self.summary,
        }
