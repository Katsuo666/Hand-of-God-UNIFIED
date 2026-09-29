# -*- coding: utf-8 -*-
"""Orquestrador OSINT de IP: threat intel + port scan opcional."""

from datetime import datetime
from typing import Any, Dict

from modules.recon.active import ActiveRecon
from modules.recon.threat_intel import ThreatIntel
from modules.recon.geo_lookup import GeoLookup


class IPOSINT:
    def __init__(self):
        self.active = ActiveRecon()
        self.threat_intel = ThreatIntel()
        self.geo = GeoLookup()

    def analyze(self, ip: str, do_scan: bool = False) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "target": ip,
            "type": "ip",
            "timestamp": datetime.now().isoformat(),
            "reputation": self.threat_intel.check_ip_reputation(ip) or {},
            "geo": self.geo.lookup(ip),
        }
        if do_scan:
            result["port_scan"] = self.active.port_scan(ip) or {}
        return result

    def close(self) -> None:
        self.active.close()
        self.threat_intel.close()
        self.geo.close()
