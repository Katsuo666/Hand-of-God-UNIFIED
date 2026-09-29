# -*- coding: utf-8 -*-
"""Orquestrador OSINT de domínio: recon passiva + ativa + threat intel."""

from datetime import datetime
from typing import Any, Dict

from modules.recon.passive import PassiveRecon
from modules.recon.active import ActiveRecon
from modules.recon.threat_intel import ThreatIntel


class DomainOSSINT:
    def __init__(self):
        self.passive = PassiveRecon()
        self.active = ActiveRecon()
        self.threat_intel = ThreatIntel()

    def analyze(self, domain: str, deep: bool = False) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "target": domain,
            "type": "domain",
            "timestamp": datetime.now().isoformat(),
            "passive": self.passive.analyze(domain) or {},
            "threat_intel": self.threat_intel.check_domain_reputation(domain) or {},
        }
        if deep:
            result["active"] = self.active.analyze(f"https://{domain}") or {}
        return result

    def close(self) -> None:
        self.passive.close()
        self.active.close()
        self.threat_intel.close()
