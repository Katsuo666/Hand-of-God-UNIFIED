# -*- coding: utf-8 -*-
"""Pipeline 1 — Tradicional: recon passiva + OSINT profunda + threat intel."""

from datetime import datetime
from typing import Any, Dict

from modules.intelligence.nexus_engine import NexusEngine
from modules.osint import DomainOSSINT, EmailOSSINT, IPOSINT
from modules.recon.threat_intel import ThreatIntel


def run(target: str) -> Dict[str, Any]:
    """Executa recon passiva completa sobre o alvo, roteando por tipo detectado."""
    target_type = NexusEngine().detect_type(target)

    result: Dict[str, Any] = {
        "pipeline": "traditional",
        "target": target,
        "target_type": target_type,
        "timestamp": datetime.now().isoformat(),
        "data": {},
    }

    if target_type == "domain":
        orchestrator = DomainOSSINT()
        result["data"] = orchestrator.analyze(target, deep=False)
        orchestrator.close()
    elif target_type == "email":
        orchestrator = EmailOSSINT()
        result["data"] = orchestrator.analyze(target)
        orchestrator.close()
    elif target_type == "ip":
        orchestrator = IPOSINT()
        result["data"] = orchestrator.analyze(target, do_scan=False)
        orchestrator.close()
    else:
        ti = ThreatIntel()
        result["data"] = {"threat_intel": ti.analyze_indicator(target)}
        ti.close()

    return result
