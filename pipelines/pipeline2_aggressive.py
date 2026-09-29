# -*- coding: utf-8 -*-
"""Pipeline 2 — Agressiva: recon ativa + scanner de vulnerabilidades."""

from datetime import datetime
from typing import Any, Dict, List

from core.shared_context import SharedContext
from modules.recon.active import ActiveRecon
from modules.scanner import (
    APIFuzzer,
    ClickjackingTester,
    GraphQLTester,
    IDORTester,
    JWTAnalyzer,
    RateLimitTester,
    RobotsSitemapScanner,
    SSLAnalyzer,
    VulnScanner,
    WAFDetector,
)

# Scanners que precisam apenas da URL base (sem parâmetros/tokens específicos)
SCANNERS = [
    WAFDetector, JWTAnalyzer, GraphQLTester, IDORTester,
    ClickjackingTester, RateLimitTester, APIFuzzer,
    RobotsSitemapScanner, VulnScanner,
]


def run(target: str) -> Dict[str, Any]:
    """Executa recon ativa + todo o scanner suite (Task 7) contra o alvo."""
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"

    active = ActiveRecon()
    active_result = active.analyze(url)
    active.close()

    ssl_result = SSLAnalyzer(url).scan()

    findings: List[Any] = list(ssl_result.findings)
    scan_results: Dict[str, Any] = {"SSLAnalyzer": ssl_result.to_dict()}

    for scanner_cls in SCANNERS:
        name = scanner_cls.__name__
        try:
            scan_result = scanner_cls(url).scan()
            scan_results[name] = scan_result.to_dict()
            findings.extend(scan_result.findings)
        except Exception as e:
            scan_results[name] = {"success": False, "error_message": str(e)}

    context = SharedContext()
    for finding in findings:
        context.add_finding("aggressive", {**finding.to_dict(), "target": target})

    return {
        "pipeline": "aggressive",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "active_recon": active_result,
        "scanners": scan_results,
        "total_findings": len(findings),
    }
