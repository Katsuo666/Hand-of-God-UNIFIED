# -*- coding: utf-8 -*-
"""Pipeline 3 — IA: análise estática (secrets/keywords/tech) + correlação NEXUS."""

from datetime import datetime
from typing import Any, Dict

from core.http_client import HTTPClient
from core.shared_context import SharedContext
from modules.ai.secret_scanner import SecretScanner
from modules.ai.exploit_tester import ExploitTester
from modules.intelligence.nexus_engine import NexusEngine


def run(target: str, deep: bool = True, exploit: bool = False) -> Dict[str, Any]:
    """
    Faz análise estática do HTML servido pelo alvo e correlaciona via NEXUS.

    Args:
        exploit: se True, também injeta payloads ativos de XSS/SQLi/SSRF
            (ExploitTester). Desligado por padrão — só use contra alvos
            com autorização explícita para teste de exploração.
    """
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"

    context = SharedContext()

    http_client = HTTPClient()
    response = http_client.get(url)
    static_analysis: Dict[str, Any] = {}
    if response:
        static_analysis = SecretScanner().scan(response.text, url)
        for secret in static_analysis.get("secrets", []):
            context.add_finding("ai:secrets", {**secret, "target": target})
        for kw in static_analysis.get("context_flags", []):
            context.add_finding("ai:keywords", {**kw, "target": target})

    exploit_result: Dict[str, Any] = {}
    if exploit:
        exploit_scan = ExploitTester(url).scan()
        exploit_result = exploit_scan.to_dict()
        for finding in exploit_scan.findings:
            context.add_finding("ai:exploit", {**finding.to_dict(), "target": target})

    nexus = NexusEngine()
    nexus_result, graph = nexus.analyze(target, deep=deep)

    return {
        "pipeline": "ai",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "static_analysis": static_analysis,
        "exploit_tests": exploit_result,
        "nexus": nexus_result,
    }
