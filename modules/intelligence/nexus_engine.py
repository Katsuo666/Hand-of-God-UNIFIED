# -*- coding: utf-8 -*-
"""
NEXUS: motor de reconhecimento automático e correlação de inteligência.

Detecta o tipo do alvo, executa os módulos relevantes (core/recon já
portados) em paralelo, constrói um grafo de conhecimento (IntelGraph)
e calcula um score de risco consolidado (RiskAnalyzer).
"""

import concurrent.futures
import time
from datetime import datetime
from typing import Any, Dict, Tuple
from urllib.parse import urlparse

from core.validator import Validator
from modules.recon.passive import PassiveRecon
from modules.recon.active import ActiveRecon
from modules.recon.osint_deep import OSINTDeep
from modules.recon.threat_intel import ThreatIntel
from modules.scanner import WAFDetector, VulnScanner
from modules.intelligence.intel_graph import IntelGraph
from modules.intelligence.risk_analyzer import RiskAnalyzer


class NexusEngine:
    """Motor de reconhecimento automático e correlação de inteligência."""

    def detect_type(self, target: str) -> str:
        target = target.strip()
        if Validator.is_email(target):
            return 'email'
        if Validator.is_ip(target):
            return 'ip'
        if Validator.is_md5(target) or Validator.is_sha1(target) or Validator.is_sha256(target):
            return 'hash'
        if target.startswith(('http://', 'https://')):
            return 'url'
        if Validator.is_domain(target):
            return 'domain'
        return 'unknown'

    def analyze(self, target: str, deep: bool = False, max_workers: int = 8) -> Tuple[Dict[str, Any], IntelGraph]:
        start = time.perf_counter()
        target_type = self.detect_type(target)

        graph = IntelGraph()
        cid = graph.add_node(target, target_type, target)

        tasks = self._build_tasks(target, target_type, deep)
        findings: Dict[str, Any] = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(fn): name for name, fn in tasks.items()}
            for future in concurrent.futures.as_completed(futures, timeout=120):
                name = futures[future]
                try:
                    result = future.result(timeout=60)
                    if result:
                        findings[name] = result
                except Exception:
                    continue

        self._build_graph(graph, cid, target_type, findings)

        threat_intel = findings.get('threat_intel', {})
        risk = RiskAnalyzer.analyze(findings, threat_intel, graph)
        graph.set_risk(target, risk['score'])

        elapsed = round(time.perf_counter() - start, 2)

        result_data = {
            'target': target,
            'target_type': target_type,
            'timestamp': datetime.now().isoformat(),
            'elapsed_s': elapsed,
            'risk': risk,
            'findings': findings,
            'graph': graph.to_dict(),
        }
        return result_data, graph

    # ── Construção de tarefas ─────────────────────────────────

    def _build_tasks(self, target: str, target_type: str, deep: bool) -> Dict[str, Any]:
        tasks: Dict[str, Any] = {}

        if target_type == 'domain':
            passive = PassiveRecon()
            tasks['passive'] = lambda: passive.analyze(target)
            ti = ThreatIntel()
            tasks['threat_intel'] = lambda: ti.analyze_indicator(target)
            if deep:
                active = ActiveRecon()
                tasks['active'] = lambda: active.analyze(f"https://{target}")
                tasks['scanner'] = lambda: self._run_scanner(f"https://{target}")

        elif target_type == 'ip':
            ti = ThreatIntel()
            tasks['threat_intel'] = lambda: ti.analyze_indicator(target)
            if deep:
                active = ActiveRecon()
                tasks['active'] = lambda: {'findings': {'port_scan': active.port_scan(target)}}

        elif target_type == 'email':
            osint_deep = OSINTDeep()
            tasks['osint'] = lambda: osint_deep.analyze(target)

        elif target_type == 'url':
            ti = ThreatIntel()
            tasks['threat_intel'] = lambda: ti.analyze_indicator(target)
            osint_deep = OSINTDeep()
            tasks['osint'] = lambda: {'findings': osint_deep.url_anti_phishing(target)}
            host = urlparse(target).hostname
            if host:
                passive = PassiveRecon()
                tasks['passive'] = lambda: passive.analyze(host)

        elif target_type == 'hash':
            ti = ThreatIntel()
            tasks['threat_intel'] = lambda: ti.analyze_indicator(target)

        return tasks

    def _run_scanner(self, url: str) -> Dict[str, Any]:
        """Roda checagens ativas leves (WAF + arquivos sensíveis) para o modo deep."""
        all_findings = []
        for scanner_cls in (WAFDetector, VulnScanner):
            try:
                all_findings.extend(scanner_cls(url).scan().findings)
            except Exception:
                continue
        return {'findings': all_findings}

    # ── Construção do grafo a partir dos achados ──────────────

    def _build_graph(self, graph: IntelGraph, cid: str, target_type: str, findings: Dict[str, Any]) -> None:
        passive = findings.get('passive', {}).get('findings', {})

        for ip in (passive.get('dns') or {}).get('A', []) if passive.get('dns') else []:
            nid = graph.add_node(ip, 'ip', ip)
            graph.add_edge(cid, nid, 'resolve A')

        whois = passive.get('whois') or {}
        if isinstance(whois, dict) and whois.get('org'):
            nid = graph.add_node(whois['org'], 'org', whois['org'][:40])
            graph.add_edge(cid, nid, 'registrado por')

        for sub in (passive.get('subdomains') or [])[:40]:
            nid = graph.add_node(sub, 'subdomain', sub[:40])
            graph.add_edge(cid, nid, 'subdomínio')

        active = findings.get('active', {}).get('findings', {})
        for port in (active.get('port_scan') or {}).get('open_ports', []):
            risk = 60 if port in {21, 23, 445, 3389, 27017, 6379, 9200, 2375} else 20
            nid = graph.add_node(f"{cid}:{port}", 'url', f":{port}", risk=risk)
            graph.add_edge(cid, nid, 'porta aberta')

        for finding in findings.get('scanner', {}).get('findings', []):
            sev = getattr(finding, 'severity', None) or (finding.get('severity') if isinstance(finding, dict) else 'LOW')
            title = getattr(finding, 'title', None) or (finding.get('title') if isinstance(finding, dict) else str(finding))
            risk = {'CRITICAL': 90, 'HIGH': 70, 'MEDIUM': 50, 'LOW': 25}.get(str(sev).upper(), 20)
            nid = graph.add_node(f"vuln:{title}", 'cve', f"VULN:{str(title)[:28]}", risk=risk)
            graph.add_edge(cid, nid, 'vulnerabilidade')

        threat_intel = findings.get('threat_intel', {}).get('analysis', {})
        if threat_intel.get('is_malicious') or threat_intel.get('is_suspicious'):
            nid = graph.add_node(f"threat:{cid}", 'threat', '⚠ Threat Intel', risk=85)
            graph.add_edge(cid, nid, 'detectado em', weight=3)
