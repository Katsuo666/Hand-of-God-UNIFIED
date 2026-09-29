# -*- coding: utf-8 -*-
"""Motor de análise de risco centralizado (score 0-100) sobre achados NEXUS."""

from typing import Any, Dict, List

DANGEROUS_PORTS = {21, 23, 445, 3389, 27017, 6379, 9200, 2375}


class RiskAnalyzer:
    """Consolida achados de recon/threat-intel/graph num score de risco único."""

    @staticmethod
    def analyze(findings: Dict[str, Any], threat_intel: Dict[str, Any],
                graph: "IntelGraph") -> Dict[str, Any]:  # noqa: F821
        scores: List[int] = []
        factors: List[str] = []

        # Threat intelligence
        ti_analysis = threat_intel.get('analysis', {})
        if ti_analysis.get('is_malicious') or ti_analysis.get('is_suspicious'):
            scores.append(85)
            factors.append('Indicador marcado como malicioso/suspeito em threat intel')
        rep_score = ti_analysis.get('reputation_score', 0)
        if rep_score:
            scores.append(min(abs(rep_score) * 10, 90))
            factors.append(f'Reputation score: {rep_score}')

        # Portas perigosas (recon ativo)
        port_scan = findings.get('active', {}).get('findings', {}).get('port_scan', {}) or {}
        open_ports = set(port_scan.get('open_ports', []))
        risky_open = open_ports & DANGEROUS_PORTS
        if risky_open:
            scores.append(min(30 + len(risky_open) * 10, 75))
            factors.append(f'Portas perigosas abertas: {sorted(risky_open)}')

        # SSL
        ssl_data = findings.get('passive', {}).get('findings', {}).get('ssl', {}) or {}
        if ssl_data.get('is_expired'):
            scores.append(70)
            factors.append('Certificado SSL expirado')
        elif ssl_data and not ssl_data.get('valid', True):
            scores.append(50)
            factors.append('Certificado SSL inválido')

        # Vulnerabilidades ativas (scanner)
        sev_map = {'CRITICAL': 90, 'HIGH': 70, 'MEDIUM': 50, 'LOW': 25}
        for vuln in findings.get('scanner', {}).get('findings', []):
            sev = getattr(vuln, 'severity', None) or vuln.get('severity', '')
            sev = str(sev).upper()
            if sev in sev_map:
                scores.append(sev_map[sev])
                title = getattr(vuln, 'title', None) or vuln.get('title', sev)
                factors.append(f'{sev}: {title}')

        # Maior risco já atribuído a algum nó do grafo
        max_node = max((n.get('risk', 0) for n in graph.nodes.values()), default=0)
        if max_node:
            scores.append(max_node)

        # Superfície de ataque (subdomínios)
        subdomains = findings.get('passive', {}).get('findings', {}).get('subdomains') or []
        if len(subdomains) > 50:
            scores.append(40)
            factors.append(f'Superfície de ataque ampla: {len(subdomains)} subdomínios')

        final = min(int(sum(scores) / max(len(scores), 1)), 100) if scores else 0

        if final >= 70:
            level = 'CRÍTICO'
        elif final >= 50:
            level = 'ALTO'
        elif final >= 30:
            level = 'MÉDIO'
        else:
            level = 'BAIXO'

        return {
            'score': final,
            'level': level,
            'factors': factors,
            'node_count': len(graph.nodes),
            'edge_count': len(graph.edges),
            'summary': f'Pontuação de risco: {final}/100 — {level}. {len(factors)} fator(es) detectado(s).',
        }
