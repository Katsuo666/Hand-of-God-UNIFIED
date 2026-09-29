# -*- coding: utf-8 -*-
"""Extração e explicação de findings, partilhado entre terminal, PDF e Markdown."""

from typing import Any, Dict, List

SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

# Explicações curtas por tipo de finding — usadas no resumo do terminal e nos
# relatórios exportados, para quem não é especialista em segurança entender
# o que foi encontrado e o que fazer a respeito.
FINDING_EXPLANATIONS: Dict[str, str] = {
    'XSS_REFLECTED': (
        'O alvo devolveu, sem sanitizar, um script injetado num parâmetro da URL. '
        'Um atacante pode montar um link malicioso que executa JavaScript no navegador da vítima.'
    ),
    'SSRF_POSSIBLE': (
        'O alvo aceitou uma URL apontando para um endereço interno/loopback e respondeu 200. '
        'Pode permitir que o servidor faça requisições para a rede interna em nome do atacante.'
    ),
    'IDOR_INCREMENTAL_ID': (
        'Heurística: respostas diferentes ao variar um ID numérico no parâmetro. '
        'Pode ser IDOR real (acesso a dados de outro usuário) ou apenas conteúdo dinâmico '
        '(tokens/timestamps) — confirmar manualmente comparando os dados retornados.'
    ),
    'IDOR_UUID': (
        'Heurística: um UUID aleatório foi aceito com resposta 200. Em SPAs com rota '
        'catch-all isto é comum e não prova acesso indevido — confirmar manualmente.'
    ),
    'IDOR_PARAMETER_TAMPERING': (
        'Heurística: a palavra "admin"/"root" apareceu na resposta ao trocar o valor do '
        'parâmetro. Pode ser falso positivo (a palavra aparece em JS/CSS da própria página) '
        '— confirmar manualmente que são dados sensíveis reais.'
    ),
    'NO_RATE_LIMITING': (
        'Nenhuma das requisições rápidas foi bloqueada. Facilita ataques de força bruta '
        '(login, tokens) e abuso de API.'
    ),
    'MISSING_HEADER': (
        'Cabeçalho de segurança HTTP ausente, reduzindo proteções do navegador contra '
        'ataques comuns (clickjacking, MIME sniffing, downgrade para HTTP).'
    ),
    'SENSITIVE_KEYWORD': (
        'Palavra sensível encontrada na URL/conteúdo (ex: token, senha). Pode indicar '
        'exposição acidental de informação sensível — revisar manualmente.'
    ),
}

GENERIC_EXPLANATION = 'Finding reportado por um scanner automático — revisar manualmente antes de agir.'


def collect_findings(node: Any, out: List[Dict] = None) -> List[Dict]:
    """Percorre qualquer estrutura de resultado (scanner único ou pipeline aninhada)
    e junta todos os dicts que parecem um Finding (têm 'severity' e 'title')."""
    if out is None:
        out = []
    if isinstance(node, dict):
        if 'severity' in node and 'title' in node:
            out.append(node)
            return out
        for v in node.values():
            collect_findings(v, out)
    elif isinstance(node, list):
        for item in node:
            collect_findings(item, out)
    return out


def sort_by_severity(findings: List[Dict]) -> List[Dict]:
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.get('severity', 'INFO'))
        if f.get('severity', 'INFO') in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )


def count_by_severity(findings: List[Dict]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get('severity', 'INFO')
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def explain(finding_type: str) -> str:
    return FINDING_EXPLANATIONS.get(finding_type, GENERIC_EXPLANATION)
