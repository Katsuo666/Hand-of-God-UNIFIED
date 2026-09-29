# -*- coding: utf-8 -*-
"""
Pipelines unificadas: tradicional (passiva), agressiva (ativa) e IA (estática + NEXUS).
"""

from typing import Any, Dict

from . import pipeline1_traditional
from . import pipeline2_aggressive
from . import pipeline3_ai

__all__ = [
    'pipeline1_traditional',
    'pipeline2_aggressive',
    'pipeline3_ai',
    'run_pipeline',
]

__version__ = '1.0.0'


def run_pipeline(target: str, pipeline: str = "1", exploit: bool = False) -> Dict[str, Any]:
    """
    Executa uma ou mais pipelines sobre o alvo.

    Args:
        target: domínio, IP, email, URL ou hash
        pipeline: "1" (tradicional), "2" (agressiva), "3" (IA) ou "all"
        exploit: (pipeline "3"/"all") também injeta payloads ativos de
            XSS/SQLi/SSRF — só use com autorização explícita do alvo.
    """
    if pipeline == "1":
        return pipeline1_traditional.run(target)
    if pipeline == "2":
        return pipeline2_aggressive.run(target)
    if pipeline == "3":
        return pipeline3_ai.run(target, exploit=exploit)
    if pipeline == "all":
        return {
            "target": target,
            "traditional": pipeline1_traditional.run(target),
            "aggressive": pipeline2_aggressive.run(target),
            "ai": pipeline3_ai.run(target, exploit=exploit),
        }
    raise ValueError(f"Pipeline desconhecida: {pipeline!r} (use '1', '2', '3' ou 'all')")
