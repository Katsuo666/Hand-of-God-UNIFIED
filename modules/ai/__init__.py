# -*- coding: utf-8 -*-
"""
Análise estática (secrets, keywords sensíveis, fingerprint de tecnologias)
e testes ativos de exploração (XSS/SQLi/SSRF) — use apenas com autorização.
"""

from .secret_scanner import SecretScanner
from .exploit_tester import ExploitTester

__all__ = ['SecretScanner', 'ExploitTester']

__version__ = '1.0.0'
