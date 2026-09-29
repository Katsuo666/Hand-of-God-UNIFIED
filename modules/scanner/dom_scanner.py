# -*- coding: utf-8 -*-
"""
DOM Cloaking / DOM Clobbering Scanner — único scanner deste projeto que precisa
de um motor JS real (Playwright + Chromium), por isso fica isolado num módulo
próprio com import opcional (mesmo padrão de `frida` em dynamic_instrumentation.py).

A definição usada na lista de vulnerabilidades ("injeção de elementos HTML com
IDs específicos que sobrepõem e neutralizam variáveis globais do JavaScript
usadas para controlos de segurança") é a técnica conhecida como DOM Clobbering:
o HTML parser do browser expõe elementos com id/name como propriedades
implícitas de `window`/`document`, e se um script referencia uma variável
global sem declará-la (`if (config.debug)` em vez de `var config = {...}`),
um atacante que consiga injetar HTML (mesmo sem executar <script>, ex. via
uma sanitização de XSS incompleta) pode clobbing essa variável.
"""

import re
import time
from typing import Any, Dict, List, Set
from urllib.parse import urljoin

from core.logger import get_logger
from .active_scanner import Finding, ScanResult

logger = get_logger(__name__)

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

# Nomes de variáveis globais tipicamente usadas em decisões de segurança no
# front-end — os candidatos mais valiosos para um ataque de DOM Clobbering.
SECURITY_SENSITIVE_GLOBALS = [
    'config', 'CONFIG', 'settings', 'isAdmin', 'is_admin', 'DEBUG', 'debug',
    'csrf', 'csrfToken', 'CSRF_TOKEN', 'authToken', 'auth', 'session',
    'policy', 'secure', 'isSecure', 'trustedOrigins', 'ALLOWED_ORIGINS',
    'redirectUrl', 'apiBase', 'API_URL', 'baseUrl',
]

# Identifica uso de uma variável global sem que ela tenha sido declarada
# localmente (var/let/const/function <nome>) — heurística por regex, não um
# parser de JS completo.
_UNGUARDED_GLOBAL_USE = re.compile(
    r'(?<![.\w])(' + '|'.join(re.escape(g) for g in SECURITY_SENSITIVE_GLOBALS) + r')\s*(\.|&&|\?\.|\[|\)|==)'
)
_DECLARATION = re.compile(
    r'\b(?:var|let|const|function)\s+(' + '|'.join(re.escape(g) for g in SECURITY_SENSITIVE_GLOBALS) + r')\b'
)


class DOMCloakingScanner:
    """Renderiza a página com um browser real e procura elementos HTML cujo
    id/name colide com uma variável global sensível referenciada sem
    declaração nos scripts da página (superfície de DOM Clobbering)."""

    def __init__(self, target: str, timeout: float = 20.0):
        self.target = target
        self.timeout = timeout
        self.findings: List[Finding] = []

    def _extract_clobberable_ids(self, html: str) -> Set[str]:
        ids = set(re.findall(r'\bid\s*=\s*["\']([A-Za-z_$][\w$]*)["\']', html))
        names = set(re.findall(r'\bname\s*=\s*["\']([A-Za-z_$][\w$]*)["\']', html))
        return ids | names

    def _find_unguarded_globals(self, scripts: List[str]) -> Set[str]:
        unguarded: Set[str] = set()
        for content in scripts:
            declared = set(_DECLARATION.findall(content))
            for match in _UNGUARDED_GLOBAL_USE.finditer(content):
                name = match.group(1)
                if name not in declared:
                    unguarded.add(name)
        return unguarded

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[DOMCloaking] Iniciando scan: {self.target}")

        if not PLAYWRIGHT_AVAILABLE:
            return ScanResult(
                scanner_name='DOMCloakingScanner', target=self.target,
                findings=[], execution_time=time.time() - start_time, success=False,
                error_message="Dependência opcional 'playwright' não instalada/configurada. "
                              "Rode: pip install playwright && playwright install chromium",
            )

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                script_contents: List[str] = []

                def capture_script(response):
                    try:
                        ctype = response.headers.get('content-type', '')
                        if 'javascript' in ctype or response.url.endswith('.js'):
                            script_contents.append(response.text())
                    except Exception:
                        pass

                page.on('response', capture_script)
                page.goto(self.target, timeout=int(self.timeout * 1000), wait_until='networkidle')

                rendered_html = page.content()
                inline_scripts = page.eval_on_selector_all(
                    'script:not([src])', 'els => els.map(e => e.textContent)'
                )
                script_contents.extend(s for s in inline_scripts if s)

                browser.close()

            clobberable_ids = self._extract_clobberable_ids(rendered_html)
            unguarded_globals = self._find_unguarded_globals(script_contents)
            overlap = clobberable_ids & unguarded_globals

            if overlap:
                self.findings.append(Finding(
                    type='DOM_CLOBBERING_SURFACE', severity='HIGH',
                    title=f'Superfície de DOM Clobbering: {", ".join(sorted(overlap))}',
                    description=f'O(s) identificador(es) {sorted(overlap)} são usados como variável global '
                                'em scripts sem declaração explícita (var/let/const) E existem elementos HTML '
                                'com id/name igual. Um atacante capaz de injetar HTML (mesmo sem executar '
                                '<script>, ex. via sanitização de HTML incompleta) pode sobrepor essa '
                                'variável com um elemento DOM e neutralizar/alterar a lógica de segurança '
                                'que depende dela.',
                    details={'overlapping_names': sorted(overlap)},
                    evidence=sorted(overlap),
                    remediation='Sempre declarar variáveis globais usadas em decisões de segurança '
                                '(var/let/const explícito) e nunca confiar em `window.<nome>` implícito; '
                                'usar `Object.hasOwnProperty` + checagem de tipo antes de usar um valor global.',
                    affected_url=self.target,
                ))

            return ScanResult(
                scanner_name='DOMCloakingScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=True,
                metadata={
                    'clobberable_ids_sample': sorted(clobberable_ids)[:20],
                    'unguarded_globals_found': sorted(unguarded_globals),
                    'scripts_analyzed': len(script_contents),
                },
            )
        except Exception as e:
            logger.error(f"[DOMCloaking] Erro: {e}")
            return ScanResult(
                scanner_name='DOMCloakingScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )
