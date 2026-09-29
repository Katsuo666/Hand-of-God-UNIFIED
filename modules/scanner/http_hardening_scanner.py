# -*- coding: utf-8 -*-
"""
Checks passivos de configuração HTTP: headers de segurança, cookies,
redirecionamento HTTP->HTTPS, open redirect, directory listing, modo debug
e credenciais padrão em painéis comuns. Mesmo padrão de
modules/scanner/active_scanner.py (Finding/ScanResult).
"""

import time
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from core.config import Config
from core.http_client import HTTPClient
from core.logger import get_logger
from .active_scanner import Finding, ScanResult

logger = get_logger(__name__)


class SecurityHeadersScanner:
    """Verifica ausência de cabeçalhos de segurança HTTP e fuga de versão em Server/X-Powered-By."""

    REQUIRED_HEADERS = {
        'Strict-Transport-Security': ('HSTS ausente', 'MEDIUM',
            'Adicionar Strict-Transport-Security: max-age=31536000; includeSubDomains'),
        'Content-Security-Policy': ('CSP ausente', 'MEDIUM',
            'Definir uma Content-Security-Policy restritiva'),
        'X-Content-Type-Options': ('X-Content-Type-Options ausente', 'LOW',
            'Adicionar X-Content-Type-Options: nosniff'),
        'Referrer-Policy': ('Referrer-Policy ausente', 'LOW',
            'Adicionar Referrer-Policy: no-referrer ou strict-origin-when-cross-origin'),
        'Permissions-Policy': ('Permissions-Policy ausente', 'LOW',
            'Definir Permissions-Policy restringindo APIs sensíveis'),
    }

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[SecurityHeaders] Iniciando scan: {self.target}")
        try:
            resp = self.http_client.get(self.target, timeout=Config.HTTP_TIMEOUT)
            if resp:
                headers = resp.headers
                for header, (title, severity, remediation) in self.REQUIRED_HEADERS.items():
                    if header not in headers:
                        self.findings.append(Finding(
                            type='MISSING_SECURITY_HEADER', severity=severity,
                            title=title,
                            description=f'A resposta não inclui o cabeçalho {header}.',
                            details={'header': header}, evidence=[f'{header}: ausente'],
                            remediation=remediation, affected_url=self.target,
                        ))

                server = headers.get('Server', '')
                powered_by = headers.get('X-Powered-By', '')
                if server and any(c.isdigit() for c in server):
                    self.findings.append(Finding(
                        type='SERVER_VERSION_DISCLOSURE', severity='LOW',
                        title='Versão do servidor exposta no header Server',
                        description=f'Header Server revela versão: {server}',
                        details={'server': server}, evidence=[server],
                        remediation='Remover/generalizar o header Server.',
                        affected_url=self.target,
                    ))
                if powered_by:
                    self.findings.append(Finding(
                        type='TECH_STACK_DISCLOSURE', severity='LOW',
                        title='X-Powered-By revela tecnologia do backend',
                        description=f'Header X-Powered-By: {powered_by}',
                        details={'x_powered_by': powered_by}, evidence=[powered_by],
                        remediation='Remover o header X-Powered-By.',
                        affected_url=self.target,
                    ))

            return ScanResult(
                scanner_name='SecurityHeadersScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[SecurityHeaders] Erro: {e}")
            return ScanResult(
                scanner_name='SecurityHeadersScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class CookieSecurityScanner:
    """Verifica flags Secure/HttpOnly/SameSite em cookies de sessão."""

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[CookieSecurity] Iniciando scan: {self.target}")
        try:
            resp = self.http_client.get(self.target, timeout=Config.HTTP_TIMEOUT)
            cookies_checked = 0
            if resp:
                set_cookie_headers = None
                if hasattr(resp.raw, 'headers') and hasattr(resp.raw.headers, 'getlist'):
                    set_cookie_headers = resp.raw.headers.getlist('Set-Cookie')
                if not set_cookie_headers:
                    single = resp.headers.get('Set-Cookie')
                    set_cookie_headers = [single] if single else []

                for cookie_str in set_cookie_headers:
                    cookies_checked += 1
                    name = cookie_str.split('=', 1)[0].strip()
                    low = cookie_str.lower()
                    missing = []
                    if 'secure' not in low:
                        missing.append('Secure')
                    if 'httponly' not in low:
                        missing.append('HttpOnly')
                    if 'samesite' not in low:
                        missing.append('SameSite')
                    if missing:
                        self.findings.append(Finding(
                            type='COOKIE_MISSING_FLAGS', severity='MEDIUM',
                            title=f'Cookie "{name}" sem flag(s): {", ".join(missing)}',
                            description=f'O cookie "{name}" não define {", ".join(missing)}.',
                            details={'cookie': name, 'missing_flags': missing},
                            evidence=[cookie_str],
                            remediation='Definir Secure, HttpOnly e SameSite=Strict/Lax no cookie.',
                            affected_url=self.target,
                        ))

            return ScanResult(
                scanner_name='CookieSecurityScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=True, metadata={'cookies_checked': cookies_checked},
            )
        except Exception as e:
            logger.error(f"[CookieSecurity] Erro: {e}")
            return ScanResult(
                scanner_name='CookieSecurityScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class TLSConfigScanner:
    """Verifica se HTTP puro redireciona para HTTPS (complementa SSLAnalyzer)."""

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[TLSConfig] Iniciando scan: {self.target}")
        try:
            parsed = urlparse(self.target)
            http_url = f"http://{parsed.netloc or parsed.path}"
            resp = self.http_client.get(http_url, timeout=Config.HTTP_TIMEOUT,
                                         allow_redirects=False, raise_for_status=False)
            if resp is not None:
                if resp.status_code not in (301, 302, 307, 308) or \
                        not resp.headers.get('Location', '').startswith('https://'):
                    self.findings.append(Finding(
                        type='NO_HTTPS_REDIRECT', severity='HIGH',
                        title='HTTP não redireciona para HTTPS',
                        description=f'{http_url} respondeu {resp.status_code} sem redirecionar para HTTPS.',
                        details={'status_code': resp.status_code,
                                 'location': resp.headers.get('Location', '')},
                        evidence=[f'Status: {resp.status_code}'],
                        remediation='Forçar redirect 301 de HTTP para HTTPS em todo o site.',
                        affected_url=http_url,
                    ))

            return ScanResult(
                scanner_name='TLSConfigScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[TLSConfig] Erro: {e}")
            return ScanResult(
                scanner_name='TLSConfigScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class OpenRedirectScanner:
    """Testa parâmetros comuns de redirecionamento com um destino externo."""

    REDIRECT_PARAMS = ['redirect', 'next', 'return', 'return_url', 'returnUrl',
                        'url', 'dest', 'destination', 'continue', 'redirect_uri']
    EXTERNAL_TARGET = 'https://example-external-redirect-test.invalid'

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[OpenRedirect] Iniciando scan: {self.target}")
        try:
            for param in self.REDIRECT_PARAMS:
                resp = self.http_client.get(
                    self.target, params={param: self.EXTERNAL_TARGET},
                    timeout=5, allow_redirects=False, raise_for_status=False,
                )
                if resp is None:
                    continue
                location = resp.headers.get('Location', '')
                if resp.status_code in (301, 302, 303, 307, 308) and \
                        self.EXTERNAL_TARGET.split('//')[1] in location:
                    self.findings.append(Finding(
                        type='OPEN_REDIRECT', severity='MEDIUM',
                        title=f'Open Redirect via parâmetro "{param}"',
                        description=f'O parâmetro "{param}" redireciona para um domínio externo arbitrário.',
                        details={'param': param, 'location': location},
                        evidence=[location],
                        remediation='Validar destino contra uma allowlist antes de redirecionar.',
                        affected_url=self.target,
                    ))

            return ScanResult(
                scanner_name='OpenRedirectScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[OpenRedirect] Erro: {e}")
            return ScanResult(
                scanner_name='OpenRedirectScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class DirectoryListingScanner:
    """Testa paths comuns por listagem de diretório ('Index of /')."""

    COMMON_DIRS = ['/uploads/', '/images/', '/backup/', '/files/', '/static/',
                    '/assets/', '/tmp/', '/data/', '/logs/', '/old/']
    SIGNATURES = ['index of /', '<title>directory listing', 'parent directory']

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target.rstrip('/')
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[DirectoryListing] Iniciando scan: {self.target}")
        try:
            for path in self.COMMON_DIRS:
                url = urljoin(self.target + '/', path.lstrip('/'))
                resp = self.http_client.get(url, timeout=5, raise_for_status=False)
                if resp and resp.status_code == 200:
                    low = resp.text.lower()
                    if any(sig in low for sig in self.SIGNATURES):
                        self.findings.append(Finding(
                            type='DIRECTORY_LISTING_ENABLED', severity='MEDIUM',
                            title=f'Listagem de diretório habilitada em {path}',
                            description=f'{url} expõe o conteúdo do diretório.',
                            details={'path': path}, evidence=[url],
                            remediation='Desabilitar listagem de diretório no servidor web.',
                            affected_url=url,
                        ))

            return ScanResult(
                scanner_name='DirectoryListingScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[DirectoryListing] Erro: {e}")
            return ScanResult(
                scanner_name='DirectoryListingScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class DebugModeScanner:
    """Força erros com input inválido e procura assinaturas de modo debug/stack trace."""

    SIGNATURES = {
        'django': ['django.core.exceptions', 'you\'re seeing this error because you have debug = true'],
        'flask_werkzeug': ['werkzeug debugger', 'traceback (most recent call last)'],
        'laravel': ['stack trace', 'illuminate\\\\', 'whoops'],
        'php': ['fatal error:', 'warning: ', 'on line <b>'],
        'phpinfo': ['phpinfo()', 'php version'],
        'aspnet': ['server error in', 'runtime error'],
        'node': ['at module._compile', 'nodejs.org'],
    }

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[DebugMode] Iniciando scan: {self.target}")
        try:
            probes = [
                {'__debug_probe__': "' \" <>"},
                {'id': '999999999999999999999999999999'},
                {'page': -1},
            ]
            for probe in probes:
                resp = self.http_client.get(self.target, params=probe, timeout=5, raise_for_status=False)
                if not resp:
                    continue
                low = resp.text.lower()
                for framework, sigs in self.SIGNATURES.items():
                    if any(sig in low for sig in sigs):
                        self.findings.append(Finding(
                            type='DEBUG_MODE_ENABLED', severity='HIGH',
                            title=f'Modo debug/stack trace exposto ({framework})',
                            description=f'A resposta revela um erro detalhado típico de {framework} em produção.',
                            details={'framework': framework, 'probe': probe, 'status': resp.status_code},
                            evidence=[framework],
                            remediation='Desabilitar modo debug em produção.',
                            affected_url=self.target,
                        ))
                        return self._finish(start_time)

            return self._finish(start_time)
        except Exception as e:
            logger.error(f"[DebugMode] Erro: {e}")
            return ScanResult(
                scanner_name='DebugModeScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )

    def _finish(self, start_time: float) -> ScanResult:
        return ScanResult(
            scanner_name='DebugModeScanner', target=self.target,
            findings=self.findings, execution_time=time.time() - start_time, success=True,
        )


class DefaultCredentialsScanner:
    """Tenta login em painéis conhecidos com credenciais padrão de fábrica."""

    KNOWN_PANELS = [
        {'path': '/phpmyadmin/', 'user_field': 'pma_username', 'pass_field': 'pma_password'},
        {'path': '/adminer.php', 'user_field': 'auth[username]', 'pass_field': 'auth[password]'},
        {'path': '/manager/html', 'user_field': None, 'pass_field': None},  # Tomcat: basic auth
        {'path': '/login', 'user_field': 'username', 'pass_field': 'password'},
        {'path': '/admin/login', 'user_field': 'username', 'pass_field': 'password'},
    ]

    DEFAULT_CREDS = [
        ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
        ('root', 'root'), ('root', 'toor'), ('admin', ''),
    ]

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target.rstrip('/')
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[DefaultCredentials] Iniciando scan: {self.target}")
        try:
            for panel in self.KNOWN_PANELS:
                url = urljoin(self.target + '/', panel['path'].lstrip('/'))
                check = self.http_client.get(url, timeout=5, raise_for_status=False)
                if not check or check.status_code == 404:
                    continue

                for user, pwd in self.DEFAULT_CREDS:
                    if panel['user_field'] is None:
                        resp = self.http_client.get(url, timeout=5, auth=(user, pwd), raise_for_status=False)
                    else:
                        resp = self.http_client.post(
                            url, data={panel['user_field']: user, panel['pass_field']: pwd},
                            timeout=5, raise_for_status=False,
                        )
                    if resp and resp.status_code in (200, 302) and \
                            'invalid' not in resp.text.lower() and 'incorrect' not in resp.text.lower():
                        self.findings.append(Finding(
                            type='DEFAULT_CREDENTIALS_ACCEPTED', severity='CRITICAL',
                            title=f'Painel {panel["path"]} pode aceitar credenciais padrão',
                            description=f'Tentativa com {user}/{pwd} em {url} retornou {resp.status_code} '
                                        'sem indicação clara de falha (verificar manualmente).',
                            details={'path': panel['path'], 'user': user, 'status': resp.status_code},
                            evidence=[f'{user}:{pwd}'],
                            remediation='Trocar credenciais padrão e desabilitar painéis não usados.',
                            affected_url=url,
                        ))
                        break  # já achou indício suficiente para este painel

            return ScanResult(
                scanner_name='DefaultCredentialsScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[DefaultCredentials] Erro: {e}")
            return ScanResult(
                scanner_name='DefaultCredentialsScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )
