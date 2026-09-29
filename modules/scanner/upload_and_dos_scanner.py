# -*- coding: utf-8 -*-
"""
File upload sem restrição, mass assignment, e probes seguros (timeout curto,
payload pequeno) para ReDoS e XML bomb — não enviam payload capaz de travar
o servidor por muito tempo, o próprio timeout do request limita o dano.
Também um check passivo de headers de cache em respostas sensíveis.
"""

import time
from typing import Any, Dict, List
from urllib.parse import urlparse

from core.config import Config
from core.http_client import HTTPClient
from core.logger import get_logger
from modules.recon.web_crawler import WebCrawler
from .active_scanner import Finding, ScanResult

logger = get_logger(__name__)

DANGEROUS_EXTENSIONS = ['php', 'jsp', 'asp', 'aspx', 'sh']


class FileUploadScanner:
    """Descobre formulários de upload via crawler e tenta subir arquivos executáveis disfarçados."""

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def _discover_upload_forms(self) -> List[Dict[str, Any]]:
        forms = []
        try:
            page = WebCrawler(http_client=self.http_client).crawl_page(self.target)
            for form in page.get('forms', []):
                names = [i.lower() for i in form.get('inputs', []) if i]
                if any('file' in n or 'upload' in n or 'image' in n or 'photo' in n for n in names):
                    forms.append(form)
        except Exception as e:
            logger.debug(f"[FileUpload] Crawler falhou: {e}")
        return forms

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[FileUpload] Iniciando scan: {self.target}")
        try:
            forms = self._discover_upload_forms()
            for form in forms:
                action = form.get('action') or self.target
                field = next((i for i in form.get('inputs', []) if 'file' in i.lower()), 'file')

                for ext in DANGEROUS_EXTENSIONS:
                    filename = f'mao_de_deus_test.{ext}'
                    payload = b'<?php echo "mao-de-deus-upload-test"; ?>' if ext in ('php',) \
                        else b'mao-de-deus-upload-test'
                    files = {field: (filename, payload, 'image/png')}  # Content-Type falso de propósito
                    resp = self.http_client.post(action, files=files, timeout=10, raise_for_status=False)
                    if resp and resp.status_code in (200, 201):
                        self.findings.append(Finding(
                            type='UNRESTRICTED_FILE_UPLOAD', severity='CRITICAL',
                            title=f'Upload sem restrição aceitou .{ext} disfarçado de imagem',
                            description=f'O endpoint {action} aceitou um arquivo .{ext} com Content-Type '
                                        'falso de imagem, sem validar o conteúdo real.',
                            details={'extension': ext, 'status': resp.status_code}, evidence=[filename],
                            remediation='Validar tipo real do arquivo (magic bytes), não extensão/Content-Type; '
                                        'servir uploads fora do diretório executável.',
                            affected_url=action,
                        ))
                        break

            return ScanResult(
                scanner_name='FileUploadScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=True, metadata={'upload_forms_found': len(forms)},
            )
        except Exception as e:
            logger.error(f"[FileUpload] Erro: {e}")
            return ScanResult(
                scanner_name='FileUploadScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class MassAssignmentTester:
    """Envia campos extras privilegiados (is_admin/role) em endpoints JSON de criação/update."""

    EXTRA_FIELDS = {'is_admin': True, 'isAdmin': True, 'admin': True, 'role': 'admin'}

    def __init__(self, target: str, http_client: HTTPClient = None, base_payload: Dict[str, Any] = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.base_payload = base_payload or {'name': 'mao_de_deus_test', 'email': 'test@example.com'}
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[MassAssignment] Iniciando scan: {self.target}")
        try:
            for field, value in self.EXTRA_FIELDS.items():
                body = dict(self.base_payload)
                body[field] = value
                resp = self.http_client.post(self.target, json=body, timeout=8, raise_for_status=False)
                if not resp or resp.status_code not in (200, 201):
                    continue
                try:
                    data = resp.json()
                except Exception:
                    continue
                if isinstance(data, dict) and data.get(field) == value:
                    self.findings.append(Finding(
                        type='MASS_ASSIGNMENT', severity='HIGH',
                        title=f'Mass Assignment via campo "{field}"',
                        description=f'O campo privilegiado "{field}" enviado no body foi aceito e refletido '
                                    'na resposta, sugerindo ausência de allowlist de campos.',
                        details={'field': field, 'value': value}, evidence=[str({field: value})],
                        remediation='Usar allowlist explícita de campos aceitos (DTO), nunca bind direto do body.',
                        affected_url=self.target,
                    ))

            return ScanResult(
                scanner_name='MassAssignmentTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[MassAssignment] Erro: {e}")
            return ScanResult(
                scanner_name='MassAssignmentTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class ReDoSProbe:
    """Mede tempo de resposta com strings conhecidas por explodir regex mal desenhadas.

    ponytail: usa timeout curto e um único payload moderado por parâmetro —
    não tenta encontrar o pior caso exato, só sinaliza indício de ReDoS.
    """

    PAYLOAD_PARAM_VALUE = 'a' * 35 + '!'
    BASELINE_VALUE = 'a' * 35
    PROBE_TIMEOUT = 6

    def __init__(self, target: str, http_client: HTTPClient = None, params: List[str] = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.params = params or ['q', 'search', 'email', 'input', 'value']
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[ReDoS] Iniciando scan: {self.target}")
        try:
            for param in self.params:
                t0 = time.time()
                self.http_client.get(self.target, params={param: self.BASELINE_VALUE},
                                      timeout=self.PROBE_TIMEOUT, raise_for_status=False)
                baseline = time.time() - t0

                t0 = time.time()
                self.http_client.get(self.target, params={param: self.PAYLOAD_PARAM_VALUE},
                                      timeout=self.PROBE_TIMEOUT, raise_for_status=False)
                elapsed = time.time() - t0

                if elapsed - baseline > 3:
                    self.findings.append(Finding(
                        type='POSSIBLE_REDOS', severity='MEDIUM',
                        title=f'Possível ReDoS em parâmetro "{param}"',
                        description=f'Entrada com repetição em "{param}" atrasou a resposta em '
                                    f'{elapsed - baseline:.1f}s a mais que a baseline (probe controlado).',
                        details={'param': param, 'delay': elapsed - baseline},
                        evidence=[self.PAYLOAD_PARAM_VALUE],
                        remediation='Revisar regex usada para validar esse campo; evitar quantificadores aninhados.',
                        affected_url=self.target,
                    ))

            return ScanResult(
                scanner_name='ReDoSProbe', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[ReDoS] Erro: {e}")
            return ScanResult(
                scanner_name='ReDoSProbe', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class XMLBombProbe:
    """Envia uma versão pequena e controlada de 'billion laughs' (poucos níveis) com timeout curto."""

    # Apenas 4 níveis (~10^4 expansões), não a bomba completa — suficiente para
    # detectar ausência de limite de expansão de entidades sem risco real ao alvo.
    SMALL_BILLION_LAUGHS = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE lolz ['
        '<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
        ']>'
        '<lolz>&lol4;</lolz>'
    )
    PROBE_TIMEOUT = 6

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[XMLBomb] Iniciando scan: {self.target}")
        try:
            for content_type in ('application/xml', 'text/xml'):
                t0 = time.time()
                resp = self.http_client.post(
                    self.target, data=self.SMALL_BILLION_LAUGHS,
                    headers={'Content-Type': content_type},
                    timeout=self.PROBE_TIMEOUT, raise_for_status=False,
                )
                elapsed = time.time() - t0

                if resp is None and elapsed >= self.PROBE_TIMEOUT - 0.5:
                    self.findings.append(Finding(
                        type='POSSIBLE_XML_BOMB', severity='MEDIUM',
                        title='Parser XML pode ser vulnerável a entity expansion (XML bomb)',
                        description=f'Um payload controlado de entidades aninhadas (Content-Type: {content_type}) '
                                    'causou timeout, sugerindo ausência de limite de expansão.',
                        details={'content_type': content_type, 'elapsed': elapsed},
                        evidence=['DOCTYPE com entidades aninhadas (4 níveis)'],
                        remediation='Desabilitar DTDs externas e limitar expansão de entidades no parser XML.',
                        affected_url=self.target,
                    ))
                    break

            return ScanResult(
                scanner_name='XMLBombProbe', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[XMLBomb] Erro: {e}")
            return ScanResult(
                scanner_name='XMLBombProbe', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class CacheHeaderScanner:
    """Verifica Cache-Control/Vary em respostas potencialmente sensíveis (check passivo)."""

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[CacheHeaders] Iniciando scan: {self.target}")
        try:
            resp = self.http_client.get(self.target, timeout=Config.HTTP_TIMEOUT, raise_for_status=False)
            if resp:
                cache_control = resp.headers.get('Cache-Control', '').lower()
                has_auth_cookie = any('session' in c.lower() or 'auth' in c.lower() or 'token' in c.lower()
                                       for c in resp.cookies.keys())
                if has_auth_cookie and 'no-store' not in cache_control and 'private' not in cache_control:
                    self.findings.append(Finding(
                        type='SENSITIVE_RESPONSE_CACHEABLE', severity='MEDIUM',
                        title='Resposta com cookie de sessão sem Cache-Control restritivo',
                        description='A resposta define um cookie de sessão/autenticação mas não envia '
                                    'Cache-Control: no-store/private, podendo ser armazenada por caches/CDNs.',
                        details={'cache_control': cache_control or '(ausente)'},
                        evidence=[cache_control or '(ausente)'],
                        remediation='Adicionar Cache-Control: no-store, private em respostas autenticadas/sensíveis.',
                        affected_url=self.target,
                    ))

            return ScanResult(
                scanner_name='CacheHeaderScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[CacheHeaders] Erro: {e}")
            return ScanResult(
                scanner_name='CacheHeaderScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )
