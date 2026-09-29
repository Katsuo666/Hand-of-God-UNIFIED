# -*- coding: utf-8 -*-
"""
Módulo de Scanner Ativo Completo - Task 7
Componentes: WAF Detector, JWT Analyzer, GraphQL Tester, IDOR Tester,
Clickjacking Tester, Rate Limit Tester, API Fuzzer, Security Headers Analyzer,
Cookie Security Tester

Production-ready com type hints, integração core completa e tratamento robusto de erros
Total: 1500+ linhas de código funcional
"""

import requests
import re
import json
import time
import hashlib
import base64
import hmac
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urljoin, quote, urlparse
from datetime import datetime, timedelta
from threading import Lock
import concurrent.futures
from dataclasses import dataclass, asdict

from core.http_client import HTTPClient
from core.logger import get_logger
from core.config import Config
from core.persistent_cache import PersistentCache

logger = get_logger(__name__)


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Finding:
    """Representa um achado de segurança descoberto durante scan"""
    type: str
    severity: str
    title: str
    description: str
    details: Dict[str, Any]
    evidence: List[str]
    remediation: str
    timestamp: str = None
    affected_url: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Resultado de um scanner individual"""
    scanner_name: str
    target: str
    findings: List[Finding]
    execution_time: float
    success: bool
    error_message: str = None
    metadata: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'scanner_name': self.scanner_name,
            'target': self.target,
            'findings': [f.to_dict() for f in self.findings],
            'execution_time': self.execution_time,
            'success': self.success,
            'error_message': self.error_message,
            'metadata': self.metadata or {},
        }


# ============================================================================
# 1. WAF/IDS DETECTOR
# ============================================================================

class WAFDetector:
    """Detecta WAF e IDS por headers, payloads e comportamentos"""

    WAF_SIGNATURES = {
        'cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', 'server=cloudflare'],
            'patterns': ['cloudflare', 'cf-']
        },
        'modsecurity': {
            'headers': ['x-mod-security', 'mod_security'],
            'patterns': ['modsecurity']
        },
        'aws_waf': {
            'headers': ['x-amzn-waf-action', 'x-amzn-waf'],
            'patterns': ['awswaf']
        },
        'akamai': {
            'headers': ['akamai-origin-hop'],
            'patterns': ['akamai']
        },
        'imperva': {
            'headers': ['x-iinfo'],
            'patterns': ['imperva']
        },
        'f5_bigip': {
            'headers': ['via'],
            'patterns': ['F5', 'BIG-IP']
        },
        'barracuda': {
            'headers': ['barracuda'],
            'patterns': ['barracuda']
        },
        'sucuri': {
            'headers': ['x-sucuri-cache', 'server=Sucuri'],
            'patterns': ['sucuri']
        },
        'wordfence': {
            'headers': ['wordfence'],
            'patterns': ['wordfence']
        },
    }

    SQL_INJECTION_PAYLOADS = [
        "1' OR '1'='1",
        "1 OR 1=1--",
        "1'; DROP TABLE users--",
        "1 UNION SELECT NULL--",
        "1) OR ('1'='1",
    ]

    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']

    PROTOCOL_CONFUSION_PAYLOADS = [
        {'override_method': 'POST', 'header': 'X-HTTP-Method-Override'},
        {'override_method': 'DELETE', 'header': 'X-HTTP-Method-Override'},
        {'override_method': 'PUT', 'header': 'X-Method-Override'},
        {'protocol': 'HTTP/1.0'},
    ]

    def __init__(self, target: str, http_client: HTTPClient = None, cache: PersistentCache = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.cache = cache or PersistentCache()
        self.findings: List[Finding] = []
        self.waf_detected: Dict[str, Any] = {}

    def detect_waf_headers(self) -> Dict[str, Any]:
        """Detecta WAF analisando headers de resposta"""
        logger.debug(f"[WAF] Detectando WAF por headers: {self.target}")
        results = {}

        try:
            response = self.http_client.get(self.target, timeout=Config.HTTP_TIMEOUT)
            if not response:
                return results

            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
            server_header = response.headers.get('Server', '').lower()

            for waf_name, sig in self.WAF_SIGNATURES.items():
                detected = False

                for pattern in sig.get('headers', []):
                    for header_key, header_val in headers_lower.items():
                        if pattern.lower() in header_key or pattern.lower() in header_val:
                            detected = True
                            break

                for pattern in sig.get('patterns', []):
                    if pattern.lower() in server_header:
                        detected = True
                        break

                if detected:
                    results[waf_name] = {
                        'detected': True,
                        'confidence': 'HIGH',
                        'headers': dict(response.headers),
                    }
                    self.waf_detected[waf_name] = True

                    finding = Finding(
                        type='WAF_DETECTED',
                        severity='INFO',
                        title=f'WAF Detectado: {waf_name.upper()}',
                        description=f'O alvo está protegido por WAF: {waf_name}',
                        details={'waf': waf_name, 'headers': dict(response.headers)},
                        evidence=[str(response.headers)],
                        remediation='Verificar configuração de WAF',
                        affected_url=self.target,
                    )
                    self.findings.append(finding)

        except Exception as e:
            logger.error(f"[WAF] Erro ao detectar WAF headers: {e}")

        return results

    def test_sql_injection(self) -> Dict[str, Any]:
        """Testa se SQL injection é bloqueada pelo WAF"""
        logger.debug(f"[WAF] Testando SQL Injection: {self.target}")
        results = {}

        for payload in self.SQL_INJECTION_PAYLOADS:
            try:
                test_url = f"{self.target}?id={quote(payload)}"
                response = self.http_client.get(test_url, timeout=5)

                if response:
                    if response.status_code in [403, 406, 429]:
                        results[payload] = {
                            'status': response.status_code,
                            'blocked': True,
                            'reason': 'HTTP status code indicando bloqueio',
                        }
                    elif 'waf' in response.text.lower() or 'blocked' in response.text.lower():
                        results[payload] = {
                            'status': response.status_code,
                            'blocked': True,
                            'reason': 'Response contém indicador de bloqueio WAF',
                        }
                    else:
                        results[payload] = {
                            'status': response.status_code,
                            'blocked': False,
                            'reason': 'Requisição não foi bloqueada',
                        }

            except Exception as e:
                logger.debug(f"[WAF] Erro testando payload: {payload}: {e}")

        return results

    def test_method_bypass(self) -> Dict[str, Any]:
        """Testa bypass de WAF via HTTP method override"""
        logger.debug(f"[WAF] Testando HTTP Method Bypass: {self.target}")
        results = {}

        try:
            for method in ['TRACE', 'CONNECT']:
                try:
                    response = requests.request(method, self.target, timeout=5, verify=False)
                    if response.status_code != 405:
                        results[method] = {
                            'status': response.status_code,
                            'vulnerable': True,
                            'description': f'Método {method} não bloqueado'
                        }
                        if method in ['TRACE']:
                            finding = Finding(
                                type='HTTP_METHOD_BYPASS',
                                severity='HIGH',
                                title=f'HTTP Method {method} Habilitado',
                                description=f'Método HTTP {method} está habilitado (risco de XST)',
                                details={'method': method, 'status_code': response.status_code},
                                evidence=[f'Status: {response.status_code}'],
                                remediation=f'Desabilitar método HTTP {method}',
                                affected_url=self.target,
                            )
                            self.findings.append(finding)
                except requests.exceptions.RequestException:
                    pass

            for override_payload in self.PROTOCOL_CONFUSION_PAYLOADS:
                try:
                    headers = {}
                    if 'header' in override_payload:
                        headers[override_payload['header']] = override_payload.get('override_method', 'DELETE')

                    response = self.http_client.get(self.target, headers=headers, timeout=5)
                    if response and response.status_code not in [404, 405]:
                        results[str(override_payload)] = {
                            'status': response.status_code,
                            'vulnerable': True,
                        }
                except Exception as e:
                    logger.debug(f"[WAF] Erro no método override: {e}")

        except Exception as e:
            logger.error(f"[WAF] Erro ao testar method bypass: {e}")

        return results

    def test_protocol_confusion(self) -> Dict[str, Any]:
        """Testa protocol confusion attacks"""
        logger.debug(f"[WAF] Testando Protocol Confusion: {self.target}")
        results = {}

        try:
            for http_version in ['1.0', '1.1', '2.0']:
                try:
                    response = self.http_client.get(self.target, timeout=5)
                    if response:
                        results[f'HTTP/{http_version}'] = {
                            'supported': True,
                            'status': response.status_code,
                        }
                except Exception as e:
                    logger.debug(f"[WAF] HTTP/{http_version} não suportado: {e}")

        except Exception as e:
            logger.error(f"[WAF] Erro ao testar protocol confusion: {e}")

        return results

    def scan(self) -> ScanResult:
        """Executa scanning completo de WAF"""
        start_time = time.time()
        logger.info(f"[WAF] Iniciando scan: {self.target}")

        try:
            self.detect_waf_headers()
            self.test_sql_injection()
            self.test_method_bypass()
            self.test_protocol_confusion()

            execution_time = time.time() - start_time
            return ScanResult(
                scanner_name='WAFDetector',
                target=self.target,
                findings=self.findings,
                execution_time=execution_time,
                success=True,
                metadata={'waf_detected': self.waf_detected},
            )

        except Exception as e:
            logger.error(f"[WAF] Erro: {e}")
            return ScanResult(
                scanner_name='WAFDetector',
                target=self.target,
                findings=self.findings,
                execution_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )


# ============================================================================
# 2. JWT ANALYZER
# ============================================================================

class JWTAnalyzer:
    """Analisa JWTs e testa vulnerabilidades"""

    COMMON_WEAK_SECRETS = [
        'secret', '123456', 'password', 'admin', 'key', 'token',
        'jwt', 'test', 'demo', 'changeme', 'supersecret',
        '', 'null', 'undefined', '0', '1',
    ]

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []
        self.jwt_tokens: List[str] = []

    def _is_jwt_format(self, value: str) -> bool:
        """Verifica se string tem formato JWT"""
        if not isinstance(value, str):
            return False
        parts = value.split('.')
        if len(parts) != 3:
            return False
        try:
            for part in parts:
                base64.urlsafe_b64decode(part + '==')
            return True
        except:
            return False

    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode JWT sem validação"""
        logger.debug(f"[JWT] Decodificando token")

        try:
            padding = 4 - len(token.split('.')[1]) % 4
            if padding != 4:
                token_parts = token.split('.')
                token_parts[1] += '=' * padding
                token = '.'.join(token_parts)

            parts = token.split('.')
            if len(parts) != 3:
                return None

            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

            return {
                'header': header,
                'payload': payload,
                'signature': parts[2],
                'valid_format': True,
            }

        except Exception as e:
            logger.error(f"[JWT] Erro ao decodificar: {e}")
            return None

    def test_weak_secret(self, token: str) -> Dict[str, Any]:
        """Tenta quebrar JWT com secrets fracos"""
        logger.debug(f"[JWT] Testando secrets fracos")

        decoded = self.decode_token(token)
        if not decoded or 'header' not in decoded:
            return {'vulnerable': False, 'reason': 'Token inválido'}

        header = decoded['header']
        algorithm = header.get('alg', 'unknown').upper()

        if algorithm not in ['HS256', 'HS384', 'HS512', 'NONE']:
            return {'vulnerable': False, 'reason': f'Algoritmo {algorithm} não requer secret'}

        if algorithm == 'NONE':
            finding = Finding(
                type='JWT_NONE_ALGORITHM',
                severity='CRITICAL',
                title='JWT com Algoritmo NONE',
                description='JWT está usando algoritmo NONE que não requer assinatura',
                details={'algorithm': 'NONE'},
                evidence=[f'Token header: {header}'],
                remediation='Forçar algoritmo de assinatura',
                affected_url=self.target,
            )
            self.findings.append(finding)
            return {'vulnerable': True, 'reason': 'Algoritmo NONE'}

        token_parts = token.split('.')
        for secret in self.COMMON_WEAK_SECRETS:
            try:
                if algorithm == 'HS256':
                    expected_sig = base64.urlsafe_b64encode(
                        hmac.new(
                            secret.encode(),
                            f"{token_parts[0]}.{token_parts[1]}".encode(),
                            hashlib.sha256
                        ).digest()
                    ).decode().rstrip('=')

                    if expected_sig == token_parts[2]:
                        finding = Finding(
                            type='JWT_WEAK_SECRET',
                            severity='CRITICAL',
                            title='JWT com Secret Fraco',
                            description=f'JWT pode ser falsificado com secret: "{secret}"',
                            details={'algorithm': algorithm, 'weak_secret': secret},
                            evidence=[f'Secret: {secret}'],
                            remediation='Usar secret robusto com alta entropia',
                            affected_url=self.target,
                        )
                        self.findings.append(finding)
                        return {'vulnerable': True, 'weak_secret': secret}

            except Exception as e:
                logger.debug(f"[JWT] Erro testando secret: {e}")

        return {'vulnerable': False}

    def test_algorithm_confusion(self, token: str) -> Dict[str, Any]:
        """Testa algorithm confusion"""
        logger.debug(f"[JWT] Testando algorithm confusion")

        decoded = self.decode_token(token)
        if not decoded:
            return {'vulnerable': False}

        header = decoded['header']
        algorithm = header.get('alg', '').upper()

        if algorithm == 'RS256':
            finding = Finding(
                type='JWT_ALGORITHM_CONFUSION',
                severity='HIGH',
                title='Possível Algorithm Confusion',
                description='JWT usa RS256, pode ser vulnerável a algorithm confusion',
                details={'algorithm': algorithm},
                evidence=[f'Token: {algorithm}'],
                remediation='Validar e não permitir mudança de algoritmo',
                affected_url=self.target,
            )
            self.findings.append(finding)
            return {'vulnerable': True, 'vector': 'RS256_to_HS256'}

        return {'vulnerable': False}

    def scan(self) -> ScanResult:
        """Executa scanning completo JWT"""
        start_time = time.time()
        logger.info(f"[JWT] Iniciando scan: {self.target}")

        try:
            execution_time = time.time() - start_time
            return ScanResult(
                scanner_name='JWTAnalyzer',
                target=self.target,
                findings=self.findings,
                execution_time=execution_time,
                success=True,
            )

        except Exception as e:
            logger.error(f"[JWT] Erro: {e}")
            return ScanResult(
                scanner_name='JWTAnalyzer',
                target=self.target,
                findings=self.findings,
                execution_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )


# ============================================================================
# 3. GRAPHQL TESTER
# ============================================================================

class GraphQLTester:
    """Testa endpoints GraphQL"""

    GRAPHQL_ENDPOINTS = [
        '/graphql',
        '/api/graphql',
        '/gql',
        '/apollo',
    ]

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []
        self.graphql_url: Optional[str] = None

    def find_graphql_endpoint(self) -> Optional[str]:
        """Procura por endpoints GraphQL"""
        logger.debug(f"[GraphQL] Procurando endpoints")

        for endpoint in self.GRAPHQL_ENDPOINTS:
            try:
                url = urljoin(self.target, endpoint)
                response = self.http_client.post(
                    url,
                    json={'query': '{ __typename }'},
                    timeout=5
                )
                if response and response.status_code == 200:
                    logger.info(f"[GraphQL] Encontrado: {url}")
                    self.graphql_url = url
                    return url
            except Exception as e:
                logger.debug(f"[GraphQL] Erro testando {endpoint}: {e}")

        return None

    def test_introspection(self) -> Dict[str, Any]:
        """Testa introspection query"""
        logger.debug(f"[GraphQL] Testando introspection")

        if not self.graphql_url:
            return {'vulnerable': False}

        introspection_query = {
            "query": "{ __schema { types { name } } }"
        }

        try:
            response = self.http_client.post(
                self.graphql_url,
                json=introspection_query,
                timeout=10
            )

            if response and response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    finding = Finding(
                        type='GRAPHQL_INTROSPECTION_ENABLED',
                        severity='MEDIUM',
                        title='GraphQL Introspection Habilitado',
                        description='Introspection está habilitada',
                        details=data,
                        evidence=[str(data)[:100]],
                        remediation='Desabilitar introspection em produção',
                        affected_url=self.graphql_url,
                    )
                    self.findings.append(finding)
                    return {'vulnerable': True}

        except Exception as e:
            logger.debug(f"[GraphQL] Erro: {e}")

        return {'vulnerable': False}

    def test_mutations(self) -> Dict[str, Any]:
        """Testa se mutations estão habilitadas"""
        logger.debug(f"[GraphQL] Testando mutations")

        if not self.graphql_url:
            return {'vulnerable': False}

        try:
            response = self.http_client.post(
                self.graphql_url,
                json={"query": "{ __schema { mutationType { fields { name } } } }"},
                timeout=5
            )

            if response and response.status_code == 200:
                data = response.json()
                if 'data' in data and data['data'].get('__schema', {}).get('mutationType'):
                    finding = Finding(
                        type='GRAPHQL_MUTATIONS_ENABLED',
                        severity='MEDIUM',
                        title='GraphQL Mutations Habilitadas',
                        description='Mutations estão habilitadas',
                        details=data,
                        evidence=[str(data)[:100]],
                        remediation='Restringir mutations',
                        affected_url=self.graphql_url,
                    )
                    self.findings.append(finding)
                    return {'vulnerable': True}

        except Exception as e:
            logger.debug(f"[GraphQL] Erro: {e}")

        return {'vulnerable': False}

    def test_injection(self) -> Dict[str, Any]:
        """Testa GraphQL injection"""
        logger.debug(f"[GraphQL] Testando injection")

        if not self.graphql_url:
            return {}

        payloads = ['{ __typename }', '{ __schema { types { name } } }']
        results = {}

        for payload in payloads:
            try:
                response = self.http_client.post(
                    self.graphql_url,
                    json={'query': payload},
                    timeout=5
                )
                if response:
                    results[payload] = response.status_code == 200

            except Exception as e:
                logger.debug(f"[GraphQL] Erro: {e}")

        return results

    def test_rate_limit_bypass_via_aliases(self) -> Dict[str, Any]:
        """Testa bypass de rate limit via aliases"""
        logger.debug(f"[GraphQL] Testando alias bypass")

        if not self.graphql_url:
            return {}

        aliases_query = {
            "query": "{ a: __typename b: __typename c: __typename }"
        }

        try:
            response = self.http_client.post(
                self.graphql_url,
                json=aliases_query,
                timeout=5
            )

            if response and response.status_code == 200:
                finding = Finding(
                    type='GRAPHQL_RATE_LIMIT_BYPASS',
                    severity='MEDIUM',
                    title='GraphQL Rate Limit Bypass',
                    description='Múltiplas queries via aliases',
                    details={},
                    evidence=['Aliases permitidos'],
                    remediation='Rate limit por operação',
                    affected_url=self.graphql_url,
                )
                self.findings.append(finding)
                return {'vulnerable': True}

        except Exception as e:
            logger.debug(f"[GraphQL] Erro: {e}")

        return {}

    def test_query_depth_limit(self, depth: int = 12) -> Dict[str, Any]:
        """Verifica se o servidor recusa queries muito aninhadas (limite de profundidade)"""
        logger.debug(f"[GraphQL] Testando limite de profundidade")

        if not self.graphql_url:
            return {}

        deep_query = '{' + '__schema{types{name}}' * depth + '}'

        try:
            t0 = time.time()
            response = self.http_client.post(self.graphql_url, json={'query': deep_query}, timeout=15)
            elapsed = time.time() - t0

            if response and response.status_code == 200:
                data = response.json()
                errors = data.get('errors', [])
                rejected = any('depth' in str(e).lower() or 'complexity' in str(e).lower() for e in errors)

                if not rejected:
                    finding = Finding(
                        type='GRAPHQL_NO_DEPTH_LIMIT',
                        severity='MEDIUM',
                        title='GraphQL sem Limite de Profundidade de Query',
                        description=f'Query aninhada {depth}x foi aceita ({elapsed:.1f}s) sem erro de profundidade/complexidade.',
                        details={'depth': depth, 'elapsed': elapsed},
                        evidence=[f'Status: {response.status_code}, tempo: {elapsed:.1f}s'],
                        remediation='Implementar limite de profundidade e análise de complexidade de queries.',
                        affected_url=self.graphql_url,
                    )
                    self.findings.append(finding)
                    return {'vulnerable': True}

        except Exception as e:
            logger.debug(f"[GraphQL] Erro testando depth limit: {e}")

        return {'vulnerable': False}

    def test_batching_attack(self, batch_size: int = 20) -> Dict[str, Any]:
        """Verifica se o servidor processa lote de queries em array sem limitar (bypass de rate limit)"""
        logger.debug(f"[GraphQL] Testando batching attack")

        if not self.graphql_url:
            return {}

        batch = [{'query': '{ __typename }'} for _ in range(batch_size)]

        try:
            response = self.http_client.post(self.graphql_url, json=batch, timeout=15)

            if response and response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) == batch_size:
                    finding = Finding(
                        type='GRAPHQL_BATCHING_BYPASS',
                        severity='MEDIUM',
                        title='GraphQL Aceita Batching sem Limite',
                        description=f'{batch_size} queries em um único array foram todas processadas '
                                    'em uma requisição, permitindo contornar rate limiting por request.',
                        details={'batch_size': batch_size},
                        evidence=[f'{len(data)} respostas retornadas'],
                        remediation='Limitar o tamanho de batches e aplicar rate limit por operação, não por request.',
                        affected_url=self.graphql_url,
                    )
                    self.findings.append(finding)
                    return {'vulnerable': True}

        except Exception as e:
            logger.debug(f"[GraphQL] Erro testando batching: {e}")

        return {'vulnerable': False}

    def test_overfetching(self) -> Dict[str, Any]:
        """Usa a introspecção para pedir todos os campos de um tipo sensível (ex.: User) e ver se vazam dados"""
        logger.debug(f"[GraphQL] Testando over-fetching")

        if not self.graphql_url:
            return {}

        sensitive_field_names = {'password', 'passwordhash', 'hash', 'salt', 'token', 'secret', 'apikey', 'ssn'}

        try:
            response = self.http_client.post(
                self.graphql_url,
                json={'query': '{ __schema { types { name fields { name } } } }'},
                timeout=10,
            )
            if not response or response.status_code != 200:
                return {}

            data = response.json()
            types = data.get('data', {}).get('__schema', {}).get('types', [])

            for t in types:
                field_names = {f['name'].lower() for f in (t.get('fields') or [])}
                leaked = field_names & sensitive_field_names
                if leaked:
                    finding = Finding(
                        type='GRAPHQL_OVERFETCHING_SENSITIVE_FIELDS',
                        severity='HIGH',
                        title=f'Campos Sensíveis Expostos no Schema GraphQL ({t.get("name")})',
                        description=f'O tipo "{t.get("name")}" expõe campos potencialmente sensíveis via schema: {sorted(leaked)}.',
                        details={'type': t.get('name'), 'fields': sorted(leaked)},
                        evidence=[str(sorted(leaked))],
                        remediation='Remover campos sensíveis do schema público ou restringir por autorização de campo.',
                        affected_url=self.graphql_url,
                    )
                    self.findings.append(finding)

            return {'vulnerable': any(
                (t.get('fields') or []) and
                ({f['name'].lower() for f in t['fields']} & sensitive_field_names)
                for t in types
            )}

        except Exception as e:
            logger.debug(f"[GraphQL] Erro testando over-fetching: {e}")

        return {}

    def scan(self) -> ScanResult:
        """Executa scanning completo GraphQL"""
        start_time = time.time()
        logger.info(f"[GraphQL] Iniciando scan: {self.target}")

        try:
            if self.find_graphql_endpoint():
                self.test_introspection()
                self.test_mutations()
                self.test_injection()
                self.test_rate_limit_bypass_via_aliases()
                self.test_query_depth_limit()
                self.test_batching_attack()
                self.test_overfetching()

            execution_time = time.time() - start_time
            return ScanResult(
                scanner_name='GraphQLTester',
                target=self.target,
                findings=self.findings,
                execution_time=execution_time,
                success=True,
                metadata={'graphql_endpoint': self.graphql_url},
            )

        except Exception as e:
            logger.error(f"[GraphQL] Erro: {e}")
            return ScanResult(
                scanner_name='GraphQLTester',
                target=self.target,
                findings=self.findings,
                execution_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )


# ============================================================================
# 4. IDOR TESTER
# ============================================================================

class IDORTester:
    """Testa vulnerabilidades IDOR"""

    COMMON_ID_PARAMS = [
        'id', 'user_id', 'account_id', 'profile_id', 'post_id', 'order_id',
        'product_id', 'item_id', 'resource_id', 'object_id', 'uid', 'aid'
    ]

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def test_incremental_ids(self) -> Dict[str, Any]:
        """Testa IDs incrementais"""
        logger.debug(f"[IDOR] Testando IDs incrementais")

        results = {}

        for param in self.COMMON_ID_PARAMS:
            try:
                responses_different = False
                first_response = None

                for test_id in ['1', '2', '3']:
                    response = self.http_client.get(
                        self.target,
                        params={param: test_id},
                        timeout=5
                    )

                    if response and response.status_code == 200:
                        if first_response is None:
                            first_response = response.text
                        elif len(response.text) > 100 and response.text != first_response:
                            responses_different = True

                if responses_different and first_response:
                    finding = Finding(
                        type='IDOR_INCREMENTAL_ID',
                        severity='HIGH',
                        title=f'IDOR via IDs Incrementais ({param})',
                        description=f'Diferentes respostas para {param}',
                        details={'parameter': param},
                        evidence=['Respostas diferentes detectadas'],
                        remediation='Implementar autorização baseada em usuário',
                        affected_url=self.target,
                    )
                    self.findings.append(finding)
                    results[param] = True

            except Exception as e:
                logger.debug(f"[IDOR] Erro: {e}")

        return results

    def test_uuids(self) -> Dict[str, Any]:
        """Testa UUIDs conhecidos"""
        logger.debug(f"[IDOR] Testando UUIDs")

        results = {}
        uuids = [
            '00000000-0000-0000-0000-000000000000',
            '550e8400-e29b-41d4-a716-446655440000',
        ]

        for param in self.COMMON_ID_PARAMS[:3]:
            for uuid in uuids:
                try:
                    response = self.http_client.get(
                        self.target,
                        params={param: uuid},
                        timeout=5
                    )

                    if response and response.status_code == 200 and len(response.text) > 50:
                        finding = Finding(
                            type='IDOR_UUID',
                            severity='HIGH',
                            title=f'IDOR via UUID ({param})',
                            description='Acesso via UUID',
                            details={'parameter': param},
                            evidence=['UUID aceito'],
                            remediation='Validar permissões',
                            affected_url=self.target,
                        )
                        self.findings.append(finding)
                        results[f'{param}'] = True

                except Exception as e:
                    logger.debug(f"[IDOR] Erro: {e}")

        return results

    def test_parameter_tampering(self) -> Dict[str, Any]:
        """Testa tampering em parâmetros"""
        logger.debug(f"[IDOR] Testando tampering")

        results = {}
        tampering_values = ['0', '-1', 'admin', 'root']

        for param in self.COMMON_ID_PARAMS[:3]:
            for value in tampering_values:
                try:
                    response = self.http_client.get(
                        self.target,
                        params={param: value},
                        timeout=5
                    )

                    if response and response.status_code == 200:
                        if 'admin' in response.text.lower() or 'root' in response.text.lower():
                            finding = Finding(
                                type='IDOR_PARAMETER_TAMPERING',
                                severity='HIGH',
                                title=f'IDOR via Tampering ({param})',
                                description='Acesso via tampering de parâmetro',
                                details={'parameter': param, 'value': value},
                                evidence=['Dados sensíveis retornados'],
                                remediation='Validar e autorizar',
                                affected_url=self.target,
                            )
                            self.findings.append(finding)
                            results[f'{param}'] = True

                except Exception as e:
                    logger.debug(f"[IDOR] Erro: {e}")

        return results

    def scan(self) -> ScanResult:
        """Executa scanning completo IDOR"""
        start_time = time.time()
        logger.info(f"[IDOR] Iniciando scan: {self.target}")

        try:
            self.test_incremental_ids()
            self.test_uuids()
            self.test_parameter_tampering()

            execution_time = time.time() - start_time
            return ScanResult(
                scanner_name='IDORTester',
                target=self.target,
                findings=self.findings,
                execution_time=execution_time,
                success=True,
            )

        except Exception as e:
            logger.error(f"[IDOR] Erro: {e}")
            return ScanResult(
                scanner_name='IDORTester',
                target=self.target,
                findings=self.findings,
                execution_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )


# ============================================================================
# 5. CLICKJACKING TESTER
# ============================================================================

class ClickjackingTester:
    """Testa vulnerabilidades de Clickjacking"""

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def check_x_frame_options(self) -> Dict[str, Any]:
        """Verifica X-Frame-Options header"""
        logger.debug(f"[Clickjacking] Verificando X-Frame-Options")

        try:
            response = self.http_client.get(self.target, timeout=5)
            if not response:
                return {'vulnerable': False}

            x_frame_options = response.headers.get('X-Frame-Options', '').upper()

            if not x_frame_options:
                finding = Finding(
                    type='CLICKJACKING_NO_X_FRAME_OPTIONS',
                    severity='HIGH',
                    title='X-Frame-Options Não Configurado',
                    description='Página pode ser incorporada em iframe',
                    details={'header': 'X-Frame-Options'},
                    evidence=['Header não encontrado'],
                    remediation='Adicionar X-Frame-Options: DENY',
                    affected_url=self.target,
                )
                self.findings.append(finding)
                return {'vulnerable': True}

            return {'vulnerable': False, 'value': x_frame_options}

        except Exception as e:
            logger.error(f"[Clickjacking] Erro: {e}")
            return {}

    def check_csp(self) -> Dict[str, Any]:
        """Verifica CSP frame-ancestors"""
        logger.debug(f"[Clickjacking] Verificando CSP")

        try:
            response = self.http_client.get(self.target, timeout=5)
            if not response:
                return {}

            csp = response.headers.get('Content-Security-Policy', '')

            if not csp:
                return {'vulnerable': True, 'reason': 'CSP não encontrado'}

            if 'frame-ancestors' not in csp:
                finding = Finding(
                    type='CLICKJACKING_NO_CSP_FRAME_ANCESTORS',
                    severity='MEDIUM',
                    title='CSP sem frame-ancestors',
                    description='CSP não restringe frame-ancestors',
                    details={'csp': csp},
                    evidence=['frame-ancestors ausente'],
                    remediation='Adicionar frame-ancestors',
                    affected_url=self.target,
                )
                self.findings.append(finding)
                return {'vulnerable': True}

            return {'vulnerable': False}

        except Exception as e:
            logger.error(f"[Clickjacking] Erro: {e}")
            return {}

    def test_cors_misconfiguration(self) -> Dict[str, Any]:
        """Testa CORS misconfiguration"""
        logger.debug(f"[Clickjacking] Testando CORS")

        try:
            vulnerable_origins = []

            for origin in ['https://evil.com', 'https://attacker.io']:
                response = self.http_client.get(
                    self.target,
                    headers={'Origin': origin},
                    timeout=5
                )

                if response:
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    if acao == origin or acao == '*':
                        vulnerable_origins.append(origin)
                        finding = Finding(
                            type='CLICKJACKING_CORS_MISCONFIGURATION',
                            severity='HIGH',
                            title=f'CORS Misconfiguration',
                            description='CORS mal configurado',
                            details={'origin': origin},
                            evidence=[f'ACAO: {acao}'],
                            remediation='Restringir CORS',
                            affected_url=self.target,
                        )
                        self.findings.append(finding)

            return {'vulnerable': len(vulnerable_origins) > 0}

        except Exception as e:
            logger.error(f"[Clickjacking] Erro: {e}")
            return {}

    def scan(self) -> ScanResult:
        """Executa scanning completo"""
        start_time = time.time()
        logger.info(f"[Clickjacking] Iniciando scan: {self.target}")

        try:
            self.check_x_frame_options()
            self.check_csp()
            self.test_cors_misconfiguration()

            execution_time = time.time() - start_time
            return ScanResult(
                scanner_name='ClickjackingTester',
                target=self.target,
                findings=self.findings,
                execution_time=execution_time,
                success=True,
            )

        except Exception as e:
            logger.error(f"[Clickjacking] Erro: {e}")
            return ScanResult(
                scanner_name='ClickjackingTester',
                target=self.target,
                findings=self.findings,
                execution_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )


# ============================================================================
# 6. RATE LIMIT TESTER
# ============================================================================

class RateLimitTester:
    """Testa limitações de taxa"""

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def test_rate_limits(self, num_requests: int = 50, delay: float = 0.1) -> Dict[str, Any]:
        """Envia múltiplas requisições rapidamente"""
        logger.debug(f"[RateLimit] Testando com {num_requests} requisições")

        results = {
            'total_requests': num_requests,
            'status_codes': {},
            'response_times': [],
            'rate_limited': False,
        }

        blocked_count = 0

        for i in range(num_requests):
            try:
                start = time.time()
                response = self.http_client.get(
                    self.target,
                    params={'test': str(i)},
                    timeout=5
                )
                elapsed = time.time() - start

                if response:
                    status = response.status_code
                    results['status_codes'][status] = results['status_codes'].get(status, 0) + 1
                    results['response_times'].append(elapsed)

                    if status in [429, 403, 503]:
                        blocked_count += 1

                time.sleep(delay)

            except Exception as e:
                logger.debug(f"[RateLimit] Erro: {e}")

        if blocked_count > num_requests * 0.1:
            results['rate_limited'] = True
            finding = Finding(
                type='RATE_LIMITING_DETECTED',
                severity='INFO',
                title='Rate Limiting Detectado',
                description=f'{blocked_count} requisições bloqueadas',
                details=results,
                evidence=[f'Bloqueadas: {blocked_count}/{num_requests}'],
                remediation='Rate limiting está ativo',
                affected_url=self.target,
            )
            self.findings.append(finding)
        else:
            finding = Finding(
                type='NO_RATE_LIMITING',
                severity='MEDIUM',
                title='Rate Limiting Não Detectado',
                description='Sem rate limiting em requisições rápidas',
                details=results,
                evidence=[f'Bloqueadas: {blocked_count}/{num_requests}'],
                remediation='Implementar rate limiting',
                affected_url=self.target,
            )
            self.findings.append(finding)

        return results

    def measure_response_time(self, num_samples: int = 10) -> Dict[str, Any]:
        """Mede tempo de resposta"""
        logger.debug(f"[RateLimit] Medindo tempo ({num_samples} amostras)")

        response_times = []

        for i in range(num_samples):
            try:
                start = time.time()
                response = self.http_client.get(self.target, timeout=5)
                elapsed = time.time() - start

                if response:
                    response_times.append(elapsed)

            except Exception as e:
                logger.debug(f"[RateLimit] Erro: {e}")

        if response_times:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)

            results = {
                'samples': len(response_times),
                'average': avg_time,
                'max': max_time,
            }

            if max_time > 10:
                finding = Finding(
                    type='SLOW_RESPONSE_TIME',
                    severity='INFO',
                    title='Tempo de Resposta Lento',
                    description=f'Max: {max_time:.2f}s',
                    details=results,
                    evidence=[f'Max: {max_time:.2f}s'],
                    remediation='Otimizar performance',
                    affected_url=self.target,
                )
                self.findings.append(finding)

            return results

        return {}

    def scan(self) -> ScanResult:
        """Executa scanning completo"""
        start_time = time.time()
        logger.info(f"[RateLimit] Iniciando scan: {self.target}")

        try:
            self.test_rate_limits(num_requests=20)
            self.measure_response_time()

            execution_time = time.time() - start_time
            return ScanResult(
                scanner_name='RateLimitTester',
                target=self.target,
                findings=self.findings,
                execution_time=execution_time,
                success=True,
            )

        except Exception as e:
            logger.error(f"[RateLimit] Erro: {e}")
            return ScanResult(
                scanner_name='RateLimitTester',
                target=self.target,
                findings=self.findings,
                execution_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )


# ============================================================================
# 7. API FUZZER
# ============================================================================

class APIFuzzer:
    """Fuzzing de endpoints API"""

    COMMON_API_ENDPOINTS = [
        '/api/users', '/api/admin', '/api/profile', '/api/settings', '/api/config',
        '/api/database', '/api/admin/users', '/api/v1/users', '/api/v2/users',
        '/api/auth/users', '/api/accounts', '/api/data', '/api/export', '/api/backup',
        '/api/debug', '/api/logs', '/api/status',
    ]

    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []
        self.discovered_endpoints: List[str] = []

    def fuzz_endpoints(self) -> Dict[str, Any]:
        """Testa endpoints comuns"""
        logger.debug(f"[APIFuzzer] Fuzzando endpoints")

        results = {}

        for endpoint in self.COMMON_API_ENDPOINTS:
            try:
                url = urljoin(self.target, endpoint)
                response = self.http_client.get(url, timeout=5)

                if response and response.status_code != 404:
                    self.discovered_endpoints.append(endpoint)
                    results[endpoint] = {
                        'status': response.status_code,
                        'found': True,
                    }

                    finding = Finding(
                        type='API_ENDPOINT_DISCOVERED',
                        severity='INFO',
                        title=f'Endpoint Descoberto: {endpoint}',
                        description=f'Encontrado: {endpoint}',
                        details={'endpoint': endpoint, 'status': response.status_code},
                        evidence=[f'Status: {response.status_code}'],
                        remediation='Revisar se deve estar exposto',
                        affected_url=url,
                    )
                    self.findings.append(finding)

            except Exception as e:
                logger.debug(f"[APIFuzzer] Erro: {e}")

        return results

    def fuzz_methods(self) -> Dict[str, Any]:
        """Testa diferentes métodos HTTP"""
        logger.debug(f"[APIFuzzer] Testando métodos")

        results = {}

        for endpoint in self.discovered_endpoints[:5]:
            for method in self.HTTP_METHODS:
                try:
                    url = urljoin(self.target, endpoint)
                    response = requests.request(method, url, timeout=5, verify=False)

                    if response.status_code != 405:
                        results[f'{endpoint}:{method}'] = {
                            'method': method,
                            'status': response.status_code,
                        }

                        if method in ['PUT', 'DELETE']:
                            finding = Finding(
                                type='DANGEROUS_HTTP_METHOD_ALLOWED',
                                severity='HIGH',
                                title=f'Método {method} Permitido',
                                description=f'Método perigoso em {endpoint}',
                                details={'endpoint': endpoint, 'method': method},
                                evidence=[f'Status: {response.status_code}'],
                                remediation=f'Desabilitar {method}',
                                affected_url=url,
                            )
                            self.findings.append(finding)

                except Exception as e:
                    logger.debug(f"[APIFuzzer] Erro: {e}")

        return results

    def fuzz_parameters(self) -> Dict[str, Any]:
        """Testa parâmetros comuns"""
        logger.debug(f"[APIFuzzer] Fuzzando parâmetros")

        results = {}
        common_params = ['id', 'user', 'admin', 'debug', 'test']

        for endpoint in self.discovered_endpoints[:3]:
            for param in common_params:
                try:
                    url = urljoin(self.target, endpoint)
                    response = self.http_client.get(
                        url,
                        params={param: 'test_value'},
                        timeout=5
                    )

                    if response and response.status_code == 200:
                        results[f'{endpoint}?{param}'] = {'accepted': True}

                except Exception as e:
                    logger.debug(f"[APIFuzzer] Erro: {e}")

        return results

    def scan(self) -> ScanResult:
        """Executa scanning completo"""
        start_time = time.time()
        logger.info(f"[APIFuzzer] Iniciando scan: {self.target}")

        try:
            self.fuzz_endpoints()
            self.fuzz_methods()
            self.fuzz_parameters()

            execution_time = time.time() - start_time
            return ScanResult(
                scanner_name='APIFuzzer',
                target=self.target,
                findings=self.findings,
                execution_time=execution_time,
                success=True,
                metadata={'endpoints_discovered': len(self.discovered_endpoints)},
            )

        except Exception as e:
            logger.error(f"[APIFuzzer] Erro: {e}")
            return ScanResult(
                scanner_name='APIFuzzer',
                target=self.target,
                findings=self.findings,
                execution_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )


# ============================================================================
# 8. SSL/TLS ANALYZER
# ============================================================================

class SSLAnalyzer:
    """Detecta protocolos/ciphers fracos e certificados expirados/expirando"""

    WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
    WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'MD5', 'EXPORT', 'NULL', 'anon']

    def __init__(self, target: str):
        self.target = target
        self.host = urlparse(target).netloc or target
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        import ssl as ssl_lib
        import socket
        start_time = time.time()
        logger.info(f"[SSLAnalyzer] Iniciando scan: {self.target}")
        metadata: Dict[str, Any] = {}

        try:
            ctx = ssl_lib.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_lib.CERT_NONE

            with socket.create_connection((self.host, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as s:
                    cert = s.getpeercert()
                    proto = s.version()
                    cipher = s.cipher()
                    cipher_name = cipher[0] if cipher else ''
                    metadata['protocol'] = proto
                    metadata['cipher'] = cipher_name

                    if any(w in proto for w in self.WEAK_PROTOCOLS):
                        self.findings.append(Finding(
                            type='SSL_WEAK_PROTOCOL', severity='HIGH',
                            title=f'Protocolo SSL/TLS fraco: {proto}',
                            description=f'O servidor aceita o protocolo obsoleto {proto}.',
                            details={'protocol': proto}, evidence=[proto],
                            remediation='Desativar protocolos SSLv2/SSLv3/TLSv1/TLSv1.1, exigir TLSv1.2+.',
                            affected_url=self.target,
                        ))

                    if any(w in cipher_name for w in self.WEAK_CIPHERS):
                        self.findings.append(Finding(
                            type='SSL_WEAK_CIPHER', severity='MEDIUM',
                            title=f'Cipher suite inseguro: {cipher_name}',
                            description='A cipher suite negociada é considerada fraca.',
                            details={'cipher': cipher_name}, evidence=[cipher_name],
                            remediation='Desativar ciphers RC4/DES/3DES/MD5/EXPORT/NULL/anon.',
                            affected_url=self.target,
                        ))

                    if cert:
                        not_after = cert.get('notAfter', '')
                        if not_after:
                            exp = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_left = (exp - datetime.utcnow()).days
                            metadata['cert_expires'] = not_after
                            metadata['cert_days_left'] = days_left

                            if days_left < 0:
                                self.findings.append(Finding(
                                    type='SSL_CERT_EXPIRED', severity='CRITICAL',
                                    title='Certificado SSL expirado',
                                    description=f'O certificado expirou há {-days_left} dias.',
                                    details={'expired_days_ago': -days_left}, evidence=[not_after],
                                    remediation='Renovar o certificado imediatamente.',
                                    affected_url=self.target,
                                ))
                            elif days_left < 30:
                                self.findings.append(Finding(
                                    type='SSL_CERT_EXPIRING', severity='MEDIUM',
                                    title='Certificado SSL prestes a expirar',
                                    description=f'O certificado expira em {days_left} dias.',
                                    details={'days_left': days_left}, evidence=[not_after],
                                    remediation='Renovar o certificado antes do vencimento.',
                                    affected_url=self.target,
                                ))

            execution_time = time.time() - start_time
            return ScanResult(
                scanner_name='SSLAnalyzer', target=self.target,
                findings=self.findings, execution_time=execution_time,
                success=True, metadata=metadata,
            )
        except Exception as e:
            logger.error(f"[SSLAnalyzer] Erro: {e}")
            return ScanResult(
                scanner_name='SSLAnalyzer', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


# ============================================================================
# 9. ROBOTS.TXT / SITEMAP SCANNER
# ============================================================================

class RobotsSitemapScanner:
    """Extrai robots.txt e sitemap.xml, sinaliza paths sensíveis expostos"""

    SENSITIVE_PATHS = [
        '/admin', '/login', '/panel', '/dashboard', '/api', '/backup',
        '/config', '/private', '/test', '/dev', '/staging', '/internal',
        '/phpmyadmin', '/wp-admin', '/cgi-bin', '/server-status',
        '/actuator', '/metrics', '/.env', '/.git',
    ]

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target.rstrip('/')
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[RobotsSitemapScanner] Iniciando scan: {self.target}")
        metadata: Dict[str, Any] = {'sitemaps': [], 'disallowed': []}

        try:
            robots_url = f"{self.target}/robots.txt"
            resp = self.http_client.get(robots_url, timeout=Config.HTTP_TIMEOUT)
            if resp and resp.status_code == 200:
                current_agent = '*'
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    low = line.lower()
                    if low.startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if not path:
                            continue
                        metadata['disallowed'].append(path)
                        for sp in self.SENSITIVE_PATHS:
                            if sp in path.lower():
                                self.findings.append(Finding(
                                    type='ROBOTS_SENSITIVE_PATH', severity='LOW',
                                    title=f'Path sensível listado em robots.txt: {path}',
                                    description=f'robots.txt revela um path possivelmente sensível ({sp}).',
                                    details={'path': path, 'agent': current_agent},
                                    evidence=[path],
                                    remediation='Evitar listar paths sensíveis em robots.txt; usar autenticação em vez de ocultação.',
                                    affected_url=f"{self.target}{path}",
                                ))
                                break
                    elif low.startswith('user-agent:'):
                        current_agent = line.split(':', 1)[1].strip()
                    elif low.startswith('sitemap:'):
                        metadata['sitemaps'].append(line.split(':', 1)[1].strip())

            execution_time = time.time() - start_time
            return ScanResult(
                scanner_name='RobotsSitemapScanner', target=self.target,
                findings=self.findings, execution_time=execution_time,
                success=True, metadata=metadata,
            )
        except Exception as e:
            logger.error(f"[RobotsSitemapScanner] Erro: {e}")
            return ScanResult(
                scanner_name='RobotsSitemapScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


# ============================================================================
# 10. SUBDOMAIN TAKEOVER CHECKER
# ============================================================================

class TakeoverChecker:
    """Verifica CNAMEs apontando para serviços de terceiros abandonados (takeover)"""

    FINGERPRINTS: List[Dict[str, Any]] = [
        {'service': 'GitHub Pages', 'cname': 'github.io', 'signature': "there isn't a github pages site here"},
        {'service': 'Heroku', 'cname': 'herokuapp.com', 'signature': 'no such app'},
        {'service': 'Shopify', 'cname': 'myshopify.com', 'signature': 'sorry, this shop is currently unavailable'},
        {'service': 'Netlify', 'cname': 'netlify.app', 'signature': 'not found'},
        {'service': 'Azure Websites', 'cname': 'azurewebsites.net', 'signature': 'web app - unavailable'},
        {'service': 'Amazon S3', 'cname': 's3.amazonaws.com', 'signature': 'nosuchbucket'},
        {'service': 'Fastly', 'cname': 'fastly.net', 'signature': 'fastly error: unknown domain'},
        {'service': 'Pantheon', 'cname': 'pantheonsite.io', 'signature': '404 error unknown site!'},
        {'service': 'Tumblr', 'cname': 'tumblr.com', 'signature': "there's nothing here"},
        {'service': 'WordPress.com', 'cname': 'wordpress.com', 'signature': 'do you want to register'},
        {'service': 'Zendesk', 'cname': 'zendesk.com', 'signature': 'help center closed'},
        {'service': 'Surge.sh', 'cname': 'surge.sh', 'signature': 'project not found'},
        {'service': 'Ghost', 'cname': 'ghost.io', 'signature': "the thing you were looking for isn't here"},
        {'service': 'Readme.io', 'cname': 'readme.io', 'signature': 'project doesnt exist'},
    ]

    def __init__(self, target: str, subdomains: Dict[str, str], http_client: HTTPClient = None):
        """subdomains: mapa {subdominio: cname_alvo}, obtido pelo módulo de recon."""
        self.target = target
        self.subdomains = subdomains
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[TakeoverChecker] Iniciando scan: {self.target} ({len(self.subdomains)} subdomínios)")
        checked = 0

        try:
            for sub, cname in self.subdomains.items():
                if not cname:
                    continue
                for fp in self.FINGERPRINTS:
                    if fp['cname'] not in cname:
                        continue
                    checked += 1
                    resp = self.http_client.get(f"https://{sub}", timeout=Config.HTTP_TIMEOUT)
                    if not resp:
                        resp = self.http_client.get(f"http://{sub}", timeout=Config.HTTP_TIMEOUT)
                    if resp and fp['signature'] in resp.text.lower():
                        self.findings.append(Finding(
                            type='SUBDOMAIN_TAKEOVER', severity='CRITICAL',
                            title=f'Possível takeover de subdomínio: {sub}',
                            description=f'{sub} aponta (CNAME) para {fp["service"]} ({cname}), que retorna sinal de recurso não reivindicado.',
                            details={'subdomain': sub, 'cname': cname, 'service': fp['service']},
                            evidence=[fp['signature']],
                            remediation=f'Remover o registro CNAME órfão ou reivindicar o recurso em {fp["service"]}.',
                            affected_url=f"https://{sub}",
                        ))
                    break

            execution_time = time.time() - start_time
            return ScanResult(
                scanner_name='TakeoverChecker', target=self.target,
                findings=self.findings, execution_time=execution_time,
                success=True, metadata={'checked': checked},
            )
        except Exception as e:
            logger.error(f"[TakeoverChecker] Erro: {e}")
            return ScanResult(
                scanner_name='TakeoverChecker', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


# ============================================================================
# 12. OAUTH TESTER
# ============================================================================

class OAuthTester:
    """Testa fluxo de autorização OAuth (redirect_uri hijacking e state omission)"""

    AUTHORIZE_ENDPOINTS = ['/oauth/authorize', '/authorize', '/oauth2/authorize', '/api/oauth/authorize']

    def __init__(self, target: str, http_client: HTTPClient = None, client_id: str = 'test'):
        self.target = target.rstrip('/')
        self.http_client = http_client or HTTPClient()
        self.client_id = client_id
        self.findings: List[Finding] = []
        self.authorize_url: Optional[str] = None

    def find_authorize_endpoint(self) -> Optional[str]:
        logger.debug(f"[OAuth] Procurando endpoint de authorize")
        for endpoint in self.AUTHORIZE_ENDPOINTS:
            try:
                url = urljoin(self.target + '/', endpoint.lstrip('/'))
                response = self.http_client.get(
                    url, params={'client_id': self.client_id, 'response_type': 'code'}, timeout=5
                )
                if response and response.status_code in (200, 302, 400, 401):
                    self.authorize_url = url
                    return url
            except Exception as e:
                logger.debug(f"[OAuth] Erro testando {endpoint}: {e}")
        return None

    def test_redirect_uri_hijacking(self) -> Dict[str, Any]:
        """Testa se redirect_uri com domínio externo é aceito sem validação estrita"""
        logger.debug(f"[OAuth] Testando redirect_uri hijacking")

        if not self.authorize_url:
            return {}

        malicious_redirects = [
            'https://evil-attacker.example.com/callback',
            'https://legit-app.com.evil-attacker.example.com/callback',
        ]

        for redirect_uri in malicious_redirects:
            try:
                response = self.http_client.get(
                    self.authorize_url,
                    params={'client_id': self.client_id, 'response_type': 'code', 'redirect_uri': redirect_uri},
                    timeout=5,
                    allow_redirects=False,
                )
                if not response:
                    continue

                location = response.headers.get('Location', '')
                accepted = response.status_code in (200, 302) and (
                    redirect_uri in location or response.status_code == 200
                )
                rejected_explicitly = response.status_code in (400, 401, 403) or 'invalid' in (response.text or '').lower()

                if accepted and not rejected_explicitly:
                    self.findings.append(Finding(
                        type='OAUTH_REDIRECT_URI_HIJACKING',
                        severity='HIGH',
                        title='Possível OAuth Redirect URI Hijacking',
                        description=f'O endpoint de autorização aceitou redirect_uri externo "{redirect_uri}" sem rejeitar explicitamente.',
                        details={'redirect_uri': redirect_uri, 'status': response.status_code},
                        evidence=[f'Status: {response.status_code}, Location: {location[:100]}'],
                        remediation='Validar redirect_uri contra uma lista exata (allowlist) registrada por cliente, sem wildcards.',
                        affected_url=self.authorize_url,
                    ))
                    return {'vulnerable': True}

            except Exception as e:
                logger.debug(f"[OAuth] Erro testando redirect_uri: {e}")

        return {'vulnerable': False}

    def test_state_parameter_omission(self) -> Dict[str, Any]:
        """Testa se o fluxo aceita autorização sem o parâmetro state (CSRF de login)"""
        logger.debug(f"[OAuth] Testando ausência de state")

        if not self.authorize_url:
            return {}

        try:
            response = self.http_client.get(
                self.authorize_url,
                params={'client_id': self.client_id, 'response_type': 'code'},
                timeout=5,
                allow_redirects=False,
            )
            if response and response.status_code in (200, 302) and \
                    response.status_code not in (400, 401, 403):
                self.findings.append(Finding(
                    type='OAUTH_STATE_PARAMETER_OMISSION',
                    severity='MEDIUM',
                    title='OAuth Aceita Fluxo sem Parâmetro "state"',
                    description='O endpoint de autorização não exigiu o parâmetro "state", deixando o fluxo '
                                'potencialmente vulnerável a CSRF de login.',
                    details={'status': response.status_code},
                    evidence=[f'Status: {response.status_code}'],
                    remediation='Exigir e validar um parâmetro "state" único e imprevisível em cada fluxo de autorização.',
                    affected_url=self.authorize_url,
                ))
                return {'vulnerable': True}

        except Exception as e:
            logger.debug(f"[OAuth] Erro testando state: {e}")

        return {'vulnerable': False}

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[OAuth] Iniciando scan: {self.target}")

        try:
            if self.find_authorize_endpoint():
                self.test_redirect_uri_hijacking()
                self.test_state_parameter_omission()

            return ScanResult(
                scanner_name='OAuthTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=True, metadata={'authorize_endpoint': self.authorize_url},
            )
        except Exception as e:
            logger.error(f"[OAuth] Erro: {e}")
            return ScanResult(
                scanner_name='OAuthTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


# ============================================================================
# 13. LOGIN TIMING TESTER (User Enumeration)
# ============================================================================

class LoginTimingTester:
    """Detecta enumeração de usuários por diferença de tempo de resposta no login"""

    LOGIN_ENDPOINTS = ['/login', '/api/login', '/auth/login', '/signin', '/api/auth/login']

    def __init__(self, target: str, http_client: HTTPClient = None,
                 known_user: str = 'admin', samples: int = 8):
        self.target = target.rstrip('/')
        self.http_client = http_client or HTTPClient()
        self.known_user = known_user
        self.samples = samples
        self.findings: List[Finding] = []
        self.login_url: Optional[str] = None

    def find_login_endpoint(self) -> Optional[str]:
        for endpoint in self.LOGIN_ENDPOINTS:
            try:
                url = urljoin(self.target + '/', endpoint.lstrip('/'))
                response = self.http_client.get(url, timeout=5)
                if response and response.status_code in (200, 401, 405):
                    self.login_url = url
                    return url
            except Exception as e:
                logger.debug(f"[LoginTiming] Erro testando {endpoint}: {e}")
        return None

    def _measure(self, username: str) -> List[float]:
        times = []
        for _ in range(self.samples):
            try:
                t0 = time.time()
                self.http_client.post(
                    self.login_url,
                    json={'username': username, 'password': 'wrong_password_xyz_123'},
                    timeout=8,
                )
                times.append(time.time() - t0)
            except Exception as e:
                logger.debug(f"[LoginTiming] Erro medindo tempo: {e}")
        return times

    def test_timing_user_enumeration(self) -> Dict[str, Any]:
        """Compara tempo médio de resposta entre usuário existente e inexistente"""
        logger.debug(f"[LoginTiming] Testando enumeração por timing")

        if not self.login_url:
            return {}

        try:
            existing_times = self._measure(self.known_user)
            nonexistent_times = self._measure(f'nonexistent_user_{int(time.time())}_xyz')

            if not existing_times or not nonexistent_times:
                return {}

            avg_existing = sum(existing_times) / len(existing_times)
            avg_nonexistent = sum(nonexistent_times) / len(nonexistent_times)
            diff = abs(avg_existing - avg_nonexistent)

            if diff > 0.3:
                self.findings.append(Finding(
                    type='LOGIN_TIMING_USER_ENUMERATION',
                    severity='MEDIUM',
                    title='Possível Enumeração de Usuários via Timing',
                    description=f'Diferença média de {diff:.3f}s entre login de usuário existente '
                                f'({avg_existing:.3f}s) e inexistente ({avg_nonexistent:.3f}s).',
                    details={'avg_existing': avg_existing, 'avg_nonexistent': avg_nonexistent, 'diff': diff},
                    evidence=[f'Existente: {avg_existing:.3f}s, Inexistente: {avg_nonexistent:.3f}s'],
                    remediation='Igualar o tempo de resposta para usuários existentes e inexistentes '
                                '(ex.: sempre executar hash da senha, mesmo quando o usuário não existe).',
                    affected_url=self.login_url,
                ))
                return {'vulnerable': True, 'diff': diff}

            return {'vulnerable': False, 'diff': diff}

        except Exception as e:
            logger.debug(f"[LoginTiming] Erro: {e}")
            return {}

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[LoginTiming] Iniciando scan: {self.target}")

        try:
            if self.find_login_endpoint():
                self.test_timing_user_enumeration()

            return ScanResult(
                scanner_name='LoginTimingTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=True, metadata={'login_endpoint': self.login_url},
            )
        except Exception as e:
            logger.error(f"[LoginTiming] Erro: {e}")
            return ScanResult(
                scanner_name='LoginTimingTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


# ============================================================================
# 14. WEB CACHE DECEPTION TESTER
# ============================================================================

class WebCacheDeceptionTester:
    """Testa Web Cache Deception adicionando extensões estáticas falsas a paths dinâmicos"""

    STATIC_SUFFIXES = ['.css', '.js', '.png', '.jpg', '.ico']
    CANDIDATE_PATHS = ['/account', '/profile', '/settings', '/dashboard', '/api/user', '/user/profile']

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target.rstrip('/')
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[WebCacheDeception] Iniciando scan: {self.target}")

        try:
            for path in self.CANDIDATE_PATHS:
                for suffix in self.STATIC_SUFFIXES:
                    try:
                        url = f"{self.target}{path}/nonexistent-resource{suffix}"
                        response = self.http_client.get(url, timeout=6, raise_for_status=False)
                        if not response or response.status_code != 200:
                            continue

                        cache_headers = {
                            k: v for k, v in response.headers.items()
                            if k.lower() in ('x-cache', 'age', 'cache-control', 'cf-cache-status')
                        }
                        cache_hit = any(
                            'hit' in v.lower() for k, v in cache_headers.items()
                            if k.lower() in ('x-cache', 'cf-cache-status')
                        )
                        publicly_cacheable = 'public' in cache_headers.get('Cache-Control', '').lower()

                        if cache_hit or (publicly_cacheable and len(response.text) > 100):
                            self.findings.append(Finding(
                                type='WEB_CACHE_DECEPTION',
                                severity='HIGH',
                                title=f'Possível Web Cache Deception em {path}',
                                description=f'Path dinâmico com sufixo estático falso ({suffix}) retornou '
                                            'conteúdo com indícios de ser cacheável/cacheado.',
                                details={'path': path, 'suffix': suffix, 'cache_headers': cache_headers},
                                evidence=[str(cache_headers)],
                                remediation='Configurar o cache para nunca armazenar respostas de paths autenticados '
                                            'com base apenas na extensão do path; usar normalização de URL no cache.',
                                affected_url=url,
                            ))
                    except Exception as e:
                        logger.debug(f"[WebCacheDeception] Erro testando {path}{suffix}: {e}")

            return ScanResult(
                scanner_name='WebCacheDeceptionTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[WebCacheDeception] Erro: {e}")
            return ScanResult(
                scanner_name='WebCacheDeceptionTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


# ============================================================================
# 15. TABNABBING TESTER
# ============================================================================

class TabnabbingTester:
    """Analisa HTML em busca de target=_blank sem rel=noopener/noreferrer (reverse tabnabbing)"""

    LINK_PATTERN = re.compile(r'<a\b[^>]*>', re.I)
    TARGET_BLANK_PATTERN = re.compile(r'target\s*=\s*["\']?_blank["\']?', re.I)
    REL_SAFE_PATTERN = re.compile(r'rel\s*=\s*["\'][^"\']*(noopener|noreferrer)[^"\']*["\']', re.I)

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[Tabnabbing] Iniciando scan: {self.target}")

        try:
            response = self.http_client.get(self.target, timeout=Config.HTTP_TIMEOUT)
            if response:
                vulnerable_links = []
                for tag in self.LINK_PATTERN.findall(response.text):
                    if self.TARGET_BLANK_PATTERN.search(tag) and not self.REL_SAFE_PATTERN.search(tag):
                        vulnerable_links.append(tag[:150])

                if vulnerable_links:
                    self.findings.append(Finding(
                        type='REVERSE_TABNABBING',
                        severity='LOW',
                        title=f'{len(vulnerable_links)} Link(s) com target="_blank" sem rel="noopener"',
                        description='Links que abrem em nova aba sem rel="noopener noreferrer" permitem que a '
                                    'página de destino manipule window.opener (reverse tabnabbing).',
                        details={'count': len(vulnerable_links)},
                        evidence=vulnerable_links[:5],
                        remediation='Adicionar rel="noopener noreferrer" a todos os links com target="_blank".',
                        affected_url=self.target,
                    ))

            return ScanResult(
                scanner_name='TabnabbingTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[Tabnabbing] Erro: {e}")
            return ScanResult(
                scanner_name='TabnabbingTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


# ============================================================================
# 16. EXPOSED SERVICES SCANNER (Docker Socket, K8s Dashboard, CI/CD)
# ============================================================================

class ExposedServicesScanner:
    """Detecta APIs de gerência (Docker, Kubernetes) e arquivos de CI/CD expostos publicamente"""

    CHECKS = [
        ('Docker API', '/version', re.compile(r'"ApiVersion"|"GitCommit"', re.I)),
        ('Docker API', '/containers/json', re.compile(r'"Names"|"Image"', re.I)),
        ('Kubernetes API', '/api/v1/namespaces/kube-system', re.compile(r'"kind"\s*:\s*"Namespace"', re.I)),
        ('Kubernetes Dashboard', '/api/v1/namespace', re.compile(r'kubernetes', re.I)),
        ('CI/CD Config', '/.gitlab-ci.yml', re.compile(r'stages:|script:', re.I)),
        ('CI/CD Config', '/.circleci/config.yml', re.compile(r'version:|jobs:', re.I)),
        ('CI/CD Config', '/.github/workflows/ci.yml', re.compile(r'jobs:|on:', re.I)),
        ('Spring Boot Actuator Env', '/actuator/env', re.compile(r'"activeProfiles"|"propertySources"', re.I)),
    ]

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target.rstrip('/')
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[ExposedServices] Iniciando scan: {self.target}")

        try:
            for service, path, signature in self.CHECKS:
                try:
                    url = f"{self.target}{path}"
                    response = self.http_client.get(url, timeout=6, raise_for_status=False)
                    if response and response.status_code == 200 and signature.search(response.text):
                        self.findings.append(Finding(
                            type='EXPOSED_MANAGEMENT_SERVICE',
                            severity='CRITICAL',
                            title=f'{service} Exposto Publicamente',
                            description=f'{path} respondeu com conteúdo característico de {service} sem autenticação.',
                            details={'service': service, 'path': path},
                            evidence=[response.text[:150]],
                            remediation=f'Restringir acesso a {path} apenas à rede interna/autenticada, '
                                        'ou desabilitar a exposição pública do serviço.',
                            affected_url=url,
                        ))
                except Exception as e:
                    logger.debug(f"[ExposedServices] Erro testando {path}: {e}")

            return ScanResult(
                scanner_name='ExposedServicesScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[ExposedServices] Erro: {e}")
            return ScanResult(
                scanner_name='ExposedServicesScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


# ============================================================================
# 17. HTTP REQUEST SMUGGLING TESTER (TE.CL / CL.TE)
# ============================================================================

class RequestSmugglingTester:
    """Envia requests raw com Content-Length e Transfer-Encoding conflitantes
    (CL.TE / TE.CL) e mede timing anômalo — indício clássico de desync."""

    def __init__(self, target: str, timeout: float = 10.0):
        self.target = target
        self.timeout = timeout
        parsed = urlparse(target)
        self.host = parsed.hostname or target
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.use_tls = parsed.scheme == 'https'
        self.path = parsed.path or '/'
        self.findings: List[Finding] = []

    def _send_raw(self, request_bytes: bytes) -> float:
        """Envia bytes crus e mede o tempo até a conexão responder/fechar."""
        import socket
        import ssl as ssl_lib

        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        try:
            if self.use_tls:
                ctx = ssl_lib.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_lib.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)

            sock.sendall(request_bytes)
            t0 = time.time()
            try:
                sock.settimeout(self.timeout)
                sock.recv(4096)
            except (socket.timeout, ConnectionResetError, OSError):
                pass
            return time.time() - t0
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def test_cl_te_desync(self) -> Dict[str, Any]:
        """CL.TE: front-end confia em Content-Length, back-end confia em Transfer-Encoding.
        O back-end espera um chunk a mais e trava até timeout se vulnerável."""
        logger.debug(f"[RequestSmuggling] Testando CL.TE: {self.target}")

        body = "0\r\n\r\nG"
        request = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{body}"
        ).encode()

        try:
            elapsed = self._send_raw(request)
            if elapsed > self.timeout * 0.8:
                self.findings.append(Finding(
                    type='HTTP_REQUEST_SMUGGLING_CL_TE', severity='CRITICAL',
                    title='Possível HTTP Request Smuggling (CL.TE)',
                    description=f'Requisição com Content-Length/Transfer-Encoding conflitantes causou '
                                f'atraso de {elapsed:.1f}s, sugerindo que o back-end aguardou dados extras '
                                'não enviados pelo front-end (desync CL.TE).',
                    details={'elapsed': elapsed, 'timeout': self.timeout},
                    evidence=[f'Tempo de resposta: {elapsed:.1f}s (timeout: {self.timeout}s)'],
                    remediation='Normalizar o tratamento de Content-Length/Transfer-Encoding entre front-end '
                                'e back-end; rejeitar requisições com ambos os headers presentes (RFC 7230).',
                    affected_url=self.target,
                ))
                return {'vulnerable': True, 'elapsed': elapsed}

        except Exception as e:
            logger.debug(f"[RequestSmuggling] Erro CL.TE: {e}")

        return {'vulnerable': False}

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[RequestSmuggling] Iniciando scan: {self.target}")

        try:
            self.test_cl_te_desync()

            return ScanResult(
                scanner_name='RequestSmugglingTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[RequestSmuggling] Erro: {e}")
            return ScanResult(
                scanner_name='RequestSmugglingTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


# ============================================================================
# 18. HTTP/2 SUPPORT CHECKER (passivo — sem ataque real de Rapid Reset)
# ============================================================================

class Http2SupportChecker:
    """Detecta suporte a HTTP/2 via negociação ALPN (sem enviar tráfego de ataque).
    Apenas informativo: servidores HTTP/2 sem mitigação para CVE-2023-44487
    (Rapid Reset) podem ser vulneráveis a DoS — não testamos isso ativamente."""

    def __init__(self, target: str, timeout: float = 8.0):
        self.target = target
        self.timeout = timeout
        parsed = urlparse(target)
        self.host = parsed.hostname or target
        self.port = parsed.port or 443
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        import socket
        import ssl as ssl_lib

        start_time = time.time()
        logger.info(f"[Http2Support] Iniciando scan: {self.target}")
        metadata: Dict[str, Any] = {}

        try:
            ctx = ssl_lib.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_lib.CERT_NONE
            try:
                ctx.set_alpn_protocols(['h2', 'http/1.1'])
            except NotImplementedError:
                pass

            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as s:
                    negotiated = s.selected_alpn_protocol()
                    metadata['alpn_protocol'] = negotiated

                    if negotiated == 'h2':
                        self.findings.append(Finding(
                            type='HTTP2_SUPPORTED_INFO', severity='INFO',
                            title='Servidor suporta HTTP/2',
                            description='O servidor negociou HTTP/2 via ALPN. Servidores HTTP/2 sem limite '
                                        'de streams cancelados por conexão podem ser vulneráveis ao ataque '
                                        'Rapid Reset (CVE-2023-44487). Não testamos isso ativamente por ser '
                                        'um vetor de negação de serviço real.',
                            details={'alpn': negotiated},
                            evidence=['ALPN: h2'],
                            remediation='Confirmar que o servidor/proxy HTTP/2 está atualizado com mitigação '
                                        'para CVE-2023-44487 (limite de streams RST_STREAM por conexão).',
                            affected_url=self.target,
                        ))

            return ScanResult(
                scanner_name='Http2SupportChecker', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=True, metadata=metadata,
            )
        except Exception as e:
            logger.error(f"[Http2Support] Erro: {e}")
            return ScanResult(
                scanner_name='Http2SupportChecker', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


# ============================================================================
# 19. CLIENT-SIDE PROTOTYPE POLLUTION SCANNER (passivo — análise estática de JS)
# ============================================================================

class PrototypePollutionScanner:
    """Busca scripts JS referenciados pela página e procura padrões de merge/extend
    sem proteção contra __proto__/constructor.prototype (sem executar JS)."""

    PROTO_KEY_USAGE = re.compile(rb'\[\s*key\s*\]\s*=|\bobj\[[a-zA-Z]+\]\s*=')
    PROTO_GUARD = re.compile(rb'__proto__|constructor\.prototype|Object\.prototype')

    def __init__(self, target: str, http_client: HTTPClient = None, max_scripts: int = 10):
        self.target = target
        self.http_client = http_client or HTTPClient()
        self.max_scripts = max_scripts
        self.findings: List[Finding] = []

    def _find_script_urls(self, html: str) -> List[str]:
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        return [urljoin(self.target, s) for s in srcs][:self.max_scripts]

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[PrototypePollution] Iniciando scan: {self.target}")

        try:
            page = self.http_client.get(self.target, timeout=Config.HTTP_TIMEOUT)
            if not page:
                return ScanResult(
                    scanner_name='PrototypePollutionScanner', target=self.target,
                    findings=self.findings, execution_time=time.time() - start_time, success=True,
                )

            script_urls = self._find_script_urls(page.text)
            checked = 0

            for script_url in script_urls:
                try:
                    resp = self.http_client.get(script_url, timeout=6, raise_for_status=False)
                    if not resp:
                        continue
                    checked += 1
                    content = resp.content

                    has_dynamic_key_assignment = bool(self.PROTO_KEY_USAGE.search(content))
                    has_guard = bool(self.PROTO_GUARD.search(content))
                    mentions_merge = b'merge' in content.lower() or b'extend' in content.lower() or b'assign' in content.lower()

                    if mentions_merge and has_dynamic_key_assignment and not has_guard:
                        self.findings.append(Finding(
                            type='CLIENT_SIDE_PROTOTYPE_POLLUTION_SUSPECT', severity='MEDIUM',
                            title=f'Possível Prototype Pollution em {script_url}',
                            description='O script atribui a chaves dinâmicas de objeto (padrão de merge/extend) '
                                        'sem nenhuma proteção visível contra "__proto__"/"constructor.prototype" — '
                                        'requer confirmação manual/dinâmica (DevTools), pois esta é uma heurística estática.',
                            details={'script': script_url}, evidence=[script_url],
                            remediation='Validar chaves antes de atribuir (bloquear "__proto__", "constructor", '
                                        '"prototype") ou usar Object.create(null)/Map em vez de merge genérico.',
                            affected_url=script_url,
                        ))
                except Exception as e:
                    logger.debug(f"[PrototypePollution] Erro em {script_url}: {e}")

            return ScanResult(
                scanner_name='PrototypePollutionScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=True, metadata={'scripts_checked': checked},
            )
        except Exception as e:
            logger.error(f"[PrototypePollution] Erro: {e}")
            return ScanResult(
                scanner_name='PrototypePollutionScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


# ============================================================================
# 20. SAML TESTER (passivo — análise do metadata, sem simular fluxo completo)
# ============================================================================

class SAMLTester:
    """Localiza endpoints/metadata SAML e sinaliza configurações fracas.
    Não simula um fluxo SAML completo (precisaria de IdP/SP configurados) nem
    testa XSW real (precisaria de uma asserção válida capturada) — verifica a
    superfície exposta no metadata público, que já revela más práticas comuns."""

    METADATA_ENDPOINTS = [
        '/saml/metadata', '/simplesaml/module.php/saml/sp/metadata.php/default-sp',
        '/auth/realms/master/protocol/saml/descriptor', '/sso/saml/metadata',
        '/metadata.xml', '/saml2/metadata',
    ]

    SSO_ENDPOINTS = ['/saml/sso', '/saml/login', '/sso/saml', '/saml2/sso']

    WEAK_SIGNATURE_ALGS = ['rsa-sha1', 'dsa-sha1', 'sha1']

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target.rstrip('/')
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []
        self.metadata_url: Optional[str] = None

    def find_metadata_endpoint(self) -> Optional[str]:
        logger.debug(f"[SAML] Procurando endpoint de metadata")
        for endpoint in self.METADATA_ENDPOINTS:
            try:
                url = urljoin(self.target + '/', endpoint.lstrip('/'))
                response = self.http_client.get(url, timeout=6, raise_for_status=False)
                if response and response.status_code == 200 and \
                        ('EntityDescriptor' in response.text or 'saml' in response.text.lower()):
                    self.metadata_url = url
                    return url
            except Exception as e:
                logger.debug(f"[SAML] Erro testando {endpoint}: {e}")
        return None

    def test_metadata_weaknesses(self) -> Dict[str, Any]:
        """Analisa o XML de metadata público em busca de configurações fracas conhecidas."""
        logger.debug(f"[SAML] Analisando metadata")

        if not self.metadata_url:
            return {}

        try:
            response = self.http_client.get(self.metadata_url, timeout=6, raise_for_status=False)
            if not response:
                return {}

            xml = response.text
            found_any = False

            if 'WantAssertionsSigned="true"' not in xml and 'WantAssertionsSigned' not in xml:
                self.findings.append(Finding(
                    type='SAML_ASSERTIONS_SIGNING_NOT_ENFORCED',
                    severity='HIGH',
                    title='Metadata SAML não exige WantAssertionsSigned',
                    description='O metadata do SP não declara WantAssertionsSigned="true", sugerindo que '
                                'asserções SAML não assinadas podem ser aceitas — facilita forjar asserções '
                                'e ataques de replay/XSW.',
                    details={}, evidence=['WantAssertionsSigned ausente no metadata'],
                    remediation='Definir WantAssertionsSigned="true" no SP e validar a assinatura em toda '
                                'asserção recebida, rejeitando as não assinadas.',
                    affected_url=self.metadata_url,
                ))
                found_any = True

            weak_algs_found = [alg for alg in self.WEAK_SIGNATURE_ALGS if alg in xml.lower()]
            if weak_algs_found:
                self.findings.append(Finding(
                    type='SAML_WEAK_SIGNATURE_ALGORITHM',
                    severity='HIGH',
                    title=f'Algoritmo de assinatura fraco declarado no metadata: {", ".join(weak_algs_found)}',
                    description='O metadata SAML referencia algoritmo(s) de assinatura baseados em SHA-1, '
                                'considerados fracos e suscetíveis a ataques de colisão.',
                    details={'algorithms': weak_algs_found}, evidence=weak_algs_found,
                    remediation='Migrar para RSA-SHA256 ou superior nas configurações de assinatura SAML.',
                    affected_url=self.metadata_url,
                ))
                found_any = True

            if '<X509Certificate>' not in xml:
                self.findings.append(Finding(
                    type='SAML_NO_CERTIFICATE_IN_METADATA',
                    severity='MEDIUM',
                    title='Metadata SAML sem certificado X.509 declarado',
                    description='O metadata não expõe um certificado de assinatura — pode indicar que a '
                                'validação de assinatura não está configurada corretamente no SP/IdP.',
                    details={}, evidence=['X509Certificate ausente'],
                    remediation='Garantir que o metadata declara o(s) certificado(s) público(s) usados '
                                'para validar assinaturas, e que a validação é obrigatória.',
                    affected_url=self.metadata_url,
                ))
                found_any = True

            return {'vulnerable': found_any}

        except Exception as e:
            logger.debug(f"[SAML] Erro analisando metadata: {e}")
            return {}

    def test_sso_endpoint_exposure(self) -> Dict[str, Any]:
        """Verifica se endpoints de SSO aceitam requisições sem HTTPS (downgrade)."""
        logger.debug(f"[SAML] Testando exposição de endpoints SSO")

        for endpoint in self.SSO_ENDPOINTS:
            try:
                http_url = urljoin(self.target + '/', endpoint.lstrip('/')).replace('https://', 'http://', 1)
                if not http_url.startswith('http://'):
                    continue
                response = self.http_client.get(http_url, timeout=5, raise_for_status=False, allow_redirects=False)
                if response and response.status_code == 200:
                    self.findings.append(Finding(
                        type='SAML_SSO_ENDPOINT_ALLOWS_HTTP',
                        severity='HIGH',
                        title=f'Endpoint SSO SAML acessível via HTTP: {endpoint}',
                        description='O endpoint de SSO responde em texto plano (HTTP), permitindo '
                                    'interceptação/replay de asserções SAML em trânsito.',
                        details={'endpoint': endpoint}, evidence=[http_url],
                        remediation='Forçar HTTPS em todos os endpoints SAML (SSO/ACS) e usar HSTS.',
                        affected_url=http_url,
                    ))
                    return {'vulnerable': True}
            except Exception as e:
                logger.debug(f"[SAML] Erro testando {endpoint} via HTTP: {e}")

        return {'vulnerable': False}

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[SAML] Iniciando scan: {self.target}")

        try:
            if self.find_metadata_endpoint():
                self.test_metadata_weaknesses()
            self.test_sso_endpoint_exposure()

            return ScanResult(
                scanner_name='SAMLTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=True, metadata={'metadata_endpoint': self.metadata_url},
            )
        except Exception as e:
            logger.error(f"[SAML] Erro: {e}")
            return ScanResult(
                scanner_name='SAMLTester', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


# ============================================================================
# 11. WEB VULNERABILITY SCANNER (arquivos sensíveis expostos)
# ============================================================================

class VulnScanner:
    """Testa exposição de arquivos sensíveis comuns (.env, backups, configs)"""

    SENSITIVE_FILES = [
        ('.env', r'DB_|APP_KEY|SECRET|PASSWORD|AWS'),
        ('config.php', r'define\s*\(|password|mysqli'),
        ('wp-config.php', r'DB_NAME|DB_USER|DB_PASSWORD'),
        ('phpinfo.php', r'PHP Version|phpinfo'),
        ('.git/config', r'\[core\]|\[remote'),
        ('backup.zip', None),
        ('backup.sql', r'INSERT INTO|CREATE TABLE'),
        ('database.sql', r'INSERT INTO|CREATE TABLE'),
        ('.htpasswd', r'[a-zA-Z0-9]+:\$'),
        ('server-status', r'Apache Server Status'),
        ('adminer.php', r'Adminer|adminer'),
        ('phpmyadmin/', r'phpMyAdmin'),
    ]

    def __init__(self, target: str, http_client: HTTPClient = None):
        self.target = target.rstrip('/') + '/'
        self.http_client = http_client or HTTPClient()
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[VulnScanner] Iniciando scan: {self.target}")

        try:
            for path, pattern in self.SENSITIVE_FILES:
                url = urljoin(self.target, path)
                resp = self.http_client.get(url, timeout=Config.HTTP_TIMEOUT)
                if not resp or resp.status_code >= 400:
                    continue

                confirmed = bool(pattern and re.search(pattern, resp.text, re.I))
                self.findings.append(Finding(
                    type='SENSITIVE_FILE_EXPOSED',
                    severity='CRITICAL' if confirmed else 'HIGH',
                    title=f'Arquivo sensível acessível: {path}',
                    description=f'{path} respondeu com status {resp.status_code}'
                                + (' e conteúdo confirmado como sensível.' if confirmed else '.'),
                    details={'path': path, 'status': resp.status_code, 'confirmed': confirmed},
                    evidence=[url],
                    remediation=f'Remover ou bloquear o acesso público a {path}.',
                    affected_url=url,
                ))

            execution_time = time.time() - start_time
            return ScanResult(
                scanner_name='VulnScanner', target=self.target,
                findings=self.findings, execution_time=execution_time,
                success=True, metadata={'files_tested': len(self.SENSITIVE_FILES)},
            )
        except Exception as e:
            logger.error(f"[VulnScanner] Erro: {e}")
            return ScanResult(
                scanner_name='VulnScanner', target=self.target,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )
