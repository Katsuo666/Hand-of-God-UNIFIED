# -*- coding: utf-8 -*-
"""
Scanners WHITE-BOX (analisam arquivos locais do projeto, não o alvo remoto):
dependências (supply chain) e Infrastructure as Code (IaC).

Dependency Confusion, typosquatting, protestware e tráfego inseguro do
gestor de pacotes só são detetáveis com acesso ao código-fonte/lockfiles —
por isso este módulo recebe um caminho de diretório, não uma URL.
"""

import json
import os
import re
import time
from typing import Any, Dict, List

from core.logger import get_logger
from .active_scanner import Finding, ScanResult

logger = get_logger(__name__)

# Nomes de pacotes populares usados como referência para detectar typosquatting
# (distância de edição 1 de um nome popular, mas não igual a ele).
POPULAR_PACKAGES = {
    'python': ['requests', 'numpy', 'flask', 'django', 'pandas', 'urllib3',
               'pyyaml', 'boto3', 'cryptography', 'pillow', 'six'],
    'npm': ['react', 'lodash', 'express', 'axios', 'chalk', 'commander',
            'moment', 'webpack', 'vue', 'jquery'],
}


def _levenshtein1(a: str, b: str) -> bool:
    """True se `a` e `b` têm distância de edição exatamente 1 (typosquat clássico)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = sum(1 for x, y in zip(a, b) if x != y)
        return diffs == 1
    longer, shorter = (a, b) if len(a) > len(b) else (b, a)
    for i in range(len(longer)):
        if longer[:i] + longer[i + 1:] == shorter:
            return True
    return False


class DependencyScanner:
    """Analisa requirements.txt/package.json locais em busca de riscos de supply chain."""

    def __init__(self, project_path: str):
        self.project_path = project_path
        self.findings: List[Finding] = []

    def _check_requirements_txt(self, path: str) -> None:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line.startswith('http://') or '--index-url http://' in line or '-i http://' in line:
                self.findings.append(Finding(
                    type='SUPPLY_CHAIN_INSECURE_REGISTRY', severity='HIGH',
                    title='Dependência instalada via HTTP não encriptado',
                    description=f'A linha "{line}" referencia um índice/URL de pacote via HTTP, '
                                'permitindo Man-in-the-Middle no pipeline de build.',
                    details={'line': line, 'file': path}, evidence=[line],
                    remediation='Usar sempre HTTPS para índices de pacotes (--index-url https://...).',
                    affected_url=path,
                ))

            pkg_match = re.match(r'^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<)?\s*([\w.\-]*)', line)
            if not pkg_match:
                continue
            pkg_name = pkg_match.group(1).lower()
            has_pin = bool(pkg_match.group(2))

            if not has_pin:
                self.findings.append(Finding(
                    type='SUPPLY_CHAIN_UNPINNED_DEPENDENCY', severity='LOW',
                    title=f'Dependência sem versão fixada: {pkg_name}',
                    description='Instalar sem pin de versão expõe a builds futuros silenciosamente '
                                'trocados (protestware/sabotagem) ou a versões maliciosas recém-publicadas.',
                    details={'package': pkg_name, 'file': path}, evidence=[line],
                    remediation=f'Fixar a versão exata: {pkg_name}==<versão testada>.',
                    affected_url=path,
                ))

            for popular in POPULAR_PACKAGES['python']:
                if pkg_name != popular and _levenshtein1(pkg_name, popular):
                    self.findings.append(Finding(
                        type='SUPPLY_CHAIN_TYPOSQUATTING_SUSPECT', severity='HIGH',
                        title=f'Possível typosquatting: "{pkg_name}" parece com "{popular}"',
                        description=f'O nome do pacote "{pkg_name}" difere de apenas 1 caractere do pacote '
                                    f'popular "{popular}" — verificar se não é um erro de digitação.',
                        details={'package': pkg_name, 'similar_to': popular, 'file': path},
                        evidence=[line],
                        remediation=f'Confirmar se o pacote correto não é "{popular}".',
                        affected_url=path,
                    ))

    def _check_package_json(self, path: str) -> None:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)

        all_deps: Dict[str, str] = {}
        all_deps.update(data.get('dependencies', {}) or {})
        all_deps.update(data.get('devDependencies', {}) or {})

        for pkg_name, version in all_deps.items():
            pkg_lower = pkg_name.lower()

            if isinstance(version, str) and version.startswith('http://'):
                self.findings.append(Finding(
                    type='SUPPLY_CHAIN_INSECURE_REGISTRY', severity='HIGH',
                    title=f'Dependência "{pkg_name}" referenciada via HTTP não encriptado',
                    description=f'A versão "{version}" de "{pkg_name}" é buscada via HTTP.',
                    details={'package': pkg_name, 'version': version, 'file': path},
                    evidence=[f'{pkg_name}: {version}'],
                    remediation='Usar apenas fontes HTTPS/registry oficial (npm registry) para dependências.',
                    affected_url=path,
                ))

            for popular in POPULAR_PACKAGES['npm']:
                if pkg_lower != popular and _levenshtein1(pkg_lower, popular):
                    self.findings.append(Finding(
                        type='SUPPLY_CHAIN_TYPOSQUATTING_SUSPECT', severity='HIGH',
                        title=f'Possível typosquatting: "{pkg_name}" parece com "{popular}"',
                        description=f'O nome do pacote "{pkg_name}" difere de apenas 1 caractere do pacote '
                                    f'popular "{popular}" — verificar se não é um erro de digitação.',
                        details={'package': pkg_name, 'similar_to': popular, 'file': path},
                        evidence=[f'{pkg_name}: {version}'],
                        remediation=f'Confirmar se o pacote correto não é "{popular}".',
                        affected_url=path,
                    ))

        npmrc_path = os.path.join(os.path.dirname(path), '.npmrc')
        if os.path.isfile(npmrc_path):
            with open(npmrc_path, 'r', encoding='utf-8', errors='ignore') as f:
                npmrc = f.read()
            if 'registry=http://' in npmrc:
                self.findings.append(Finding(
                    type='SUPPLY_CHAIN_INSECURE_REGISTRY', severity='HIGH',
                    title='.npmrc configurado com registry HTTP',
                    description='O .npmrc aponta para um registry npm via HTTP, sem TLS.',
                    details={'file': npmrc_path}, evidence=['registry=http://...'],
                    remediation='Usar registry=https://registry.npmjs.org/ (ou registry privado com HTTPS).',
                    affected_url=npmrc_path,
                ))

    def _check_dependency_confusion_risk(self) -> None:
        """Sinaliza pacotes internos (sem escopo/prefixo) que poderiam colidir com o registry público."""
        pkg_json_path = os.path.join(self.project_path, 'package.json')
        if not os.path.isfile(pkg_json_path):
            return
        try:
            with open(pkg_json_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            name = data.get('name', '')
            if name and not name.startswith('@'):
                self.findings.append(Finding(
                    type='SUPPLY_CHAIN_DEPENDENCY_CONFUSION_RISK', severity='MEDIUM',
                    title=f'Pacote interno "{name}" sem escopo (@org/) — risco de Dependency Confusion',
                    description='Se este pacote é interno/privado e alguém publicar um pacote público '
                                'com o mesmo nome no npm, builds podem instalar a versão pública maliciosa.',
                    details={'package': name}, evidence=[name],
                    remediation=f'Publicar como pacote com escopo (@sua-org/{name}) e configurar '
                                '.npmrc para resolver o escopo apenas no registry privado.',
                    affected_url=pkg_json_path,
                ))
        except Exception as e:
            logger.debug(f"[DependencyScanner] Erro checando dependency confusion: {e}")

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[DependencyScanner] Iniciando scan: {self.project_path}")

        try:
            requirements_path = os.path.join(self.project_path, 'requirements.txt')
            if os.path.isfile(requirements_path):
                self._check_requirements_txt(requirements_path)

            package_json_path = os.path.join(self.project_path, 'package.json')
            if os.path.isfile(package_json_path):
                self._check_package_json(package_json_path)
                self._check_dependency_confusion_risk()

            return ScanResult(
                scanner_name='DependencyScanner', target=self.project_path,
                findings=self.findings, execution_time=time.time() - start_time, success=True,
            )
        except Exception as e:
            logger.error(f"[DependencyScanner] Erro: {e}")
            return ScanResult(
                scanner_name='DependencyScanner', target=self.project_path,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )


class IaCScanner:
    """Analisa arquivos Terraform/CloudFormation/Ansible locais em busca de configs inseguras."""

    TERRAFORM_CHECKS = [
        (re.compile(r'cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"'), 'IAC_OPEN_SECURITY_GROUP', 'HIGH',
         'Security group/regra de firewall aberta para 0.0.0.0/0',
         'Restringir cidr_blocks a faixas de IP específicas necessárias.'),
        (re.compile(r'acl\s*=\s*"public-read(-write)?"'), 'IAC_PUBLIC_BUCKET', 'CRITICAL',
         'Bucket S3/storage configurado com ACL pública',
         'Definir acl = "private" e usar políticas de bucket explícitas para acesso controlado.'),
        (re.compile(r'\bencrypted\s*=\s*false'), 'IAC_UNENCRYPTED_STORAGE', 'HIGH',
         'Recurso de storage/volume criado sem encriptação (encrypted = false)',
         'Definir encrypted = true em volumes/buckets/bancos de dados.'),
        (re.compile(r'publicly_accessible\s*=\s*true'), 'IAC_PUBLIC_DATABASE', 'CRITICAL',
         'Banco de dados criado com publicly_accessible = true',
         'Definir publicly_accessible = false e usar VPC/security groups para acesso.'),
        (re.compile(r'management_type\s*=\s*"MANAGED"|force_destroy\s*=\s*true'), 'IAC_FORCE_DESTROY', 'LOW',
         'Recurso com force_destroy habilitado',
         'Revisar se force_destroy é realmente necessário (risco de perda de dados).'),
    ]

    ANSIBLE_CHECKS = [
        (re.compile(r'mode:\s*["\']?0?777'), 'IAC_INSECURE_FILE_PERMISSIONS', 'MEDIUM',
         'Task do Ansible define permissões de arquivo 777 (leitura/escrita/execução para todos)',
         'Usar o menor privilégio necessário (ex.: 0644 para arquivos, 0750 para diretórios).'),
        (re.compile(r'no_log:\s*false'), 'IAC_ANSIBLE_SECRETS_LOGGED', 'MEDIUM',
         'Task sem no_log pode vazar secrets nos logs do Ansible',
         'Definir no_log: true em tasks que manipulam credenciais/secrets.'),
    ]

    IAC_EXTENSIONS = {'.tf', '.tfvars', '.yml', '.yaml'}

    def __init__(self, project_path: str):
        self.project_path = project_path
        self.findings: List[Finding] = []

    def _scan_file(self, path: str) -> None:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.debug(f"[IaCScanner] Erro lendo {path}: {e}")
            return

        checks = self.TERRAFORM_CHECKS if path.endswith(('.tf', '.tfvars')) else self.ANSIBLE_CHECKS

        for pattern, ftype, severity, title, remediation in checks:
            for match in pattern.finditer(content):
                line_no = content[:match.start()].count('\n') + 1
                self.findings.append(Finding(
                    type=ftype, severity=severity, title=title,
                    description=f'{title} (arquivo: {os.path.basename(path)}, linha {line_no}).',
                    details={'file': path, 'line': line_no},
                    evidence=[match.group(0)],
                    remediation=remediation,
                    affected_url=f'{path}:{line_no}',
                ))

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[IaCScanner] Iniciando scan: {self.project_path}")
        files_scanned = 0

        try:
            for root, dirs, files in os.walk(self.project_path):
                dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', 'venv', '.terraform')]
                for filename in files:
                    if os.path.splitext(filename)[1] in self.IAC_EXTENSIONS:
                        self._scan_file(os.path.join(root, filename))
                        files_scanned += 1

            return ScanResult(
                scanner_name='IaCScanner', target=self.project_path,
                findings=self.findings, execution_time=time.time() - start_time,
                success=True, metadata={'files_scanned': files_scanned},
            )
        except Exception as e:
            logger.error(f"[IaCScanner] Erro: {e}")
            return ScanResult(
                scanner_name='IaCScanner', target=self.project_path,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )
