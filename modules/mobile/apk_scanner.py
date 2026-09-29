# -*- coding: utf-8 -*-
"""
Análise ESTÁTICA de segurança de um APK Android (sem instrumentação/Frida,
sem device/emulador — só parsing do próprio arquivo .apk via `androguard`).
Cobre: manifest (debuggable/allowBackup/exported/cleartext), secrets
hardcoded (reaproveita os padrões de modules/ai/secret_scanner.py), indícios
de SSL pinning ausente, deep links, ausência de ofuscação e FLAG_SECURE.

ponytail: heurísticas por string/regex no manifest e no dex bruto, não uma
descompilação completa (jadx/apktool) — suficiente para uma triagem rápida;
para um relatório definitivo, revisar manualmente os achados MEDIUM/LOW.
"""

import re
import time
from typing import Any, Dict, List

from core.logger import get_logger
from modules.ai.secret_scanner import SECRET_SIGNATURES
from modules.scanner.active_scanner import Finding, ScanResult

logger = get_logger(__name__)

try:
    from androguard.core.bytecodes.apk import APK
    ANDROGUARD_AVAILABLE = True
except Exception:
    ANDROGUARD_AVAILABLE = False

DANGEROUS_PERMISSIONS = [
    'READ_SMS', 'SEND_SMS', 'READ_CONTACTS', 'WRITE_CONTACTS',
    'ACCESS_FINE_LOCATION', 'RECORD_AUDIO', 'CAMERA', 'READ_CALL_LOG',
    'WRITE_CALL_LOG', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
    'SYSTEM_ALERT_WINDOW', 'REQUEST_INSTALL_PACKAGES',
]

INSECURE_TRUST_SIGNATURES = [
    b'checkServerTrusted', b'X509TrustManager', b'ALLOW_ALL_HOSTNAME_VERIFIER',
    b'setHostnameVerifier',
]


class ApkStaticScanner:
    """Recebe caminho de um .apk e devolve um ScanResult com achados estáticos."""

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.findings: List[Finding] = []

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[ApkStaticScanner] Iniciando análise: {self.apk_path}")

        if not ANDROGUARD_AVAILABLE:
            return ScanResult(
                scanner_name='ApkStaticScanner', target=self.apk_path,
                findings=[], execution_time=time.time() - start_time, success=False,
                error_message="Dependência 'androguard' não instalada. Rode: pip install androguard",
            )

        try:
            apk = APK(self.apk_path)
            manifest_xml = apk.get_android_manifest_axml().get_xml().decode('utf-8', errors='ignore')

            self._check_manifest_flags(manifest_xml)
            self._check_permissions(apk)
            self._check_exported_components(manifest_xml)
            self._check_deep_links(manifest_xml)
            self._check_strandhogg(manifest_xml)

            dex_bytes = self._get_dex_bytes(apk)
            if dex_bytes:
                self._check_hardcoded_secrets(dex_bytes)
                self._check_ssl_pinning(dex_bytes)
                self._check_obfuscation(dex_bytes)
                self._check_flag_secure(dex_bytes)
                self._check_tapjacking(dex_bytes)
                self._check_clipboard_exposure(dex_bytes)
                self._check_keystore_usage(dex_bytes)

            metadata = {
                'package': apk.get_package(),
                'version_name': apk.get_androidversion_name(),
                'min_sdk': apk.get_min_sdk_version(),
                'target_sdk': apk.get_target_sdk_version(),
            }

            return ScanResult(
                scanner_name='ApkStaticScanner', target=self.apk_path,
                findings=self.findings, execution_time=time.time() - start_time,
                success=True, metadata=metadata,
            )
        except Exception as e:
            logger.error(f"[ApkStaticScanner] Erro: {e}")
            return ScanResult(
                scanner_name='ApkStaticScanner', target=self.apk_path,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )

    def _check_manifest_flags(self, manifest_xml: str) -> None:
        checks = [
            ('android:debuggable="true"', 'APK_DEBUGGABLE', 'HIGH',
             'Aplicativo compilado com android:debuggable="true"',
             'Remover android:debuggable ou setar "false" no build de release.'),
            ('android:allowBackup="true"', 'APK_ALLOW_BACKUP', 'MEDIUM',
             'android:allowBackup="true" permite extrair dados do app via adb backup',
             'Definir android:allowBackup="false" no AndroidManifest.xml.'),
            ('android:usesCleartextTraffic="true"', 'APK_CLEARTEXT_TRAFFIC', 'HIGH',
             'App permite tráfego HTTP em texto plano (usesCleartextTraffic="true")',
             'Definir usesCleartextTraffic="false" e usar Network Security Config restritiva.'),
        ]
        for needle, ftype, severity, title, remediation in checks:
            if needle in manifest_xml:
                self.findings.append(Finding(
                    type=ftype, severity=severity, title=title,
                    description=title, details={}, evidence=[needle],
                    remediation=remediation, affected_url=self.apk_path,
                ))

        if 'usesCleartextTraffic' not in manifest_xml:
            self.findings.append(Finding(
                type='APK_CLEARTEXT_TRAFFIC_DEFAULT', severity='LOW',
                title='usesCleartextTraffic não definido explicitamente',
                description='Sem o atributo, o padrão depende do targetSdkVersion (permitido em SDK < 28).',
                details={}, evidence=['usesCleartextTraffic ausente'],
                remediation='Definir explicitamente usesCleartextTraffic="false" e Network Security Config.',
                affected_url=self.apk_path,
            ))

    def _check_permissions(self, apk) -> None:
        try:
            perms = apk.get_permissions() or []
        except Exception:
            perms = []
        dangerous_found = [p for p in perms if any(d in p for d in DANGEROUS_PERMISSIONS)]
        if dangerous_found:
            self.findings.append(Finding(
                type='APK_DANGEROUS_PERMISSIONS', severity='INFO',
                title=f'{len(dangerous_found)} permissão(ões) perigosa(s) declarada(s)',
                description='Revisar se cada permissão é realmente necessária para a funcionalidade do app.',
                details={'permissions': dangerous_found}, evidence=dangerous_found,
                remediation='Remover permissões não usadas (princípio do menor privilégio).',
                affected_url=self.apk_path,
            ))

    def _check_exported_components(self, manifest_xml: str) -> None:
        # ponytail: heurística por regex no XML bruto (tag a tag), não um parser
        # DOM completo com namespaces — suficiente para sinalizar candidatos.
        tag_re = re.compile(r'<(activity|service|receiver|provider)\b([^>]*)/?>', re.I)
        exported_without_permission = 0
        for match in tag_re.finditer(manifest_xml):
            attrs = match.group(2)
            if 'exported="true"' in attrs and 'permission=' not in attrs:
                exported_without_permission += 1

        if exported_without_permission:
            self.findings.append(Finding(
                type='APK_EXPORTED_COMPONENT_NO_PERMISSION', severity='HIGH',
                title=f'{exported_without_permission} componente(s) exportado(s) sem permission',
                description='Activities/Services/Receivers/Providers com exported="true" e sem '
                            'android:permission podem ser invocados por qualquer app instalado.',
                details={'count': exported_without_permission},
                evidence=[f'{exported_without_permission} ocorrências'],
                remediation='Definir android:permission ou exported="false" nesses componentes.',
                affected_url=self.apk_path,
            ))

    def _check_deep_links(self, manifest_xml: str) -> None:
        if '<data' in manifest_xml and 'android:scheme=' in manifest_xml:
            schemes = set(re.findall(r'android:scheme="([^"]+)"', manifest_xml))
            custom_schemes = schemes - {'http', 'https'}
            if custom_schemes:
                self.findings.append(Finding(
                    type='APK_CUSTOM_DEEP_LINK', severity='LOW',
                    title=f'Deep link(s) customizado(s) detectado(s): {", ".join(sorted(custom_schemes))}',
                    description='Deep links customizados podem ser usados por apps maliciosos para '
                                'invocar Activities/interceptar dados se não validados corretamente.',
                    details={'schemes': sorted(custom_schemes)}, evidence=sorted(custom_schemes),
                    remediation='Validar todo parâmetro recebido via deep link; preferir App Links (https) verificados.',
                    affected_url=self.apk_path,
                ))

    def _check_strandhogg(self, manifest_xml: str) -> None:
        """Heurística StrandHogg 1.0: Activity não-principal com taskAffinity customizado
        + launchMode singleTask/singleInstance, permitindo sequestro de tarefa (task hijacking)."""
        activity_re = re.compile(r'<activity\b([^>]*)/?>', re.I)
        suspicious = 0
        for match in activity_re.finditer(manifest_xml):
            attrs = match.group(1)
            has_task_affinity = bool(re.search(r'android:taskAffinity="[^"]*"', attrs))
            launch_mode_match = re.search(r'android:launchMode="([^"]+)"', attrs)
            launch_mode = launch_mode_match.group(1) if launch_mode_match else ''
            is_main = 'MAIN' in attrs or 'LAUNCHER' in attrs

            if has_task_affinity and launch_mode in ('singleTask', 'singleInstance') and not is_main:
                suspicious += 1

        if suspicious:
            self.findings.append(Finding(
                type='APK_STRANDHOGG_RISK', severity='HIGH',
                title=f'{suspicious} Activity(s) com padrão vulnerável a StrandHogg (task hijacking)',
                description='Activity(s) não-principal(is) com taskAffinity customizado e '
                            'launchMode singleTask/singleInstance permitem que um app malicioso '
                            'sobreponha sua tela na tarefa da vítima.',
                details={'count': suspicious}, evidence=[f'{suspicious} ocorrências'],
                remediation='Remover taskAffinity customizado ou usar launchMode="standard"; '
                            'atualizar targetSdkVersion (Android 10+ mitiga parcialmente).',
                affected_url=self.apk_path,
            ))

    def _check_tapjacking(self, dex_bytes: bytes) -> None:
        """Ausência de filterTouchesWhenObscured indica possível vulnerabilidade a tapjacking."""
        if b'setFilterTouchesWhenObscured' not in dex_bytes and b'filterTouchesWhenObscured' not in dex_bytes:
            self.findings.append(Finding(
                type='APK_TAPJACKING_RISK', severity='MEDIUM',
                title='FilterTouchesWhenObscured não encontrado no bytecode',
                description='O app não parece usar setFilterTouchesWhenObscured/android:filterTouchesWhenObscured '
                            'em nenhuma view, permitindo que overlays maliciosos capturem toques (tapjacking).',
                details={}, evidence=['filterTouchesWhenObscured ausente'],
                remediation='Definir android:filterTouchesWhenObscured="true" em botões/views críticas '
                            '(confirmação de pagamento, permissões, login).',
                affected_url=self.apk_path,
            ))

    def _check_clipboard_exposure(self, dex_bytes: bytes) -> None:
        """Uso de ClipboardManager sem indício de limpeza posterior pode expor dados sensíveis."""
        if b'ClipboardManager' in dex_bytes and b'setPrimaryClip' in dex_bytes:
            has_sensitive_hint = any(
                kw in dex_bytes for kw in (b'password', b'senha', b'token', b'secret', b'cvv', b'card')
            )
            if has_sensitive_hint:
                self.findings.append(Finding(
                    type='APK_INSECURE_CLIPBOARD_EXPOSURE', severity='MEDIUM',
                    title='Uso de Clipboard próximo a strings sensíveis (password/token/cartão)',
                    description='O app usa ClipboardManager.setPrimaryClip() e contém strings relacionadas a '
                                'dados sensíveis — verificar se senhas/tokens são copiados sem necessidade, '
                                'já que ficam acessíveis a outros apps via clipboard global.',
                    details={}, evidence=['ClipboardManager + termo sensível no bytecode'],
                    remediation='Evitar copiar dados sensíveis para o clipboard; se necessário, usar '
                                'ClipDescription.EXTRA_IS_SENSITIVE (Android 13+) e limpar após uso.',
                    affected_url=self.apk_path,
                ))

    def _check_keystore_usage(self, dex_bytes: bytes) -> None:
        """Uso de criptografia (Cipher) sem referência ao AndroidKeyStore sugere chaves não protegidas por hardware."""
        if b'javax/crypto/Cipher' in dex_bytes and b'AndroidKeyStore' not in dex_bytes:
            self.findings.append(Finding(
                type='APK_NO_ANDROID_KEYSTORE', severity='MEDIUM',
                title='Uso de criptografia sem AndroidKeyStore',
                description='O app usa javax.crypto.Cipher mas não referencia "AndroidKeyStore" — '
                            'as chaves de criptografia podem estar em memória/hardcoded em vez de '
                            'protegidas pelo hardware-backed Keystore/Secure Element.',
                details={}, evidence=['Cipher presente, AndroidKeyStore ausente'],
                remediation='Gerar e armazenar chaves via android.security.keystore.KeyGenParameterSpec '
                            'com o provider "AndroidKeyStore".',
                affected_url=self.apk_path,
            ))

    def _get_dex_bytes(self, apk) -> bytes:
        try:
            return apk.get_dex() or b''
        except Exception:
            return b''

    def _check_hardcoded_secrets(self, dex_bytes: bytes) -> None:
        text = dex_bytes.decode('utf-8', errors='ignore')
        seen = set()
        for signature_id, spec in SECRET_SIGNATURES.items():
            label = spec['label']
            for match in re.finditer(spec['pattern'], text):
                value = match.group(0)
                key = f'{signature_id}:{value[:30]}'
                if key in seen:
                    continue
                seen.add(key)
                self.findings.append(Finding(
                    type='APK_HARDCODED_SECRET', severity='CRITICAL',
                    title=f'Secret hardcoded no bytecode: {label}',
                    description=f'Encontrado padrão de {label} embutido diretamente no código.',
                    details={'kind': label}, evidence=[value[:80]],
                    remediation='Mover secrets para armazenamento seguro (Keystore/backend), nunca hardcode.',
                    affected_url=self.apk_path,
                ))

    def _check_ssl_pinning(self, dex_bytes: bytes) -> None:
        if any(sig in dex_bytes for sig in INSECURE_TRUST_SIGNATURES):
            self.findings.append(Finding(
                type='APK_POSSIBLE_NO_SSL_PINNING', severity='MEDIUM',
                title='Indício de TrustManager/HostnameVerifier customizado',
                description='O app implementa checkServerTrusted/X509TrustManager/HostnameVerifier próprios — '
                            'verificar manualmente se aceitam qualquer certificado (bypass de SSL pinning).',
                details={}, evidence=['TrustManager customizado detectado'],
                remediation='Usar SSL pinning real (Network Security Config pin-set ou OkHttp CertificatePinner).',
                affected_url=self.apk_path,
            ))

    def _check_obfuscation(self, dex_bytes: bytes) -> None:
        # ponytail: heurística simples por nomes de pacote legíveis conhecidos vs.
        # nomes curtos típicos de ProGuard/R8 — não é uma métrica exata.
        text = dex_bytes.decode('utf-8', errors='ignore')
        readable_packages = len(re.findall(r'L(com|org|net)/[a-z]+/[a-z]{4,}/', text))
        obfuscated_like = len(re.findall(r'L[a-z]/[a-z]/[a-z];', text))
        if readable_packages > 20 and obfuscated_like < 5:
            self.findings.append(Finding(
                type='APK_NO_OBFUSCATION', severity='LOW',
                title='APK parece não estar ofuscado (ProGuard/R8)',
                description='Nomes de pacote/classe legíveis predominam, facilitando engenharia reversa.',
                details={'readable_packages_sample': readable_packages},
                evidence=[f'{readable_packages} nomes de pacote legíveis encontrados'],
                remediation='Habilitar minifyEnabled/R8 (ou ProGuard) no build de release.',
                affected_url=self.apk_path,
            ))

    def _check_flag_secure(self, dex_bytes: bytes) -> None:
        if b'FLAG_SECURE' not in dex_bytes:
            self.findings.append(Finding(
                type='APK_NO_FLAG_SECURE', severity='LOW',
                title='FLAG_SECURE não encontrado no bytecode',
                description='O app não parece usar WindowManager.LayoutParams.FLAG_SECURE em nenhuma tela — '
                            'screenshots e a prévia no gerenciador de tarefas podem expor dados sensíveis.',
                details={}, evidence=['FLAG_SECURE ausente'],
                remediation='Aplicar FLAG_SECURE nas telas com dados sensíveis (login, dados financeiros, etc.).',
                affected_url=self.apk_path,
            ))
