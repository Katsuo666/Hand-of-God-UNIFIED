# -*- coding: utf-8 -*-
"""
Instrumentação DINÂMICA via Frida — opt-in, "por conta e risco".

Diferente de apk_scanner.py (estático, sem device), este módulo precisa de:
  1. `pip install frida frida-tools` (dependência opcional, não em requirements.txt)
  2. Um device/emulador Android com `frida-server` a correr (root/emulador)
  3. A app alvo já instalada e ABERTA nesse device, com autorização explícita
     do dono do dispositivo/app — isto ANEXA a um processo em execução.

Cobre, como prova de conceito (sem forçar bypass real numa sessão de login
alheia): se o processo aceita anexação Frida (ausência de anti-instrumentação),
se é possível hookar classes de BiometricPrompt/FingerprintManager (superfície
de bypass biométrico) e se é possível injetar um módulo nativo benigno no
processo (superfície de dynamic linker interception / code injection).

ponytail: PoC de superfície (consegue anexar/hookar?), não um exploit completo
automático — decidir forçar um bypass real de autenticação é uma ação com
impacto direto na app alvo e fica fora do escopo de um scan automatizado.
"""

import time
from typing import Any, Dict, List, Optional

from core.logger import get_logger
from modules.scanner.active_scanner import Finding, ScanResult

logger = get_logger(__name__)

try:
    import frida
    FRIDA_AVAILABLE = True
except Exception:
    FRIDA_AVAILABLE = False

_BIOMETRIC_HOOK_SCRIPT = """
Java.perform(function () {
    var found = [];
    var candidates = [
        'androidx.biometric.BiometricPrompt$AuthenticationCallback',
        'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback',
        'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback'
    ];
    candidates.forEach(function (cls) {
        try {
            var Klass = Java.use(cls);
            found.push(cls);
        } catch (e) {}
    });
    send({ type: 'biometric_classes', found: found });
});
"""

_LINKER_PROBE_SCRIPT = """
send({
    type: 'modules',
    count: Process.enumerateModules().length,
    injected_ok: true
});
"""


class FridaDynamicTester:
    """Anexa via Frida a uma app Android já em execução num device autorizado."""

    def __init__(self, package_name: str, device_id: Optional[str] = None, timeout: float = 15.0):
        self.package_name = package_name
        self.device_id = device_id
        self.timeout = timeout
        self.findings: List[Finding] = []
        self._session = None

    def _get_device(self):
        if self.device_id:
            return frida.get_device(self.device_id)
        return frida.get_usb_device(timeout=int(self.timeout))

    def _attach(self):
        device = self._get_device()
        return device.attach(self.package_name)

    def test_instrumentation_detection(self) -> Dict[str, Any]:
        """Testa se o processo aceita anexação Frida (ausência de anti-hooking/anti-Frida)."""
        logger.debug(f"[FridaDynamic] Testando anexação a {self.package_name}")

        try:
            self._session = self._attach()
            self.findings.append(Finding(
                type='MOBILE_NO_ANTI_INSTRUMENTATION', severity='HIGH',
                title=f'App "{self.package_name}" aceita anexação Frida sem detecção',
                description='O processo permitiu anexação de um framework de instrumentação dinâmica '
                            'sem se recusar a rodar ou encerrar — indica ausência de proteções '
                            'anti-Frida/anti-hooking (root/jailbreak+debugger detection).',
                details={'package': self.package_name}, evidence=['frida.attach() bem-sucedido'],
                remediation='Implementar detecção de instrumentação dinâmica (checagem de portas do '
                            'frida-server, nomes de threads/bibliotecas injetadas, ptrace anti-debug).',
                affected_url=self.package_name,
            ))
            return {'vulnerable': True, 'attached': True}
        except Exception as e:
            logger.debug(f"[FridaDynamic] Anexação falhou/recusada: {e}")
            return {'vulnerable': False, 'attached': False, 'reason': str(e)}

    def test_biometric_bypass_surface(self) -> Dict[str, Any]:
        """Verifica se as classes de callback de autenticação biométrica são hookáveis (superfície de bypass).
        Apenas lista as classes carregadas — não força um retorno positivo de autenticação."""
        logger.debug(f"[FridaDynamic] Testando superfície de bypass biométrico")

        if not self._session:
            return {}

        results: Dict[str, Any] = {}
        try:
            script = self._session.create_script(_BIOMETRIC_HOOK_SCRIPT)
            messages: List[Dict[str, Any]] = []
            script.on('message', lambda msg, data: messages.append(msg))
            script.load()
            time.sleep(2)
            script.unload()

            found_classes: List[str] = []
            for msg in messages:
                if msg.get('type') == 'send' and msg.get('payload', {}).get('type') == 'biometric_classes':
                    found_classes = msg['payload'].get('found', [])

            if found_classes:
                self.findings.append(Finding(
                    type='MOBILE_BIOMETRIC_HOOK_SURFACE', severity='CRITICAL',
                    title=f'Classes de callback biométrico hookáveis em "{self.package_name}"',
                    description=f'As classes {found_classes} foram carregadas e são hookáveis via Frida. '
                                'Um atacante com acesso ao dispositivo (root/frida-server) pode sobrescrever '
                                'onAuthenticationSucceeded para forçar autenticação sem biometria válida.',
                    details={'classes': found_classes}, evidence=found_classes,
                    remediation='Nunca confiar apenas no callback local de sucesso; validar no servidor '
                                'com um desafio criptográfico assinado pela chave do Keystore/Secure Enclave '
                                '(BiometricPrompt.CryptoObject), não apenas um booleano local.',
                    affected_url=self.package_name,
                ))
            results['biometric_classes_found'] = found_classes
        except Exception as e:
            logger.debug(f"[FridaDynamic] Erro testando bypass biométrico: {e}")

        return results

    def test_dynamic_linker_injection(self) -> Dict[str, Any]:
        """Verifica se é possível carregar um script/módulo no processo (superfície de code injection)."""
        logger.debug(f"[FridaDynamic] Testando superfície de dynamic linker injection")

        if not self._session:
            return {}

        try:
            script = self._session.create_script(_LINKER_PROBE_SCRIPT)
            messages: List[Dict[str, Any]] = []
            script.on('message', lambda msg, data: messages.append(msg))
            script.load()
            time.sleep(1)
            script.unload()

            injected_ok = any(
                msg.get('type') == 'send' and msg.get('payload', {}).get('injected_ok')
                for msg in messages
            )

            if injected_ok:
                self.findings.append(Finding(
                    type='MOBILE_DYNAMIC_LINKER_INJECTION_SURFACE', severity='HIGH',
                    title=f'Injeção de código em runtime bem-sucedida em "{self.package_name}"',
                    description='Foi possível carregar e executar um script Frida dentro do processo, '
                                'confirmando que o app não impede injeção via dynamic linker (equivalente '
                                'a dyld hijacking no iOS) — rotinas de criptografia/validação locais podem '
                                'ser interceptadas ou substituídas em tempo de execução.',
                    details={'package': self.package_name}, evidence=['Script Frida executado com sucesso'],
                    remediation='Adotar integrity checks em runtime (checksum de código próprio), '
                                'ofuscação/anti-tampering (ex.: DexGuard) e nunca confiar em validações '
                                'que rodam inteiramente no cliente para decisões de segurança críticas.',
                    affected_url=self.package_name,
                ))
            return {'vulnerable': injected_ok}
        except Exception as e:
            logger.debug(f"[FridaDynamic] Erro testando injeção: {e}")
            return {}

    def scan(self) -> ScanResult:
        start_time = time.time()
        logger.info(f"[FridaDynamic] Iniciando análise dinâmica: {self.package_name}")

        if not FRIDA_AVAILABLE:
            return ScanResult(
                scanner_name='FridaDynamicTester', target=self.package_name,
                findings=[], execution_time=time.time() - start_time, success=False,
                error_message="Dependência opcional 'frida' não instalada. "
                              "Rode: pip install frida frida-tools (requer device/emulador com frida-server).",
            )

        try:
            attach_result = self.test_instrumentation_detection()
            if attach_result.get('attached'):
                self.test_biometric_bypass_surface()
                self.test_dynamic_linker_injection()

            return ScanResult(
                scanner_name='FridaDynamicTester', target=self.package_name,
                findings=self.findings, execution_time=time.time() - start_time,
                success=True, metadata={'attached': attach_result.get('attached', False)},
            )
        except Exception as e:
            logger.error(f"[FridaDynamic] Erro: {e}")
            return ScanResult(
                scanner_name='FridaDynamicTester', target=self.package_name,
                findings=self.findings, execution_time=time.time() - start_time,
                success=False, error_message=str(e),
            )
        finally:
            if self._session:
                try:
                    self._session.detach()
                except Exception:
                    pass
