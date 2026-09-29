# -*- coding: utf-8 -*-
"""
Contexto compartilhado entre módulos
Permite comunicação e compartilhamento de estado entre componentes
"""

from typing import Any, Dict, Optional, List, Callable
from datetime import datetime
from threading import Lock
from .logger import get_logger

logger = get_logger(__name__)


class SharedContext:
    """Contexto global compartilhado entre módulos"""

    _instance: Optional['SharedContext'] = None
    _lock = Lock()

    # Data storage
    _data: Dict[str, Any] = {}
    _metadata: Dict[str, Dict[str, Any]] = {}

    # Listeners para mudanças
    _listeners: Dict[str, List[Callable]] = {}

    def __new__(cls):
        """Implementa singleton thread-safe"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init()
        return cls._instance

    def _init(self) -> None:
        """Inicialização do contexto"""
        self._data = {}
        self._metadata = {}
        self._listeners = {}
        logger.debug("SharedContext inicializado")

    def set(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Define valor no contexto

        Args:
            key: Chave
            value: Valor
            metadata: Metadados opcionais (source, timestamp, etc)
        """
        with self._lock:
            old_value = self._data.get(key)
            self._data[key] = value

            # Armazenar metadados
            if metadata:
                self._metadata[key] = metadata
            else:
                self._metadata[key] = {
                    "timestamp": datetime.now().isoformat(),
                    "source": "direct",
                }

            # Notificar listeners
            self._notify_listeners(key, old_value, value)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Obtém valor do contexto

        Args:
            key: Chave
            default: Valor padrão

        Returns:
            Valor ou default
        """
        with self._lock:
            return self._data.get(key, default)

    def get_all(self) -> Dict[str, Any]:
        """Obtém todos os dados"""
        with self._lock:
            return self._data.copy()

    def has(self, key: str) -> bool:
        """Verifica se chave existe"""
        with self._lock:
            return key in self._data

    def delete(self, key: str) -> bool:
        """
        Remove chave do contexto

        Args:
            key: Chave

        Returns:
            True se removido
        """
        with self._lock:
            if key in self._data:
                del self._data[key]
                self._metadata.pop(key, None)
                self._notify_listeners(key, self._data.get(key), None)
                return True
        return False

    def clear(self) -> None:
        """Limpa todo o contexto"""
        with self._lock:
            self._data.clear()
            self._metadata.clear()
            logger.debug("SharedContext limpo")

    def get_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """Obtém metadados de uma chave"""
        with self._lock:
            return self._metadata.get(key)

    def subscribe(self, key: str, callback: Callable[[str, Any, Any], None]) -> None:
        """
        Se inscreve em mudanças de chave

        Args:
            key: Chave
            callback: Função (key, old_value, new_value)
        """
        with self._lock:
            if key not in self._listeners:
                self._listeners[key] = []
            self._listeners[key].append(callback)

    def unsubscribe(self, key: str, callback: Callable) -> None:
        """Remove inscrição"""
        with self._lock:
            if key in self._listeners:
                try:
                    self._listeners[key].remove(callback)
                except ValueError:
                    pass

    def _notify_listeners(self, key: str, old_value: Any, new_value: Any) -> None:
        """Notifica listeners de mudança"""
        if key in self._listeners:
            for callback in self._listeners[key]:
                try:
                    callback(key, old_value, new_value)
                except Exception as e:
                    logger.error(f"Erro ao chamar listener para {key}: {e}")

    def set_result(self, operation: str, target: str, data: Dict[str, Any]) -> None:
        """
        Armazena resultado de operação

        Args:
            operation: Nome da operação
            target: Alvo (username, email, etc)
            data: Dados do resultado
        """
        key = f"result:{operation}:{target}"
        self.set(key, data, metadata={
            "operation": operation,
            "target": target,
            "timestamp": datetime.now().isoformat(),
        })

    def get_result(self, operation: str, target: str) -> Optional[Dict[str, Any]]:
        """
        Obtém resultado de operação armazenado

        Args:
            operation: Nome da operação
            target: Alvo

        Returns:
            Dados do resultado ou None
        """
        key = f"result:{operation}:{target}"
        return self.get(key)

    def add_finding(self, category: str, finding: Dict[str, Any]) -> None:
        """
        Adiciona um finding/resultado

        Args:
            category: Categoria do finding
            finding: Dados do finding
        """
        findings_key = f"findings:{category}"
        findings = self.get(findings_key, [])
        if not isinstance(findings, list):
            findings = []
        findings.append({
            **finding,
            "timestamp": datetime.now().isoformat(),
        })
        self.set(findings_key, findings)

    def get_findings(self, category: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Obtém findings

        Args:
            category: Filtrar por categoria (opcional)

        Returns:
            Dict de findings
        """
        findings = {}
        for key, value in self.get_all().items():
            if key.startswith("findings:"):
                cat = key.split(":", 1)[1]
                if category is None or cat == category:
                    findings[cat] = value
        return findings

    def get_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas do contexto"""
        with self._lock:
            return {
                "total_keys": len(self._data),
                "keys": list(self._data.keys()),
                "listeners_count": sum(len(v) for v in self._listeners.values()),
            }
