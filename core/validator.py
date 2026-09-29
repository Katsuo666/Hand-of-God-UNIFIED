# -*- coding: utf-8 -*-
"""
Validação centralizada de entrada
Fornece validadores reutilizáveis para dados de entrada
"""

import re
import json
from typing import Any, Optional, List, Dict, Union
from urllib.parse import urlparse
from .logger import get_logger

logger = get_logger(__name__)


class Validator:
    """Validador centralizado"""

    # Padrões regex
    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )
    URL_PATTERN = re.compile(
        r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE
    )
    DOMAIN_PATTERN = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE
    )
    USERNAME_PATTERN = re.compile(
        r"^[a-zA-Z0-9_-]{3,32}$"
    )
    IP_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    MD5_PATTERN = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
    SHA1_PATTERN = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
    SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)

    @staticmethod
    def is_email(value: str) -> bool:
        """Valida email"""
        if not isinstance(value, str):
            return False
        return bool(Validator.EMAIL_PATTERN.match(value.lower()))

    @staticmethod
    def is_url(value: str) -> bool:
        """Valida URL"""
        if not isinstance(value, str):
            return False
        try:
            result = urlparse(value)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    @staticmethod
    def is_domain(value: str) -> bool:
        """Valida domínio"""
        if not isinstance(value, str):
            return False
        return bool(Validator.DOMAIN_PATTERN.match(value.lower()))

    @staticmethod
    def is_username(value: str) -> bool:
        """Valida username"""
        if not isinstance(value, str):
            return False
        return bool(Validator.USERNAME_PATTERN.match(value))

    @staticmethod
    def is_ip(value: str) -> bool:
        """Valida IP v4"""
        if not isinstance(value, str):
            return False
        return bool(Validator.IP_PATTERN.match(value))

    @staticmethod
    def is_md5(value: str) -> bool:
        """Valida MD5"""
        if not isinstance(value, str):
            return False
        return bool(Validator.MD5_PATTERN.match(value))

    @staticmethod
    def is_sha1(value: str) -> bool:
        """Valida SHA1"""
        if not isinstance(value, str):
            return False
        return bool(Validator.SHA1_PATTERN.match(value))

    @staticmethod
    def is_sha256(value: str) -> bool:
        """Valida SHA256"""
        if not isinstance(value, str):
            return False
        return bool(Validator.SHA256_PATTERN.match(value))

    @staticmethod
    def is_json(value: str) -> bool:
        """Valida JSON"""
        if not isinstance(value, str):
            return False
        try:
            json.loads(value)
            return True
        except (json.JSONDecodeError, TypeError):
            return False

    @staticmethod
    def is_not_empty(value: Any) -> bool:
        """Valida que não é vazio"""
        if isinstance(value, str):
            return bool(value.strip())
        return value is not None and value != ""

    @staticmethod
    def is_in_range(value: Union[int, float], min_val: Union[int, float], max_val: Union[int, float]) -> bool:
        """Valida que está em range"""
        try:
            return min_val <= value <= max_val
        except Exception:
            return False

    @staticmethod
    def is_type(value: Any, expected_type: type) -> bool:
        """Valida tipo"""
        return isinstance(value, expected_type)

    @staticmethod
    def is_one_of(value: Any, options: List[Any]) -> bool:
        """Valida que está em lista de opções"""
        return value in options

    @staticmethod
    def sanitize_input(value: str, max_length: int = 500, allow_special: bool = False) -> str:
        """
        Sanitiza entrada

        Args:
            value: Valor a sanitizar
            max_length: Comprimento máximo
            allow_special: Permitir caracteres especiais

        Returns:
            Valor sanitizado
        """
        if not isinstance(value, str):
            return ""

        # Truncar
        value = value[:max_length]

        # Remover caracteres perigosos se necessário
        if not allow_special:
            value = re.sub(r"[<>\"'%;()&+]", "", value)

        return value.strip()

    @staticmethod
    def validate_dict(data: Dict[str, Any], schema: Dict[str, type]) -> bool:
        """
        Valida estrutura de dicionário

        Args:
            data: Dicionário a validar
            schema: Schema com types esperados

        Returns:
            True se válido
        """
        if not isinstance(data, dict):
            return False

        for key, expected_type in schema.items():
            if key not in data:
                return False
            if not isinstance(data[key], expected_type):
                return False

        return True

    @staticmethod
    def validate_email_list(emails: List[str]) -> List[str]:
        """Valida lista de emails, retorna apenas válidos"""
        return [email for email in emails if Validator.is_email(email)]

    @staticmethod
    def validate_url_list(urls: List[str]) -> List[str]:
        """Valida lista de URLs, retorna apenas válidos"""
        return [url for url in urls if Validator.is_url(url)]
