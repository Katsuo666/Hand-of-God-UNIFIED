# -*- coding: utf-8 -*-
"""Validação/normalização internacional de telefone via CountryRegistry."""

from typing import Any, Dict, Optional

from modules.localization.country_registry import CountryRegistry


class PhoneValidator:
    """Valida e normaliza telefones (E.164) para qualquer país registrado."""

    def __init__(self):
        self.registry = CountryRegistry()

    def validate(self, phone: str, country_code: Optional[str] = None) -> Dict[str, Any]:
        """Valida telefone para um país específico ou detecta automaticamente pelo prefixo."""
        if country_code is None:
            country_code = self.registry.detect_country_from_phone(phone)

        country = self.registry.get(country_code)
        is_valid = country.phone_validator(phone)
        normalized = country.phone_normalize(phone) if is_valid else None

        return {
            'input': phone,
            'country_code': country.code,
            'country_name': country.name,
            'valid': is_valid,
            'normalized_e164': normalized,
        }
