# -*- coding: utf-8 -*-
"""
Internacionalização: registro de países, validação de IDs fiscais,
validação de telefone E.164 e lista de emails descartáveis.
"""

from .country_registry import AreaCode, Country, CountryRegistry, TaxIDSpec
from .tax_validators import TaxIDValidator
from .phone_validators import PhoneValidator
from .email_disposable import DISPOSABLE_EMAIL_DOMAINS, is_disposable_email

__all__ = [
    'AreaCode',
    'Country',
    'CountryRegistry',
    'TaxIDSpec',
    'TaxIDValidator',
    'PhoneValidator',
    'DISPOSABLE_EMAIL_DOMAINS',
    'is_disposable_email',
]

__version__ = '1.0.0'
