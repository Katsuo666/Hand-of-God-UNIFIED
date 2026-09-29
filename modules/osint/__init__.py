# -*- coding: utf-8 -*-
"""
Orquestradores OSINT especializados
Cada um combina os módulos de core/recon em uma análise consolidada por tipo de alvo.
"""

from .domain import DomainOSSINT
from .email import EmailOSSINT
from .ip import IPOSINT
from .phone import PhoneOSSINT
from .person import PersonOSSINT
from .company import CompanyOSSINT
from .image import ImageOSSINT
from .darkweb import DarkWebOSSINT

__all__ = [
    'DomainOSSINT',
    'EmailOSSINT',
    'IPOSINT',
    'PhoneOSSINT',
    'PersonOSSINT',
    'CompanyOSSINT',
    'ImageOSSINT',
    'DarkWebOSSINT',
]

__version__ = '1.0.0'
