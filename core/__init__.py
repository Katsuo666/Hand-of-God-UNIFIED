# -*- coding: utf-8 -*-
"""
Core module initialization
Exports principais classes e funções do core
"""

from .enums import (
    ReconType,
    SeverityLevel,
    CacheStrategy,
    HTTPMethod,
)
from .config import Config
from .logger import setup_logger, get_logger
from .http_client import HTTPClient
from .persistent_cache import PersistentCache
from .validator import Validator
from .utils import (
    parse_url,
    extract_domain,
    normalize_email,
    is_valid_email,
    sanitize_input,
    merge_dicts,
    retry_with_backoff,
)
from .shared_context import SharedContext

__all__ = [
    'ReconType',
    'SeverityLevel',
    'CacheStrategy',
    'HTTPMethod',
    'Config',
    'setup_logger',
    'get_logger',
    'HTTPClient',
    'PersistentCache',
    'Validator',
    'parse_url',
    'extract_domain',
    'normalize_email',
    'is_valid_email',
    'sanitize_input',
    'merge_dicts',
    'retry_with_backoff',
    'SharedContext',
]

__version__ = '1.0.0'
__author__ = 'Security Team'
__license__ = 'MIT'
