# -*- coding: utf-8 -*-
"""
Utilitários comuns
Funções auxiliares reutilizáveis em todo o projeto
"""

import time
import random
from typing import Any, Dict, List, Optional, Callable, TypeVar
from urllib.parse import urlparse, parse_qs
from .logger import get_logger

logger = get_logger(__name__)

T = TypeVar('T')


def parse_url(url: str) -> Optional[Dict[str, Any]]:
    """
    Parse URL em componentes

    Args:
        url: URL a fazer parse

    Returns:
        Dict com componentes ou None
    """
    try:
        parsed = urlparse(url)
        return {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "params": parsed.params,
            "query": parse_qs(parsed.query),
            "fragment": parsed.fragment,
            "username": parsed.username,
            "password": parsed.password,
            "hostname": parsed.hostname,
            "port": parsed.port,
        }
    except Exception as e:
        logger.error(f"Erro ao fazer parse de URL: {e}")
        return None


def extract_domain(url: str) -> Optional[str]:
    """
    Extrai domínio de URL

    Args:
        url: URL

    Returns:
        Domínio ou None
    """
    try:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    except Exception:
        return None


def normalize_email(email: str) -> str:
    """
    Normaliza email (lowercase, strip)

    Args:
        email: Email

    Returns:
        Email normalizado
    """
    return email.lower().strip() if isinstance(email, str) else ""


def is_valid_email(email: str) -> bool:
    """
    Valida email simples

    Args:
        email: Email

    Returns:
        True se válido
    """
    from .validator import Validator
    return Validator.is_email(email)


def sanitize_input(value: str, max_length: int = 500) -> str:
    """
    Sanitiza entrada

    Args:
        value: Valor
        max_length: Comprimento máximo

    Returns:
        Valor sanitizado
    """
    from .validator import Validator
    return Validator.sanitize_input(value, max_length)


def merge_dicts(*dicts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mescla múltiplos dicionários

    Args:
        *dicts: Dicionários a mesclar

    Returns:
        Dicionário mesclado
    """
    result = {}
    for d in dicts:
        if isinstance(d, dict):
            result.update(d)
    return result


def retry_with_backoff(
    func: Callable[..., T],
    *args,
    max_retries: int = 3,
    backoff_factor: float = 1.0,
    **kwargs
) -> Optional[T]:
    """
    Executa função com retry e backoff exponencial

    Args:
        func: Função a executar
        *args: Argumentos posicionais
        max_retries: Número máximo de tentativas
        backoff_factor: Fator de backoff
        **kwargs: Argumentos nomeados

    Returns:
        Resultado da função ou None
    """
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if attempt == max_retries - 1:
                logger.error(f"Falha após {max_retries} tentativas: {e}")
                return None

            delay = backoff_factor * (2 ** attempt) + random.uniform(0, 1)
            logger.warning(f"Tentativa {attempt + 1} falhou, retry em {delay:.1f}s: {e}")
            time.sleep(delay)

    return None


def flatten_list(nested_list: List[Any]) -> List[Any]:
    """
    Achata lista aninhada

    Args:
        nested_list: Lista potencialmente aninhada

    Returns:
        Lista achatada
    """
    result = []
    for item in nested_list:
        if isinstance(item, list):
            result.extend(flatten_list(item))
        else:
            result.append(item)
    return result


def chunk_list(lst: List[T], chunk_size: int) -> List[List[T]]:
    """
    Divide lista em chunks

    Args:
        lst: Lista
        chunk_size: Tamanho de cada chunk

    Returns:
        Lista de chunks
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def filter_dict(d: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    """
    Filtra dicionário para apenas chaves especificadas

    Args:
        d: Dicionário
        keys: Chaves a manter

    Returns:
        Dicionário filtrado
    """
    return {k: v for k, v in d.items() if k in keys}


def exclude_dict(d: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    """
    Remove chaves de dicionário

    Args:
        d: Dicionário
        keys: Chaves a remover

    Returns:
        Dicionário filtrado
    """
    return {k: v for k, v in d.items() if k not in keys}


def get_nested(d: Dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Obtém valor aninhado com dot notation

    Args:
        d: Dicionário
        path: Caminho (ex: "user.profile.name")
        default: Valor padrão

    Returns:
        Valor ou default
    """
    keys = path.split(".")
    result = d
    for key in keys:
        if isinstance(result, dict):
            result = result.get(key)
        else:
            return default
    return result if result is not None else default


def set_nested(d: Dict[str, Any], path: str, value: Any) -> Dict[str, Any]:
    """
    Define valor aninhado com dot notation

    Args:
        d: Dicionário
        path: Caminho (ex: "user.profile.name")
        value: Valor

    Returns:
        Dicionário modificado
    """
    keys = path.split(".")
    current = d
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value
    return d


def format_bytes(num_bytes: int) -> str:
    """
    Formata bytes em unidade legível

    Args:
        num_bytes: Número de bytes

    Returns:
        String formatada
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.2f} PB"


def format_duration(seconds: float) -> str:
    """
    Formata duração em string legível

    Args:
        seconds: Número de segundos

    Returns:
        String formatada
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"
