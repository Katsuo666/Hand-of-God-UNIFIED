# -*- coding: utf-8 -*-
"""
Descoberta de parâmetros testáveis num alvo: reaproveita a mesma estratégia
usada por modules/ai/exploit_tester.py (query string do alvo + crawler +
fallback de nomes genéricos), extraída aqui para ser compartilhada pelos
testers de injeção novos sem duplicar lógica.
"""

from typing import Dict, List
from urllib.parse import parse_qs, urlparse, urlunparse

from core.http_client import HTTPClient
from core.logger import get_logger
from modules.recon.web_crawler import WebCrawler

logger = get_logger(__name__)

COMMON_PARAMS = [
    "q", "search", "s", "query", "id", "page", "user",
    "url", "redirect", "next", "file", "path", "src", "href",
    "input", "data", "text", "value", "name", "email",
    "username", "token", "key", "lang", "cat", "doc", "template",
]


def collect_targets(target: str, http_client: HTTPClient, max_params: int = 10) -> List[Dict[str, str]]:
    """Params a testar: 1) já na query string do alvo, 2) via crawler, 3) fallback genérico."""
    targets: List[Dict[str, str]] = []
    seen = set()

    def _add(base_url: str, param: str, source: str) -> None:
        key = f"{base_url}|{param}"
        if key not in seen:
            seen.add(key)
            targets.append({"base_url": base_url, "param": param, "source": source})

    parsed = urlparse(target)
    base = urlunparse(parsed._replace(query="", fragment=""))

    if parsed.query:
        for param in parse_qs(parsed.query).keys():
            _add(base, param, "url")

    try:
        page = WebCrawler(http_client=http_client).crawl_page(target)
        if not page.get("error"):
            for form in page.get("forms", []):
                action = form.get("action") or target
                if urlparse(action).netloc != parsed.netloc:
                    continue
                for input_name in form.get("inputs", []):
                    _add(action, input_name, "crawler")
            for link in page.get("links_internal", []):
                link_parsed = urlparse(link)
                if not link_parsed.query:
                    continue
                link_base = urlunparse(link_parsed._replace(query="", fragment=""))
                for param in parse_qs(link_parsed.query).keys():
                    _add(link_base, param, "crawler")
    except Exception as e:
        logger.debug(f"Crawler falhou para {target}: {e}")

    for param in COMMON_PARAMS[:max_params]:
        _add(base, param, "generic")

    return targets
