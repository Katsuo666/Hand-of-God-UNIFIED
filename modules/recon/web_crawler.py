# -*- coding: utf-8 -*-
"""Crawler passivo: extrai links, emails e formulários de uma única página."""

import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.http_client import HTTPClient
from core.logger import get_logger

logger = get_logger(__name__)

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


class WebCrawler:
    """Faz parsing de uma página (sem seguir links) para extrair superfície de OSINT."""

    def __init__(self, http_client: HTTPClient = None):
        self.http_client = http_client or HTTPClient()

    def crawl_page(self, url: str) -> Dict[str, Any]:
        response = self.http_client.get(url, timeout=10, raise_for_status=False)
        if not response or response.status_code != 200:
            return {"url": url, "error": f"Não foi possível obter a página (status: {response.status_code if response else 'sem resposta'})"}

        soup = BeautifulSoup(response.text, "html.parser")
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        links_internal, links_external = [], []
        for a in soup.find_all("a", href=True):
            full = urljoin(url, a["href"])
            (links_internal if full.startswith(base) else links_external).append(full)

        emails = sorted(set(EMAIL_RE.findall(response.text)))

        forms = []
        for form in soup.find_all("form"):
            forms.append({
                "action": urljoin(url, form.get("action", "")),
                "method": form.get("method", "get").upper(),
                "inputs": [i.get("name") for i in form.find_all("input") if i.get("name")],
            })

        meta = {m.get("name", m.get("property", "")): m.get("content")
                for m in soup.find_all("meta") if m.get("name") or m.get("property")}

        return {
            "url": url,
            "title": soup.title.string.strip() if soup.title and soup.title.string else None,
            "meta": meta,
            "links_internal": sorted(set(links_internal))[:200],
            "links_external": sorted(set(links_external))[:200],
            "emails_found": emails,
            "forms": forms,
        }

    def close(self) -> None:
        pass
