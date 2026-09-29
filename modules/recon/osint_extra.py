# -*- coding: utf-8 -*-
"""
OSINT Extra — funcionalidades sem orquestrador próprio:
CVE lookup, ASN/BGP lookup, detecção de nó Tor, Wayback Machine, Google Dorks.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
from core.logger import get_logger
from core.http_client import HTTPClient
from core.validator import Validator

logger = get_logger(__name__)

# Lista pública de exit nodes Tor, atualizada pelo próprio Tor Project
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"

DORK_TEMPLATES = [
    'site:{d} filetype:pdf',
    'site:{d} filetype:xls OR filetype:xlsx',
    'site:{d} filetype:doc OR filetype:docx',
    'site:{d} intitle:"index of"',
    'site:{d} inurl:admin',
    'site:{d} inurl:login',
    'site:{d} ext:sql | ext:env | ext:log',
    'site:{d} "password" filetype:txt',
    'site:pastebin.com "{d}"',
    'site:github.com "{d}" password OR secret OR api_key',
]


class OSINTExtra:
    """Ferramentas OSINT avulsas que não pertencem a nenhum orquestrador de alvo único."""

    def __init__(self):
        self.http_client = HTTPClient()

    def cve_lookup(self, keyword: str, limit: int = 15) -> Dict[str, Any]:
        """Procura CVEs por palavra-chave na base da NVD."""
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        data = self.http_client.get_json(url, params={"keywordSearch": keyword, "resultsPerPage": limit})
        if not data:
            return {"keyword": keyword, "total": 0, "cves": [], "error": "NVD indisponível ou sem resultados"}

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            descriptions = cve.get("descriptions", [])
            desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
            metrics = cve.get("metrics", {})
            severity = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    severity = metrics[key][0]["cvssData"].get("baseSeverity") \
                        or metrics[key][0].get("baseSeverity")
                    break
            cves.append({
                "id": cve.get("id"),
                "published": cve.get("published"),
                "description": desc_en,
                "severity": severity,
            })

        return {
            "keyword": keyword,
            "total": data.get("totalResults", len(cves)),
            "cves": cves,
        }

    def asn_lookup(self, target: str) -> Dict[str, Any]:
        """Lookup de ASN/BGP para um IP ou nome de ASN, via bgpview.io."""
        if Validator.is_ip(target):
            data = self.http_client.get_json(f"https://api.bgpview.io/ip/{target}")
        else:
            data = self.http_client.get_json(f"https://api.bgpview.io/search?query_term={target}")

        if not data or data.get("status") != "ok":
            return {"target": target, "error": "bgpview indisponível ou alvo não encontrado"}

        return {"target": target, "data": data.get("data")}

    def tor_exit_check(self, ip: str) -> Dict[str, Any]:
        """Verifica se um IP é um nó de saída (exit node) da rede Tor."""
        if not Validator.is_ip(ip):
            return {"ip": ip, "error": "IP inválido"}

        response = self.http_client.get(TOR_EXIT_LIST_URL, timeout=10)
        is_tor = False
        if response and response.status_code == 200:
            exit_ips = set(line.strip() for line in response.text.splitlines() if line.strip())
            is_tor = ip in exit_ips

        return {
            "ip": ip,
            "is_tor_exit_node": is_tor,
            "checked_at": datetime.now().isoformat(),
        }

    def wayback_lookup(self, url: str, limit: int = 10) -> Dict[str, Any]:
        """Consulta snapshots arquivados no Wayback Machine para uma URL."""
        api = "http://web.archive.org/cdx/search/cdx"
        data = self.http_client.get_json(api, params={
            "url": url, "output": "json", "limit": limit, "collapse": "timestamp:8",
        })
        if not data or len(data) < 2:
            return {"url": url, "snapshots": []}

        header, *rows = data
        snapshots = [dict(zip(header, row)) for row in rows]
        for s in snapshots:
            ts = s.get("timestamp")
            if ts:
                s["archive_url"] = f"https://web.archive.org/web/{ts}/{s.get('original', url)}"
        return {"url": url, "total": len(snapshots), "snapshots": snapshots}

    def google_dorks(self, domain: str) -> Dict[str, Any]:
        """Gera dorks Google prontos a copiar/colar para reconhecimento passivo de um domínio."""
        return {
            "domain": domain,
            "dorks": [tmpl.format(d=domain) for tmpl in DORK_TEMPLATES],
        }
