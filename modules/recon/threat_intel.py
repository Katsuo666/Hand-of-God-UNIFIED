# -*- coding: utf-8 -*-
"""
Threat Intelligence Module
Integração com feeds de ameaças, abuse.ch, AlienVault OTX, etc
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import feedparser
import shodan
from core.logger import get_logger
from core.http_client import HTTPClient
from core.validator import Validator
from core.config import Config
from core.persistent_cache import PersistentCache

logger = get_logger(__name__)


class ThreatIntel:
    """Motor de Threat Intelligence"""

    def __init__(self, cache_enabled: bool = True):
        """
        Inicializa ThreatIntel

        Args:
            cache_enabled: Habilitar cache
        """
        self.http_client = HTTPClient()
        self.cache = PersistentCache() if cache_enabled else None
        self.cache_enabled = cache_enabled

    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Verifica reputação de IP

        Args:
            ip: IP address

        Returns:
            Dict com dados de reputação
        """
        if not Validator.is_ip(ip):
            logger.warning(f"IP inválido: {ip}")
            return {"error": "invalid_ip"}

        cache_key = f"ip_rep:{ip}"
        if self.cache_enabled:
            cached = self.cache.get(cache_key)
            if cached:
                logger.debug(f"IP reputation encontrado em cache: {ip}")
                return cached

        logger.info(f"Verificando reputação de IP: {ip}")

        result = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "reputation_score": 0,
            "is_malicious": False,
            "abuse_reports": [],
            "sources": [],
        }

        try:
            # AlienVault OTX API (free)
            otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            response = self.http_client.get(otx_url)

            if response:
                data = response.json()
                result["reputation_score"] = data.get("reputation", 0)
                result["sources"].append("AlienVault OTX")

                if data.get("reputation", 0) > 0:
                    result["is_malicious"] = True

        except Exception as e:
            logger.debug(f"Erro ao consultar AlienVault: {e}")

        # AbuseIPDB lookup (requer API key própria — antes usava SHODAN_API_KEY por engano)
        if Config.ABUSEIPDB_API_KEY:
            try:
                abuse_url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    "Key": Config.ABUSEIPDB_API_KEY,
                    "Accept": "application/json",
                }
                params = {"ipAddress": ip, "maxAgeInDays": 90}

                response = self.http_client.get(abuse_url, params=params, headers=headers)

                if response:
                    data = response.json().get("data", {})
                    result["sources"].append("AbuseIPDB")
                    result["abuse_confidence_score"] = data.get("abuseConfidenceScore")
                    if data.get("abuseConfidenceScore", 0) > 25:
                        result["is_malicious"] = True

            except Exception as e:
                logger.debug(f"Erro ao consultar AbuseIPDB: {e}")

        result["shodan"] = self.shodan_lookup(ip)
        if result["shodan"].get("available") and result["shodan"].get("ports"):
            result["sources"].append("Shodan")

        if self.cache_enabled:
            self.cache.set(cache_key, result, ttl=86400)

        return result

    def shodan_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Consulta host no Shodan: portas abertas, serviços, banners e organização.
        Requer SHODAN_API_KEY no .env.

        Args:
            ip: IP a consultar

        Returns:
            Dict com dados do host ou aviso se a API key não estiver configurada
        """
        if not Config.SHODAN_API_KEY:
            return {"available": False, "hint": "Configura SHODAN_API_KEY no .env para usar esta funcionalidade"}

        try:
            api = shodan.Shodan(Config.SHODAN_API_KEY)
            host = api.host(ip)
            return {
                "available": True,
                "ip": host.get("ip_str"),
                "org": host.get("org"),
                "isp": host.get("isp"),
                "country": host.get("country_name"),
                "city": host.get("city"),
                "os": host.get("os"),
                "ports": host.get("ports", []),
                "hostnames": host.get("hostnames", []),
                "vulns": sorted(host.get("vulns", [])),
                "services": [
                    {"port": s.get("port"), "product": s.get("product"), "banner": (s.get("data") or "")[:200]}
                    for s in host.get("data", [])
                ],
            }
        except shodan.exception.APIError as e:
            logger.debug(f"Shodan não encontrou dados para {ip}: {e}")
            return {"available": True, "error": str(e)}
        except Exception as e:
            logger.error(f"Erro ao consultar Shodan para {ip}: {e}")
            return {"available": False, "error": str(e)}

    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Verifica reputação de domínio

        Args:
            domain: Domínio

        Returns:
            Dict com dados de reputação
        """
        if not Validator.is_domain(domain):
            logger.warning(f"Domínio inválido: {domain}")
            return {"error": "invalid_domain"}

        cache_key = f"domain_rep:{domain}"
        if self.cache_enabled:
            cached = self.cache.get(cache_key)
            if cached:
                logger.debug(f"Domain reputation encontrado em cache: {domain}")
                return cached

        logger.info(f"Verificando reputação de domínio: {domain}")

        result = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "is_suspicious": False,
            "phishing_indicators": [],
            "malware_indicators": [],
            "sources": [],
        }

        try:
            # AlienVault OTX para domínio
            otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
            response = self.http_client.get(otx_url)

            if response:
                data = response.json()
                result["sources"].append("AlienVault OTX")

                if data.get("reputation", 0) > 0:
                    result["is_suspicious"] = True

        except Exception as e:
            logger.debug(f"Erro ao consultar AlienVault: {e}")

        if self.cache_enabled:
            self.cache.set(cache_key, result, ttl=86400)

        return result

    def check_hash_reputation(self, hash_value: str) -> Dict[str, Any]:
        """
        Verifica reputação de arquivo (hash)

        Args:
            hash_value: MD5, SHA1 ou SHA256

        Returns:
            Dict com dados de reputação
        """
        # Validar tipo de hash
        is_md5 = Validator.is_md5(hash_value)
        is_sha1 = Validator.is_sha1(hash_value)
        is_sha256 = Validator.is_sha256(hash_value)

        if not (is_md5 or is_sha1 or is_sha256):
            logger.warning(f"Hash inválido: {hash_value}")
            return {"error": "invalid_hash"}

        hash_type = "md5" if is_md5 else ("sha1" if is_sha1 else "sha256")
        cache_key = f"hash_rep:{hash_value}"

        if self.cache_enabled:
            cached = self.cache.get(cache_key)
            if cached:
                logger.debug(f"Hash reputation encontrado em cache: {hash_value}")
                return cached

        logger.info(f"Verificando reputação de {hash_type}: {hash_value}")

        result = {
            "hash": hash_value,
            "hash_type": hash_type,
            "timestamp": datetime.now().isoformat(),
            "is_malicious": False,
            "detections": [],
            "sources": [],
        }

        # VirusTotal check (requer API key)
        if Config.VIRUSTOTAL_API_KEY:
            try:
                vt_url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
                headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}

                response = self.http_client.get(vt_url, headers=headers)

                if response:
                    data = response.json()
                    result["sources"].append("VirusTotal")

                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    result["detections"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                    }

                    if stats.get("malicious", 0) > 0:
                        result["is_malicious"] = True

            except Exception as e:
                logger.debug(f"Erro ao consultar VirusTotal: {e}")

        if self.cache_enabled:
            self.cache.set(cache_key, result, ttl=604800)  # 1 semana

        return result

    def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """
        Verifica reputação de URL

        Args:
            url: URL

        Returns:
            Dict com dados de reputação
        """
        if not Validator.is_url(url):
            logger.warning(f"URL inválida: {url}")
            return {"error": "invalid_url"}

        cache_key = f"url_rep:{url}"
        if self.cache_enabled:
            cached = self.cache.get(cache_key)
            if cached:
                logger.debug(f"URL reputation encontrado em cache: {url}")
                return cached

        logger.info(f"Verificando reputação de URL: {url}")

        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "is_malicious": False,
            "categories": [],
            "last_analysis": {},
            "sources": [],
        }

        # VirusTotal URL check
        if Config.VIRUSTOTAL_API_KEY:
            try:
                vt_url = "https://www.virustotal.com/api/v3/urls"
                headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
                data = {"url": url}

                response = self.http_client.post(vt_url, data=data, headers=headers)

                if response:
                    result["sources"].append("VirusTotal")

            except Exception as e:
                logger.debug(f"Erro ao consultar VirusTotal: {e}")

        if self.cache_enabled:
            self.cache.set(cache_key, result, ttl=86400)

        return result

    def get_threat_feeds(self) -> Dict[str, Any]:
        """
        Obtém feeds de ameaças públicos

        Returns:
            Dict com feeds
        """
        logger.info("Obtendo feeds de ameaças públicos")

        result = {
            "timestamp": datetime.now().isoformat(),
            "feeds": {},
        }

        feeds = {
            "abuse_ch_malware": "https://api.abuse.ch/api/v1/urlhaus/urls/download/malware_urls/",
            "otx_pulses": "https://otx.alienvault.com/api/v1/pulses/subscribed/",
        }

        for feed_name, feed_url in feeds.items():
            try:
                response = self.http_client.get(feed_url, timeout=10)
                if response:
                    result["feeds"][feed_name] = {
                        "status": "success",
                        "count": len(response.json()),
                    }
            except Exception as e:
                logger.debug(f"Erro ao obter feed {feed_name}: {e}")
                result["feeds"][feed_name] = {"status": "error"}

        return result

    # Feeds RSS públicos de advisories/CVEs, sem necessidade de API key
    RSS_FEEDS = {
        "cisa_advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "sans_isc": "https://isc.sans.edu/rssfeed_full.xml",
    }

    def get_rss_advisories(self, limit: int = 10) -> Dict[str, Any]:
        """
        Obtém os alertas/advisories mais recentes de feeds RSS de segurança públicos
        (CISA, SANS Internet Storm Center). Não requer API key.

        Args:
            limit: Máximo de itens por feed

        Returns:
            Dict com os itens de cada feed
        """
        logger.info("Obtendo advisories RSS de segurança")
        result = {"timestamp": datetime.now().isoformat(), "feeds": {}}

        for feed_name, feed_url in self.RSS_FEEDS.items():
            try:
                parsed = feedparser.parse(feed_url)
                entries = [
                    {
                        "title": e.get("title"),
                        "link": e.get("link"),
                        "published": e.get("published", e.get("updated")),
                        "summary": e.get("summary"),
                    }
                    for e in parsed.entries[:limit]
                ]
                result["feeds"][feed_name] = {"status": "success", "count": len(entries), "entries": entries}
            except Exception as e:
                logger.debug(f"Erro ao obter feed RSS {feed_name}: {e}")
                result["feeds"][feed_name] = {"status": "error", "error": str(e)}

        return result

    def analyze_indicator(self, indicator: str) -> Dict[str, Any]:
        """
        Analisa indicador (auto-detecta tipo)

        Args:
            indicator: IP, domínio, URL ou hash

        Returns:
            Dict com análise
        """
        logger.info(f"Analisando indicador: {indicator}")

        result = {
            "indicator": indicator,
            "timestamp": datetime.now().isoformat(),
            "type": None,
            "analysis": {},
        }

        # Auto-detect tipo
        if Validator.is_ip(indicator):
            result["type"] = "ip"
            result["analysis"] = self.check_ip_reputation(indicator)
        elif Validator.is_domain(indicator):
            result["type"] = "domain"
            result["analysis"] = self.check_domain_reputation(indicator)
        elif Validator.is_url(indicator):
            result["type"] = "url"
            result["analysis"] = self.check_url_reputation(indicator)
        elif Validator.is_md5(indicator) or Validator.is_sha1(indicator) or Validator.is_sha256(indicator):
            result["type"] = "hash"
            result["analysis"] = self.check_hash_reputation(indicator)
        else:
            result["error"] = "unknown_type"

        return result

    def generate_report(self, indicators: List[str]) -> Dict[str, Any]:
        """
        Gera relatório de threat intel para múltiplos indicadores

        Args:
            indicators: Lista de indicadores

        Returns:
            Relatório
        """
        logger.info(f"Gerando relatório de threat intel para {len(indicators)} indicadores")

        report = {
            "generated_at": datetime.now().isoformat(),
            "total_indicators": len(indicators),
            "malicious_found": 0,
            "suspicious_found": 0,
            "indicators": [],
        }

        for indicator in indicators:
            analysis = self.analyze_indicator(indicator)
            report["indicators"].append(analysis)

            if analysis.get("analysis", {}).get("is_malicious"):
                report["malicious_found"] += 1
            elif analysis.get("analysis", {}).get("is_suspicious"):
                report["suspicious_found"] += 1

        return report

    def close(self) -> None:
        """Fecha conexões"""
        self.http_client.close()
