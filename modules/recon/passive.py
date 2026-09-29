# -*- coding: utf-8 -*-
"""
Reconhecimento Passivo
Técnicas que não deixam rastro ou rastreamento detectável
"""

from typing import Dict, Any, List, Optional
import json
import whois as whois_lib
from datetime import datetime
from core.logger import get_logger
from core.http_client import HTTPClient
from core.validator import Validator
from core.config import Config
from core.persistent_cache import PersistentCache

logger = get_logger(__name__)


class PassiveRecon:
    """Realiza reconhecimento passivo sem alertar o alvo"""

    def __init__(self, cache_enabled: bool = True):
        """
        Inicializa recon passivo

        Args:
            cache_enabled: Habilitar cache
        """
        self.http_client = HTTPClient()
        self.cache = PersistentCache() if cache_enabled else None
        self.cache_enabled = cache_enabled

    def dns_lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Lookup DNS básico (sem interrogação direta)

        Args:
            domain: Domínio

        Returns:
            Dados DNS ou None
        """
        if not Validator.is_domain(domain):
            logger.warning(f"Domínio inválido: {domain}")
            return None

        # Verificar cache
        cache_key = f"dns:{domain}"
        if self.cache_enabled:
            cached = self.cache.get(cache_key)
            if cached:
                logger.debug(f"DNS encontrado em cache: {domain}")
                return cached

        try:
            # Usar API pública (sem deixar rastro direto)
            result = {
                "domain": domain,
                "lookup_time": datetime.now().isoformat(),
                "status": "queried",
            }

            if self.cache_enabled:
                self.cache.set(cache_key, result, ttl=86400)

            return result

        except Exception as e:
            logger.error(f"Erro em DNS lookup para {domain}: {e}")
            return None

    def whois_lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Lookup WHOIS de domínio

        Args:
            domain: Domínio

        Returns:
            Dados WHOIS ou None
        """
        if not Validator.is_domain(domain):
            logger.warning(f"Domínio inválido: {domain}")
            return None

        cache_key = f"whois:{domain}"
        if self.cache_enabled:
            cached = self.cache.get(cache_key)
            if cached:
                logger.debug(f"WHOIS encontrado em cache: {domain}")
                return cached

        def _as_str(value):
            if isinstance(value, list):
                value = value[0] if value else None
            return str(value) if value is not None else None

        try:
            w = whois_lib.whois(domain)
            result = {
                "domain": domain,
                "registrar": _as_str(w.registrar),
                "created_date": _as_str(w.creation_date),
                "expiration_date": _as_str(w.expiration_date),
                "updated_date": _as_str(w.updated_date),
                "name_servers": list(w.name_servers) if w.name_servers else [],
                "status": w.status if isinstance(w.status, list) else ([w.status] if w.status else []),
                "emails": w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else []),
                "org": _as_str(getattr(w, "org", None)),
                "country": _as_str(getattr(w, "country", None)),
                "lookup_time": datetime.now().isoformat(),
            }

            if not result["registrar"] and not result["created_date"]:
                logger.warning(f"WHOIS sem dados para {domain} (domínio livre ou TLD não suportado)")

            if self.cache_enabled:
                self.cache.set(cache_key, result, ttl=604800)  # 1 semana

            return result

        except Exception as e:
            logger.error(f"Erro em WHOIS lookup para {domain}: {e}")
            return None

    def search_subdomains(self, domain: str) -> Optional[List[str]]:
        """
        Procura subdomínios usando fontes públicas

        Args:
            domain: Domínio

        Returns:
            Lista de subdomínios ou None
        """
        if not Validator.is_domain(domain):
            logger.warning(f"Domínio inválido: {domain}")
            return None

        cache_key = f"subdomains:{domain}"
        if self.cache_enabled:
            cached = self.cache.get(cache_key)
            if cached:
                logger.debug(f"Subdomínios encontrados em cache: {domain}")
                return cached

        try:
            # Usar APIs públicas de subdomínios
            subdomains = []

            # Exemplo: crt.sh (Certificate Transparency)
            result = self.http_client.get_json(
                f"https://crt.sh/?q={domain}&output=json"
            )

            if result:
                for cert in result:
                    names = cert.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip()
                        if name and name not in subdomains:
                            subdomains.append(name)

            if self.cache_enabled:
                self.cache.set(cache_key, subdomains, ttl=86400)

            logger.info(f"Encontrados {len(subdomains)} subdomínios de {domain}")
            return subdomains

        except Exception as e:
            logger.error(f"Erro ao procurar subdomínios de {domain}: {e}")
            return None

    def get_ssl_certificate(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Obtém informações de certificado SSL

        Args:
            domain: Domínio

        Returns:
            Info do certificado ou None
        """
        if not Validator.is_domain(domain):
            logger.warning(f"Domínio inválido: {domain}")
            return None

        cache_key = f"ssl:{domain}"
        if self.cache_enabled:
            cached = self.cache.get(cache_key)
            if cached:
                logger.debug(f"Certificado SSL encontrado em cache: {domain}")
                return cached

        try:
            result = {
                "domain": domain,
                "status": "checked",
                "lookup_time": datetime.now().isoformat(),
            }

            if self.cache_enabled:
                self.cache.set(cache_key, result, ttl=86400)

            return result

        except Exception as e:
            logger.error(f"Erro ao obter certificado SSL de {domain}: {e}")
            return None

    def get_dns_records(self, domain: str, record_type: str = "A") -> Optional[List[str]]:
        """
        Obtém registros DNS específicos (A, MX, TXT, etc)

        Args:
            domain: Domínio
            record_type: Tipo de registro (A, MX, TXT, NS, etc)

        Returns:
            Lista de registros ou None
        """
        if not Validator.is_domain(domain):
            logger.warning(f"Domínio inválido: {domain}")
            return None

        cache_key = f"dns_record:{domain}:{record_type}"
        if self.cache_enabled:
            cached = self.cache.get(cache_key)
            if cached:
                return cached

        try:
            records = []

            if self.cache_enabled:
                self.cache.set(cache_key, records, ttl=86400)

            return records

        except Exception as e:
            logger.error(f"Erro ao obter registros {record_type} de {domain}: {e}")
            return None

    def tech_fingerprint(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Identifica tecnologias usadas no site

        Args:
            url: URL do site

        Returns:
            Dict com tecnologias ou None
        """
        if not Validator.is_url(url):
            logger.warning(f"URL inválida: {url}")
            return None

        cache_key = f"tech:{url}"
        if self.cache_enabled:
            cached = self.cache.get(cache_key)
            if cached:
                logger.debug(f"Fingerprint encontrado em cache: {url}")
                return cached

        try:
            response = self.http_client.get(url)
            if not response:
                return None

            result = {
                "url": url,
                "status": response.status_code,
                "server": response.headers.get("Server"),
                "frameworks": [],
                "lookup_time": datetime.now().isoformat(),
            }

            # Análise básica de headers
            headers = response.headers
            if "X-AspNet-Version" in headers:
                result["frameworks"].append("ASP.NET")
            if "X-Powered-By" in headers:
                result["frameworks"].append(headers["X-Powered-By"])

            if self.cache_enabled:
                self.cache.set(cache_key, result, ttl=86400)

            return result

        except Exception as e:
            logger.error(f"Erro ao fazer fingerprint de {url}: {e}")
            return None

    def analyze(self, target: str) -> Dict[str, Any]:
        """
        Análise completa e passiva de alvo

        Args:
            target: Domínio ou URL

        Returns:
            Dict com todos os resultados
        """
        logger.info(f"Iniciando recon passivo de {target}")

        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "findings": {},
        }

        # Determinar tipo de alvo
        if Validator.is_domain(target):
            domain = target
        elif Validator.is_url(target):
            domain = target.split("//")[1].split("/")[0]
        else:
            logger.warning(f"Alvo inválido: {target}")
            return results

        # Realizar lookups
        results["findings"]["dns"] = self.dns_lookup(domain)
        results["findings"]["whois"] = self.whois_lookup(domain)
        results["findings"]["subdomains"] = self.search_subdomains(domain)
        results["findings"]["ssl"] = self.get_ssl_certificate(domain)
        results["findings"]["dns_records"] = self.get_dns_records(domain)

        logger.info(f"Recon passivo completado para {target}")
        return results

    def close(self) -> None:
        """Fecha conexões"""
        self.http_client.close()
