# -*- coding: utf-8 -*-
"""
Reconhecimento Ativo
Técnicas que envolvem interação direta com o alvo
"""

from typing import Dict, Any, List, Optional
import socket
from datetime import datetime
from core.logger import get_logger
from core.http_client import HTTPClient
from core.validator import Validator
from core.config import Config

logger = get_logger(__name__)


class ActiveRecon:
    """Realiza reconhecimento ativo com varredura e testes diretos"""

    def __init__(self):
        """Inicializa recon ativo"""
        self.http_client = HTTPClient()

    def port_scan(self, host: str, ports: Optional[List[int]] = None) -> Optional[Dict[str, Any]]:
        """
        Escaneia portas abertas

        Args:
            host: Host/IP
            ports: Lista de portas (default: principais)

        Returns:
            Dict com portas abertas ou None
        """
        if not ports:
            ports = [21, 22, 25, 53, 80, 110, 143, 443, 587, 3306, 5432, 8080, 8443]

        if not (Validator.is_ip(host) or Validator.is_domain(host)):
            logger.warning(f"Host inválido: {host}")
            return None

        logger.info(f"Iniciando port scan em {host} ({len(ports)} portas)")

        result = {
            "host": host,
            "timestamp": datetime.now().isoformat(),
            "open_ports": [],
            "closed_ports": [],
        }

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                res = sock.connect_ex((host, port))

                if res == 0:
                    result["open_ports"].append(port)
                    logger.debug(f"Porta aberta: {host}:{port}")
                else:
                    result["closed_ports"].append(port)

                sock.close()

            except (socket.gaierror, socket.error) as e:
                logger.warning(f"Erro ao escanear porta {port}: {e}")
                result["closed_ports"].append(port)

        logger.info(f"Port scan concluído: {len(result['open_ports'])} portas abertas")
        return result

    def cidr_scan(self, cidr: str, ports: Optional[List[int]] = None,
                   max_hosts: int = 256) -> Dict[str, Any]:
        """
        Varre um range de IPs (CIDR), fazendo port_scan em cada host.

        Args:
            cidr: Range no formato CIDR, ex: 192.168.1.0/24
            ports: Portas a testar por host (default: principais)
            max_hosts: Limite de segurança de hosts a varrer

        Returns:
            Dict com resultado por host
        """
        import ipaddress
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            logger.warning(f"CIDR inválido: {cidr} ({e})")
            return {"cidr": cidr, "error": str(e)}

        hosts = list(network.hosts())[:max_hosts]
        logger.info(f"Iniciando CIDR scan em {cidr} ({len(hosts)} hosts)")

        results = []
        for host in hosts:
            host_result = self.port_scan(str(host), ports=ports)
            if host_result and host_result["open_ports"]:
                results.append(host_result)

        return {
            "cidr": cidr,
            "hosts_scanned": len(hosts),
            "hosts_with_open_ports": len(results),
            "results": results,
            "timestamp": datetime.now().isoformat(),
        }

    def http_probe(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Probes HTTP/HTTPS em alvo

        Args:
            url: URL

        Returns:
            Informações de resposta ou None
        """
        if not Validator.is_url(url):
            logger.warning(f"URL inválida: {url}")
            return None

        logger.debug(f"HTTP probe em {url}")

        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "status": None,
            "headers": {},
            "title": None,
        }

        response = self.http_client.get(url, timeout=5)
        if response:
            result["status"] = response.status_code
            result["headers"] = dict(response.headers)

            # Extrair título
            try:
                import re
                match = re.search(r"<title>([^<]+)</title>", response.text)
                if match:
                    result["title"] = match.group(1)
            except Exception:
                pass

        return result

    def service_detection(self, host: str, port: int) -> Optional[str]:
        """
        Detecta serviço rodando em porta

        Args:
            host: Host
            port: Porta

        Returns:
            Nome do serviço ou None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))

            # Tentar banner grab
            banner = sock.recv(1024).decode().strip()
            sock.close()

            logger.debug(f"Banner de {host}:{port}: {banner[:50]}")
            return banner

        except Exception as e:
            logger.debug(f"Erro ao detectar serviço: {e}")
            return None

    def vulnerability_scan(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Escaneia vulnerabilidades comuns

        Args:
            url: URL

        Returns:
            Dict com vulnerabilidades encontradas ou None
        """
        if not Validator.is_url(url):
            logger.warning(f"URL inválida: {url}")
            return None

        logger.info(f"Iniciando scan de vulnerabilidades em {url}")

        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": [],
        }

        # Testar paths comuns
        common_paths = [
            "/admin",
            "/admin.php",
            "/.git",
            "/.env",
            "/backup",
            "/config",
            "/wp-admin",
        ]

        for path in common_paths:
            response = self.http_client.get(url.rstrip("/") + path, timeout=3)
            if response and response.status_code < 400:
                result["vulnerabilities"].append({
                    "type": "exposed_path",
                    "path": path,
                    "status": response.status_code,
                })

        logger.info(f"Scan concluído: {len(result['vulnerabilities'])} issues encontrados")
        return result

    def header_analysis(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Analisa headers HTTP de segurança

        Args:
            url: URL

        Returns:
            Dict com análise de headers ou None
        """
        if not Validator.is_url(url):
            logger.warning(f"URL inválida: {url}")
            return None

        response = self.http_client.get(url, timeout=5)
        if not response:
            return None

        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "headers": dict(response.headers),
            "missing_headers": [],
            "security_issues": [],
        }

        # Headers de segurança esperados
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
        ]

        for header in security_headers:
            if header not in response.headers:
                result["missing_headers"].append(header)

        # Verificar headers perigosos
        if "Server" in response.headers:
            result["security_issues"].append({
                "type": "server_disclosure",
                "value": response.headers["Server"],
            })

        return result

    def analyze(self, target: str) -> Dict[str, Any]:
        """
        Análise completa ativa de alvo

        Args:
            target: Domínio, URL ou IP

        Returns:
            Dict com todos os resultados
        """
        logger.info(f"Iniciando recon ativo de {target}")

        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "findings": {},
        }

        # Port scan
        host = target.split("//")[-1].split("/")[0]
        results["findings"]["port_scan"] = self.port_scan(host)

        # HTTP probe
        if target.startswith("http"):
            url = target
        else:
            url = f"https://{target}"

        results["findings"]["http_probe"] = self.http_probe(url)
        results["findings"]["headers"] = self.header_analysis(url)
        results["findings"]["vulnerabilities"] = self.vulnerability_scan(url)

        logger.info(f"Recon ativo completado para {target}")
        return results

    def close(self) -> None:
        """Fecha conexões"""
        self.http_client.close()
