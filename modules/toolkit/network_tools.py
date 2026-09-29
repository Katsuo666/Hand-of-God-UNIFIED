# -*- coding: utf-8 -*-
"""Utilitários de rede: ping, traceroute, resolução DNS, banner grabbing."""

import platform
import re
import socket
import subprocess
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import urlparse


def _normalize_host(host: str) -> str:
    """Aceita URL completa ('http://exemplo.com/caminho') ou host puro e
    devolve só o hostname, já que ping/traceroute/DNS/sockets não entendem
    esquema nem path."""
    if '://' in host:
        return urlparse(host).hostname or host
    return host.split('/', 1)[0]


def _classify_latency(avg_ms: Optional[float]) -> Optional[str]:
    """Classifica a latência média do ping em baixa/média/alta (limiares comuns
    para percepção humana de responsividade de rede)."""
    if avg_ms is None:
        return None
    if avg_ms < 50:
        return "baixa"
    if avg_ms < 150:
        return "média"
    return "alta"


class NetworkTools:
    """Operações de rede local (usa utilitários do SO para ping/traceroute)."""

    @staticmethod
    def ping(host: str, count: int = 4) -> Dict[str, Any]:
        host = _normalize_host(host)
        flag = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            proc = subprocess.run(
                ["ping", flag, str(count), host],
                capture_output=True, text=True, timeout=count * 3 + 5,
            )
            output = proc.stdout or proc.stderr
            avg_ms = None
            m = re.search(r'=\s*[\d.]+/([\d.]+)/[\d.]+', output)
            if m:
                avg_ms = float(m.group(1))
            return {
                "host": host,
                "success": proc.returncode == 0,
                "output": output,
                "avg_latency_ms": avg_ms,
                "latency": _classify_latency(avg_ms),
            }
        except Exception as e:
            return {"host": host, "success": False, "error": str(e)}

    @staticmethod
    def traceroute(host: str, max_hops: int = 30) -> Dict[str, Any]:
        host = _normalize_host(host)
        cmd = ["tracert", "-h", str(max_hops), host] if platform.system().lower() == "windows" \
            else ["traceroute", "-m", str(max_hops), host]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {
                "host": host,
                "success": proc.returncode == 0,
                "output": proc.stdout or proc.stderr,
            }
        except FileNotFoundError:
            return {"host": host, "success": False, "error": "traceroute/tracert não disponível no sistema"}
        except Exception as e:
            return {"host": host, "success": False, "error": str(e)}

    @staticmethod
    def dns_lookup(host: str) -> Dict[str, Any]:
        host = _normalize_host(host)
        result = {"host": host, "timestamp": datetime.now().isoformat()}
        try:
            result["ipv4"] = list({info[4][0] for info in socket.getaddrinfo(host, None, socket.AF_INET)})
        except socket.gaierror as e:
            result["ipv4"] = []
            result["error"] = str(e)
        try:
            result["ipv6"] = list({info[4][0] for info in socket.getaddrinfo(host, None, socket.AF_INET6)})
        except socket.gaierror:
            result["ipv6"] = []
        try:
            result["reverse"] = socket.gethostbyaddr(result["ipv4"][0])[0] if result["ipv4"] else None
        except Exception:
            result["reverse"] = None
        return result

    @staticmethod
    def banner_grab(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
        host = _normalize_host(host)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                try:
                    banner = sock.recv(1024).decode(errors="replace").strip()
                except socket.timeout:
                    banner = ""
                return {"host": host, "port": port, "open": True, "banner": banner or None}
        except Exception as e:
            return {"host": host, "port": port, "open": False, "error": str(e)}
