# -*- coding: utf-8 -*-
"""Informação de sistema: specs, monitor de recursos, lista de processos (via psutil)."""

import platform
from datetime import datetime
from typing import Any, Dict, List

import psutil


class SystemTools:
    """Introspecção do sistema local."""

    @staticmethod
    def info() -> Dict[str, Any]:
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "cpu": {
                "physical_cores": psutil.cpu_count(logical=False),
                "logical_cores": psutil.cpu_count(logical=True),
                "usage_percent": psutil.cpu_percent(interval=0.5),
            },
            "memory": {
                "total_gb": round(vm.total / (1024 ** 3), 2),
                "used_gb": round(vm.used / (1024 ** 3), 2),
                "percent": vm.percent,
            },
            "disk": {
                "total_gb": round(disk.total / (1024 ** 3), 2),
                "used_gb": round(disk.used / (1024 ** 3), 2),
                "percent": disk.percent,
            },
            "timestamp": datetime.now().isoformat(),
        }

    @staticmethod
    def monitor(interval: float = 1.0) -> Dict[str, Any]:
        """Amostra pontual de uso de recursos (chamar em loop externo para monitorização contínua)."""
        return {
            "cpu_percent": psutil.cpu_percent(interval=interval),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
            "network": dict(psutil.net_io_counters()._asdict()),
            "timestamp": datetime.now().isoformat(),
        }

    @staticmethod
    def list_processes(limit: int = 30) -> List[Dict[str, Any]]:
        procs = []
        for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
            try:
                procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        procs.sort(key=lambda x: x.get("cpu_percent") or 0, reverse=True)
        return procs[:limit]
