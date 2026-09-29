# -*- coding: utf-8 -*-
"""
Configuração centralizada do aplicativo
Carrega e gerencia settings de ambiente, arquivos e defaults
"""

import os
import json
from pathlib import Path
from typing import Any, Dict, Optional
from .enums import CacheStrategy


def _load_dotenv(path: Path) -> None:
    """Lê um ficheiro .env simples (KEY=VALUE por linha) para os.environ.

    Não sobrepõe variáveis já definidas no ambiente real (shell/CI tem prioridade).
    """
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(Path(__file__).parent.parent / ".env")


class Config:
    """Gerenciador de configuração do aplicativo"""

    # Paths
    PROJECT_ROOT = Path(__file__).parent.parent
    CORE_DIR = Path(__file__).parent
    MODULES_DIR = PROJECT_ROOT / "modules"
    DATA_DIR = PROJECT_ROOT / "data"
    CACHE_DIR = PROJECT_ROOT / ".cache"
    LOGS_DIR = PROJECT_ROOT / "logs"
    REPORTS_DIR = PROJECT_ROOT / "reports_output"

    # Garantir que diretórios existem
    for _dir in [DATA_DIR, CACHE_DIR, LOGS_DIR, REPORTS_DIR]:
        _dir.mkdir(exist_ok=True, parents=True)

    # HTTP
    HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "30"))
    HTTP_MAX_RETRIES = int(os.getenv("HTTP_MAX_RETRIES", "3"))
    HTTP_USER_AGENT = os.getenv(
        "HTTP_USER_AGENT",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )

    # Cache
    CACHE_STRATEGY = CacheStrategy[os.getenv("CACHE_STRATEGY", "HYBRID").upper()]
    CACHE_TTL = int(os.getenv("CACHE_TTL", "300"))
    CACHE_MAX_SIZE = int(os.getenv("CACHE_MAX_SIZE", "1000"))
    CACHE_BACKEND = os.getenv("CACHE_BACKEND", "sqlite")

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = os.getenv(
        "LOG_FORMAT",
        "[%(asctime)s] %(levelname)s - %(name)s - %(message)s"
    )
    LOG_FILE = LOGS_DIR / "app.log"

    # Recon
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", "20"))
    MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
    RATE_LIMIT = float(os.getenv("RATE_LIMIT", "0.5"))

    # APIs e credenciais
    HIBP_API_KEY = os.getenv("HIBP_API_KEY")
    HUNTER_API_KEY = os.getenv("HUNTER_API_KEY")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
    TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH")

    # Features
    ENABLE_DEEP_WEB = os.getenv("ENABLE_DEEP_WEB", "false").lower() == "true"
    ENABLE_CACHE = os.getenv("ENABLE_CACHE", "true").lower() == "true"
    ENABLE_METRICS = os.getenv("ENABLE_METRICS", "false").lower() == "true"
    ENABLE_PROXY = os.getenv("ENABLE_PROXY", "false").lower() == "true"

    # Proxy
    PROXY_LIST = os.getenv("PROXY_LIST", "").split(",") if os.getenv("PROXY_LIST") else []
    PROXY_ROTATION = os.getenv("PROXY_ROTATION", "false").lower() == "true"

    # Banco de dados
    DB_PATH = DATA_DIR / "results.db"
    DB_ENGINE = os.getenv("DB_ENGINE", "sqlite")

    # Paths de configuração
    CONFIG_FILE = PROJECT_ROOT / "config.json"
    ENV_FILE = PROJECT_ROOT / ".env"

    @classmethod
    def load_from_file(cls, config_path: Optional[Path] = None) -> Dict[str, Any]:
        """Carrega configuração de arquivo JSON"""
        if config_path is None:
            config_path = cls.CONFIG_FILE

        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"Erro ao carregar config de {config_path}: {e}")
                return {}
        return {}

    @classmethod
    def save_config(cls, config: Dict[str, Any], config_path: Optional[Path] = None) -> bool:
        """Salva configuração em arquivo JSON"""
        if config_path is None:
            config_path = cls.CONFIG_FILE

        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Erro ao salvar config em {config_path}: {e}")
            return False

    @classmethod
    def get_path(cls, name: str) -> Path:
        """Obtém um path configurado por nome"""
        paths = {
            "project_root": cls.PROJECT_ROOT,
            "core": cls.CORE_DIR,
            "modules": cls.MODULES_DIR,
            "data": cls.DATA_DIR,
            "cache": cls.CACHE_DIR,
            "logs": cls.LOGS_DIR,
            "db": cls.DB_PATH,
            "log_file": cls.LOG_FILE,
        }
        return paths.get(name, cls.PROJECT_ROOT)

    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        """Converte configuração para dicionário"""
        return {
            "paths": {
                "project_root": str(cls.PROJECT_ROOT),
                "data": str(cls.DATA_DIR),
                "cache": str(cls.CACHE_DIR),
                "logs": str(cls.LOGS_DIR),
            },
            "http": {
                "timeout": cls.HTTP_TIMEOUT,
                "max_retries": cls.HTTP_MAX_RETRIES,
                "user_agent": cls.HTTP_USER_AGENT,
            },
            "cache": {
                "strategy": str(cls.CACHE_STRATEGY),
                "ttl": cls.CACHE_TTL,
                "max_size": cls.CACHE_MAX_SIZE,
            },
            "logging": {
                "level": cls.LOG_LEVEL,
                "format": cls.LOG_FORMAT,
            },
            "recon": {
                "max_workers": cls.MAX_WORKERS,
                "max_retries": cls.MAX_RETRIES,
                "rate_limit": cls.RATE_LIMIT,
            },
            "features": {
                "deep_web": cls.ENABLE_DEEP_WEB,
                "cache": cls.ENABLE_CACHE,
                "metrics": cls.ENABLE_METRICS,
                "proxy": cls.ENABLE_PROXY,
            },
        }
