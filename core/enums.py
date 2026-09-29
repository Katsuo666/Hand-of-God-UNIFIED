# -*- coding: utf-8 -*-
"""
Enumerações centralizadas para o projeto
Define tipos, estados e constantes reutilizáveis
"""

from enum import Enum, auto
from typing import Dict, List


class ReconType(Enum):
    """Tipos de reconhecimento disponíveis"""
    PASSIVE = auto()
    ACTIVE = auto()
    OSINT = auto()
    THREAT_INTEL = auto()
    WEB_CRAWL = auto()
    NETWORK = auto()
    SOCIAL = auto()
    ALL = auto()

    def __str__(self) -> str:
        return self.name.lower()


class SeverityLevel(Enum):
    """Níveis de severidade para encontrados"""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    def __str__(self) -> str:
        return self.name

    @property
    def description(self) -> str:
        """Descrição em texto do nível de severidade"""
        descriptions = {
            SeverityLevel.INFO: "Informação",
            SeverityLevel.LOW: "Baixo",
            SeverityLevel.MEDIUM: "Médio",
            SeverityLevel.HIGH: "Alto",
            SeverityLevel.CRITICAL: "Crítico",
        }
        return descriptions.get(self, "Desconhecido")


class CacheStrategy(Enum):
    """Estratégias de cache disponíveis"""
    NO_CACHE = auto()
    MEMORY_ONLY = auto()
    DISK_ONLY = auto()
    HYBRID = auto()
    AGGRESSIVE = auto()

    def __str__(self) -> str:
        return self.name.lower()


class HTTPMethod(Enum):
    """Métodos HTTP suportados"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"

    def __str__(self) -> str:
        return self.value


class ResultStatus(Enum):
    """Status de resultado de operação"""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


class DataSourceType(Enum):
    """Tipos de fonte de dados"""
    API = "api"
    WEB = "web"
    DATABASE = "database"
    FILE = "file"
    CACHE = "cache"
    SOCIAL = "social"
    THREAT_FEED = "threat_feed"
    DNS = "dns"
    WHOIS = "whois"

    def __str__(self) -> str:
        return self.value


class Platform(Enum):
    """Plataformas sociais e web suportadas"""
    # Dev platforms
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    NPM = "npm"
    PYPI = "pypi"
    DOCKERHUB = "dockerhub"

    # Social networks
    TWITTER = "twitter"
    INSTAGRAM = "instagram"
    FACEBOOK = "facebook"
    TIKTOK = "tiktok"
    LINKEDIN = "linkedin"
    REDDIT = "reddit"

    # Video/Music
    YOUTUBE = "youtube"
    TWITCH = "twitch"
    SPOTIFY = "spotify"

    # Others
    TELEGRAM = "telegram"
    DISCORD = "discord"
    STEAM = "steam"

    def __str__(self) -> str:
        return self.value


# Constantes globais
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".review", ".faith",
    ".men", ".work", ".pw", ".download", ".webcam",
]

PHISHING_KEYWORDS = [
    "login", "verify", "confirm", "update", "secure",
    "validate", "auth", "account", "admin", "paypal",
    "amazon", "apple", "google", "microsoft", "bank",
]

HTTP_TIMEOUT_DEFAULT = 30
HTTP_RETRY_COUNT = 3
HTTP_RETRY_DELAY = 1

CACHE_TTL_DEFAULT = 300  # 5 minutes
CACHE_TTL_LONG = 86400  # 24 hours
CACHE_TTL_SHORT = 60  # 1 minute

MAX_WORKERS_DEFAULT = 20
MAX_RETRIES_DEFAULT = 3
