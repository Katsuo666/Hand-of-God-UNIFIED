# -*- coding: utf-8 -*-
"""
Sistema de cache persistente com suporte a múltiplos backends
Fornece caching híbrido (memória + disco) com TTL configurável
"""

import json
import sqlite3
import hashlib
import time
from pathlib import Path
from typing import Any, Optional, Dict, List
from datetime import datetime, timedelta
from .config import Config
from .logger import get_logger

logger = get_logger(__name__)


class PersistentCache:
    """Sistema de cache com backend SQLite"""

    def __init__(
        self,
        cache_dir: Path = Config.CACHE_DIR,
        db_name: str = "cache.db",
        ttl: int = Config.CACHE_TTL,
        max_size: int = Config.CACHE_MAX_SIZE,
    ):
        """
        Inicializa cache persistente

        Args:
            cache_dir: Diretório para cache
            db_name: Nome do banco de dados
            ttl: Time-to-live em segundos
            max_size: Número máximo de entradas
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True, parents=True)
        self.db_path = self.cache_dir / db_name
        self.ttl = ttl
        self.max_size = max_size
        self.memory_cache: Dict[str, Dict[str, Any]] = {}

        self._init_db()

    def _init_db(self) -> None:
        """Inicializa banco de dados SQLite"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cache (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        ttl INTEGER,
                        created_at REAL,
                        accessed_at REAL,
                        access_count INTEGER DEFAULT 0
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_created_at
                    ON cache(created_at)
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Erro ao inicializar cache DB: {e}")

    def _get_key_hash(self, key: str) -> str:
        """Gera hash da chave para normalização"""
        return hashlib.md5(key.encode()).hexdigest()

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Armazena valor no cache

        Args:
            key: Chave
            value: Valor (será serializado como JSON)
            ttl: TTL em segundos (usa default se None)

        Returns:
            True se sucesso
        """
        if ttl is None:
            ttl = self.ttl

        try:
            # Memory cache
            self.memory_cache[key] = {
                "value": value,
                "expires_at": time.time() + ttl,
            }

            # Disk cache
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO cache
                    (key, value, ttl, created_at, accessed_at, access_count)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    key,
                    json.dumps(value, default=str),
                    ttl,
                    time.time(),
                    time.time(),
                    0,
                ))
                conn.commit()

            # Cleanup se necessário
            if self._get_db_size() > self.max_size:
                self._cleanup_oldest()

            return True
        except Exception as e:
            logger.error(f"Erro ao setar cache [{key}]: {e}")
            return False

    def get(self, key: str) -> Optional[Any]:
        """
        Obtém valor do cache

        Args:
            key: Chave

        Returns:
            Valor ou None se expirado/não encontrado
        """
        # Memory cache
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            if time.time() < entry["expires_at"]:
                return entry["value"]
            else:
                del self.memory_cache[key]

        # Disk cache
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT value, ttl, created_at, access_count
                    FROM cache WHERE key = ?
                """, (key,))
                row = cursor.fetchone()

                if row:
                    # Verificar TTL
                    age = time.time() - row["created_at"]
                    if age < row["ttl"]:
                        # Atualizar access count
                        conn.execute("""
                            UPDATE cache SET accessed_at = ?, access_count = ?
                            WHERE key = ?
                        """, (time.time(), row["access_count"] + 1, key))
                        conn.commit()

                        # Atualizar memory cache
                        value = json.loads(row["value"])
                        self.memory_cache[key] = {
                            "value": value,
                            "expires_at": time.time() + row["ttl"],
                        }
                        return value
                    else:
                        # Expirou, remover
                        conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                        conn.commit()

        except Exception as e:
            logger.error(f"Erro ao obter cache [{key}]: {e}")

        return None

    def delete(self, key: str) -> bool:
        """Remove chave do cache"""
        try:
            # Memory cache
            self.memory_cache.pop(key, None)

            # Disk cache
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Erro ao deletar cache [{key}]: {e}")
            return False

    def clear(self) -> bool:
        """Limpa todo o cache"""
        try:
            self.memory_cache.clear()
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("DELETE FROM cache")
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Erro ao limpar cache: {e}")
            return False

    def exists(self, key: str) -> bool:
        """Verifica se chave existe e não expirou"""
        return self.get(key) is not None

    def _get_db_size(self) -> int:
        """Retorna número de entradas no DB"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM cache")
                return cursor.fetchone()[0]
        except Exception:
            return 0

    def _cleanup_oldest(self) -> None:
        """Remove entradas antigas quando atinge max_size"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Remover 20% das entradas antigas
                remove_count = int(self.max_size * 0.2)
                conn.execute("""
                    DELETE FROM cache WHERE key IN (
                        SELECT key FROM cache
                        ORDER BY accessed_at ASC
                        LIMIT ?
                    )
                """, (remove_count,))
                conn.commit()
        except Exception as e:
            logger.error(f"Erro durante cleanup de cache: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas do cache"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute("""
                    SELECT COUNT(*) as total, SUM(access_count) as total_hits
                    FROM cache
                """)
                row = cursor.fetchone()
                return {
                    "memory_entries": len(self.memory_cache),
                    "disk_entries": row[0] if row else 0,
                    "total_hits": row[1] if row else 0,
                    "db_size_mb": (self.db_path.stat().st_size / 1024 / 1024)
                    if self.db_path.exists() else 0,
                }
        except Exception as e:
            logger.error(f"Erro ao obter stats de cache: {e}")
            return {}
