# -*- coding: utf-8 -*-
"""Geolocalização de IP via base local MaxMind GeoLite2 (geoip2).

A MaxMind exige registo gratuito + licença para descarregar o .mmdb — não pode
vir embutido no repositório. Configura GEOIP_DB_PATH no .env a apontar para o
ficheiro GeoLite2-City.mmdb; sem isso, a função devolve um aviso claro em vez
de falhar forma silenciosa.
"""

from typing import Any, Dict

import geoip2.database
import geoip2.errors

from core.config import Config
from core.logger import get_logger

logger = get_logger(__name__)

_DOWNLOAD_HINT = (
    "GEOIP_DB_PATH não configurado. Descarrega GeoLite2-City.mmdb gratuitamente em "
    "https://www.maxmind.com/en/geolite2/signup e define GEOIP_DB_PATH=/caminho/para/GeoLite2-City.mmdb no .env"
)


class GeoLookup:
    """Lookup de geolocalização de IP usando uma base GeoLite2 local."""

    def __init__(self):
        self._reader = None
        db_path = Config.GEOIP_DB_PATH
        if db_path:
            try:
                self._reader = geoip2.database.Reader(db_path)
            except Exception as e:
                logger.warning(f"Não foi possível abrir GEOIP_DB_PATH ({db_path}): {e}")

    def lookup(self, ip: str) -> Dict[str, Any]:
        if not self._reader:
            return {"ip": ip, "available": False, "hint": _DOWNLOAD_HINT}

        try:
            response = self._reader.city(ip)
            return {
                "ip": ip,
                "available": True,
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "city": response.city.name,
                "region": response.subdivisions.most_specific.name,
                "postal_code": response.postal.code,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone,
            }
        except geoip2.errors.AddressNotFoundError:
            return {"ip": ip, "available": True, "error": "IP não encontrado na base GeoLite2 (provável IP privado/reservado)"}
        except Exception as e:
            logger.error(f"Erro no lookup GeoIP para {ip}: {e}")
            return {"ip": ip, "available": False, "error": str(e)}

    def close(self) -> None:
        if self._reader:
            self._reader.close()
