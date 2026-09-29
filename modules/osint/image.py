# -*- coding: utf-8 -*-
"""Orquestrador OSINT de imagem: metadados, hashes e links de busca reversa."""

import hashlib
import struct
from datetime import datetime
from typing import Any, Dict
from urllib.parse import quote

from core.http_client import HTTPClient
from core.validator import Validator


class ImageOSSINT:
    def __init__(self):
        self.http_client = HTTPClient()

    def _dimensions(self, content: bytes, content_type: str) -> Dict[str, int]:
        try:
            if content_type.startswith("image/png") and len(content) > 24:
                w = struct.unpack(">I", content[16:20])[0]
                h = struct.unpack(">I", content[20:24])[0]
                return {"width": w, "height": h}
            if content_type.startswith("image/jpeg"):
                i = 2
                while i < len(content) - 4:
                    if content[i] == 0xFF and content[i + 1] in (0xC0, 0xC2):
                        h = struct.unpack(">H", content[i + 5:i + 7])[0]
                        w = struct.unpack(">H", content[i + 7:i + 9])[0]
                        return {"width": w, "height": h}
                    i += 1
        except (IndexError, struct.error):
            pass
        return {}

    def analyze(self, url: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "target": url,
            "type": "image",
            "timestamp": datetime.now().isoformat(),
            "available": False,
            "metadata": {},
            "reverse_search": {},
        }

        if not Validator.is_url(url):
            result["error"] = "URL inválida"
            return result

        resp = self.http_client.get(url)
        if not resp or resp.status_code != 200:
            result["error"] = "Imagem inacessível"
            return result

        content = resp.content
        content_type = resp.headers.get("Content-Type", "")

        result["available"] = True
        result["metadata"] = {
            "content_type": content_type,
            "size_kb": round(len(content) / 1024, 2),
            "md5": hashlib.md5(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
            **self._dimensions(content, content_type),
        }

        enc_url = quote(url, safe="")
        result["reverse_search"] = {
            "Google Images": f"https://www.google.com/searchbyimage?image_url={enc_url}",
            "TinEye": f"https://tineye.com/search?url={enc_url}",
            "Yandex Images": f"https://yandex.com/images/search?url={enc_url}&rpt=imageview",
        }

        return result
