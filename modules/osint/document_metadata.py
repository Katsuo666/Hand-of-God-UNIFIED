# -*- coding: utf-8 -*-
"""Extração de metadados de documentos (PDF/DOCX) — autor, software, datas."""

import re
import zipfile
from typing import Any, Dict
from xml.etree import ElementTree as ET

from core.logger import get_logger

logger = get_logger(__name__)

_DOCX_CORE_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
}


class DocumentMetadata:
    """Lê metadados embutidos em PDF/DOCX a partir do caminho de ficheiro."""

    def extract(self, path: str) -> Dict[str, Any]:
        lower = path.lower()
        if lower.endswith(".pdf"):
            return self._pdf_metadata(path)
        if lower.endswith((".docx", ".xlsx", ".pptx")):
            return self._ooxml_metadata(path)
        return {"path": path, "error": "Formato não suportado (use .pdf, .docx, .xlsx ou .pptx)"}

    @staticmethod
    def _pdf_metadata(path: str) -> Dict[str, Any]:
        # ponytail: regex sobre o dicionário /Info em texto puro — cobre PDFs simples/não
        # comprimidos; PDFs com xref em stream comprimido (comuns em exports recentes) podem
        # não expor o /Info assim. Upgrade: usar pikepdf se isso se tornar um problema real.
        with open(path, "rb") as f:
            data = f.read()

        fields = {}
        for key in (b"Author", b"Creator", b"Producer", b"Title", b"CreationDate", b"ModDate"):
            match = re.search(key + rb"\s*\((.*?)(?<!\\)\)", data)
            if match:
                fields[key.decode()] = match.group(1).decode("latin-1", errors="replace")

        gps = re.search(rb"GPS\s?(?:Latitude|Position)", data, re.IGNORECASE)
        return {
            "path": path,
            "type": "pdf",
            "metadata": fields or {"info": "Nenhum /Info dict encontrado (PDF comprimido ou sem metadata)"},
            "gps_hint_found": bool(gps),
        }

    @staticmethod
    def _ooxml_metadata(path: str) -> Dict[str, Any]:
        fields: Dict[str, Any] = {}
        with zipfile.ZipFile(path) as z:
            if "docProps/core.xml" in z.namelist():
                root = ET.fromstring(z.read("docProps/core.xml"))
                for child in root:
                    tag = child.tag.split("}")[-1]
                    fields[tag] = child.text
            if "docProps/app.xml" in z.namelist():
                root = ET.fromstring(z.read("docProps/app.xml"))
                for child in root:
                    tag = child.tag.split("}")[-1]
                    if tag == "Application":
                        fields["software"] = child.text

        return {"path": path, "type": "ooxml", "metadata": fields}
