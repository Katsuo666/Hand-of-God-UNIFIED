# -*- coding: utf-8 -*-
"""Análise de cabeçalho de email bruto: SPF/DKIM/DMARC, hops, possível spoofing."""

import re
from email import message_from_string
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any, Dict, List

from core.logger import get_logger

logger = get_logger(__name__)


class EmailHeaderAnalyzer:
    """Analisa um cabeçalho de email colado em bruto (texto do 'Show original')."""

    def analyze(self, raw_header: str) -> Dict[str, Any]:
        msg = message_from_string(raw_header)

        from_addr = parseaddr(msg.get("From", ""))[1]
        return_path = parseaddr(msg.get("Return-Path", ""))[1]

        result = {
            "from": from_addr,
            "to": parseaddr(msg.get("To", ""))[1],
            "subject": msg.get("Subject"),
            "return_path": return_path,
            "message_id": msg.get("Message-ID"),
            "date": msg.get("Date"),
            "hops": self._extract_hops(msg.get_all("Received", [])),
            "authentication": self._extract_auth(msg.get_all("Authentication-Results", [])
                                                   + [msg.get("Received-SPF", "")]),
            "spoofing_suspected": False,
        }

        if from_addr and return_path and from_addr.split("@")[-1] != return_path.split("@")[-1]:
            result["spoofing_suspected"] = True
            result["spoofing_reason"] = (
                f"Domínio de 'From' ({from_addr.split('@')[-1]}) difere de "
                f"'Return-Path' ({return_path.split('@')[-1]})"
            )

        return result

    @staticmethod
    def _extract_hops(received_headers: List[str]) -> List[Dict[str, Any]]:
        hops = []
        # Received headers vêm do mais recente para o mais antigo; invertemos p/ ordem cronológica.
        for header in reversed(received_headers):
            from_match = re.search(r"from\s+(\S+)", header)
            by_match = re.search(r"by\s+(\S+)", header)
            date_str = header.split(";")[-1].strip() if ";" in header else None
            hops.append({
                "from": from_match.group(1) if from_match else None,
                "by": by_match.group(1) if by_match else None,
                "raw_date": date_str,
            })
        return hops

    @staticmethod
    def _extract_auth(auth_headers: List[str]) -> Dict[str, Any]:
        combined = " ".join(h for h in auth_headers if h)
        result = {}
        for mechanism in ("spf", "dkim", "dmarc"):
            match = re.search(rf"{mechanism}=(\w+)", combined, re.IGNORECASE)
            result[mechanism] = match.group(1).lower() if match else "não presente"
        return result
