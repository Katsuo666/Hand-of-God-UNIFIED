# -*- coding: utf-8 -*-
"""Orquestrador OSINT de email: recon profunda + verificação de breach."""

from datetime import datetime
from typing import Any, Dict

from modules.recon.osint_deep import OSINTDeep
from modules.localization.email_disposable import is_disposable_email


class EmailOSSINT:
    def __init__(self):
        self.osint_deep = OSINTDeep()

    def analyze(self, email: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "target": email,
            "type": "email",
            "timestamp": datetime.now().isoformat(),
            "is_disposable": is_disposable_email(email),
            "reconnaissance": self.osint_deep.email_reconnaissance(email) or {},
            "breaches": self.osint_deep.password_check(email, check_email=True) or [],
        }
        return result

    def close(self) -> None:
        self.osint_deep.close()
