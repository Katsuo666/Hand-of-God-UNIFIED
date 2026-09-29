# -*- coding: utf-8 -*-
"""Orquestrador OSINT de dark web: Ahmia + paste sites + links de threat intel."""

from datetime import datetime
from typing import Any, Dict
from urllib.parse import quote

from modules.recon.osint_deep import OSINTDeep


class DarkWebOSSINT:
    def __init__(self):
        self.osint_deep = OSINTDeep()

    def monitor(self, term: str) -> Dict[str, Any]:
        enc = quote(term)
        result: Dict[str, Any] = {
            "target": term,
            "type": "darkweb",
            "timestamp": datetime.now().isoformat(),
            "ahmia": self.osint_deep.darkweb_monitor(term) or {},
            "pastes": self.osint_deep.paste_search(term) or {},
            "threat_intel_links": {
                "VirusTotal Graph": f"https://www.virustotal.com/gui/search/{enc}",
                "Shodan": f"https://www.shodan.io/search?query={enc}",
                "Censys": f"https://search.censys.io/search?resource=hosts&q={enc}",
                "URLScan": f"https://urlscan.io/search/#page.domain%3A{enc}",
            },
        }
        return result

    def close(self) -> None:
        self.osint_deep.close()
