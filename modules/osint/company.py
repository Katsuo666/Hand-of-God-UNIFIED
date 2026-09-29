# -*- coding: utf-8 -*-
"""Orquestrador OSINT de empresa: descoberta de domínio + links de registro/notícias."""

import re
import socket
from datetime import datetime
from typing import Any, Dict
from urllib.parse import quote

from modules.osint.domain import DomainOSSINT
from modules.localization.country_registry import CountryRegistry

REGISTRY_LINKS = {
    "BR": {"Receita Federal": "https://solucoes.receita.fazenda.gov.br/Servicos/cnpjreva/Cnpjreva_Solicitacao.asp"},
    "US": {"SEC EDGAR": "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany"},
    "UK": {"Companies House": "https://beta.companieshouse.gov.uk/search/companies"},
    "ES": {"BOE": "https://www.boe.es/"},
    "FR": {"INPI": "https://www.inpi.fr/"},
    "PT": {"Portal da Empresa": "https://www.portaldaempresa.pt/"},
}


class CompanyOSSINT:
    def __init__(self):
        self.domain_ossint = DomainOSSINT()
        self.registry = CountryRegistry()

    def analyze(self, company: str, country: str = "BR") -> Dict[str, Any]:
        country = country.upper()
        country_obj = self.registry.get(country)
        slug = re.sub(r"[^\w]", "", company.lower())

        result: Dict[str, Any] = {
            "target": company,
            "type": "company",
            "country": country_obj.code,
            "country_name": country_obj.name,
            "timestamp": datetime.now().isoformat(),
            "domain_guess": None,
            "domain_analysis": {},
            "registry_links": REGISTRY_LINKS.get(country_obj.code, REGISTRY_LINKS["BR"]),
            "social": {
                "LinkedIn": f"https://www.linkedin.com/search/results/companies/?keywords={quote(company)}",
                "Facebook": f"https://www.facebook.com/search/companies/?q={quote(company)}",
            },
        }

        tld_guesses = country_obj.email_country_tlds + [".com", ".net"]
        for tld in tld_guesses:
            candidate = f"{slug}{tld}"
            try:
                socket.gethostbyname(candidate)
                result["domain_guess"] = candidate
                break
            except OSError:
                continue

        if result["domain_guess"]:
            result["domain_analysis"] = self.domain_ossint.analyze(result["domain_guess"], deep=False)

        return result

    def close(self) -> None:
        self.domain_ossint.close()
