# -*- coding: utf-8 -*-
"""
Registro de países suportados: código de telefone, códigos de área,
IDs fiscais e TLDs. Portado do V1 (main.py) para uso modular.
"""
# ponytail: mapas de area_codes reduzidos às capitais/cidades principais
# (V1 tinha a lista completa de DDDs do BR). Ampliar aqui se granularidade
# regional completa for necessária.

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class AreaCode:
    """Código de área/região com geolocalização."""
    code: str
    city: str
    state: Optional[str]
    country_code: str
    region: str
    carrier: Optional[str] = None


@dataclass
class TaxIDSpec:
    """Especificação de ID fiscal/tributário."""
    name: str
    country: str
    length: int
    pattern: str
    format_template: str
    checksum: bool
    description: str


@dataclass
class Country:
    """Dados de um país para análise OSINT internacional."""
    code: str
    name: str
    region: str
    phone_country_code: str
    phone_pattern: str
    area_codes: Dict[str, AreaCode]
    tax_ids: List[TaxIDSpec]
    company_registry_api: Optional[str] = None
    company_registry_name: Optional[str] = None
    email_country_tlds: List[str] = field(default_factory=list)

    def phone_validator(self, phone: str) -> bool:
        try:
            return bool(re.match(self.phone_pattern, phone))
        except re.error:
            return False

    def phone_normalize(self, phone: str) -> Optional[str]:
        clean = re.sub(r'[^\d\+]', '', phone)
        if not clean.startswith('+'):
            clean = self.phone_country_code + clean
        return clean if self.phone_validator(clean) else None


class CountryRegistry:
    """Registro singleton de países suportados com lazy-loading."""

    _instance: Optional['CountryRegistry'] = None
    _countries: Dict[str, Country] = {}
    _initialized: bool = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._load_countries()

    def _load_countries(self):
        # BRASIL
        area_codes_br = {
            '11': AreaCode('11', 'São Paulo', 'SP', 'BR', 'Sudeste'),
            '12': AreaCode('12', 'São José dos Campos', 'SP', 'BR', 'Sudeste'),
            '13': AreaCode('13', 'Santos', 'SP', 'BR', 'Sudeste'),
            '19': AreaCode('19', 'Campinas', 'SP', 'BR', 'Sudeste'),
            '21': AreaCode('21', 'Rio de Janeiro', 'RJ', 'BR', 'Sudeste'),
            '27': AreaCode('27', 'Vitória', 'ES', 'BR', 'Sudeste'),
            '31': AreaCode('31', 'Belo Horizonte', 'MG', 'BR', 'Sudeste'),
            '41': AreaCode('41', 'Curitiba', 'PR', 'BR', 'Sul'),
            '47': AreaCode('47', 'Joinville', 'SC', 'BR', 'Sul'),
            '48': AreaCode('48', 'Florianópolis', 'SC', 'BR', 'Sul'),
            '51': AreaCode('51', 'Porto Alegre', 'RS', 'BR', 'Sul'),
            '61': AreaCode('61', 'Brasília', 'DF', 'BR', 'Centro-Oeste'),
            '62': AreaCode('62', 'Goiânia', 'GO', 'BR', 'Centro-Oeste'),
            '65': AreaCode('65', 'Cuiabá', 'MT', 'BR', 'Centro-Oeste'),
            '67': AreaCode('67', 'Campo Grande', 'MS', 'BR', 'Centro-Oeste'),
            '71': AreaCode('71', 'Salvador', 'BA', 'BR', 'Nordeste'),
            '81': AreaCode('81', 'Recife', 'PE', 'BR', 'Nordeste'),
            '84': AreaCode('84', 'Natal', 'RN', 'BR', 'Nordeste'),
            '85': AreaCode('85', 'Fortaleza', 'CE', 'BR', 'Nordeste'),
            '91': AreaCode('91', 'Belém', 'PA', 'BR', 'Norte'),
            '92': AreaCode('92', 'Manaus', 'AM', 'BR', 'Norte'),
            '98': AreaCode('98', 'São Luís', 'MA', 'BR', 'Nordeste'),
        }
        tax_ids_br = [
            TaxIDSpec('CPF', 'BR', 11, r'^\d{11}$', 'XXX.XXX.XXX-XX', True,
                      'Cadastro de Pessoa Física'),
            TaxIDSpec('CNPJ', 'BR', 14, r'^\d{14}$', 'XX.XXX.XXX/0001-XX', True,
                      'Cadastro Nacional de Pessoa Jurídica'),
        ]
        self._countries['BR'] = Country(
            code='BR', name='Brasil', region='South America',
            phone_country_code='+55',
            phone_pattern=r'^\+?55\s?(\(?\d{2}\)?\s?)[\s\-]?(\d{4,5})[\s\-]?(\d{4})$',
            area_codes=area_codes_br, tax_ids=tax_ids_br,
            company_registry_api='https://brasilapi.com.br/api/cnpj/v1/',
            company_registry_name='BrasilAPI',
            email_country_tlds=['.br', '.com.br'],
        )

        # USA
        area_codes_us = {
            '202': AreaCode('202', 'Washington DC', 'DC', 'US', 'District of Columbia'),
            '212': AreaCode('212', 'New York City', 'NY', 'US', 'Northeast'),
            '305': AreaCode('305', 'Miami', 'FL', 'US', 'Southeast'),
            '310': AreaCode('310', 'Los Angeles', 'CA', 'US', 'West'),
            '415': AreaCode('415', 'San Francisco', 'CA', 'US', 'West'),
            '312': AreaCode('312', 'Chicago', 'IL', 'US', 'Midwest'),
        }
        tax_ids_us = [
            TaxIDSpec('SSN', 'US', 9, r'^\d{3}-\d{2}-\d{4}$', 'XXX-XX-XXXX', True,
                      'Social Security Number'),
            TaxIDSpec('EIN', 'US', 9, r'^\d{2}-\d{7}$', 'XX-XXXXXXX', False,
                      'Employer Identification Number'),
        ]
        self._countries['US'] = Country(
            code='US', name='United States', region='North America',
            phone_country_code='+1',
            phone_pattern=r'^\+?1\s?(\(?\d{3}\)?\s?)[\s\-]?\d{3}[\s\-]?\d{4}$',
            area_codes=area_codes_us, tax_ids=tax_ids_us,
            company_registry_api='https://data.sec.gov/api/xbrl/',
            company_registry_name='SEC EDGAR',
            email_country_tlds=['.us', '.com'],
        )

        # UNITED KINGDOM
        area_codes_uk = {
            '20': AreaCode('20', 'London', None, 'UK', 'England'),
            '121': AreaCode('121', 'Birmingham', None, 'UK', 'England'),
            '161': AreaCode('161', 'Manchester', None, 'UK', 'England'),
            '131': AreaCode('131', 'Edinburgh', None, 'UK', 'Scotland'),
        }
        tax_ids_uk = [
            TaxIDSpec('UTR', 'UK', 10, r'^\d{10}$', 'XXXXXXXXXX', False,
                      'Unique Taxpayer Reference'),
        ]
        self._countries['UK'] = Country(
            code='UK', name='United Kingdom', region='Europe',
            phone_country_code='+44',
            phone_pattern=r'^\+?44\s?(\d{3,5})[\s\-]?\d{6,8}$',
            area_codes=area_codes_uk, tax_ids=tax_ids_uk,
            company_registry_api='https://beta.companieshouse.gov.uk/company/',
            company_registry_name='Companies House',
            email_country_tlds=['.uk', '.co.uk'],
        )

        # ESPAÑA
        area_codes_es = {
            '1': AreaCode('1', 'Madrid', None, 'ES', 'Madrid'),
            '2': AreaCode('2', 'Barcelona', None, 'ES', 'Catalonia'),
            '5': AreaCode('5', 'Sevilla', None, 'ES', 'Andalusia'),
        }
        tax_ids_es = [
            TaxIDSpec('NIF', 'ES', 9, r'^[0-9]{8}[A-Z]$', 'XXXXXXXX-X', True,
                      'Número de Identidad Fiscal'),
            TaxIDSpec('CIF', 'ES', 9, r'^[A-Z][0-9]{7}[0-9A-Z]$', 'X-XXXXXXX-X', False,
                      'Código de Identificación Fiscal'),
        ]
        self._countries['ES'] = Country(
            code='ES', name='España', region='Europe',
            phone_country_code='+34',
            phone_pattern=r'^\+?34\s?[\s\-]?\d{9}$',
            area_codes=area_codes_es, tax_ids=tax_ids_es,
            company_registry_api='https://www.boe.es/',
            company_registry_name='BOE',
            email_country_tlds=['.es', '.com.es'],
        )

        # FRANCE
        area_codes_fr = {
            '1': AreaCode('1', "Paris/Île-de-France", None, 'FR', 'Île-de-France'),
            '4': AreaCode('4', 'Southeast', None, 'FR', "Provence-Alpes-Côte d'Azur"),
        }
        tax_ids_fr = [
            TaxIDSpec('SIREN', 'FR', 9, r'^\d{9}$', 'XXXXXXXXX', False,
                      "Système d'Identification du Répertoire des Entreprises"),
            TaxIDSpec('SIRET', 'FR', 14, r'^\d{14}$', 'XXXXXXXXXXXXXX', False,
                      "Système d'Identification du Répertoire des Établissements"),
        ]
        self._countries['FR'] = Country(
            code='FR', name='France', region='Europe',
            phone_country_code='+33',
            phone_pattern=r'^\+?33\s?[1-9][\s\-]?\d{8}$',
            area_codes=area_codes_fr, tax_ids=tax_ids_fr,
            company_registry_api='https://api.sirene.insee.fr/',
            company_registry_name='API Sirene (INSEE)',
            email_country_tlds=['.fr', '.com.fr'],
        )

        # PORTUGAL
        area_codes_pt = {
            '21': AreaCode('21', 'Lisboa', None, 'PT', 'Lisbon'),
            '22': AreaCode('22', 'Porto', None, 'PT', 'Porto'),
        }
        tax_ids_pt = [
            TaxIDSpec('NIF', 'PT', 9, r'^\d{9}$', 'XXXXXXXXX', True,
                      'Número de Identificação Fiscal'),
        ]
        self._countries['PT'] = Country(
            code='PT', name='Portugal', region='Europe',
            phone_country_code='+351',
            phone_pattern=r'^\+?351\s?\d{9}$',
            area_codes=area_codes_pt, tax_ids=tax_ids_pt,
            company_registry_api='https://www.portaldaempresa.pt/',
            company_registry_name='Portal da Empresa',
            email_country_tlds=['.pt', '.com.pt'],
        )

        # GENERIC (fallback E.164 para países não mapeados)
        self._countries['GENERIC'] = Country(
            code='GENERIC', name='Generic (Fallback)', region='World',
            phone_country_code='+0',
            phone_pattern=r'^\+\d{1,3}\s?\d{5,15}$',
            area_codes={}, tax_ids=[],
            company_registry_api=None, company_registry_name=None,
            email_country_tlds=['.com'],
        )

    def get(self, country_code: str) -> Country:
        """Retorna dados de um país; se não suportado, retorna GENERIC (E.164)."""
        return self._countries.get(country_code.upper(), self._countries['GENERIC'])

    def list_supported(self) -> List[str]:
        return [code for code in self._countries.keys() if code != 'GENERIC']

    def register(self, country: Country) -> None:
        self._countries[country.code] = country

    def phone_validator(self, phone: str, country_code: str) -> bool:
        return self.get(country_code).phone_validator(phone)

    def phone_normalize(self, phone: str, country_code: str) -> Optional[str]:
        return self.get(country_code).phone_normalize(phone)

    def detect_country_from_phone(self, phone: str) -> str:
        """Detecta o país a partir do prefixo internacional (+55, +1, ...)."""
        clean = re.sub(r'[^\d\+]', '', phone)
        if clean.startswith('+'):
            for code, country in self._countries.items():
                if code != 'GENERIC' and clean.startswith(country.phone_country_code):
                    return code
            return 'GENERIC'
        return 'BR'
