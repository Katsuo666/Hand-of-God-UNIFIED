# -*- coding: utf-8 -*-
"""
Módulo de scanner ativo
WAF, JWT, GraphQL, IDOR, clickjacking, rate-limit, API fuzzing,
SSL/TLS, robots/sitemap, subdomain takeover e arquivos sensíveis expostos.
Mais: headers de segurança, cookies, TLS redirect, open redirect, directory
listing, debug mode, credenciais padrão, path traversal, command injection,
XXE, SSTI, NoSQLi, LDAP injection, HTML injection, deserialização insegura,
Zip Slip, upload sem restrição, mass assignment, ReDoS/XML bomb probes e
cache headers.
"""

from .active_scanner import (
    Finding,
    ScanResult,
    WAFDetector,
    JWTAnalyzer,
    GraphQLTester,
    IDORTester,
    ClickjackingTester,
    RateLimitTester,
    APIFuzzer,
    SSLAnalyzer,
    RobotsSitemapScanner,
    TakeoverChecker,
    VulnScanner,
    OAuthTester,
    LoginTimingTester,
    WebCacheDeceptionTester,
    TabnabbingTester,
    ExposedServicesScanner,
    RequestSmugglingTester,
    Http2SupportChecker,
    PrototypePollutionScanner,
    SAMLTester,
)
from .supply_chain_scanner import (
    DependencyScanner,
    IaCScanner,
)
from .dom_scanner import DOMCloakingScanner
from .http_hardening_scanner import (
    SecurityHeadersScanner,
    CookieSecurityScanner,
    TLSConfigScanner,
    OpenRedirectScanner,
    DirectoryListingScanner,
    DebugModeScanner,
    DefaultCredentialsScanner,
)
from .injection_scanner import (
    PathTraversalTester,
    CommandInjectionTester,
    XXETester,
    SSTITester,
    NoSQLiTester,
    LDAPInjectionTester,
    HTMLInjectionTester,
    InsecureDeserializationTester,
    ZipSlipTester,
    SSRFTester,
)
from .upload_and_dos_scanner import (
    FileUploadScanner,
    MassAssignmentTester,
    ReDoSProbe,
    XMLBombProbe,
    CacheHeaderScanner,
)

__all__ = [
    'Finding',
    'ScanResult',
    'WAFDetector',
    'JWTAnalyzer',
    'GraphQLTester',
    'IDORTester',
    'ClickjackingTester',
    'RateLimitTester',
    'APIFuzzer',
    'SSLAnalyzer',
    'RobotsSitemapScanner',
    'TakeoverChecker',
    'VulnScanner',
    'OAuthTester',
    'LoginTimingTester',
    'WebCacheDeceptionTester',
    'TabnabbingTester',
    'ExposedServicesScanner',
    'RequestSmugglingTester',
    'Http2SupportChecker',
    'PrototypePollutionScanner',
    'SAMLTester',
    'DependencyScanner',
    'IaCScanner',
    'DOMCloakingScanner',
    'SecurityHeadersScanner',
    'CookieSecurityScanner',
    'TLSConfigScanner',
    'OpenRedirectScanner',
    'DirectoryListingScanner',
    'DebugModeScanner',
    'DefaultCredentialsScanner',
    'PathTraversalTester',
    'CommandInjectionTester',
    'XXETester',
    'SSTITester',
    'NoSQLiTester',
    'LDAPInjectionTester',
    'HTMLInjectionTester',
    'InsecureDeserializationTester',
    'ZipSlipTester',
    'SSRFTester',
    'FileUploadScanner',
    'MassAssignmentTester',
    'ReDoSProbe',
    'XMLBombProbe',
    'CacheHeaderScanner',
]

__version__ = '1.1.0'
