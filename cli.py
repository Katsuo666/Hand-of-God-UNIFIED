#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI unificada da Mão de Deus UNIFIED — Task 13.

Liga os módulos já portados (core/, modules/, pipelines/, reports/) a
subcomandos de linha de comando, modo interativo por menu e watch
(monitorização contínua com diff). Não substitui main.py (o monólito V1
original, com 36+ subcomandos); é um entrypoint novo sobre a arquitetura
modular construída nas Tasks 1-12.
"""

import argparse
import json
import sys
import time
from types import SimpleNamespace
from typing import Any, Dict

import colorama
from colorama import Fore, Style

from core.shared_context import SharedContext
from core.watch_store import WatchStore, diff_dicts

from modules.osint import (
    CompanyOSSINT, DarkWebOSSINT, DomainOSSINT, EmailOSSINT,
    ImageOSSINT, IPOSINT, PersonOSSINT, PhoneOSSINT,
)
from modules.recon.active import ActiveRecon
from modules.recon.osint_deep import OSINTDeep
from modules.recon.osint_extra import OSINTExtra
from modules.recon.passive import PassiveRecon
from modules.recon.threat_intel import ThreatIntel
from modules.recon.web_crawler import WebCrawler
from modules.osint.email_header import EmailHeaderAnalyzer
from modules.osint.document_metadata import DocumentMetadata
from modules.scanner import (
    APIFuzzer, ClickjackingTester, GraphQLTester, IDORTester, JWTAnalyzer,
    RateLimitTester, RobotsSitemapScanner, SSLAnalyzer, TakeoverChecker, VulnScanner, WAFDetector,
    SecurityHeadersScanner, CookieSecurityScanner, TLSConfigScanner, OpenRedirectScanner,
    DirectoryListingScanner, DebugModeScanner, DefaultCredentialsScanner,
    PathTraversalTester, CommandInjectionTester, XXETester, SSTITester, NoSQLiTester,
    LDAPInjectionTester, HTMLInjectionTester, InsecureDeserializationTester, ZipSlipTester,
    FileUploadScanner, MassAssignmentTester, ReDoSProbe, XMLBombProbe, CacheHeaderScanner,
    OAuthTester, LoginTimingTester, WebCacheDeceptionTester, TabnabbingTester,
    ExposedServicesScanner, SSRFTester, RequestSmugglingTester, Http2SupportChecker,
    PrototypePollutionScanner, DependencyScanner, IaCScanner, SAMLTester,
    DOMCloakingScanner,
)
from modules.mobile.apk_scanner import ApkStaticScanner
from modules.mobile.dynamic_instrumentation import FridaDynamicTester
from modules.localization.tax_validators import TaxIDValidator
from modules.intelligence.nexus_engine import NexusEngine
from modules.toolkit.crypto_tools import CryptoTools
from modules.toolkit.security_tools import SecurityTools
from modules.toolkit.network_tools import NetworkTools
from modules.toolkit.system_tools import SystemTools
from pipelines import run_pipeline
from reports import NexusReporter, ReportGenerator

SCANNERS = {
    'waf': WAFDetector,
    'jwt': JWTAnalyzer,
    'graphql': GraphQLTester,
    'idor': IDORTester,
    'clickjacking': ClickjackingTester,
    'ratelimit': RateLimitTester,
    'apifuzzer': APIFuzzer,
    'ssl': SSLAnalyzer,
    'robots': RobotsSitemapScanner,
    'vuln': VulnScanner,
    'headers': SecurityHeadersScanner,
    'cookies': CookieSecurityScanner,
    'tlsredirect': TLSConfigScanner,
    'openredirect': OpenRedirectScanner,
    'dirlisting': DirectoryListingScanner,
    'debug': DebugModeScanner,
    'defaultcreds': DefaultCredentialsScanner,
    'traversal': PathTraversalTester,
    'cmdi': CommandInjectionTester,
    'xxe': XXETester,
    'ssti': SSTITester,
    'nosqli': NoSQLiTester,
    'ldapi': LDAPInjectionTester,
    'htmli': HTMLInjectionTester,
    'deserialization': InsecureDeserializationTester,
    'zipslip': ZipSlipTester,
    'upload': FileUploadScanner,
    'massassignment': MassAssignmentTester,
    'redos': ReDoSProbe,
    'xmlbomb': XMLBombProbe,
    'cache': CacheHeaderScanner,
    'oauth': OAuthTester,
    'logintiming': LoginTimingTester,
    'cachedeception': WebCacheDeceptionTester,
    'tabnabbing': TabnabbingTester,
    'exposedservices': ExposedServicesScanner,
    'ssrf': SSRFTester,
    'smuggling': RequestSmugglingTester,
    'http2': Http2SupportChecker,
    'protopollution': PrototypePollutionScanner,
    'saml': SAMLTester,
    'domcloaking': DOMCloakingScanner,
}

# Scanners que enviam payloads de ataque reais (injeção/upload/DoS-safe probes) —
# exigem o mesmo opt-in --exploit já usado pelo ExploitTester em pipeline3.
ACTIVE_EXPLOIT_SCANNERS = {
    'traversal', 'cmdi', 'xxe', 'ssti', 'nosqli', 'ldapi', 'htmli',
    'zipslip', 'upload', 'massassignment', 'redos', 'xmlbomb', 'defaultcreds',
    'ssrf', 'oauth', 'logintiming', 'smuggling',
}

# Agrupamento dos 30 scanners por categoria, só para organizar a navegação do
# menu interativo (cmd_scanner/SCANNERS continuam sendo a fonte de verdade).
SCANNER_GROUPS = [
    ("Reconhecimento & Hardening (passivo)", [
        'waf', 'ssl', 'robots', 'headers', 'cookies', 'tlsredirect', 'dirlisting', 'cache',
        'tabnabbing', 'cachedeception', 'exposedservices',
    ]),
    ("Autenticação & Acesso", ['jwt', 'idor', 'defaultcreds', 'oauth', 'logintiming', 'saml']),
    ("Exposição & Configuração", ['vuln', 'debug', 'openredirect', 'clickjacking']),
    ("API (GraphQL/REST)", ['graphql', 'apifuzzer', 'ratelimit']),
    ("Injeção ativa ⚠️ payloads reais", [
        'cmdi', 'traversal', 'xxe', 'ssti', 'nosqli', 'ldapi', 'htmli', 'deserialization', 'ssrf',
    ]),
    ("Upload & DoS-safe ⚠️ payloads reais", ['upload', 'zipslip', 'massassignment', 'redos', 'xmlbomb']),
    ("Protocolo & Client-side (avançado)", ['smuggling', 'http2', 'protopollution', 'domcloaking']),
]


_JSON_LINE_COLORS = (
    # (regex, cor) — a primeira que bater na linha decide a cor.
    (r'"success":\s*false', Fore.RED + Style.BRIGHT),
    (r'"error_message":\s*(?!null)', Fore.RED),
    (r'"(findings|vulnerabilities|issues)":\s*\[\s*\]', Fore.GREEN),
    (r'"(findings|vulnerabilities|issues)"', Fore.YELLOW + Style.BRIGHT),
    (r'"(severity|risk)":\s*"(critical|high)"', Fore.RED + Style.BRIGHT),
    (r'"(severity|risk)":\s*"(medium)"', Fore.YELLOW),
    (r'"success":\s*true', Fore.GREEN),
)


def _colorize_json(text: str) -> str:
    """Realça linhas importantes do JSON (erros, findings, severidade) com ANSI."""
    import re
    out_lines = []
    for line in text.splitlines():
        for pattern, color in _JSON_LINE_COLORS:
            if re.search(pattern, line, re.IGNORECASE):
                out_lines.append(f"{color}{line}{Style.RESET_ALL}")
                break
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


_SEVERITY_COLOR = {
    'CRITICAL': Fore.RED + Style.BRIGHT,
    'HIGH': Fore.RED,
    'MEDIUM': Fore.YELLOW,
    'LOW': Fore.CYAN,
    'INFO': Fore.WHITE,
}


def _has_findings_shape(node: Any) -> bool:
    """True se a estrutura vem de um scanner de vulnerabilidades (tem uma chave
    'findings' em algum nível) — usado para não afirmar 'nenhuma vulnerabilidade
    encontrada' em resultados de ferramentas que não procuram vulnerabilidades
    (ping, DNS, crypto, etc.)."""
    if isinstance(node, dict):
        if 'findings' in node:
            return True
        return any(_has_findings_shape(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_findings_shape(i) for i in node)
    return False


def _print_summary(data: Any) -> None:
    """Resumo colorido: contagem por severidade + explicação de cada tipo de finding."""
    from reports.findings import collect_findings, count_by_severity, explain, sort_by_severity

    if not _has_findings_shape(data):
        status_key = 'success' if isinstance(data, dict) and 'success' in data \
            else 'open' if isinstance(data, dict) and 'open' in data else None
        if status_key:
            if data[status_key]:
                label = 'Porta aberta.' if status_key == 'open' else 'Comando executado com sucesso.'
                print(f"\n{Fore.GREEN}{Style.BRIGHT}✔ {label}{Style.RESET_ALL}")
            else:
                err = data.get('error') or data.get('error_message') or data.get('output') or 'sem detalhes'
                label = 'Porta fechada/inacessível' if status_key == 'open' else 'Comando falhou'
                print(f"\n{Fore.RED}{Style.BRIGHT}✘ {label}:{Style.RESET_ALL} {err}")
            latency = data.get('latency')
            if latency:
                lat_color = {'baixa': Fore.GREEN, 'média': Fore.YELLOW, 'alta': Fore.RED}.get(latency, '')
                print(f"  {lat_color}Latência: {latency} ({data.get('avg_latency_ms')} ms){Style.RESET_ALL}")
        return

    findings = sort_by_severity(collect_findings(data))
    if not findings:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}✔ Nenhuma vulnerabilidade encontrada.{Style.RESET_ALL}")
        return

    counts = count_by_severity(findings)
    print(f"\n{Style.BRIGHT}── Resumo ──────────────────────────────{Style.RESET_ALL}")
    for sev, n in counts.items():
        if n:
            c = _SEVERITY_COLOR.get(sev, '')
            print(f"  {c}{sev}: {n}{Style.RESET_ALL}")

    print(f"\n{Style.BRIGHT}── Notas ───────────────────────────────{Style.RESET_ALL}")
    seen_types = set()
    for f in findings:
        ftype = f.get('type', '')
        if ftype in seen_types:
            continue
        seen_types.add(ftype)
        c = _SEVERITY_COLOR.get(f.get('severity', 'INFO'), '')
        print(f"  {c}[{f.get('severity')}]{Style.RESET_ALL} {f.get('title', ftype)}")
        print(f"    {Fore.WHITE + Style.DIM}{explain(ftype)}{Style.RESET_ALL}")
    print(
        f"\n{Fore.YELLOW}⚠ Findings HIGH baseados em heurísticas (diferença de resposta, "
        f"palavra-chave) podem ser falsos positivos — confirme manualmente.{Style.RESET_ALL}"
    )


def _output(data: Any, args: argparse.Namespace, default_filename: str) -> Any:
    """Imprime o resultado em stdout e, se --output for passado, também grava em disco."""
    _print_summary(data)
    print(f"\n{Style.BRIGHT}── Dados completos ─────────────────────{Style.RESET_ALL}")
    print(_colorize_json(json.dumps(data, indent=2, ensure_ascii=False, default=str)))
    if getattr(args, 'output', None):
        rg = ReportGenerator()
        path = rg.generate(data, args.format, filename=args.output)
        print(f"\n[salvo em {path}]", file=sys.stderr)
    return data


def _offer_save(data: Any, default_filename: str) -> None:
    """Pergunta, DEPOIS de o resultado já estar visível, se quer salvar em arquivo."""
    if not _ask_bool("\nSalvar este resultado em arquivo (PDF/HTML/...)?"):
        return
    fmt = _ask_choice("Formato", ['pdf', 'html', 'json', 'csv', 'xml', 'markdown', 'text'], default='pdf')
    name = _ask("Nome do arquivo", default_filename)
    rg = ReportGenerator()
    path = rg.generate(data, fmt, filename=name)
    print(f"[salvo em {path}]")


def _add_report_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--format', choices=['json', 'csv', 'html', 'xml', 'markdown', 'text', 'pdf'],
                         default='json', help='Formato do relatório salvo (com --output)')
    parser.add_argument('--output', help='Nome do arquivo a salvar (sem extensão)')


def cmd_osint(args: argparse.Namespace) -> None:
    if args.type == 'domain':
        orch = DomainOSSINT()
        data = orch.analyze(args.target, deep=args.deep)
        orch.close()
    elif args.type == 'email':
        orch = EmailOSSINT()
        data = orch.analyze(args.target)
        orch.close()
    elif args.type == 'ip':
        orch = IPOSINT()
        data = orch.analyze(args.target, do_scan=args.deep)
        orch.close()
    elif args.type == 'phone':
        data = PhoneOSSINT().analyze(args.target)
    elif args.type == 'person':
        data = PersonOSSINT().analyze(args.target, location=args.location)
    elif args.type == 'company':
        orch = CompanyOSSINT()
        data = orch.analyze(args.target, country=args.country)
        orch.close()
    elif args.type == 'image':
        data = ImageOSSINT().analyze(args.target)
    elif args.type == 'darkweb':
        orch = DarkWebOSSINT()
        data = orch.monitor(args.target)
        orch.close()
    else:
        raise ValueError(f'Tipo OSINT desconhecido: {args.type}')

    _output(data, args, f'osint_{args.type}')


def cmd_recon(args: argparse.Namespace) -> None:
    if args.mode == 'passive':
        recon = PassiveRecon()
        data = recon.analyze(args.target)
        recon.close()
    elif args.mode == 'active':
        recon = ActiveRecon()
        data = recon.analyze(args.target)
        recon.close()
    elif args.mode == 'threat-intel':
        ti = ThreatIntel()
        data = ti.analyze_indicator(args.target)
        ti.close()
    elif args.mode == 'username-search':
        osint_deep = OSINTDeep()
        data = osint_deep.username_search(args.target)
        osint_deep.close()
    elif args.mode == 'password-check':
        osint_deep = OSINTDeep()
        data = {'breaches': osint_deep.password_check(args.target, check_email=False)}
        osint_deep.close()
    elif args.mode == 'url-check':
        osint_deep = OSINTDeep()
        data = osint_deep.url_anti_phishing(args.target)
        osint_deep.close()
    elif args.mode == 'paste-search':
        osint_deep = OSINTDeep()
        data = osint_deep.paste_search(args.target)
        osint_deep.close()
    elif args.mode == 'rss-advisories':
        ti = ThreatIntel()
        data = ti.get_rss_advisories()
        ti.close()
    else:
        raise ValueError(f'Modo de recon desconhecido: {args.mode}')

    _output(data, args, f'recon_{args.mode}')


def cmd_scanner(args: argparse.Namespace) -> None:
    scanner_cls = SCANNERS[args.name]
    url = args.target if args.target.startswith(('http://', 'https://')) else f'https://{args.target}'
    result = scanner_cls(url).scan()
    return _output(result.to_dict(), args, f'scanner_{args.name}')


def cmd_takeover(args: argparse.Namespace) -> None:
    """Enumera subdomínios (PassiveRecon), resolve CNAME de cada um e testa takeover."""
    import dns.resolver

    passive = PassiveRecon()
    subdomains = passive.search_subdomains(args.target) or []
    passive.close()

    subdomain_cnames = {}
    for sub in subdomains[:args.max_subdomains]:
        try:
            answer = dns.resolver.resolve(sub, 'CNAME')
            subdomain_cnames[sub] = str(answer[0].target).rstrip('.')
        except Exception:
            continue

    result = TakeoverChecker(args.target, subdomain_cnames).scan()
    data = result.to_dict()
    data['subdomains_enumerated'] = len(subdomains)
    data['subdomains_with_cname'] = len(subdomain_cnames)
    _output(data, args, 'takeover')


def cmd_taxid(args: argparse.Namespace) -> None:
    data = TaxIDValidator.validate_tax_id(args.value, country=args.country, id_type=args.type)
    _output(data, args, 'taxid')


def cmd_crawl(args: argparse.Namespace) -> None:
    data = WebCrawler().crawl_page(args.url)
    _output(data, args, 'crawl')


def cmd_cve(args: argparse.Namespace) -> None:
    data = OSINTExtra().cve_lookup(args.keyword, limit=args.limit)
    _output(data, args, 'cve')


def cmd_asn(args: argparse.Namespace) -> None:
    data = OSINTExtra().asn_lookup(args.target)
    _output(data, args, 'asn')


def cmd_tor_check(args: argparse.Namespace) -> None:
    data = OSINTExtra().tor_exit_check(args.ip)
    _output(data, args, 'tor_check')


def cmd_wayback(args: argparse.Namespace) -> None:
    data = OSINTExtra().wayback_lookup(args.url, limit=args.limit)
    _output(data, args, 'wayback')


def cmd_dorks(args: argparse.Namespace) -> None:
    data = OSINTExtra().google_dorks(args.domain)
    _output(data, args, 'dorks')


def cmd_hash_id(args: argparse.Namespace) -> None:
    data = CryptoTools.identify_hash(args.value)
    _output(data, args, 'hash_id')


def cmd_email_header(args: argparse.Namespace) -> None:
    with open(args.file, 'r', encoding='utf-8', errors='replace') as f:
        raw = f.read()
    data = EmailHeaderAnalyzer().analyze(raw)
    _output(data, args, 'email_header')


def cmd_doc_meta(args: argparse.Namespace) -> None:
    data = DocumentMetadata().extract(args.file)
    _output(data, args, 'doc_meta')


def cmd_apk(args: argparse.Namespace) -> None:
    result = ApkStaticScanner(args.file).scan()
    _output(result.to_dict(), args, 'apk_scan')


def cmd_apk_dynamic(args: argparse.Namespace) -> None:
    if not args.i_accept_risk:
        print(_c(
            "⚠️  Este comando ANEXA a um processo em execução via Frida (instrumentação dinâmica) e\n"
            "   exige device/emulador com frida-server, além de autorização explícita do dono do\n"
            "   app/dispositivo. Use --i-accept-risk para confirmar que tem essa autorização.",
            _RED,
        ))
        return
    result = FridaDynamicTester(args.package, device_id=args.device).scan()
    _output(result.to_dict(), args, 'apk_dynamic_scan')


def cmd_deps(args: argparse.Namespace) -> None:
    result = DependencyScanner(args.path).scan()
    _output(result.to_dict(), args, 'deps_scan')


def cmd_iac(args: argparse.Namespace) -> None:
    result = IaCScanner(args.path).scan()
    _output(result.to_dict(), args, 'iac_scan')


def cmd_cidr(args: argparse.Namespace) -> None:
    data = ActiveRecon().cidr_scan(args.cidr, max_hosts=args.max_hosts)
    _output(data, args, 'cidr')


def cmd_cripto(args: argparse.Namespace) -> None:
    if args.action == 'hash':
        data = CryptoTools.hash_string(args.value)
    elif args.action == 'encode':
        data = {'result': CryptoTools.encode(args.value, args.scheme)}
    elif args.action == 'decode':
        data = {'result': CryptoTools.decode(args.value, args.scheme)}
    elif args.action == 'uuid':
        data = {'uuid': CryptoTools.generate_uuid()}
    elif args.action == 'rot13':
        data = {'result': CryptoTools.rot13(args.value)}
    elif args.action == 'caesar':
        data = {'result': CryptoTools.caesar(args.value, args.shift)}
    else:
        raise ValueError(f'Ação cripto desconhecida: {args.action}')
    _output(data, args, f'cripto_{args.action}')


def cmd_seguranca(args: argparse.Namespace) -> None:
    if args.action == 'scan':
        data = SecurityTools.scan_directory(args.path)
    elif args.action == 'hash':
        data = SecurityTools.hash_file(args.path)
    elif args.action == 'permissoes':
        data = SecurityTools.check_permissions(args.path)
    elif args.action == 'senha':
        data = SecurityTools.generate_password(length=args.length)
    else:
        raise ValueError(f'Ação de segurança desconhecida: {args.action}')
    _output(data, args, f'seguranca_{args.action}')


def cmd_rede(args: argparse.Namespace) -> None:
    if args.action == 'ping':
        data = NetworkTools.ping(args.target)
    elif args.action == 'traceroute':
        data = NetworkTools.traceroute(args.target)
    elif args.action == 'dns':
        data = NetworkTools.dns_lookup(args.target)
    elif args.action == 'banner':
        data = NetworkTools.banner_grab(args.target, args.port)
    else:
        raise ValueError(f'Ação de rede desconhecida: {args.action}')
    _output(data, args, f'rede_{args.action}')


def cmd_sistema(args: argparse.Namespace) -> None:
    if args.action == 'info':
        data = SystemTools.info()
    elif args.action == 'monitor':
        data = SystemTools.monitor()
    elif args.action == 'processos':
        data = SystemTools.list_processes(limit=args.limit)
    else:
        raise ValueError(f'Ação de sistema desconhecida: {args.action}')
    _output(data, args, f'sistema_{args.action}')


def cmd_session_summary(args: argparse.Namespace) -> None:
    """
    Mostra os findings agregados no SharedContext durante ESTE processo.

    Como cada comando `cli.py` é um processo novo, só acumula algo quando
    várias análises correm no mesmo processo — ou seja, dentro do modo
    interativo, ou logo após uma pipeline 2/3/all na mesma sessão Python.
    """
    context = SharedContext()
    data = {
        'stats': context.get_stats(),
        'findings': context.get_findings(),
    }
    _output(data, args, 'session_summary')


def cmd_pentest(args: argparse.Namespace) -> None:
    data = run_pipeline(args.target, pipeline=args.pipeline, exploit=getattr(args, 'exploit', False))
    return _output(data, args, f'pentest_pipeline{args.pipeline}')


def cmd_nexus(args: argparse.Namespace) -> None:
    nexus = NexusEngine()
    result, graph = nexus.analyze(args.target, deep=args.deep)

    if args.dashboard:
        reporter = NexusReporter()
        path = reporter.generate_dashboard(result, graph)
        print(f"[dashboard salvo em {path}]", file=sys.stderr)

    _output(result, args, 'nexus')


def cmd_watch(args: argparse.Namespace) -> None:
    """Roda a pipeline escolhida, compara com o último snapshot salvo e mostra o diff."""
    store = WatchStore()

    def check_once() -> None:
        data = run_pipeline(args.target, pipeline=args.pipeline)
        old = store.load(args.target)
        store.save(args.target, data)

        if old is None:
            print(f"[watch] primeiro snapshot salvo para {args.target!r}", file=sys.stderr)
            return

        changes = [c for c in diff_dicts(old, data)
                   if 'timestamp' not in c[0].lower() and 'elapsed' not in c[0].lower()]
        if not changes:
            print(f"[watch] sem mudanças em {args.target!r}", file=sys.stderr)
        else:
            print(f"[watch] {len(changes)} mudança(s) em {args.target!r}:")
            for path, old_v, new_v in changes[:50]:
                print(f"  {path}: {old_v!r} -> {new_v!r}")

    check_once()
    if args.mode == 'loop':
        try:
            while True:
                time.sleep(args.interval)
                check_once()
        except KeyboardInterrupt:
            print("\n[watch] interrompido pelo usuário", file=sys.stderr)


# ── Modo interativo ─────────────────────────────────────────────

_RED = '\033[91m'
_GREEN = '\033[92m'
_YELLOW = '\033[93m'
_PURPLE = '\033[95m'
_BOLD = '\033[1m'
_DIM = '\033[2m'
_RESET = '\033[0m'

_BANNER = r"""
██╗   ██╗███╗   ██╗██╗███████╗██╗███████╗██████╗
██║   ██║████╗  ██║██║██╔════╝██║██╔════╝██╔══██╗
██║   ██║██╔██╗ ██║██║█████╗  ██║█████╗  ██║  ██║
██║   ██║██║╚██╗██║██║██╔══╝  ██║██╔══╝  ██║  ██║
╚██████╔╝██║ ╚████║██║██║     ██║███████╗██████╔╝
 ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚══════╝╚═════╝
""".strip('\n')


def _supports_color() -> bool:
    return sys.stdout.isatty()


def _c(text: str, color: str) -> str:
    return f"{color}{text}{_RESET}" if _supports_color() else text


def _typewriter(text: str, color: str, delay: float = 0.0015) -> None:
    for line in text.splitlines():
        print(_c(line, color) if _supports_color() else line)
        if _supports_color():
            time.sleep(delay * max(len(line), 1))


def _fullwidth(text: str) -> str:
    """Converte ASCII para variante 'fullwidth' Unicode — parece maior no terminal."""
    return "".join(chr(0xFF00 + (ord(c) - 0x20)) if '!' <= c <= '~' else c
                   for c in text)


def _clear_screen() -> None:
    if _supports_color():
        # \033[3J também limpa o scrollback, senão alguns terminais (Konsole, etc.)
        # deixam o conteúdo antigo visível ao rolar para cima.
        print('\033[H\033[2J\033[3J', end='', flush=True)


def _print_banner(animate: bool = False) -> None:
    print(_c(_fullwidth("◉ HAND OF GOD"), _BOLD + _PURPLE))
    if animate:
        _typewriter(_BANNER, _PURPLE)
    else:
        print(_c(_BANNER, _PURPLE) if _supports_color() else _BANNER)
    print(_c("OSINT + Pentest — v1.0", _DIM))
    print(_c("─" * 50, _DIM))


def _print_menu(items: list) -> None:
    print()
    for i, (label, _) in enumerate(items, start=1):
        print(f"  {_c(str(i), _GREEN + _BOLD)}. {label}")
    print(f"  {_c('0', _RED + _BOLD)}. Voltar")


def _section(title: str) -> None:
    print()
    print(_c(f"▶ {title}", _BOLD + _PURPLE))
    print(_c("─" * 50, _DIM))


def _run_action(title: str, fn) -> None:
    """Executa uma ação do menu em 3 fases claras: parâmetros → execução → resultado."""
    _clear_screen()
    _section(title)
    fn()
    print()
    print(_c("─" * 50, _DIM))
    input(_c("Pressione ENTER para voltar ao menu...", _DIM))
    _clear_screen()
    _print_banner(animate=False)


def _ask(prompt: str, default: str = None) -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{_c(prompt, _YELLOW)}{suffix}: ").strip()
    return val or default


def _ask_target(prompt: str, example: str) -> str:
    val = input(f"{_c(prompt, _YELLOW)} {_c(f'(ex: {example})', _DIM)}: ").strip()
    return val


def _ask_bool(prompt: str) -> bool:
    return input(f"{prompt} (s/n): ").strip().lower() == 's'


def _ask_choice(prompt: str, options: list, default: str = None) -> str:
    """Mostra as opções numeradas; aceita o número ou o nome digitado diretamente."""
    for i, opt in enumerate(options, start=1):
        print(f"  {_c(str(i), _GREEN)}) {opt}")
    suffix = f" [{default}]" if default else ""
    raw = input(f"{_c(prompt, _YELLOW)}{suffix}: ").strip()
    if not raw:
        return default
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1]
    return raw.lower()


def _interactive_osint() -> None:
    t = _ask_choice("Tipo", [
        'domain', 'email', 'ip', 'phone', 'person', 'company', 'image', 'darkweb',
    ], default='domain')
    examples = {
        'domain': 'exemplo.com', 'email': 'email@exemplo.com', 'ip': '8.8.8.8',
        'phone': '+351912345678', 'person': 'Nome Completo', 'company': 'Nome da Empresa',
        'image': 'caminho ou URL da imagem', 'darkweb': 'termo de busca',
    }
    target = _ask_target("Alvo", examples.get(t, 'exemplo.com'))
    if not target:
        return
    ns = SimpleNamespace(
        type=t, target=target, deep=_ask_bool("Análise profunda?"), format='json', output=None,
        location=_ask("Localização (opcional)") if t == 'person' else None,
        country=_ask("País (ex: BR, US, UK)", "BR") if t == 'company' else 'BR',
    )
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_osint(ns)


def _interactive_recon() -> None:
    mode = _ask_choice("Modo", [
        'passive', 'active', 'threat-intel', 'username-search',
        'password-check', 'url-check', 'paste-search', 'rss-advisories',
    ], default='passive')
    if mode == 'rss-advisories':
        target = None
    else:
        recon_examples = {
            'passive': 'exemplo.com', 'active': 'exemplo.com', 'threat-intel': '8.8.8.8 ou exemplo.com',
            'username-search': 'username (sem @)', 'password-check': 'email@exemplo.com',
            'url-check': 'https://exemplo.com/pagina', 'paste-search': 'termo de busca',
        }
        target = _ask_target("Alvo", recon_examples.get(mode, 'exemplo.com'))
        if not target:
            return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_recon(SimpleNamespace(mode=mode, target=target, format='json', output=None))


def _interactive_scanner() -> None:
    group_labels = [g[0] for g in SCANNER_GROUPS]
    group_label = _ask_choice("Categoria de scanner", group_labels, default=group_labels[0])
    names = next(names for label, names in SCANNER_GROUPS if label == group_label)
    name = _ask_choice("Scanner", names, default=names[0])
    if name in ACTIVE_EXPLOIT_SCANNERS:
        print(_c("⚠️  Este scanner envia payloads de ataque reais — use só com autorização.", _RED))
    target = _ask_target("URL/domínio alvo", "https://exemplo.com")
    if not target:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    data = cmd_scanner(SimpleNamespace(name=name, target=target, format='json', output=None))
    _offer_save(data, f'scanner_{name}')


def _interactive_takeover() -> None:
    target = _ask_target("Domínio raiz", "exemplo.com")
    if not target:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_takeover(SimpleNamespace(target=target, max_subdomains=40, format='json', output=None))


def _interactive_taxid() -> None:
    value = _ask_target("Valor do documento", "123.456.789-00")
    if not value:
        return
    country = _ask("País", "BR")
    id_type = _ask("Tipo (CPF/CNPJ/SSN/NIF/SIRET, opcional)") or None
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_taxid(SimpleNamespace(value=value, country=country, type=id_type, format='json', output=None))


def _interactive_crawl() -> None:
    url = _ask_target("URL", "https://exemplo.com")
    if not url:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_crawl(SimpleNamespace(url=url, format='json', output=None))


def _interactive_cve() -> None:
    keyword = _ask_target("Palavra-chave", "openssh")
    if not keyword:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_cve(SimpleNamespace(keyword=keyword, limit=15, format='json', output=None))


def _interactive_asn() -> None:
    target = _ask_target("IP", "8.8.8.8")
    if not target:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_asn(SimpleNamespace(target=target, format='json', output=None))


def _interactive_tor_check() -> None:
    ip = _ask_target("IP", "8.8.8.8")
    if not ip:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_tor_check(SimpleNamespace(ip=ip, format='json', output=None))


def _interactive_wayback() -> None:
    url = _ask_target("URL", "exemplo.com")
    if not url:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_wayback(SimpleNamespace(url=url, limit=10, format='json', output=None))


def _interactive_dorks() -> None:
    domain = _ask_target("Domínio", "exemplo.com")
    if not domain:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_dorks(SimpleNamespace(domain=domain, format='json', output=None))


def _interactive_hash_id() -> None:
    value = _ask_target("Hash", "5d41402abc4b2a76b9719d911017c592")
    if not value:
        return
    cmd_hash_id(SimpleNamespace(value=value, format='json', output=None))


def _interactive_email_header() -> None:
    file = _ask_target("Ficheiro com o cabeçalho bruto", "cabecalho.eml")
    if not file:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_email_header(SimpleNamespace(file=file, format='json', output=None))


def _interactive_doc_meta() -> None:
    file = _ask_target("Ficheiro", "documento.pdf")
    if not file:
        return
    cmd_doc_meta(SimpleNamespace(file=file, format='json', output=None))


def _interactive_apk() -> None:
    file = _ask_target("Caminho do .apk", "/caminho/para/app.apk")
    if not file:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_apk(SimpleNamespace(file=file, format='json', output=None))


def _interactive_apk_dynamic() -> None:
    print(_c(
        "⚠️  Instrumentação dinâmica via Frida — exige device/emulador com frida-server\n"
        "   e a app já aberta, com autorização explícita do dono do app/dispositivo.",
        _RED,
    ))
    package = _ask_target("Nome do pacote Android", "com.exemplo.app")
    if not package:
        return
    device = _ask("ID do device (Enter para o primeiro USB)") or None
    confirm = _ask("Confirma que tem autorização explícita? (sim/não)", "não")
    if confirm.strip().lower() not in ('sim', 's', 'yes', 'y'):
        print(_c("Cancelado.", _DIM))
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_apk_dynamic(SimpleNamespace(package=package, device=device, i_accept_risk=True,
                                     format='json', output=None))


def _interactive_deps() -> None:
    path = _ask_target("Caminho do diretório do projeto", "/caminho/para/projeto")
    if not path:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_deps(SimpleNamespace(path=path, format='json', output=None))


def _interactive_iac() -> None:
    path = _ask_target("Caminho do diretório do projeto", "/caminho/para/projeto")
    if not path:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_iac(SimpleNamespace(path=path, format='json', output=None))


def _interactive_cidr() -> None:
    cidr = _ask_target("Range CIDR", "192.168.1.0/24")
    if not cidr:
        return
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_cidr(SimpleNamespace(cidr=cidr, max_hosts=256, format='json', output=None))


def _interactive_cripto() -> None:
    action = _ask_choice("Ação", ['hash', 'encode', 'decode', 'uuid', 'rot13', 'caesar'], default='hash')
    value = '' if action == 'uuid' else _ask_target("Texto", "texto de exemplo")
    scheme = _ask_choice("Esquema", ['base64', 'hex', 'url'], default='base64') \
        if action in ('encode', 'decode') else 'base64'
    shift = int(_ask("Deslocamento (caesar)", "13")) if action == 'caesar' else 13
    cmd_cripto(SimpleNamespace(action=action, value=value, scheme=scheme, shift=shift,
                                format='json', output=None))


def _interactive_seguranca() -> None:
    action = _ask_choice("Ação", ['scan', 'hash', 'permissoes', 'senha'], default='senha')
    path = '.' if action == 'senha' else _ask_target("Caminho", "/home/utilizador/ficheiro")
    length = int(_ask("Comprimento", "16")) if action == 'senha' else 16
    cmd_seguranca(SimpleNamespace(action=action, path=path, length=length,
                                   format='json', output=None))


def _interactive_rede() -> None:
    action = _ask_choice("Ação", ['ping', 'traceroute', 'dns', 'banner'], default='ping')
    target = _ask_target("Alvo", "exemplo.com")
    if not target:
        return
    port = int(_ask("Porta", "80")) if action == 'banner' else 80
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_rede(SimpleNamespace(action=action, target=target, port=port, format='json', output=None))


def _interactive_sistema() -> None:
    action = _ask_choice("Ação", ['info', 'monitor', 'processos'], default='info')
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_sistema(SimpleNamespace(action=action, limit=30, format='json', output=None))


def _interactive_pentest() -> None:
    target = _ask_target("Alvo", "exemplo.com")
    if not target:
        return
    pipeline = _ask("Pipeline (1/2/3/all)", "1")
    exploit = False
    if pipeline in ('3', 'all'):
        exploit = _ask_bool("Injetar payloads ativos de XSS/SQLi/SSRF? (só com autorização)")
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    data = cmd_pentest(SimpleNamespace(target=target, pipeline=pipeline, exploit=exploit,
                                        format='json', output=None))
    _offer_save(data, f'pentest_pipeline{pipeline}')


def _interactive_nexus() -> None:
    target = _ask_target("Alvo", "exemplo.com")
    if not target:
        return
    ns = SimpleNamespace(
        target=target, deep=_ask_bool("Modo profundo?"),
        dashboard=_ask_bool("Gerar dashboard HTML?"), format='json', output=None,
    )
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_nexus(ns)


def _interactive_watch() -> None:
    target = _ask_target("Alvo", "exemplo.com")
    if not target:
        return
    pipeline = _ask("Pipeline (1/2/3)", "1")
    print()
    print(_c("⏳ Processando, aguarde...", _DIM))
    cmd_watch(SimpleNamespace(target=target, pipeline=pipeline, mode='check', interval=3600))


def _interactive_session_summary() -> None:
    cmd_session_summary(SimpleNamespace(format='json', output=None))


# Menu interativo organizado em 2 níveis: primeiro escolhe o framework/categoria,
# depois o teste dentro dela — em vez de uma lista plana de 20+ itens misturados.
_MENU_CATEGORIES = [
    ("OSINT Framework", [
        ("OSINT (domínio/email/ip/telefone/pessoa/empresa/imagem/darkweb)", _interactive_osint),
        ("Recon (passiva/ativa/threat-intel/username-search/password/url/paste)", _interactive_recon),
        ("Crawler passivo de uma página (links/emails/forms)", _interactive_crawl),
        ("Buscar CVEs por palavra-chave", _interactive_cve),
        ("Lookup de ASN/BGP", _interactive_asn),
        ("Verificar nó de saída Tor", _interactive_tor_check),
        ("Wayback Machine (snapshots arquivados)", _interactive_wayback),
        ("Gerar Google Dorks", _interactive_dorks),
        ("Analisar cabeçalho de email", _interactive_email_header),
        ("Metadados de documento (PDF/DOCX/XLSX/PPTX)", _interactive_doc_meta),
        ("Validar ID fiscal (CPF/CNPJ/SSN/NIF/SIRET)", _interactive_taxid),
        ("Identificar tipo de hash", _interactive_hash_id),
    ]),
    ("Pentest Framework", [
        ("Scanner de vulnerabilidades (30+ testes, por categoria)", _interactive_scanner),
        ("Subdomain Takeover Check", _interactive_takeover),
        ("Port scan num range CIDR", _interactive_cidr),
        ("Análise estática de APK Android", _interactive_apk),
        ("[OPT-IN, risco do usuário] Instrumentação dinâmica (Frida) em APK", _interactive_apk_dynamic),
        ("Supply chain (deps) — requirements.txt/package.json locais", _interactive_deps),
        ("Infrastructure as Code (IaC) — Terraform/Ansible locais", _interactive_iac),
        ("Pipeline (tradicional/agressiva/IA)", _interactive_pentest),
    ]),
    ("Toolkit — Sistema, Rede & Local", [
        ("Cripto (hash/encode/decode/uuid/rot13/caesar)", _interactive_cripto),
        ("Segurança local (scan/hash/permissões/senha)", _interactive_seguranca),
        ("Rede (ping/traceroute/dns/banner)", _interactive_rede),
        ("Sistema (info/monitor/processos)", _interactive_sistema),
    ]),
    ("Correlação & Monitorização", [
        ("NEXUS (grafo de correlação + risco)", _interactive_nexus),
        ("Watch — checar mudanças desde a última vez", _interactive_watch),
        ("Resumo de findings desta sessão (pipelines 2/3 rodadas até agora)", _interactive_session_summary),
    ]),
]


def _print_categories() -> None:
    print()
    for i, (label, items) in enumerate(_MENU_CATEGORIES, start=1):
        print(f"  {_c(str(i), _GREEN + _BOLD)}. {label} {_c(f'({len(items)} testes)', _DIM)}")
    print(f"  {_c('0', _RED + _BOLD)}. Sair")


def _run_category_menu(category_label: str, items: list) -> None:
    while True:
        _print_menu(items)
        choice = input(f"\n{_c('❯', _PURPLE)} [{category_label}] Escolha uma opção "
                        f"({_c('0', _RED)}=voltar): ").strip()
        if choice == '0':
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(items):
                label, action = items[idx]
                _run_action(label, action)
            else:
                print(_c("Opção inválida.", _RED))
        except ValueError:
            print(_c("Opção inválida.", _RED))
        except Exception as e:
            print(_c(f"Erro: {e}", _RED))
            input(_c("Pressione ENTER para voltar ao menu...", _DIM))
            _clear_screen()
            _print_banner(animate=False)


def cmd_interactive(_args: argparse.Namespace = None) -> None:
    _print_banner(animate=True)
    while True:
        _print_categories()
        choice = input(f"\n{_c('❯', _PURPLE)} Escolha uma categoria: ").strip()
        if choice == '0':
            print(_c("Até logo.", _DIM))
            break
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(_MENU_CATEGORIES):
                category_label, items = _MENU_CATEGORIES[idx]
                _run_category_menu(category_label, items)
                _clear_screen()
                _print_banner(animate=False)
            else:
                print(_c("Opção inválida.", _RED))
        except ValueError:
            print(_c("Opção inválida.", _RED))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='cli.py',
        description='Mão de Deus UNIFIED — OSINT + Pentest (arquitetura modular)',
    )
    sub = parser.add_subparsers(dest='command', required=True)

    p_osint = sub.add_parser('osint', help='Orquestradores OSINT por tipo de alvo')
    p_osint.add_argument('type', choices=[
        'domain', 'email', 'ip', 'phone', 'person', 'company', 'image', 'darkweb',
    ])
    p_osint.add_argument('target')
    p_osint.add_argument('--deep', action='store_true', help='Análise mais profunda (recon ativa/port scan)')
    p_osint.add_argument('--location', help='(person) localização para refinar a busca')
    p_osint.add_argument('--country', default='BR', help='(company) código do país, ex: BR, US, UK')
    _add_report_args(p_osint)
    p_osint.set_defaults(func=cmd_osint)

    p_recon = sub.add_parser('recon', help='Reconhecimento passivo/ativo/threat-intel')
    p_recon.add_argument('mode', choices=[
        'passive', 'active', 'threat-intel', 'username-search',
        'password-check', 'url-check', 'paste-search', 'rss-advisories',
    ])
    p_recon.add_argument('target', nargs='?', default=None, help='Não usado em rss-advisories')
    _add_report_args(p_recon)
    p_recon.set_defaults(func=cmd_recon)

    p_scanner = sub.add_parser('scanner', help='Scanner ativo de vulnerabilidades (Task 7)')
    p_scanner.add_argument('name', choices=sorted(SCANNERS.keys()))
    p_scanner.add_argument('target', help='URL ou domínio alvo')
    _add_report_args(p_scanner)
    p_scanner.set_defaults(func=cmd_scanner)

    p_takeover = sub.add_parser('takeover', help='Verifica subdomain takeover (enumera + resolve CNAME + testa)')
    p_takeover.add_argument('target', help='Domínio raiz')
    p_takeover.add_argument('--max-subdomains', type=int, default=40)
    _add_report_args(p_takeover)
    p_takeover.set_defaults(func=cmd_takeover)

    p_taxid = sub.add_parser('taxid', help='Validação de IDs fiscais (CPF, CNPJ, SSN, NIF, SIRET)')
    p_taxid.add_argument('value')
    p_taxid.add_argument('--country', default='BR')
    p_taxid.add_argument('--type', default=None, help='CPF, CNPJ, SSN, NIF, SIRET (auto-detectado se omitido)')
    _add_report_args(p_taxid)
    p_taxid.set_defaults(func=cmd_taxid)

    p_crawl = sub.add_parser('crawl', help='Crawler passivo de uma página (links/emails/forms)')
    p_crawl.add_argument('url')
    _add_report_args(p_crawl)
    p_crawl.set_defaults(func=cmd_crawl)

    p_cve = sub.add_parser('cve', help='Busca CVEs por palavra-chave (NVD)')
    p_cve.add_argument('keyword')
    p_cve.add_argument('--limit', type=int, default=15)
    _add_report_args(p_cve)
    p_cve.set_defaults(func=cmd_cve)

    p_asn = sub.add_parser('asn', help='Lookup de ASN/BGP para um IP')
    p_asn.add_argument('target')
    _add_report_args(p_asn)
    p_asn.set_defaults(func=cmd_asn)

    p_tor = sub.add_parser('tor-check', help='Verifica se um IP é nó de saída Tor')
    p_tor.add_argument('ip')
    _add_report_args(p_tor)
    p_tor.set_defaults(func=cmd_tor_check)

    p_wayback = sub.add_parser('wayback', help='Consulta snapshots no Wayback Machine')
    p_wayback.add_argument('url')
    p_wayback.add_argument('--limit', type=int, default=10)
    _add_report_args(p_wayback)
    p_wayback.set_defaults(func=cmd_wayback)

    p_dorks = sub.add_parser('dorks', help='Gera Google Dorks para um domínio')
    p_dorks.add_argument('domain')
    _add_report_args(p_dorks)
    p_dorks.set_defaults(func=cmd_dorks)

    p_hashid = sub.add_parser('hash-id', help='Identifica o algoritmo provável de um hash')
    p_hashid.add_argument('value')
    _add_report_args(p_hashid)
    p_hashid.set_defaults(func=cmd_hash_id)

    p_emailhdr = sub.add_parser('email-header', help='Analisa cabeçalho de email bruto (ficheiro .eml/.txt)')
    p_emailhdr.add_argument('file', help='Caminho para ficheiro com o cabeçalho bruto')
    _add_report_args(p_emailhdr)
    p_emailhdr.set_defaults(func=cmd_email_header)

    p_docmeta = sub.add_parser('doc-meta', help='Extrai metadados de PDF/DOCX/XLSX/PPTX')
    p_docmeta.add_argument('file')
    _add_report_args(p_docmeta)
    p_docmeta.set_defaults(func=cmd_doc_meta)

    p_apk = sub.add_parser('apk', help='Análise estática de segurança de um APK Android')
    p_apk.add_argument('file', help='Caminho para o arquivo .apk')
    _add_report_args(p_apk)
    p_apk.set_defaults(func=cmd_apk)

    p_apk_dyn = sub.add_parser(
        'apk-dynamic',
        help='[OPT-IN, risco do usuário] Instrumentação dinâmica via Frida em app Android em execução',
    )
    p_apk_dyn.add_argument('package', help='Nome do pacote Android (ex: com.exemplo.app)')
    p_apk_dyn.add_argument('--device', default=None, help='ID do device/emulador (default: primeiro USB)')
    p_apk_dyn.add_argument('--i-accept-risk', action='store_true',
                            help='Confirma autorização explícita para anexar via Frida ao processo')
    _add_report_args(p_apk_dyn)
    p_apk_dyn.set_defaults(func=cmd_apk_dynamic)

    p_deps = sub.add_parser('deps', help='Analisa requirements.txt/package.json locais (supply chain)')
    p_deps.add_argument('path', help='Caminho do diretório do projeto')
    _add_report_args(p_deps)
    p_deps.set_defaults(func=cmd_deps)

    p_iac = sub.add_parser('iac', help='Analisa arquivos Terraform/Ansible locais (Infrastructure as Code)')
    p_iac.add_argument('path', help='Caminho do diretório do projeto')
    _add_report_args(p_iac)
    p_iac.set_defaults(func=cmd_iac)

    p_cidr = sub.add_parser('cidr', help='Port scan num range de IPs (CIDR)')
    p_cidr.add_argument('cidr', help='Ex: 192.168.1.0/24')
    p_cidr.add_argument('--max-hosts', type=int, default=256)
    _add_report_args(p_cidr)
    p_cidr.set_defaults(func=cmd_cidr)

    p_cripto = sub.add_parser('cripto', help='Utilitários criptográficos (hash/encode/decode/uuid/rot13/caesar)')
    p_cripto.add_argument('action', choices=['hash', 'encode', 'decode', 'uuid', 'rot13', 'caesar'])
    p_cripto.add_argument('value', nargs='?', default='', help='Texto de entrada (não usado em uuid)')
    p_cripto.add_argument('--scheme', choices=['base64', 'hex', 'url'], default='base64',
                           help='(encode/decode) esquema a usar')
    p_cripto.add_argument('--shift', type=int, default=13, help='(caesar) deslocamento')
    _add_report_args(p_cripto)
    p_cripto.set_defaults(func=cmd_cripto)

    p_seguranca = sub.add_parser('seguranca', help='Utilitários de segurança local')
    p_seguranca.add_argument('action', choices=['scan', 'hash', 'permissoes', 'senha'])
    p_seguranca.add_argument('path', nargs='?', default='.', help='Caminho (não usado em senha)')
    p_seguranca.add_argument('--length', type=int, default=16, help='(senha) comprimento')
    _add_report_args(p_seguranca)
    p_seguranca.set_defaults(func=cmd_seguranca)

    p_rede = sub.add_parser('rede', help='Utilitários de rede (ping/traceroute/dns/banner)')
    p_rede.add_argument('action', choices=['ping', 'traceroute', 'dns', 'banner'])
    p_rede.add_argument('target')
    p_rede.add_argument('--port', type=int, default=80, help='(banner) porta a conectar')
    _add_report_args(p_rede)
    p_rede.set_defaults(func=cmd_rede)

    p_sistema = sub.add_parser('sistema', help='Informação de sistema local (specs/monitor/processos)')
    p_sistema.add_argument('action', choices=['info', 'monitor', 'processos'])
    p_sistema.add_argument('--limit', type=int, default=30, help='(processos) máximo a listar')
    _add_report_args(p_sistema)
    p_sistema.set_defaults(func=cmd_sistema)

    p_pentest = sub.add_parser('pentest', help='Pipelines unificadas (Task 11)')
    p_pentest.add_argument('target')
    p_pentest.add_argument('--pipeline', choices=['1', '2', '3', 'all'], default='1')
    p_pentest.add_argument('--exploit', action='store_true',
                            help='(pipeline 3/all) injeta payloads ativos de XSS/SQLi/SSRF — '
                                 'use só com autorização explícita do alvo')
    _add_report_args(p_pentest)
    p_pentest.set_defaults(func=cmd_pentest)

    p_nexus = sub.add_parser('nexus', help='NEXUS — recon automático + grafo de correlação (Task 10)')
    p_nexus.add_argument('target')
    p_nexus.add_argument('--deep', action='store_true', help='Inclui recon ativa + scanner no grafo')
    p_nexus.add_argument('--dashboard', action='store_true', help='Gera dashboard HTML com grafo D3.js')
    _add_report_args(p_nexus)
    p_nexus.set_defaults(func=cmd_nexus)

    p_watch = sub.add_parser('watch', help='Monitorização contínua de um alvo (snapshot + diff)')
    p_watch.add_argument('target')
    p_watch.add_argument('--pipeline', choices=['1', '2', '3'], default='1')
    p_watch.add_argument('--mode', choices=['check', 'loop'], default='check',
                          help="'check' roda uma vez; 'loop' repete a cada --interval segundos")
    p_watch.add_argument('--interval', type=int, default=3600,
                          help='Segundos entre checagens no modo loop (padrão 3600 = 1h)')
    p_watch.set_defaults(func=cmd_watch)

    p_interactive = sub.add_parser('interactive', help='Modo interativo por menu numerado')
    p_interactive.set_defaults(func=cmd_interactive)

    p_summary = sub.add_parser('session-summary', help='Findings agregados no SharedContext (só útil dentro do mesmo processo)')
    _add_report_args(p_summary)
    p_summary.set_defaults(func=cmd_session_summary)

    return parser


def main(argv=None) -> int:
    # No Windows, cmd.exe/PowerShell antigos não interpretam ANSI nativamente;
    # colorama.init() intercepta os códigos e traduz para a Win32 Console API.
    # No Linux/Mac é inofensivo (passa os códigos ANSI direto).
    colorama.init()

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except Exception as e:
        print(f"Erro: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
