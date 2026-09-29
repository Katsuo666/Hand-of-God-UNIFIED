# Changelog

## Não lançado

### Corrigido

- **`modules/ai/exploit_tester.py`** — `ExploitTester` agora usa o
  `WebCrawler` (`modules/recon/web_crawler.py`) para descobrir parâmetros
  reais de formulários e links antes de injetar payloads, em vez de testar
  só a query string do alvo + uma lista de nomes genéricos. Fecha a lacuna
  em relação ao `AIEngine`, documentada como nota de escopo
  na versão anterior. `WebCrawler` passou a aceitar um `http_client`
  opcional para permitir este reuso sem duplicar sessões HTTP.


### Adicionado

- **`modules/scanner/`** — mais 20 scanners ativos, cobrindo a lista de 150
  vulnerabilidades priorizadas para o projeto:
  - Remoto: `OAuthTester` (redirect_uri hijacking, state omission),
    `LoginTimingTester` (user enumeration via timing), `WebCacheDeceptionTester`,
    `TabnabbingTester`, `ExposedServicesScanner` (Docker API/Kubernetes/CI-CD
    expostos), `SSRFTester` (metadados de nuvem AWS/GCP/Azure),
    `RequestSmugglingTester` (CL.TE desync), `Http2SupportChecker` (deteção
    passiva, sem ataque Rapid Reset real), `PrototypePollutionScanner`
    (heurística estática de JS), `SAMLTester` (metadata/SSO), `DOMCloakingScanner`
    (DOM Clobbering via Playwright/Chromium — único scanner que precisa de
    motor JS real).
  - `GraphQLTester` expandido: depth limit, batching attack, over-fetching
    de campos sensíveis.
  - `SSTITester` expandido: variante blind time-based.
  - Local/white-box (recebem um caminho de diretório, não uma URL):
    `DependencyScanner` (supply chain — registries HTTP, typosquatting,
    dependency confusion) e `IaCScanner` (Terraform/Ansible — security
    groups abertos, buckets públicos, storage sem encriptação).
- **`modules/mobile/apk_scanner.py`** — 4 novos checks estáticos:
  StrandHogg (task hijacking), Tapjacking, exposição de clipboard, uso de
  criptografia sem AndroidKeyStore.
- **`modules/mobile/dynamic_instrumentation.py`** — `FridaDynamicTester`,
  opt-in (`apk-dynamic --i-accept-risk`), instrumentação dinâmica via Frida
  contra uma app em execução num device/emulador autorizado: deteção de
  anti-instrumentação, superfície de bypass biométrico, superfície de
  dynamic linker injection. Dependência `frida`/`frida-tools` opcional,
  não incluída em `requirements.txt`.
- **`cli.py`** — novos subcomandos `deps`, `iac` e `apk-dynamic`; `scanner`
  ganhou 12 novos nomes (`oauth`, `logintiming`, `cachedeception`,
  `tabnabbing`, `exposedservices`, `ssrf`, `smuggling`, `http2`,
  `protopollution`, `saml`, `domcloaking`) e um novo grupo no menu
  interativo ("Protocolo & Client-side (avançado)").
- **`requirements.txt`** — `playwright` (para `domcloaking`; exige também
  `python -m playwright install chromium`).

### Adicionado (base da versão anterior)

- **`core/`** — `Config`, `Logger`, `HTTPClient` (retry + rate-limit),
  `PersistentCache` (SQLite + TTL), `Validator`, `SharedContext` (estado
  partilhado entre módulos), `WatchStore` (snapshots para monitorização).
- **`modules/recon/`** — `PassiveRecon` (DNS/WHOIS/SSL/subdomínios),
  `ActiveRecon` (port scan/HTTP probe), `OSINTDeep` (50+ plataformas de
  username, email recon, breach check HIBP, anti-phishing, paste search,
  dark web monitor), `ThreatIntel`.
- **`modules/scanner/`** (base) — WAF, JWT, GraphQL, IDOR, Clickjacking,
  Rate Limit, API Fuzzer, SSL/TLS, Robots/Sitemap, Vuln Scanner (arquivos
  sensíveis expostos), Subdomain Takeover Checker, mais os scanners de
  hardening HTTP e injeção ativa (path traversal, command injection, XXE,
  SSTI, NoSQLi, LDAP injection, HTML injection, deserialização insegura,
  Zip Slip, upload sem restrição, mass assignment, ReDoS/XML bomb, cache).
- **`modules/osint/`** — 8 orquestradores por tipo de alvo (domain, email,
  ip, phone, person, company, image, darkweb), incluindo verificação de
  email descartável integrada.
- **`modules/localization/`** — `CountryRegistry` (BR/US/UK/ES/FR/PT +
  fallback E.164 genérico), `TaxIDValidator` (CPF, CNPJ, SSN, NIF-ES,
  SIRET, NIF-PT com checksum real), `PhoneValidator`.
- **`modules/intelligence/`** — `NexusEngine` (recon automático paralelo +
  detecção de tipo de alvo), `IntelGraph` (grafo D3.js-ready), `RiskAnalyzer`
  (score 0-100).
- **`modules/ai/`** — `SecretScanner` (regex de secrets + keywords sensíveis
  + fingerprint de tecnologia, análise estática) e `ExploitTester` (injeção
  ativa de XSS/SQLi/SSRF, opt-in via `--exploit`).
- **`pipelines/`** — pipeline 1 (tradicional), pipeline 2 (agressiva),
  pipeline 3 (IA), com dispatch unificado `run_pipeline()`.
- **`reports/`** — `ReportGenerator` (JSON/CSV/HTML/XML/Markdown/texto/PDF),
  `NexusReporter` (dashboard HTML com grafo de força D3.js interativo).
- **`cli.py`** (base) — `osint`, `recon`, `scanner`, `takeover`, `taxid`,
  `pentest`, `nexus`, `watch`, `interactive`, `session-summary`.
- **`tests/`** — 66 testes unitários (`unittest`, stdlib apenas, sem rede).

### Notas de escopo

- Fora do escopo por exigirem contexto/instrumentação que o toolkit não
  automatiza sozinho: SAML XSW real (exigiria uma asserção válida
  capturada — só a superfície de metadata é verificada), typosquatting/
  dependency confusion contra o registry público real (o `DependencyScanner`
  analisa apenas os manifestos locais, não consulta npm/PyPI).
- `main.py` (V1) tinha algumas dezenas de subcomandos e um modo interativo
  de 36 opções que não foram todos portados individualmente para `cli.py`
  antes da remoção do arquivo — ver README para o que o `cli.py` cobre.
