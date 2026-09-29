# Instruções para Desenvolvimento com IA — Mão de Deus UNIFIED

Este ficheiro serve para **qualquer assistente de IA** (Claude, Copilot,
Cursor, etc.) usado por qualquer contribuidor deste projeto. Lê isto antes
de escrever ou sugerir código aqui.

## 🎯 Visão geral do projeto

A Mão de Deus UNIFIED é uma ferramenta de **linha de comando** de OSINT e
pentest — não é uma API web, não tem servidor HTTP próprio nem base de
dados. É `cli.py` chamando módulos Python que, por sua vez, fazem
requisições a APIs públicas/de terceiros (WHOIS, Shodan, NVD, Wayback
Machine, etc.) e devolvem um dicionário JSON-serializável.

### Missão crítica
- **Funciona de graça, sempre**: nenhuma funcionalidade essencial pode
  exigir uma conta paga. Chaves de API são aditivas, não requisitos.
- **Multiplataforma real**: Linux, macOS e Windows. Sem exceções silenciosas.
- **Nunca finge um dado real**: um valor fabricado (`"N/A"`, `[]` sempre
  vazio sem tentar a chamada real) é pior do que um erro explícito — isto
  já foi um bug real do projeto (o WHOIS era um stub) e é o tipo de coisa
  que uma IA a gerar código rápido demais tende a introduzir sem perceber.
- **Uso autorizado apenas**: os módulos de exploração ativa
  (`modules/scanner/`, `modules/ai/exploit_tester.py`) nunca correm por
  padrão — exigem opt-in explícito do operador (`--exploit`).

## ⚠️ Princípios fundamentais

### 1. Nunca quebres o contrato de um subcomando existente
- Não removas nem renomeies uma chave do JSON de retorno de um comando já
  existente.
- Não mudes o tipo de um campo (`string` → `number`, lista → objeto).
- Não mudes o significado de um argumento posicional ou o comportamento
  padrão de uma flag já existente.
- Se precisares de mudar algo assim, documenta como *breaking change* no
  [CHANGELOG.md](CHANGELOG.md) e explica o porquê.

### 2. Degradação graciosa é obrigatória
Quando uma funcionalidade depende de uma API key opcional
(`core/config.py`), o padrão é sempre este — nunca deixes uma exceção subir
por falta de credencial:

```python
if not Config.SHODAN_API_KEY:
    return {
        "available": False,
        "hint": "Configura SHODAN_API_KEY no .env — https://account.shodan.io/",
    }
```

### 3. Zero dependências desnecessárias
Antes de sugerir `pip install algo`, pergunta-te:
1. A stdlib já resolve isto? (`hashlib`, `ipaddress`, `zipfile`, `socket`...)
2. Já existe uma dependência instalada que resolve? (`requests`, `bs4`,
   `phonenumbers`...)
3. Só se a resposta for "não" às duas, adiciona ao `requirements.txt` — e só
   se for realmente importada nalgum `.py`.

Se a dependência só funciona num SO (ex: `win10toast`), usa o marcador de
ambiente: `nome-pacote ; sys_platform == "win32"`.

### 4. Honestidade sobre heurísticas
Se um valor devolvido é uma estimativa (ex: risco de spam por tipo de linha
telefónica) e não uma verificação confirmada, isso tem de ficar explícito
num campo ao lado (`spam_risk_reason`, `hint`, `note`). Nunca apresentes uma
heurística como se fosse um facto verificado.

## 🏗️ Arquitetura do projeto

```
core/                configuração (+ loader de .env), logger, HTTPClient
                      (retry/timeout centralizados), cache SQLite, validador,
                      SharedContext, watch_store
modules/
  recon/              coleta de dados bruta (WHOIS, DNS, port scan, CVE,
                       ASN, Tor, Wayback, threat intel, RSS, crawler)
  osint/              ORQUESTRADORES por tipo de alvo — combinam módulos de
                       recon/ para um resultado único (domain/email/ip/
                       phone/person/company/image/darkweb)
  scanner/            testes ativos de vulnerabilidade contra uma URL/host;
                       supply_chain_scanner.py e o DependencyScanner/
                       IaCScanner são white-box (recebem um diretório local,
                       não uma URL); dom_scanner.py precisa de Playwright
  mobile/             ApkStaticScanner (estático, androguard) +
                       FridaDynamicTester (dinâmico via Frida, opt-in,
                       exige device/emulador real — nunca corre sem
                       --i-accept-risk explícito)
  toolkit/            utilitários locais sem alvo remoto (cripto, sistema,
                       segurança de ficheiros, rede)
  localization/       validação de país/telefone/CPF-CNPJ-SSN-NIF-SIRET
  intelligence/        NEXUS: grafo de correlação + score de risco
  ai/                  SecretScanner (estático) + ExploitTester (ativo, opt-in)
pipelines/            combina módulos acima em 3 níveis (tradicional/
                      agressiva/IA)
reports/              serializa o dicionário de resultado em 6 formatos
cli.py                argparse (subcomandos) + menu interativo
tests/                unittest, sem rede real (HTTPClient mockado)
```

**Regra de dependência entre camadas**: `modules/osint/` chama
`modules/recon/`, `modules/scanner/` ou `modules/toolkit/` — nunca o
contrário. Nenhum módulo em `modules/recon/` deve importar de
`modules/osint/`.

## 🧪 Testes

- Framework: `unittest` da stdlib (não há pytest instalado por padrão).
- Ficheiro: `tests/test_<área>.py` (ex: `test_osint.py`, `test_scanner.py`).
- Correr tudo: `python3 -m unittest discover -s tests -v`
- **Nunca** deixes um teste depender de rede real — mocka
  `core.http_client.HTTPClient` com `unittest.mock.patch`.

### Exemplo de teste (padrão do projeto)

```python
import unittest
from unittest.mock import patch, MagicMock
from modules.osint.phone import PhoneOSSINT

class TestPhoneOSSINT(unittest.TestCase):
    def test_telefone_valido_br(self):
        result = PhoneOSSINT().analyze('+5511987654321')
        self.assertTrue(result['valid'])
        self.assertEqual(result['country_code'], 'BR')
        self.assertIn('WhatsApp', result['social_search'])

    def test_sem_api_key_degrada_graciosamente(self):
        result = PhoneOSSINT().analyze('+5511987654321')
        self.assertFalse(result['twilio_lookup']['available'])
        self.assertIn('hint', result['twilio_lookup'])
```

## 📝 Padrões de código

### Python
- `snake_case` para variáveis/funções, `PascalCase` para classes.
- Type hints em assinaturas públicas (`def analyze(self, ip: str) -> Dict[str, Any]:`).
- Usa `core.logger.get_logger(__name__)` — nunca `print()` para debug
  deixado no código final.
- Toda chamada HTTP passa por `core.http_client.HTTPClient`
  (`self.http_client.get(url, timeout=..., raise_for_status=False)` quando
  precisas de inspecionar o corpo mesmo em erro 4xx/5xx).

### Commits
- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`
- Exemplo: `feat(osint): adiciona lookup de Shodan a osint ip`

### Tratamento de erros e resultado

- Retorna sempre um `dict`, nunca lances uma exceção genérica até ao
  utilizador final — `cli.py:main()` só captura no topo como rede de
  segurança, não é para contar com isso em código de módulo.
- Formato padrão de erro dentro do resultado:
```python
{"target": alvo, "error": "mensagem clara em português do que falhou"}
```
- Formato padrão quando falta uma API key (ver princípio 2 acima).

## 🔒 Segurança

- **Nunca** commites credenciais — usa sempre `Config.<NOME>_API_KEY` lido
  do `.env` (que está no `.gitignore`).
- Valida input do utilizador nas fronteiras (ex: `Validator.is_ip`,
  `Validator.is_domain` antes de usar num scan).
- `subprocess.run(...)` deve sempre receber uma **lista** de argumentos,
  nunca `shell=True` com uma string concatenada com input do utilizador
  (ver `modules/toolkit/network_tools.py` como referência correta).
- Módulos de exploração ativa (`modules/ai/exploit_tester.py`,
  `modules/scanner/`) nunca correm automaticamente — sempre atrás de uma
  flag explícita como `--exploit`.
- `modules/mobile/dynamic_instrumentation.py` (Frida) é a exceção mais
  sensível do projeto: anexa a um processo em execução num device real.
  **Nunca** remover, contornar ou tornar opcional o gate `--i-accept-risk`
  em `cmd_apk_dynamic` — mesmo que pedido para "simplificar" o comando.

## 🚀 Workflow: criando uma funcionalidade nova

### Caso 1 — nova fonte de dados para um tipo de alvo já existente
(ex: mais um campo para `osint ip`)

1. Adiciona o método ao módulo de recon relevante (`modules/recon/threat_intel.py`,
   por exemplo).
2. Liga o resultado no orquestrador (`modules/osint/ip.py`).
3. Se usa API key nova, regista em `core/config.py` + `.env.example`.
4. Testa: sucesso + sem API key configurada.
5. Atualiza a tabela de chaves de API no `README.md`.

### Caso 2 — tipo de alvo totalmente novo

1. Cria `modules/osint/<novo_tipo>.py` com uma classe `<Tipo>OSSINT` que
   expõe `.analyze(alvo)` e `.close()`.
2. Regista em `modules/osint/__init__.py`.
3. Adiciona o `choice` em `p_osint` (`cli.py`, `build_parser()`).
4. Cria `tests/test_osint.py::Test<Tipo>OSSINT`.
5. Atualiza README (árvore de Arquitetura + secção "Comandos diretos").

### Caso 3 — subcomando avulso novo (tipo `cve`, `asn`, `hash-id`)

1. Implementa a lógica num módulo em `modules/recon/` ou `modules/toolkit/`.
2. Em `cli.py`: cria `cmd_<nome>()`, o parser em `build_parser()`
   (`sub.add_parser('nome-em-kebab-case', help='...')`), e a função
   `_interactive_<nome>()` + entrada em `_INTERACTIVE_MENU` para o menu
   numerado.
3. Testa via `python3 cli.py <nome> -h` e uma chamada real.
4. Atualiza README + `.env.example` se aplicável.

### Caso 4 — utilitário local sem alvo remoto

Vai para `modules/toolkit/` (ex: `crypto_tools.py`, `security_tools.py`) —
segue o mesmo padrão do Caso 3 a partir do passo 2.

## 📚 Tecnologias principais

- **Python 3.8+** — stdlib como primeira escolha sempre que possível
- **argparse** — parsing de subcomandos, não usar outra lib de CLI
- **requests** (via `HTTPClient`) — nunca chamar `requests` diretamente
  num módulo novo
- **unittest** — não introduzir pytest/outros frameworks de teste
- Dependências de terceiros atuais: `dnspython`, `python-whois`, `psutil`,
  `beautifulsoup4`, `colorama`, `feedparser`, `geoip2`, `shodan`,
  `phonenumbers`, `twilio`, `certifi` — todas com uso real no código,
  consulta `requirements.txt`

## ❓ Perguntas frequentes

**P: Posso remover uma chave do JSON de retorno de um comando existente?**
R: Não. Isso quebra quem já faz parsing desse JSON. Marca como *breaking
change* no CHANGELOG se for mesmo necessário.

**P: Posso adicionar uma dependência nova?**
R: Só se a stdlib e as dependências já instaladas não resolverem. Justifica
no PR porquê é necessária.

**P: Como adiciono um subcomando novo?**
R: Segue o "Caso 3" acima: módulo → `cmd_*` + parser + menu interativo em
`cli.py` → teste → README.

**P: Uma API externa que uso não tem chave configurada — o que faço?**
R: Devolve `{"available": False, "hint": "..."}`, nunca deixes a exceção
subir nem inventes um valor.

**P: Posso fazer o módulo de exploit correr automaticamente numa pipeline?**
R: Não. Tem de continuar atrás de um opt-in explícito (`--exploit`) em
todos os pontos de entrada.

**P: Onde documento uma chave de API nova?**
R: `core/config.py` (leitura da env var) + `.env.example` (com link de onde
obter e se é grátis) + tabela no `README.md`.

## 🎓 Boas práticas específicas

### Ao trabalhar com APIs externas
- Sempre trata timeout e erro de conexão — `HTTPClient` já faz isto, usa-o.
- Usa `raise_for_status=False` quando precisas de inspecionar o corpo da
  resposta mesmo em 4xx/5xx (ex: página "user not found" com status 200
  vs. API que devolve 404 real — ver `modules/recon/osint_deep.py`).
- Usa `core.persistent_cache` quando a mesma consulta pode repetir-se
  (WHOIS, DNS, threat intel) — evita gastar limite de taxa da API externa.

### Ao trabalhar com dados de OSINT
- Normaliza formatos (E.164 para telefones, ISO 8601 para datas).
- Nunca apresentes um "provável" como "confirmado" — ver princípio de
  honestidade sobre heurísticas.
- Lembra-te de que o resultado pode ser usado para decisões reais (é
  investigação/segurança) — precisão importa mais do que velocidade.

## ⚡ Comandos rápidos

```bash
python3 -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt                     # instalar dependências
python3 cli.py --help                                 # ver subcomandos
python3 cli.py interactive                             # menu numerado
python3 -m unittest discover -s tests -v                # correr testes
python3 -c "import py_compile; py_compile.compile('cli.py', doraise=True)"  # syntax check rápido
```

---

**Lembra-te**: isto é uma ferramenta de segurança usada por uma pessoa para
tomar decisões sobre alvos reais. Um dado fabricado ou uma heurística
disfarçada de facto é o pior tipo de bug que uma IA pode introduzir aqui —
mais silencioso e mais perigoso do que um crash óbvio.
