# Guia de Revisão de Código — Mão de Deus UNIFIED

## 🎯 Objetivo da revisão

Este guia ajuda revisores a garantir que mudanças no código mantenham
qualidade, previsibilidade e segurança. A Mão de Deus UNIFIED é uma
ferramenta de OSINT/pentest usada diretamente pelo operador — um bug aqui
não derruba um servidor em produção como numa API pública, mas pode fazer o
operador confiar num dado falso (como o WHOIS que era stub e devolvia
`"N/A"` sempre) ou correr um scan ativo contra um alvo sem perceber. Ambos
os riscos merecem o mesmo rigor.

## ⚠️ Princípios de revisão

### 1. Nenhuma funcionalidade finge que funciona
Um resultado vazio, `None` silencioso ou stub que devolve dados fixos
(`"N/A"`, `[]`) sem nunca ter tentado a chamada real é **pior** do que um
erro explícito — engana quem usa a ferramenta. Isto já aconteceu uma vez
neste projeto (WHOIS stub) e é exatamente o tipo de bug que este guia existe
para apanhar antes do merge.

### 2. Degradação graciosa é obrigatória, silêncio não
Quando falta uma API key opcional, a funcionalidade deve devolver
`{"available": False, "hint": "..."}` — nunca lançar exceção não tratada
nem devolver dados fabricados como se fossem reais.

### 3. Zero dependências desnecessárias ou específicas de SO sem guarda
Toda dependência nova em `requirements.txt` deve ser realmente importada em
algum `.py`. Dependências específicas de um SO (tipo `win10toast`) precisam
de marcador de ambiente (`; sys_platform == "..."`) para não quebrar
`pip install` nos outros sistemas.

### 4. Segurança em primeiro lugar
Vulnerabilidades não são aceitáveis — nem no próprio código do projeto
(injeção de comando, path traversal), nem nos módulos de exploração ativa
correndo sem controlo (opt-in obrigatório).

## 🔍 Checklist de revisão obrigatória

### ✅ 1. Compatibilidade (CRÍTICO)

**Verificações obrigatórias:**

- [ ] Subcomandos existentes (`cli.py <nome>`) não foram removidos nem
      renomeados sem aviso no CHANGELOG
- [ ] Chaves do JSON de retorno não foram removidas nem renomeadas
- [ ] Tipos de campos não mudaram (`string` → `number`, lista → objeto)
- [ ] Argumentos posicionais existentes de um subcomando não mudaram de
      ordem ou significado
- [ ] Se algo disto foi necessário, está marcado como *breaking change* no
      [CHANGELOG.md](CHANGELOG.md)

**Como verificar:**
```bash
git diff main -- cli.py
git diff main -- modules/
```

**Perguntas a fazer:**
- Um script que já chama `cli.py <comando>` e faz parse do JSON continua a
  funcionar depois desta mudança?
- Um campo novo foi **adicionado**, não usado para substituir um existente?

### ✅ 2. Documentação

**Verificações obrigatórias:**

- [ ] Novo subcomando tem `help=` claro no `argparse` (`build_parser()`)
- [ ] [README.md](README.md) foi atualizado: secção "Comandos diretos" (se
      houver subcomando novo) e árvore de "Arquitetura" (se houver módulo
      novo)
- [ ] Nova chave de API está documentada no `.env.example` e na tabela do
      README ("Chaves de API")
- [ ] Se a mudança introduz uma heurística (não uma verificação real),
      isso está explícito no próprio output (`*_reason`/`hint`), conforme
      [GOOD_PRACTICES.md](GOOD_PRACTICES.md#honestidade-sobre-heurísticas)

**Como verificar:**
```bash
git diff main -- README.md .env.example
python3 cli.py <novo-comando> -h
```

**Perguntas a fazer:**
- Alguém que só leia `cli.py <comando> -h` consegue usar a funcionalidade?
- O README reflete exatamente o que o código faz agora?

### ✅ 3. Testes

**Verificações obrigatórias:**

- [ ] Módulo novo em `modules/` tem teste correspondente em `tests/`
- [ ] Caminho de sucesso está coberto
- [ ] Caminho de erro/entrada inválida está coberto (telefone malformado,
      domínio inválido, etc.)
- [ ] Caminho **sem** API key configurada está coberto, quando aplicável
      (degradação graciosa)
- [ ] Testes não dependem de rede real — `HTTPClient` mockado
- [ ] `python3 -m unittest discover -s tests -v` passa sem falhas

**Como verificar:**
```bash
python3 -m unittest discover -s tests -v
git diff main -- tests/
```

**Perguntas a fazer:**
- Este teste falharia se o código estivesse errado, ou só confirma o óbvio?
- Um caso real de erro de rede/API está simulado, ou só o caminho feliz?

### ✅ 4. Qualidade de código

**Verificações obrigatórias:**

- [ ] Nomenclatura segue `snake_case` (variáveis/funções) e `PascalCase`
      (classes) — ver [GOOD_PRACTICES.md](GOOD_PRACTICES.md)
- [ ] Sem `print()` de debug esquecido (usa `core.logger.get_logger`)
- [ ] Toda chamada HTTP passa por `core.http_client.HTTPClient`, nunca
      `requests` importado direto num módulo novo
- [ ] Funções grandes/complexas foram divididas em responsabilidades menores
- [ ] Sem duplicação óbvia de lógica já existente noutro módulo

**Como verificar:**
```bash
python3 -c "import py_compile; py_compile.compile('caminho/do/arquivo.py', doraise=True)"
git diff main
```

**Perguntas a fazer:**
- Este código é fácil de entender sem contexto extra?
- Haveria uma forma mais simples de resolver isto reaproveitando algo que
  já existe em `core/` ou `modules/`?

### ✅ 5. Custos e dependências

> ⚠️ Este projeto não tem orçamento para infraestrutura própria. Toda
> funcionalidade essencial deve continuar a funcionar de graça. Serviços
> pagos (Shodan, Twilio, VirusTotal, etc.) são sempre **opcionais e
> aditivos**, nunca um requisito para o uso básico da ferramenta.

**Verificações obrigatórias:**

- [ ] Dependência nova em `requirements.txt` é realmente importada em
      algum `.py` do projeto
- [ ] Dependência nova não tem alternativa já disponível na stdlib ou já
      instalada (ver [GOOD_PRACTICES.md](GOOD_PRACTICES.md))
- [ ] Dependência específica de SO tem marcador de ambiente
- [ ] Nenhuma funcionalidade **básica** passou a exigir uma API key paga
- [ ] Cache (`core.persistent_cache`) é usado quando faz sentido evitar
      repetir a mesma chamada externa

**Como verificar:**
```bash
git diff main -- requirements.txt
pip install -r requirements.txt   # confirma que instala limpo
```

**Perguntas a fazer:**
- Esta funcionalidade continua a funcionar (mesmo que com menos dados) para
  quem não tem nenhuma API key configurada?
- Esta dependência realmente precisa de ser um pacote novo?

### ✅ 6. Segurança

**Verificações obrigatórias:**

- [ ] Módulos de exploração/scan ativo continuam desligados por padrão
      (exigem flag explícita tipo `--exploit`)
- [ ] Nenhuma credencial/API key está hardcoded no código — só via
      `core.config.Config` (que lê do `.env`)
- [ ] Chamadas a `subprocess` (ex: `modules/toolkit/network_tools.py`)
      passam argumentos como lista, nunca `shell=True` com input do
      utilizador concatenado em string
- [ ] Caminhos de ficheiro fornecidos pelo utilizador (`seguranca`,
      `doc-meta`) não são usados para escrever fora do que foi pedido
      explicitamente
- [ ] Erros não vazam dados sensíveis (chave de API, caminho interno do
      sistema) na mensagem devolvida ao utilizador

**Como verificar:**
```bash
git diff main | grep -iE "shell=True|api_key.?=.?['\"]|password.?=.?['\"]"
grep -rn "subprocess" modules/
```

**Perguntas a fazer:**
- Um utilizador malicioso conseguiria injetar um comando através de um
  argumento que devia ser só um IP/domínio/URL?
- Esta mudança facilita, de alguma forma, o uso da ferramenta contra um
  alvo sem autorização?

### ✅ 7. Arquitetura e padrões

**Verificações obrigatórias:**

- [ ] Segue a separação de camadas: `modules/osint/` (orquestrador) chama
      `modules/recon/`/`modules/scanner/`/`modules/toolkit/` (coleta), nunca
      o contrário
- [ ] Novo tipo de alvo → `modules/osint/<tipo>.py` + registo em
      `modules/osint/__init__.py` + `choice` em `cli.py`
- [ ] Novo utilitário sem alvo remoto → `modules/toolkit/`
- [ ] Nova chave de API → adicionada a `core/config.py`, documentada no
      `.env.example`

**Como verificar:**
```bash
git status modules/
```

**Referência:** [GOOD_PRACTICES.md](GOOD_PRACTICES.md) — secção "Quando
adicionar um novo módulo" no [README.md](README.md#mantendo-o-projeto).

**Perguntas a fazer:**
- Este código está na pasta certa dado o que faz?
- Reaproveita `HTTPClient`/`Config`/`get_logger` em vez de reinventar?

## 🚨 Red flags — rejeitar imediatamente

1. **Stub/dado fabricado apresentado como real** — um `return {"campo": "N/A"}`
   sem sequer tentar a chamada real (o bug histórico do WHOIS).
2. **Quebra de compatibilidade sem aviso** — renomear/remover chave do JSON
   ou subcomando sem entrada no CHANGELOG.
3. **Sem testes** — código novo em `modules/` sem teste correspondente, ou
   testes existentes quebrados.
4. **Exceção não tratada por falta de API key opcional** — deve degradar
   graciosamente, nunca explodir.
5. **`subprocess` com `shell=True` e input do utilizador concatenado** —
   risco de injeção de comando.
6. **Dependência nova sem uso real no código**, ou dependência de SO sem
   marcador de ambiente.
7. **Módulo de exploração ativa ligado por padrão** (sem exigir flag
   explícita do operador).
8. **Heurística apresentada como facto verificado** — sem campo
   `*_reason`/`hint` a deixar claro que é uma estimativa.

## ✅ Aprovação condicional

Situações que podem ser aprovadas **após correções**:

1. **Documentação incompleta** → solicitar complemento no README/`.env.example`
2. **Testes insuficientes** → solicitar mais casos (erro, sem API key)
3. **Heurística sem aviso explícito** → solicitar campo `*_reason`
4. **Código complexo** → solicitar simplificação/divisão em funções menores
5. **Nomes pouco claros** → solicitar renomeação

## 💬 Dando feedback efetivo

### ✅ Bom feedback
```markdown
❌ Esta chave `spam_risk` foi removida do retorno de `osint phone`,
isso quebra quem já faz parse deste JSON. Podes manter o campo, mesmo
que sempre `null` quando não aplicável?

✅ Sugiro degradar graciosamente aqui em vez de deixar a exceção subir:
if not Config.SHODAN_API_KEY:
    return {"available": False, "hint": "Configura SHODAN_API_KEY no .env"}

💡 Esta chamada repetida à mesma API poderia usar o PersistentCache
existente em core/persistent_cache.py, reduzindo custo/latência.
```

### ❌ Feedback ruim
```markdown
❌ "Isso está errado, refaz"
❌ "Não gostei desta abordagem"
❌ "Funciona, mas eu faria diferente"
```

### Princípios de feedback

1. **Seja específico**: aponta o problema exato e sugere a solução.
2. **Seja construtivo**: critica o código, não a pessoa.
3. **Seja educativo**: explica o "porquê", não só o "o quê".
4. **Priorize**: separa crítico de nice-to-have.
5. **Reconheça**: destaca também o que ficou bem feito.

## 🎓 Perguntas para revisores iniciantes

1. **Eu entendi o que este código faz?** Se não, pede esclarecimento.
2. **Eu conseguiria dar manutenção nisto?** Se não, pode estar complexo
   demais.
3. **Isto pode fazer alguém confiar num dado falso?** É o risco nº1 deste
   projeto (OSINT/threat intel) — mais do que "vai crashar".
4. **Isto pode facilitar uso não autorizado da ferramenta?** Relevante para
   qualquer mudança em `modules/scanner/` ou `modules/ai/exploit_tester.py`
   — e ainda mais crítico em `modules/mobile/dynamic_instrumentation.py`
   (Frida), que anexa a um processo real: qualquer PR que toque no gate
   `--i-accept-risk` merece revisão redobrada.
5. **Os testes cobrem o essencial?** Tenta pensar num caso não coberto.

## 📊 Checklist rápida

```
⚠️  CRÍTICO
└─ [ ] Compatibilidade de subcomandos/JSON mantida
└─ [ ] Sem stub/dado fabricado apresentado como real
└─ [ ] Testes passando (incluindo caminho sem API key)
└─ [ ] Exploração ativa continua opt-in

⚡ IMPORTANTE
└─ [ ] Documentação (README + .env.example) atualizada
└─ [ ] Segurança validada (subprocess, paths, credenciais)
└─ [ ] Nenhuma dependência supérflua

✨ NICE-TO-HAVE
└─ [ ] Uso do cache onde reduz chamadas externas
└─ [ ] Código simplificado onde possível
└─ [ ] Heurísticas com `*_reason` explicando o porquê
```

## 🔄 Processo de revisão

### 1. Primeira leitura (5–10 min)
- Lê a descrição do PR e entende o objetivo.
- Identifica os ficheiros modificados (`modules/`? `cli.py`? `core/`?).
- Procura red flags óbvias (stub, exceção não tratada, `shell=True`).

### 2. Revisão detalhada (15–30 min)
- Percorre o checklist obrigatório.
- Corre `python3 -m unittest discover -s tests -v`.
- Testa manualmente o subcomando novo contra um alvo real, se possível.
- Confirma que a degradação sem API key funciona (`unset` a variável e
  testa de novo).

### 3. Verificação de duplicidade (obrigatório em repositórios com mais de
um revisor)
- Lê todos os comentários já existentes no PR antes de escrever os teus.
- Se o ponto já foi levantado, reforça com 👍 em vez de duplicar o
  comentário.

### 4. Feedback (5–10 min)
- Lista problemas críticos (bloqueantes) separados de sugestões.
- Destaca pontos positivos.

### 5. Decisão
- **Aprovar**: tudo certo, ou só sugestões menores.
- **Request changes**: há algo do checklist crítico por corrigir.
- **Comment**: dúvida ou discussão necessária antes de decidir.

## 🤝 Quando pedir ajuda

Não hesites em pedir uma segunda opinião quando:

- Não entendes a técnica/API externa usada (ex: um campo novo do Shodan).
- Não tens certeza se algo quebra compatibilidade.
- A mudança toca `modules/scanner/` ou `modules/ai/exploit_tester.py` e
  queres confirmar que o comportamento opt-in continua correto.

## 📚 Recursos de apoio

- [GOOD_PRACTICES.md](GOOD_PRACTICES.md) — convenções de código, formato de
  retorno e testes
- [CONTRIBUTING.md](CONTRIBUTING.md) — fluxo de contribuição e PRs
- [README.md](README.md) — arquitetura, comandos e tabela de chaves de API
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — conduta esperada na comunidade

---

**Lembra-te**: revisão de código aqui é sobre **não deixar o operador
confiar num dado falso** e **não facilitar uso indevido da ferramenta**. Sê
rigoroso, mas construtivo — um PR recusado hoje evita um WHOIS a devolver
`"N/A"` para sempre amanhã. 🛡️
