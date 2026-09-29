# Guia de boas práticas para contribuição

Este documento orienta novas contribuições a Mão de Deus UNIFIED, de forma
a manter os dados devolvidos consistentes e em formatos previsíveis,
independentemente de o resultado ser consumido via stdout, ficheiro
(`--output`) ou por outro script que chame `cli.py`.

Também orienta boas práticas de nomenclatura de variáveis, funções, classes
e subcomandos.

Neste guia usamos o termo **deve** para padrões indispensáveis e o termo
**deveria** para padrões desejáveis, mas não indispensáveis.

## Código-fonte

- Variáveis, classes, métodos e funções devem ter nomenclatura clara e
  condizente com a sua função.
- Nomes de variáveis, funções e métodos devem seguir `snake_case` (padrão
  Python/PEP 8) — nunca `camelCase`.
- Nomes de classes devem seguir `PascalCase` (ex: `PassiveRecon`,
  `ThreatIntel`, `CryptoTools`).
- A camada de orquestração (`modules/osint/*.py`, que combina resultados de
  vários módulos para um tipo de alvo) deve estar separada da camada de
  coleta de dados (`modules/recon/`, `modules/scanner/`, `modules/toolkit/`)
  — um orquestrador chama módulos de recon, nunca faz requisições HTTP
  diretamente.
- Toda chamada de rede deve passar por `core.http_client.HTTPClient`, nunca
  por `requests` importado diretamente num módulo novo — é o que garante
  retry, timeout e tratamento de erro consistentes em todo o projeto.
- Se uma função estiver muito complexa ou grande, considera dividi-la em
  funções menores com responsabilidades únicas.
- Toda funcionalidade que dependa de uma chave de API opcional deve degradar
  graciosamente: devolve `{"available": False, "hint": "..."}` com instrução
  de como obter a chave, nunca deixes uma `Exception` sem tratamento subir
  até ao utilizador só porque falta uma credencial opcional (ver
  `modules/recon/threat_intel.py:shodan_lookup` como referência).
- Para cada módulo novo em `modules/` deve haver um teste correspondente em
  `tests/`; casos que dependam de rede real devem mockar `HTTPClient` (ver
  `tests/test_osint.py`, `tests/test_scanner.py` para exemplos).

## Subcomandos da CLI

- Os nomes de subcomandos (`cli.py <nome>`) devem estar em inglês e em
  `kebab-case` quando compostos (ex: `tor-check`, `hash-id`, `doc-meta`,
  `rss-advisories`) — nunca `snake_case` ou `camelCase` na própria CLI.
- Um subcomando deve refletir claramente o seu objetivo — evita nomes
  genéricos como `run` ou `exec`.
- Qualquer alteração que quebre a assinatura de um subcomando já existente
  (renomear, remover argumento posicional, mudar o significado de uma flag)
  deve ser documentada no [CHANGELOG.md](CHANGELOG.md) com destaque de
  *breaking change* — este projeto não tem versionamento de subcomandos
  como uma API REST tem versionamento de URL, então a única rede de
  segurança é o changelog e a comunicação clara.
- Argumentos opcionais (que não mudam o significado do comando, só
  enriquecem o resultado — como `--deep`) podem ser adicionados livremente
  sem contar como breaking change.
- Todo subcomando deve terminar com código de saída `0` em sucesso e `1` em
  erro (já garantido pelo `main()` de `cli.py` — não capture exceções dentro
  do teu `cmd_*` só para "engolir" o erro).

## Formato de retorno

- O retorno de qualquer comando deve ser um dicionário Python serializável
  para JSON com `ensure_ascii=False` e `utf-8` (é o que `_output()` em
  `cli.py` já faz) — os outros formatos (`csv`, `html`, `xml`, `markdown`,
  `text`) são gerados a partir deste mesmo dicionário por
  `reports.ReportGenerator`, nunca construídos à parte.
- As chaves do dicionário devem usar `snake_case` (ex: `country_code`,
  `spam_risk`, `normalized_e164`) — nunca `camelCase`.
- Chaves que tenham nome natural em inglês devem ser escritas em inglês
  (`carrier`, `line_type`, `region`).
- Chaves específicas de um domínio sem tradução direta (`cpf`, `cnpj`,
  `nif`, `taxid`) devem manter o termo original, também em `snake_case`.
- Todo resultado deve incluir consistentemente:
  - `target` (ou `url`/`ip`/`domain`, conforme o tipo de alvo) — o que foi
    analisado;
  - `timestamp` — quando a análise correu (ver secção Datas);
  - um campo de erro (`error`) quando a análise falhar, em vez de omitir
    silenciosamente o resultado.

### Datas

| Tipo de data | Formato exigido | Exemplo |
|---|---|---|
| Data e hora | ISO 8601 via `datetime.now().isoformat()` | `2026-09-28T10:35:32.132413` |
| Data de terceiros (WHOIS, CVE, etc.) | Como a fonte devolve, convertida para `str()` | `"1997-09-15 04:00:00+00:00"` |

Nunca formates datas manualmente com `strftime` num formato ad-hoc — usa
sempre `.isoformat()` para dados gerados por este projeto, para que fiquem
comparáveis entre módulos diferentes (ex: no `watch_store` que faz diff
entre snapshots).

### Dados numéricos

- Valores numéricos devem ser devolvidos como `int`/`float` nativos, nunca
  como string (`"length": 16`, não `"length": "16"`).
- Percentagens e scores devem ser `float`, não string formatada
  (`"spam_confidence_score": 87.5`, não `"87.5%"`).

**Exemplos**

| Correto | Errado |
|---|---|
| `"total": 178` | `"total": "178"` |
| `"percent": 68.4` | `"percent": "68.4%"` |

### Objetos com "unidade + valor"

Quando um valor tem uma unidade ou classificação associada (moeda, risco,
tipo de linha), devolve um objeto explícito em vez de embutir tudo numa
string — o padrão já usado em `modules/osint/phone.py`:

```python
"carrier_intel": {
    "spam_risk": "elevado",
    "spam_risk_reason": "Linhas VOIP/toll-free/tarifa-premium têm taxa de "
                         "robocall e fraude historicamente mais alta.",
}
```

em vez de `"spam_risk": "elevado (VOIP/toll-free)"` — assim quem consome o
JSON consegue filtrar por `spam_risk == "elevado"` sem parsing de string.

### Honestidade sobre heurísticas

Quando um valor devolvido é uma **heurística** (ex: risco de spam por tipo
de linha telefónica) em vez de uma verificação real e confirmada, isso deve
ficar explícito num campo `*_reason` ou `note` ao lado — nunca apresentes
uma estimativa como se fosse um facto verificado. Ver o aviso em
`modules/osint/phone.py` sobre isto como referência de tom.

## Testes

- O teste deve ter nome/descrição coerente com o que está a testar
  (`test_cpf_invalido`, não `test_1`).
- O teste deve cobrir também o cenário de entrada inválida do utilizador
  (telefone malformado, domínio inválido, país não suportado), não só o
  caminho feliz.
- Quando o dado testado pode variar entre execuções (respostas de API
  externa, timestamps, hashes calculados com salt), prefere testar o
  **tipo**/estrutura do retorno em vez de um valor exato.
  - Exemplos de dados que variam: nomes/regiões geográficas devolvidos por
    `phonenumbers`, timestamps, resultados de scanners contra um alvo vivo.
  - Usa mocks de `HTTPClient` (ver `unittest.mock.patch`) para qualquer
    teste que dependeria de rede real — os 66 testes atuais correm todos
    offline, mantém essa garantia.
- Testes que envolvam uma chave de API opcional devem testar **o caminho
  sem a chave** (degradação graciosa) como caso obrigatório; o caminho com
  a chave real, se testado, deve ser marcado claramente como opcional/manual
  (este projeto não deve depender de segredos reais para o `unittest`
  passar em CI).

## Documentação

- Toda funcionalidade nova (subcomando, orquestrador, chave de API) deve
  atualizar o [README.md](README.md):
  - novo subcomando → secção "Comandos diretos";
  - novo módulo → árvore de `modules/` em "Arquitetura";
  - nova chave de API → tabela de "Chaves de API (opcionais)".
- Toda chave de API nova deve ser adicionada ao `.env.example` com um
  comentário curto: para que serve, onde obter, se é grátis ou paga.
- Toda mudança relevante deve ter uma linha no [CHANGELOG.md](CHANGELOG.md).
- Este projeto não usa OpenAPI/Swagger (não é uma API REST) — a
  documentação de "contrato" de cada subcomando é o próprio `--help` do
  `argparse` (`p_x.add_argument(..., help="...")`); mantém esse `help`
  sempre atualizado, é a única fonte de verdade que o utilizador vê sem
  abrir o código.
