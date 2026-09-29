# :link: Como contribuir

## Princípios do projeto

- **Zero dependências desnecessárias:** a Mão de Deus UNIFIED não depende de
  banco de dados próprio nem de serviço pago para funcionar. Tudo o que
  precisa de credencial (Shodan, VirusTotal, Twilio, etc.) é **opcional** e
  deve degradar graciosamente na ausência da chave — nunca torna uma
  funcionalidade essencial dependente de uma conta paga.
- **Multiplataforma de verdade:** o projeto deve instalar e correr em Linux,
  macOS e Windows. Qualquer dependência específica de um SO precisa de
  marcador de ambiente no `requirements.txt` (`; sys_platform == "..."`)
  para nunca quebrar o `pip install` nos outros sistemas.
- **Uso ético e autorizado:** este projeto tem módulos de scan/exploração
  ativa. Qualquer contribuição deve manter esses módulos desligados por
  padrão (opt-in explícito, como `--exploit`) e nunca facilitar o uso contra
  alvos sem autorização — ver o aviso legal no [README.md](README.md).
- **Comunidade:** qualquer contribuição que agregue valor é bem-vinda, desde
  que siga estes princípios.

**Antes de começar a desenvolver, recomendamos a leitura do
[Guia de Boas Práticas](GOOD_PRACTICES.md).**

## Iniciando

Certifica-te de estar na pasta raiz do projeto:

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

```bash
python3 cli.py --help             # ver todos os subcomandos
python3 cli.py interactive        # menu numerado, bom para explorar
python3 -m unittest discover -s tests -v   # correr a suite de testes
```

Para adicionar uma funcionalidade nova, segue a secção **"Mantendo o
projeto"** do [README.md](README.md#mantendo-o-projeto) — resume onde cada
tipo de contribuição encaixa na árvore de `modules/`.

## Mensagens de commit

Sugerimos que as mensagens de commit sigam o padrão do
[_conventional commits_](https://www.conventionalcommits.org/) (`feat:`,
`fix:`, `docs:`, `test:`, `refactor:`, ...) — ajuda a manter o
[CHANGELOG.md](CHANGELOG.md) claro e a perceber rapidamente o histórico do
projeto. Não há uma ferramenta interativa configurada para isto (o projeto
não usa Node/npm), então basta escrever a mensagem seguindo a convenção
manualmente, por exemplo:

```bash
git commit -m "feat: adiciona lookup de ASN via bgpview"
git commit -m "fix: corrige headers None no HTTPClient"
```

## Documentação

Este projeto **não** é uma API REST — não usamos OpenAPI/Swagger. A
documentação de cada subcomando vive em dois lugares:

1. O `help=` de cada argumento no `argparse` (`build_parser()` em `cli.py`)
   — é o que o utilizador vê em `cli.py <comando> -h`, mantém sempre
   atualizado.
2. O [README.md](README.md) — sempre que criares um subcomando novo ou um
   módulo novo, atualiza:
   - a secção **"Comandos diretos"** com um exemplo de uso;
   - a árvore de **"Arquitetura"** se criaste um ficheiro novo em `modules/`;
   - a tabela de **"Chaves de API (opcionais)"** se a funcionalidade usa uma
     credencial nova (não te esqueças de também documentar no
     `.env.example`).

## Compatibilidade

A Mão de Deus UNIFIED não tem versionamento de subcomandos como uma API
REST tem versionamento de URL — a única rede de segurança contra quebrar o
uso de quem já depende da CLI é disciplina + o `CHANGELOG.md`. **Evita**
fazer isto num subcomando já existente sem discutir antes:

- Remover ou renomear uma chave do JSON de retorno
- Mudar o tipo de um campo (`string` → `number`, lista → objeto, etc.)
- Renomear o próprio subcomando ou um argumento posicional
- Mudar o comportamento padrão de uma flag já existente

Se a tua mudança exige algo disto, documenta claramente como *breaking
change* no `CHANGELOG.md` e explica o motivo no PR.

Adicionar um campo novo ao JSON de retorno, uma flag opcional nova, ou um
subcomando totalmente novo é sempre seguro e não exige nenhum cuidado
especial de compatibilidade.

## Testes

Toda contribuição de código deve manter a suite de testes a passar:

```bash
python3 -m unittest discover -s tests -v
```

- Módulo novo em `modules/` → adiciona um `tests/test_<área>.py`
  correspondente (ou uma classe nova num ficheiro já existente da mesma
  área).
- Testes não devem depender de rede real — mocka `core.http_client.HTTPClient`
  (ver exemplos em `tests/test_osint.py` e `tests/test_scanner.py`).
- Se a funcionalidade usa uma chave de API opcional, o teste **deve** cobrir
  o caminho sem a chave (degradação graciosa) — é o caminho que corre em CI.

## Pull requests (PRs)

- Faz um *fork* deste repositório no GitHub.
- Clona o teu fork: `git clone https://github.com/teu-usuario/Hand-of-God-UNIFIED.git`
- Cria uma *branch* para a tua funcionalidade ou correção:
  `git checkout -b my-branch`
- Faz o *commit* das mudanças: `git commit -m 'feat: minha nova funcionalidade'`
- Faz *push* da tua *branch* para o teu fork: `git push origin my-branch`
- Abre um Pull Request para o repositório raiz, descrevendo o que mudou e
  porquê. Se adicionaste um módulo/subcomando novo, confirma no próprio PR
  que atualizaste README.md e (se aplicável) `.env.example`.

### Manter a tua branch atualizada com o repositório raiz

```bash
# Uma vez, para adicionar o remote do repositório original
git remote add upstream https://github.com/Katsuo666/Hand-of-God-UNIFIED.git

# Sempre que quiseres atualizar a tua branch
git fetch upstream
git checkout my-branch
git pull --rebase upstream main
git push origin my-branch
```

Se ocorrer conflito ao fazer o `push` depois do rebase, usa
`git push origin --force-with-lease` (nunca `--force` sem o
`--with-lease`, para não sobrescreveres trabalho de outra pessoa por
engano).
