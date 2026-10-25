# Segurança e espelho público (Zero Leaks)

## Dois repositórios, uma regra

| Repositório | Conteúdo | Como é alimentado |
|---|---|---|
| **Privado** (origem) | Código completo, `docs/internal`, branches, CI interno | `git push` normal |
| **Público** (vitrine) | Snapshot higienizado: arquitetura, código demonstrativo, dados fictícios | **Somente** `npm run mirror:sync` |

O repositório privado **nunca** tem o espelho público como remoto: o hook `pre-push` bloqueia remotos chamados `public`/`mirror`. O espelho é um repositório separado (`../genprospect-showcase`) com um commit por sincronização, de modo que o histórico privado nunca vai junto.

## Camadas de proteção

1. **`.gitignore`** cobre `.env*` (exceto `.env.example`), chaves/certificados, logs, dumps, uploads e `seed/private`.
2. **Hook `pre-commit`** roda `scripts/security/secret-scan.mjs --staged` sobre o que está no índice: bloqueia arquivos proibidos (`.env`, `*.pem`, logs, dumps) e conteúdo (chaves privadas, tokens AWS/GitHub/Meta/Google/Microsoft/Slack/Anthropic/OpenAI, JWT, URLs de banco com senha, atribuições de alta entropia). Falso positivo: comentário `scan:allow` na linha.
3. **Hook `pre-push`** repete a varredura completa e barra push ao espelho.
4. **Espelho por lista de permissão** (`scripts/mirror/manifest.json`): só o que está em `include` sai; `exclude` vence. Exporta apenas o `HEAD` commitado (árvore suja aborta), roda o scanner em modo `--public` (além de segredos, bloqueia e-mails fora de domínios reservados e CPF/CNPJ válidos) e aborta em qualquer achado. Publicar exige `--remote` explícito e `MIRROR_CONFIRM=yes`. Os commits usam identidade genérica (`MIRROR_AUTHOR_*`), nunca o e-mail pessoal.
5. **CI** (`.github/workflows/ci.yml`) repete a varredura no servidor.
6. **Dados**: seeds e fixtures só com valores fictícios (`example.com`, `.test`, CNPJs gerados em runtime).

Ferramentas externas (`gitleaks`, `trufflehog`) não estão instaladas nesta máquina; o scanner interno não tem dependências. Recomenda-se adicioná-las ao CI como segunda opinião.

## Segredos em runtime

* `npm run bootstrap` gera segredos locais aleatórios; credenciais de terceiros (Meta, Microsoft, Google, GenCode, LLM) ficam só no `.env` local ou no cofre da nuvem.
* Tokens de canais dos tenants são cifrados em repouso (AES-256-GCM) e nunca aparecem em logs (`redact` no logger).
* Serviços escutam somente em `127.0.0.1`; o Compose não tem senhas padrão (falha se ausentes).

## Procedimento: criar os repositórios no GitHub (manual, uma vez)

```bash
gh repo create <org>/genprospect-core --private --source . --remote origin
# no GitHub: ativar Secret scanning + Push protection e proteger a branch main
npm run mirror:dry                       # exporta e escaneia, sem publicar
```

O repositório público (`genprospect-showcase`) é uma **vitrine mínima**: README próprio, aviso de direitos reservados (nenhuma licença concedida), os documentos de arquitetura, segurança e módulos, e as ferramentas de segurança (scanner e exportador). **Nenhum código de produto sai**; `scripts/mirror/manifest.test.mjs` quebra se o manifesto for ampliado sem querer. Ampliar o escopo ou escolher uma licença é decisão do dono do produto. Sincronizar:

```bash
npm run mirror:dry                                   # exporta e escaneia, sem publicar
MIRROR_CONFIRM=yes node scripts/mirror/export-public.mjs --commit --push --remote https://github.com/<conta>/genprospect-showcase.git
```

O snapshot é gravado em `../genprospect-showcase` (pasta irmã, repositório Git separado, um commit por sincronização).
