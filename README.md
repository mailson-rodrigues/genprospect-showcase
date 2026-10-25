# GenProspect (vitrine)

**GenProspect** é uma plataforma **multi-tenant** de prospecção comercial. Cada cliente (tenant) conecta os próprios canais e trabalha só com os próprios dados, num produto **modular**: o cliente contrata apenas os módulos de que precisa.

> Este repositório é uma **vitrine**. O código do produto fica em repositório privado e **não está aqui**. Aqui estão a arquitetura, as decisões de segurança e as ferramentas que garantem que nada sensível vaze.

## O que há aqui

| Caminho | Conteúdo |
|---|---|
| [`docs/01-arquitetura.md`](docs/01-arquitetura.md) | Visão geral: isolamento por tenant no banco (RLS), modelo de dados, canais do cliente |
| [`docs/02-seguranca-e-espelho-publico.md`](docs/02-seguranca-e-espelho-publico.md) | Política "Zero Leaks": repositório privado + espelho público higienizado |
| [`docs/06-modulos-e-acesso.md`](docs/06-modulos-e-acesso.md) | Catálogo de módulos, direitos por organização, hierarquia de papéis, senha forte e MFA |
| [`scripts/security`](scripts/security) | Scanner de segredos e dados pessoais, sem dependências externas |
| [`scripts/mirror`](scripts/mirror) | Exportador do espelho por **lista de permissão**, com testes |
| [`.githooks`](.githooks) | Hooks que barram segredos antes do commit e do push |

## Princípios

* **Isolamento no banco, não só no código:** cada consulta de dados de cliente roda sob uma política de segurança por linha (RLS) com contexto de tenant; chaves estrangeiras compostas impedem referência entre tenants até para o dono do schema.
* **Modular e hierárquico:** módulos com dependências, permissões por papel (proprietário, administrador, gestor, operador, leitor) e papéis personalizados.
* **Acesso forte:** senhas com política robusta (argon2id), MFA por TOTP, bloqueio por tentativas, links de convite e redefinição de uso único.
* **Dados públicos com cuidado:** base de referência isolada em schema próprio, somente leitura para a aplicação, e contatos com proveniência, confiança e lista de supressão.
* **Zero Leaks:** o que sai para o público passa por uma lista de permissão, por um scanner de segredos e de dados pessoais, e nunca leva o histórico privado.

## Direitos

Todos os direitos reservados (veja [`LICENSE`](LICENSE)). Nenhuma licença de uso é concedida.
