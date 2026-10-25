# Módulos e controle de acesso

O GenProspect é um **monólito modular**: cada cliente (tenant) liga só os módulos que contratou, e o acesso de cada pessoa segue uma **hierarquia** com **permissões granulares**. Ambos são verificados **no servidor**; esconder um item do menu nunca é a proteção.

## Catálogo de módulos

Definido em `packages/modules` (`catalog.ts`), validado na inicialização (ids únicos, dependências existentes e sem ciclo, permissões prefixadas pelo módulo).

| Módulo | Conteúdo | Depende de |
|---|---|---|
| `core` (sempre ativo) | organização, usuários, hierarquia, equipes, papéis, auditoria, campanhas, painel do gestor | — |
| `prospeccao` | base da Receita, perfil de cliente ideal, descoberta, score | core |
| `enriquecimento` | validação de contatos e confiança | core |
| `captacao` | chaves públicas, formulários, consentimento | core |
| `conversas` | contas de canal, caixa unificada, aprovação de mensagens | core |
| `agentes` | SDR, Closer e Feedback com base de conhecimento | `conversas` |
| `crm` | pipeline, tarefas, agenda | core |
| `marketing` | e-mail, redes sociais, marca | core |
| `analytics` | painéis, atribuição, geomarketing | core |

Os módulos ainda não implementados já declaram suas permissões, para que contratos e papéis possam ser configurados antes da entrega.

## Direitos por tenant

* Tabela `tenant_modules` (módulo, estado, **limites**, **validade**). O tenant só **lê**; quem escreve é a plataforma, por funções `SECURITY DEFINER` que conferem no próprio banco se o ator é administrador da plataforma (`platform_admins`).
* Ativar exige as dependências ativas; desativar é recusado enquanto outro módulo ativo depende dele; o `core` não se configura.
* **Vale na próxima requisição**: contratar, suspender ou vencer um módulo não exige novo login. Módulo desligado devolve `403 module_disabled`, e a rota pública de captura passa a responder 404.
* Tenants novos recebem `DEFAULT_TENANT_MODULES` (padrão `captacao,prospeccao`); a plataforma ajusta depois.

## Hierarquia e permissões

Níveis (cada um contém o anterior): **VIEWER < OPERATOR < MANAGER (gestor) < ADMIN < OWNER**.

* Cada permissão `modulo.recurso.acao` declara o **menor papel** que a recebe por padrão. Permissão de módulo desligado não existe para ninguém.
* **Papéis personalizados** (por tenant) somam permissões ao papel do membro. Não podem conceder `core.billing.manage`, `core.members.manage` nem `core.roles.manage`, e permissões de módulo desligado ou desconhecidas são ignoradas.
* **Quem altera acessos:** o proprietário altera qualquer nível; o administrador promove até gestor, mas não mexe em pares nem proprietários; ninguém altera ou remove o próprio acesso; o último proprietário não pode ser rebaixado ou removido.
* **Equipes** formam uma árvore (sem ciclos, no próprio banco). O **escopo de dados** do gestor é ele mesmo e os membros das equipes que lidera (e subequipes); operador e leitor veem só o seu; administrador e proprietário veem tudo (`visibleUsers`). A aplicação desse escopo aos recursos entra junto com cada módulo.
* Integridade entre tenants no banco: FKs compostas `(tenant_id, id)` em tudo, inclusive equipes e papéis.

## API

`GET /v1/auth/me` agora devolve `role`, `customRoleId`, `modules`, `permissions` e `isPlatformAdmin`.

**Painel do gestor** (`/v1/manager`, por permissão):

| Rota | Permissão |
|---|---|
| `GET /members`, `GET /roles`, `GET /teams` | `core.members.read` (gestor+) |
| `PATCH /members/:userId` (`role`, `customRoleId`), `DELETE /members/:userId` | `core.members.manage` (admin+) |
| `POST /roles`, `DELETE /roles/:id` | `core.roles.manage` |
| `POST /teams`, `PATCH`/`DELETE /teams/:id`, `PUT`/`DELETE /teams/:id/members/:userId` | `core.teams.manage` |
| `GET /modules` | `core.modules.read` |
| `GET /audit?limit&before` (paginada por cursor) | `core.audit.read` (admin+) |

**Console da plataforma** (`/v1/platform`, só administradores da plataforma): `GET /modules`, `GET /tenants`, `PUT /tenants/:tenantId/modules/:moduleId` (`status`, `limits`, `validUntil`), auditado no tenant afetado.

Erros: `403 forbidden` (sem permissão), `403 module_disabled`, `403 hierarchy`, `409 cannot_change_self | last_owner | missing_dependencies | has_dependents | team_cycle | has_children | name_taken`.

## Login local: senha forte, MFA e links de uso único

**Senha** (argon2id): 12 a 128 caracteres; recusa senhas comuns, trechos do e-mail/nome, pouca variedade e sequências/repetições; não reutiliza as últimas 5. Nada de regras de composição obrigatória: o tamanho e a lista de senhas comuns pesam mais.

**Bloqueio:** 5 falhas seguidas travam a conta por 15 min (`AUTH_MAX_FAILED_ATTEMPTS`, `AUTH_LOCK_MINUTES`); o login também tem limite por IP+e-mail. A resposta de falha é sempre a mesma (`401 invalid_credentials`) e há hash de mentira para igualar o tempo quando o usuário não existe.

**MFA (TOTP, RFC 6238):** obrigatório para administradores da plataforma e para quem tem papel >= `MFA_REQUIRED_MIN_ROLE` (padrão `MANAGER`; `NONE` é recusado em produção). O segredo é cifrado (AES-256-GCM); cada código só vale uma vez (anti-replay por passo); 10 códigos de recuperação de uso único (guardados só como hash). Quem precisa de MFA e ainda não tem recebe `mfa_enrollment_required` e só ganha sessão ao confirmar a inscrição.

**Convite e redefinição sem e-mail:** o gestor gera um link de uso único (convite 72 h, redefinição 24 h; só o hash fica no banco) e o entrega por fora. Gerar um novo invalida o anterior. Regras de segurança: o link de senha só vale para conta **local e de uma única organização** (`shared_account`, `not_local` caso contrário); usuário que já existe apenas ganha o vínculo, sem link; ninguém age sobre si mesmo nem acima da própria hierarquia. Aceitar o link derruba as demais sessões.

| Rota | Quem |
|---|---|
| `POST /v1/auth/login`, `/mfa/verify`, `/mfa/enroll/start`, `/mfa/enroll/confirm` | público (tokens de fluxo curtos) |
| `GET /v1/auth/links/:token`, `POST /v1/auth/links/:token/accept` | público (o token é a credencial) |
| `GET /v1/account/security`, `POST /v1/account/password`, `/mfa/start`, `/mfa/confirm`, `/mfa/recovery-codes`, `/mfa/disable` | usuário logado (`409 mfa_required_by_policy` se a política exige MFA) |
| `POST /v1/manager/members/invite`, `/:userId/reset-link`, `/:userId/mfa-reset` | `core.members.manage` |

## Produção

O dono do schema precisa ignorar RLS (superuser ou `BYPASSRLS`): as funções `SECURITY DEFINER` leem tabelas com `FORCE ROW LEVEL SECURITY`. O provisionamento (`npm run db:provision`) **recusa** um dono sem isso. Requer PostgreSQL ≥ 15.

## Ainda não existe

Telas do painel do gestor e do console da plataforma (só a API), telas de login local/MFA/convite (a API está pronta), limpeza periódica de sessões e links vencidos, e a aplicação do escopo de dados a prospects e conversas.
