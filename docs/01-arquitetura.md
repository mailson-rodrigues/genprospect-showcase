# Arquitetura

## Visão geral

```
 Cliente GenCode (tenant)                       Meta / Microsoft / Google
        │  SSO/API                                      ▲  │ webhooks
        ▼                                               │  ▼
 ┌────────────┐   token interno   ┌──────────────┐   ┌─────────────────────┐
 │   web      │ ───────────────▶ │ api-gateway  │──▶│ ai-agents (LangGraph)│
 │ React/Vite │                   │ Fastify + TS │◀──│ Hunter SDR Closer FB │
 └────────────┘                   └──────┬───────┘   └──────────┬──────────┘
                                         │ BullMQ               │
                                  ┌──────▼───────┐       ┌──────▼──────┐
                                  │    Redis     │       │ PostgreSQL  │
                                  └──────────────┘       │ 16+pgvector │
                                                         └─────────────┘
```

* **api-gateway** é o único ponto de entrada: autenticação, RBAC, webhooks dos provedores, filas e envio pelos canais do tenant. Só ele conversa com o `ai-agents` (header `x-internal-token`, comparação em tempo constante).
* **ai-agents** não acessa canais externos diretamente; devolve decisões/rascunhos ao gateway, que aplica as regras de compliance (supressão, limites, aprovação) antes de enviar.

## Multi-tenancy

Tenant = cliente do hub GenCode (`tenants.gencode_customer_id`). O isolamento é feito **pelo banco**:

* toda tabela de dados tem `tenant_id` e Row-Level Security `FORCE` com política `tenant_id = current_tenant_id()`;
* a aplicação conecta com uma role sem `SUPERUSER`/`BYPASSRLS`; migrations rodam com o dono do schema;
* o gateway executa cada requisição dentro de `withTenant(prisma, tenantId, fn)`, que define `app.tenant_id` por transação. Sem contexto, nenhuma linha é visível (fail-closed);
* dois casos em que o tenant ainda não é conhecido usam funções `SECURITY DEFINER`: `resolve_channel_tenant(provider, external_id)` (webhook de um número/página) e `list_user_tenants(user_id)` (login);
* o teste `packages/database/src/rls.test.ts` valida o isolamento contra o Postgres real;
* **integridade entre tenants no próprio banco:** toda referência entre tabelas de tenant usa **FK composta `(tenant_id, id)`**. Uma FK simples ignora a RLS e deixaria um tenant apontar para a linha de outro se conhecesse o UUID; a composta barra isso até para o dono do schema (`tenant-integrity.test.ts`). As referências opcionais usam `ON DELETE SET NULL (coluna)`, que exige **PostgreSQL ≥ 15**: o `SET NULL` simples que o Prisma gera tentaria anular também `tenant_id`.

## Contas de canal por tenant

`channel_accounts` guarda as contas que o próprio cliente conecta: WhatsApp (phone_number_id / WABA), Instagram, Facebook, Microsoft 365, Gmail, SMTP. Tokens ficam cifrados (AES-256-GCM, `ENCRYPTION_KEY`) em `credentials_enc`. `UNIQUE (provider, external_id)` garante que um número pertença a um único tenant, o que torna o roteamento de webhooks inequívoco.

## Modelo de dados

| Grupo | Tabelas |
|---|---|
| Identidade | `tenants`, `users` (`gencode_customer_id` vem do SSO), `tenant_members` (papéis), `sessions` (hash do token; ver [04-autenticacao-e-painel.md](04-autenticacao-e-painel.md)) |
| Módulos e acesso | `tenant_modules` (direitos, limites, validade), `platform_admins`, `teams`/`team_members` (árvore e escopo), `custom_roles`. Ver [06-modulos-e-acesso.md](06-modulos-e-acesso.md) |
| Prospecção | `campaigns` (filtros ICP: CNAE, UF, porte), `prospects` (origem outbound/inbound), `prospect_channels` (validação, proveniência e confiança 0–100), `interactions` |
| Leads inbound e consentimento | `lead_captures` (Google Ads / landing page: UTM, gclid, termo de busca), `consent_records` (prova imutável do consentimento, IP só em hash), `lead_capture_keys` (chave pública por formulário: origens, texto de consentimento, captcha). API em [03-captura-de-leads.md](03-captura-de-leads.md) |
| Canais e conteúdo | `channel_accounts`, `campaign_channel_accounts`, `message_templates`, `social_posts`, `brand_profiles` |
| IA | `embeddings` (`vector(1024)`, índice HNSW cosseno) |
| Compliance | `suppression_list` (opt-out/bounce/reclamação), `audit_logs` |

Os embeddings são lidos/escritos por SQL cru (`packages/database/src/vector.ts`), sempre dentro de `withTenant`.
