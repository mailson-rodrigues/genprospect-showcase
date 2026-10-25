import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shouldInclude } from './export-public.mjs';

const manifest = {
  include: ['README.md', 'apps/', 'docs/', '.env.example'],
  exclude: ['^docs/internal/', '(^|/)seed/private/', '\\.private\\.', '(^|/)\\.env($|\\.(?!example$))'],
};

test('inclui apenas o que esta na lista de permissao', () => {
  assert.equal(shouldInclude('README.md', manifest), true);
  assert.equal(shouldInclude('apps/web/src/main.tsx', manifest), true);
  assert.equal(shouldInclude('notas-pessoais.txt', manifest), false);
  assert.equal(shouldInclude('README.md.bak', manifest), false);
});

test('exclusoes vencem a inclusao', () => {
  assert.equal(shouldInclude('docs/internal/roadmap.md', manifest), false);
  assert.equal(shouldInclude('docs/arquitetura.md', manifest), true);
  assert.equal(shouldInclude('apps/api/seed/private/clientes.json', manifest), false);
  assert.equal(shouldInclude('apps/api/config.private.ts', manifest), false);
  assert.equal(shouldInclude('apps/api/.env', manifest), false);
  assert.equal(shouldInclude('.env.example', manifest), true);
});
