import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanText, checkPath, isValidCpf, isValidCnpj } from './secret-scan.mjs';

// Todos os "segredos" abaixo sao montados em runtime para que este arquivo
// nao dispare o proprio scanner.
const AWS = 'AKIA' + 'ABCDEFGHIJKLMNOP';
const META = 'EAA' + 'B'.concat('Zq9XkL2mNp'.repeat(5));
const GH = 'ghp_' + 'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6';

function cpfFrom(base9) {
  const d = base9.split('').map(Number);
  const dv = (len) => {
    const sum = d.slice(0, len).reduce((a, n, i) => a + n * (len + 1 - i), 0);
    const r = (sum * 10) % 11;
    return r === 10 ? 0 : r;
  };
  d.push(dv(9));
  d.push(dv(10));
  const s = d.join('');
  return `${s.slice(0, 3)}.${s.slice(3, 6)}.${s.slice(6, 9)}-${s.slice(9)}`;
}

const rules = (text, opts) => scanText('src/x.ts', text, opts).map((f) => f.rule);

test('detecta chave AWS, token Meta e token GitHub', () => {
  assert.ok(rules(`const k = "${AWS}"`).includes('aws-access-key'));
  assert.ok(rules(`token: ${META}`).includes('meta-access-token'));
  assert.ok(rules(`GH=${GH}`).includes('github-token'));
});

test('detecta bloco de chave privada', () => {
  const header = '-----BEGIN ' + 'RSA PRIVATE KEY-----';
  assert.ok(rules(header).includes('private-key'));
});

test('URL de banco com senha real e bloqueada; placeholder passa', () => {
  assert.ok(rules('DATABASE_URL=postgresql://app:Zk39sLq0pX7v@db.internal:5432/x').includes('db-url-password')); // scan:allow
  assert.deepEqual(rules('DATABASE_URL=postgresql://app:__GEN:APP_DB_PASSWORD__@127.0.0.1:5433/x'), []);
  assert.deepEqual(rules('DATABASE_URL=postgresql://user:changeme@localhost/x'), []);
  assert.deepEqual(rules('REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379'), []);
});

test('atribuicao generica: valor de alta entropia e bloqueado, leitura de env nao', () => {
  assert.ok(rules('const clientSecret = "q8Zk3Lx0Pv7Rt2Ym9Wn4Bc6Hd1Js5Fg"').includes('generic-secret')); // scan:allow
  assert.deepEqual(rules('const apiKey = process.env.META_ACCESS_TOKEN_FALLBACK_VALUE'), []);
  assert.deepEqual(rules('META_ACCESS_TOKEN='), []);
  assert.deepEqual(rules('JWT_SECRET=__GEN32:JWT_SECRET__'), []);
  // leitura de objeto de configuracao tambem nao e segredo literal
  assert.deepEqual(rules('clientSecret: config.GENCODE_CLIENT_SECRET!,'), []);
  assert.deepEqual(rules('const token = env.INTERNAL_API_TOKEN_VALUE_X'), []);
  // mas um literal entre aspas, mesmo comecando assim, continua sendo pego
  assert.ok(rules('clientSecret: "config.q8Zk3Lx0Pv7Rt2Ym9Wn4Bc6Hd1"').includes('generic-secret')); // scan:allow
});

test('marcador scan:allow suprime a linha', () => {
  assert.deepEqual(rules(`const k = "${AWS}" // scan:allow`), []);
});

test('o relatorio nao expoe o segredo inteiro', () => {
  const [f] = scanText('a.ts', `k=${AWS}`);
  assert.ok(!f.preview.includes(AWS));
});

test('caminhos proibidos: .env bloqueado, .env.example liberado', () => {
  assert.ok(checkPath('.env'));
  assert.ok(checkPath('apps/api-gateway/.env.production'));
  assert.ok(checkPath('certs/server.pem'));
  assert.ok(checkPath('logs/app.log'));
  assert.ok(checkPath('db/dump-2026.sql'));
  assert.equal(checkPath('.env.example'), null);
  assert.equal(checkPath('infra/docker/docker-compose.yml'), null);
});

test('modo publico: e-mail real e CPF valido sao bloqueados; reservados passam', () => {
  const pub = { publicMode: true };
  assert.ok(rules('contato: maria.silva@empresa-real.com.br', pub).includes('public-email')); // scan:allow
  assert.deepEqual(rules('contato: lead@example.com e ops@clinica.test', pub), []);
  assert.ok(rules(`cpf ${cpfFrom('123456789')}`, pub).includes('public-cpf-cnpj'));
  // fora do modo publico nao ha verificacao de PII
  assert.deepEqual(rules('contato: maria.silva@empresa-real.com.br'), []); // scan:allow
});

test('validadores de CPF/CNPJ', () => {
  assert.equal(isValidCpf(cpfFrom('111444777')), true);
  assert.equal(isValidCpf('111.111.111-11'), false);
  assert.equal(isValidCnpj('11.222.333/0001-81'), true);
  assert.equal(isValidCnpj('11.222.333/0001-82'), false);
});

test('CNPJ alfanumerico (IN RFB 2.229/2024): DV com ASCII-48; exemplo oficial e liberado, outros validos sao PII', () => {
  assert.equal(isValidCnpj('12.ABC.345/01DE-35'), true);
  assert.equal(isValidCnpj('12.ABC.345/01DE-36'), false);

  const dv = (base) => {
    let out = '';
    for (const len of [12, 13]) {
      const w = len === 12 ? [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2] : [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
      const s = (base + out).split('').reduce((a, c, i) => a + (c.charCodeAt(0) - 48) * w[i], 0) % 11;
      out += s < 2 ? 0 : 11 - s;
    }
    return out;
  };
  const b = 'Z9Y8X7W60001';
  const real = `${b.slice(0, 2)}.${b.slice(2, 5)}.${b.slice(5, 8)}/${b.slice(8, 12)}-${dv(b)}`;
  const pub = { publicMode: true };
  assert.ok(rules(`cnpj ${real}`, pub).includes('public-cpf-cnpj'));
  assert.deepEqual(rules('cnpj 12.ABC.345/01DE-35', pub), []);
});
