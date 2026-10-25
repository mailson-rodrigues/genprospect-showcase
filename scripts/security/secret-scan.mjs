#!/usr/bin/env node
// Scanner de segredos e de dados sensiveis (sem dependencias externas).
//
//   node scripts/security/secret-scan.mjs --staged            # conteudo do indice (pre-commit)
//   node scripts/security/secret-scan.mjs --all               # arquivos rastreados + novos nao ignorados
//   node scripts/security/secret-scan.mjs --dir <pasta> --public   # pasta arbitraria + regras de PII (espelho)
//
// Suprima um falso positivo numa linha com o comentario `scan:allow`.
// Codigo de saida: 0 limpo, 1 achados, 2 erro de uso.
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const MAX_BYTES = 1_000_000;
const ALLOW_MARKER = 'scan:allow';

// ---- caminhos que nunca devem ser versionados --------------------------------
const FORBIDDEN_PATHS = [
  { re: /(^|\/)\.env($|\.(?!example$).+)/, why: 'arquivo .env' },
  { re: /\.(pem|key|p12|pfx|jks)$/i, why: 'chave/certificado privado' },
  { re: /(^|\/)id_(rsa|ed25519|ecdsa)/, why: 'chave SSH' },
  { re: /\.log$/i, why: 'arquivo de log' },
  { re: /\.(sqlite3?|dump|bak)$/i, why: 'banco/dump/backup' },
  { re: /(^|\/)dump[^/]*\.sql$/i, why: 'dump SQL' },
  { re: /(^|\/)(credentials|client_secret[^/]*|service-account[^/]*)\.json$/i, why: 'credencial JSON' },
];

export function checkPath(file) {
  const p = file.replaceAll('\\', '/');
  const hit = FORBIDDEN_PATHS.find((r) => r.re.test(p));
  return hit ? hit.why : null;
}

// ---- regras de conteudo -------------------------------------------------------
const TOKEN_RULES = [
  { id: 'private-key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/ },
  { id: 'aws-access-key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: 'github-token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/ },
  { id: 'meta-access-token', re: /\bEAA[A-Za-z0-9]{40,}\b/ },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: 'google-oauth-secret', re: /\bGOCSPX-[0-9A-Za-z_-]{20,}\b/ },
  { id: 'microsoft-client-secret', re: /\b[A-Za-z0-9_.-]{3}8Q~[A-Za-z0-9_.~-]{30,}/ },
  { id: 'slack-token', re: /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/ },
  { id: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { id: 'openai-key', re: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
];

const PLACEHOLDER =
  /(change[-_]?me|example|placeholder|your[-_]|<[^>]+>|__GEN|x{6,}|\*{4,}|\$\{|\$\(|dummy|fake|redacted|\.\.\.|localdev|^(password|secret|postgres|root|admin|user|pass)$)/i;
const ENV_READ = /process\.env|import\.meta|os\.environ|getenv|settings\./;
// Leitura de objeto de configuracao (config.X_Y, env.X) so conta como leitura se NAO estiver entre aspas.
const CONFIG_READ = /^(?:config|cfg|env|settings|options|opts)(?:\.[A-Za-z_]\w*)+$/;

// regras cujo valor capturado passa por filtro de placeholder / entropia
const VALUE_RULES = [
  {
    id: 'db-url-password',
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]*:([^\s@/]+)@/g,
    minEntropy: 0,
  },
  {
    id: 'generic-secret',
    re: /(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|private[_-]?key|access[_-]?key)[A-Za-z0-9_]*["']?\s*[:=]\s*["']?([A-Za-z0-9+/=_.~-]{20,})["']?/gi,
    minEntropy: 3.5,
  },
];

export function entropy(s) {
  const freq = new Map();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) h -= (n / s.length) * Math.log2(n / s.length);
  return h;
}

// ---- PII (somente --public) -----------------------------------------------------
const FAKE_IDS = new Set(['11.222.333/0001-81', '111.444.777-35', '12.ABC.345/01DE-35']);
const OK_EMAIL_DOMAIN =
  /(^|\.)(example\.(com|org|net)|localhost|github\.com|(\w+\.)?(test|invalid|example))$/i;

const digits = (s) => s.replace(/\D/g, '').split('').map(Number);

export function isValidCpf(raw) {
  const d = digits(raw);
  if (d.length !== 11 || new Set(d).size === 1) return false;
  const dv = (len) => {
    const r = (d.slice(0, len).reduce((a, n, i) => a + n * (len + 1 - i), 0) * 10) % 11;
    return r === 10 ? 0 : r;
  };
  return dv(9) === d[9] && dv(10) === d[10];
}

export function isValidCnpj(raw) {
  // CNPJ alfanumerico (IN RFB 2.229/2024): valor do caractere = codigo ASCII - 48
  const v = raw.replace(/[.\-/\s]/g, '').toUpperCase();
  if (!/^[0-9A-Z]{12}[0-9]{2}$/.test(v) || /^(.){13}$/.test(v)) return false;
  const dv = (len) => {
    const w = len === 12 ? [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2] : [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const r = [...v.slice(0, len)].reduce((a, c, i) => a + (c.charCodeAt(0) - 48) * w[i], 0) % 11;
    return r < 2 ? 0 : 11 - r;
  };
  return dv(12) === Number(v[12]) && dv(13) === Number(v[13]);
}

const EMAIL_RE = /[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b/g;
const CPF_RE = /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g;
const CNPJ_RE = /\b[0-9A-Z]{2}\.[0-9A-Z]{3}\.[0-9A-Z]{3}\/[0-9A-Z]{4}-\d{2}\b/g;

const mask = (v) => `${v.slice(0, 4)}...(${v.length} chars)`;
const isLock = (file) => /(^|\/)(package-lock\.json|uv\.lock|poetry\.lock|yarn\.lock)$/.test(file);

export function scanText(file, text, { publicMode = false } = {}) {
  const findings = [];
  const add = (line, rule, value) => findings.push({ file, line, rule, preview: mask(value) });
  const lock = isLock(file);

  text.split(/\r?\n/).forEach((line, i) => {
    if (line.includes(ALLOW_MARKER)) return;
    const n = i + 1;

    for (const { id, re } of TOKEN_RULES) {
      const m = line.match(re);
      if (m) add(n, id, m[0]);
    }
    if (lock) return;

    for (const { id, re, minEntropy } of VALUE_RULES) {
      for (const m of line.matchAll(re)) {
        const v = m[1];
        const quoted = /["']$/.test(m[0].slice(0, m[0].lastIndexOf(v)));
        if (PLACEHOLDER.test(v) || ENV_READ.test(v) || (!quoted && CONFIG_READ.test(v))) continue;
        if (minEntropy && entropy(v) < minEntropy) continue;
        add(n, id, v);
      }
    }

    if (publicMode) {
      for (const m of line.matchAll(EMAIL_RE)) {
        if (!OK_EMAIL_DOMAIN.test(m[1])) add(n, 'public-email', m[0]);
      }
      for (const [re, valid] of [[CPF_RE, isValidCpf], [CNPJ_RE, isValidCnpj]]) {
        for (const m of line.matchAll(re)) {
          if (valid(m[0]) && !FAKE_IDS.has(m[0])) add(n, 'public-cpf-cnpj', m[0]);
        }
      }
    }
  });
  return findings;
}

// ---- varredura de arquivos ----------------------------------------------------
function git(args, opts = {}) {
  return execFileSync('git', args, { encoding: 'buffer', maxBuffer: 256 * 1024 * 1024, ...opts });
}

const splitZ = (buf) => buf.toString('utf8').split('\0').filter(Boolean);
const isBinary = (buf) => buf.subarray(0, 8000).includes(0);

function scanBuffer(file, buf, opts, findings) {
  const why = checkPath(file);
  if (why) findings.push({ file, line: 0, rule: 'forbidden-path', preview: why });
  if (buf.length > MAX_BYTES || isBinary(buf)) return;
  findings.push(...scanText(file, buf.toString('utf8'), opts));
}

export function scanStaged(opts = {}) {
  const findings = [];
  const files = splitZ(git(['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z']));
  for (const f of files) scanBuffer(f, git(['show', `:${f}`]), opts, findings);
  return { findings, count: files.length };
}

export function scanTracked(opts = {}) {
  const findings = [];
  const files = splitZ(git(['ls-files', '-z', '--cached', '--others', '--exclude-standard']));
  for (const f of files) {
    try {
      scanBuffer(f, readFileSync(f), opts, findings);
    } catch {
      // arquivo removido da arvore de trabalho mas ainda no indice
    }
  }
  return { findings, count: files.length };
}

export function scanDirectory(dir, opts = {}) {
  const findings = [];
  let count = 0;
  const walk = (cur) => {
    for (const name of readdirSync(cur)) {
      if (name === '.git' || name === 'node_modules') continue;
      const full = path.join(cur, name);
      if (statSync(full).isDirectory()) walk(full);
      else {
        count++;
        scanBuffer(path.relative(dir, full).replaceAll('\\', '/'), readFileSync(full), opts, findings);
      }
    }
  };
  walk(dir);
  return { findings, count };
}

export function report({ findings, count }) {
  if (findings.length === 0) {
    console.log(`secret-scan: ${count} arquivo(s) verificados, nenhum achado.`);
    return 0;
  }
  console.error(`secret-scan: ${findings.length} achado(s) em ${count} arquivo(s):\n`);
  for (const f of findings) {
    console.error(`  ${f.file}${f.line ? `:${f.line}` : ''}  [${f.rule}]  ${f.preview}`);
  }
  console.error(`\nRemova o segredo (e rotacione-o se ja foi exposto). Falso positivo? Marque a linha com "${ALLOW_MARKER}".`);
  return 1;
}

function main(argv) {
  const opts = { publicMode: argv.includes('--public') };
  const dirIdx = argv.indexOf('--dir');
  if (argv.includes('--staged')) return report(scanStaged(opts));
  if (argv.includes('--all')) return report(scanTracked(opts));
  if (dirIdx !== -1 && argv[dirIdx + 1]) return report(scanDirectory(argv[dirIdx + 1], opts));
  console.error('uso: secret-scan.mjs (--staged | --all | --dir <pasta>) [--public]');
  return 2;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exit(main(process.argv.slice(2)));
}
