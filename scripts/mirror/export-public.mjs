#!/usr/bin/env node
// Gera o espelho PUBLICO higienizado a partir do HEAD do repositorio privado.
//
//   node scripts/mirror/export-public.mjs                 # dry-run: exporta + escaneia, nao commita
//   node scripts/mirror/export-public.mjs --commit        # tambem commita um snapshot no repo do espelho
//   MIRROR_CONFIRM=yes node scripts/mirror/export-public.mjs --commit --push --remote <url>
//
// Garantias:
//   * lista de PERMISSAO (manifest.json), nao de bloqueio;
//   * exporta so o que esta commitado (arvore de trabalho suja aborta);
//   * o historico privado nunca vai junto: o espelho tem repo proprio, um commit por sync;
//   * o scanner roda em modo --public (segredos + PII) e qualquer achado aborta;
//   * push exige --remote explicito e MIRROR_CONFIRM=yes.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { report, scanDirectory } from '../security/secret-scan.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..', '..');
const MARKER = '.mirror-target';

export function shouldInclude(file, manifest) {
  const included = manifest.include.some((i) => (i.endsWith('/') ? file.startsWith(i) : file === i));
  return included && !manifest.exclude.some((r) => new RegExp(r).test(file));
}

/** Caminho do arquivo no espelho: alguns arquivos publicos sao versoes proprias da vitrine (ex.: docs/showcase/README.md vira README.md). */
export function destinationOf(file, manifest) {
  return manifest.rename?.[file] ?? file;
}

const git = (cwd, args, opts = {}) => execFileSync('git', args, { cwd, encoding: 'buffer', maxBuffer: 256 * 1024 * 1024, ...opts });
const gitText = (cwd, args) => git(cwd, args).toString('utf8').trim();

function flag(argv, name) {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : (argv[i + 1]?.startsWith('--') ? true : (argv[i + 1] ?? true));
}

function prepareTarget(out) {
  const resolved = path.resolve(out);
  const unsafe = resolved === root || root.startsWith(resolved + path.sep) || path.dirname(resolved) === resolved;
  if (unsafe) throw new Error(`destino inseguro: ${resolved}`);
  if (existsSync(resolved)) {
    const entries = readdirSync(resolved);
    if (entries.length && !entries.includes(MARKER)) {
      throw new Error(`${resolved} nao esta vazio e nao e um destino de espelho (falta ${MARKER}).`);
    }
    for (const e of entries) if (e !== '.git') rmSync(path.join(resolved, e), { recursive: true, force: true });
  } else {
    mkdirSync(resolved, { recursive: true });
  }
  writeFileSync(path.join(resolved, MARKER), 'diretorio gerenciado por scripts/mirror/export-public.mjs\n');
  return resolved;
}

function main(argv) {
  const manifest = JSON.parse(readFileSync(path.join(here, 'manifest.json'), 'utf8'));
  try {
    git(root, ['rev-parse', '--verify', 'HEAD'], { stdio: 'pipe' });
  } catch {
    throw new Error('o repositorio ainda nao tem commits; faca o commit inicial antes de exportar.');
  }
  if (gitText(root, ['status', '--porcelain'])) {
    throw new Error('arvore de trabalho suja: commite ou descarte as alteracoes (o espelho exporta so o HEAD).');
  }

  const out = prepareTarget(flag(argv, '--out') || path.join(root, '..', 'genprospect-showcase'));
  const files = git(root, ['ls-tree', '-r', '--name-only', '-z', 'HEAD']).toString('utf8').split('\0').filter(Boolean);
  const selected = files.filter((f) => shouldInclude(f, manifest));
  for (const f of selected) {
    const dest = path.join(out, destinationOf(f, manifest));
    mkdirSync(path.dirname(dest), { recursive: true });
    writeFileSync(dest, git(root, ['show', `HEAD:${f}`]));
  }
  console.log(`mirror: ${selected.length}/${files.length} arquivos exportados para ${out}`);

  const result = scanDirectory(out, { publicMode: true });
  if (report(result) !== 0) throw new Error('o scanner encontrou problemas; nada foi commitado.');

  if (!argv.includes('--commit')) return console.log('dry-run concluido (use --commit para gravar o snapshot).');

  const sha = gitText(root, ['rev-parse', '--short', 'HEAD']);
  const identity = [
    '-c', `user.name=${process.env.MIRROR_AUTHOR_NAME || 'Mirror Bot'}`,
    '-c', `user.email=${process.env.MIRROR_AUTHOR_EMAIL || 'mirror-bot@users.noreply.github.com'}`,
  ];
  if (!existsSync(path.join(out, '.git'))) git(out, ['init', '-b', 'main']);
  git(out, ['add', '-A']);
  if (!gitText(out, ['status', '--porcelain'])) return console.log('espelho ja esta atualizado.');
  git(out, [...identity, 'commit', '-m', `Sync from private @ ${sha}`]);
  console.log(`snapshot commitado em ${out}`);

  if (argv.includes('--push')) {
    const remote = flag(argv, '--remote');
    if (typeof remote !== 'string') throw new Error('--push exige --remote <url> explicito.');
    if (process.env.MIRROR_CONFIRM !== 'yes') throw new Error('defina MIRROR_CONFIRM=yes para publicar.');
    git(out, ['push', remote, 'HEAD:main']);
    console.log(`publicado em ${remote}`);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    console.error(`mirror: ${err.message}`);
    process.exit(1);
  }
}
