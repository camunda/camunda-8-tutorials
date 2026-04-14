#!/usr/bin/env node
/**
 * extract-variables.mjs — Process variable extraction and schema validation tool.
 *
 * Operates on two group-level schemas:
 *   solutions/variables.schema.json  — vocabulary for all processes under solutions/
 *   quick-start/variables.schema.json — vocabulary for all processes under quick-start/
 *
 * Usage:
 *   node tools/schema/extract-variables.mjs --extract --group solutions [--write]
 *   node tools/schema/extract-variables.mjs --check   --group solutions
 *   node tools/schema/extract-variables.mjs --dead    --group solutions
 *   node tools/schema/extract-variables.mjs --check   --file solutions/absence-request/Absence\ Request.bpmn
 *
 * Modes:
 *   --extract   Scan all diagram/form files in the group. Output a draft variables.schema.json.
 *               With --write: write the file to <group>/variables.schema.json.
 *   --check     Report variables present in diagrams but absent from the group schema.
 *               Emits GitHub Actions annotations; exits 1 if violations found.
 *   --dead      Report schema entries absent from all diagram files in the group. Advisory, exits 0.
 *
 * Flags:
 *   --group solutions|quick-start   Target group.
 *   --file <path>                   Run --check on a single changed file (derives group automatically).
 *   --scope process|all             Override scope from config. Default: "process".
 *   --write                         (--extract only) Write draft to <group>/variables.schema.json.
 */

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve, join, relative, dirname } from 'path';
import { fileURLToPath } from 'url';
import { glob } from './lib/glob.mjs';
import { parseBpmn } from './lib/bpmn.mjs';
import { parseDmn } from './lib/dmn.mjs';
import { parseForm } from './lib/form.mjs';
import { parseTestJson } from './lib/test-json.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '../..');

// ── argument parsing ────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const mode = args.includes('--extract') ? 'extract'
           : args.includes('--check')   ? 'check'
           : args.includes('--dead')    ? 'dead'
           : null;

if (!mode) {
  console.error('Usage: extract-variables.mjs --extract|--check|--dead --group solutions|quick-start');
  process.exit(1);
}

const writeFlag = args.includes('--write');
const scopeArg  = args[args.indexOf('--scope') + 1] ?? null;

// Derive group from --group flag or --file path
let group;
const groupArg = args[args.indexOf('--group') + 1];
const fileArg  = args[args.indexOf('--file') + 1];

if (groupArg) {
  group = groupArg; // 'solutions' or 'quick-start'
} else if (fileArg) {
  const rel = relative(REPO_ROOT, resolve(fileArg));
  group = rel.startsWith('solutions/') ? 'solutions'
        : rel.startsWith('quick-start/') ? 'quick-start'
        : null;
  if (!group) {
    console.error(`Cannot derive group from file path: ${fileArg}`);
    process.exit(1);
  }
} else {
  console.error('Provide --group solutions|quick-start or --file <path>');
  process.exit(1);
}

const groupDir    = join(REPO_ROOT, group);
const schemaPath  = join(groupDir, 'variables.schema.json');
const schemaLabel = `${group}/variables.schema.json`;

// ── repo-level config ───────────────────────────────────────────────────────

const configPath = join(REPO_ROOT, '.variable-schema.config.json');
const repoConfig = existsSync(configPath)
  ? JSON.parse(readFileSync(configPath, 'utf8'))
  : { convention: 'camelCase', scope: 'process' };

// Determine scope: arg > schema metadata > repo config
let scope = scopeArg ?? repoConfig.scope ?? 'process';
if (existsSync(schemaPath)) {
  const existing = JSON.parse(readFileSync(schemaPath, 'utf8'));
  scope = scopeArg ?? existing?.metadata?.scope ?? repoConfig.scope ?? 'process';
}

// ── extract ─────────────────────────────────────────────────────────────────

const result = await extractGroup(groupDir, scope);

// ── modes ────────────────────────────────────────────────────────────────────

if (mode === 'extract') {
  const draft = buildDraftSchema(group, result, repoConfig, scope);
  if (writeFlag) {
    writeFileSync(schemaPath, JSON.stringify(draft, null, 2) + '\n', 'utf8');
    console.log(`Wrote ${schemaLabel} (${Object.keys(draft.variables).length} variables)`);
  } else {
    console.log(JSON.stringify(draft, null, 2));
  }
}

if (mode === 'check') {
  if (!existsSync(schemaPath)) {
    console.log(`::warning file=${schemaLabel}::No schema found. Run --extract --write to bootstrap.`);
    process.exit(0);
  }
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
  const registered = new Set(Object.keys(schema.variables ?? {}));
  const deadNames  = new Set(
    Object.entries(schema.variables ?? {})
      .filter(([, v]) => v.description?.startsWith('DEAD'))
      .map(([k]) => k)
  );

  let exitCode = 0;
  for (const [name, sources] of result.definitions) {
    if (!registered.has(name) && !deadNames.has(name)) {
      const src = sources[0];
      const file = src?.file ? relative(REPO_ROOT, src.file) : schemaLabel;
      const lineStr = src?.line ? `,line=${src.line}` : '';
      console.log(`::error file=${file}${lineStr}::Unregistered variable '${name}' (${sources.map(s => s.kind).join(', ')}). Add it to ${schemaLabel}.`);
      exitCode = 1;
    }
  }
  process.exit(exitCode);
}

if (mode === 'dead') {
  if (!existsSync(schemaPath)) process.exit(0);
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
  const allRefs = new Set([...result.definitions.keys(), ...result.references]);

  for (const [name, entry] of Object.entries(schema.variables ?? {})) {
    if (entry.description?.startsWith('DEAD')) continue;
    if (!allRefs.has(name)) {
      console.log(`::notice::Dead variable candidate in ${group}: '${name}' — not found in any diagram file. Consider prefixing description with 'DEAD - <date>.'`);
    }
  }
  process.exit(0);
}

// ── extraction ──────────────────────────────────────────────────────────────

/**
 * @param {string} groupDir  Absolute path to solutions/ or quick-start/
 * @param {string} scope     'process' | 'all'
 * @returns {{ definitions: Map<string, Array<{file,line,kind}>>, references: Set<string> }}
 */
async function extractGroup(groupDir, scope) {
  const definitions = new Map(); // name → [{file, line, kind}]
  const references  = new Set();

  function addDef(name, source) {
    if (!name || typeof name !== 'string') return;
    // Take only the root identifier: "loan.amount" → "loan", "toolCallResult.emailSent" → "toolCallResult"
    name = name.trim().split('.')[0].trim();
    if (!name || name.includes(' ') || name.startsWith('=')) return;
    if (!definitions.has(name)) definitions.set(name, []);
    definitions.get(name).push(source);
  }
  function addRef(name) {
    if (name && typeof name === 'string' && !name.includes(' ')) references.add(name);
  }

  // BPMN files — exclude target/ and test/ copies
  for (const file of glob(join(groupDir, '**/*.bpmn')).filter(exclude)) {
    const { definitions: defs, references: refs } = await parseBpmn(file);
    for (const { name, line, kind } of defs) addDef(name, { file, line, kind });
    for (const name of refs) addRef(name);
  }

  // DMN files
  for (const file of glob(join(groupDir, '**/*.dmn')).filter(exclude)) {
    const { definitions: defs } = parseDmn(file);
    for (const { name, line } of defs) addDef(name, { file, line, kind: 'dmn-output' });
  }

  // Form files
  for (const file of glob(join(groupDir, '**/*.form')).filter(exclude)) {
    const { definitions: defs } = parseForm(file);
    for (const { name } of defs) addDef(name, { file, line: null, kind: 'form-key' });
  }

  // CPT test JSON — references only
  for (const file of glob(join(groupDir, '**/test/src/test/resources/**/*.test.json'))) {
    const { references: refs } = parseTestJson(file);
    for (const name of refs) addRef(name);
  }

  return { definitions, references };
}

function exclude(f) {
  return !f.includes('/target/') && !f.includes('/test/src/') && !f.includes('/test/target/');
}

// ── draft schema builder ────────────────────────────────────────────────────

function buildDraftSchema(group, { definitions }, repoConfig, scope) {
  const title = group === 'solutions' ? 'Solutions' : 'Quick Start';

  const variables = {};
  for (const [name, sources] of [...definitions.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const kinds = [...new Set(sources.map(s => s.kind))].join(', ');
    const processes = [...new Set(sources.map(s => s.file ? relative(REPO_ROOT, s.file).split('/').slice(0, 2).join('/') : group))].join(', ');
    variables[name] = {
      title: prettifyName(name),
      type: 'string',
      description: `{TODO: business description} — used in: ${processes} (sources: ${kinds})`,
      examples: ['{TODO: example value}'],
    };
  }

  return {
    $schema: '../schema/process-variables.meta-schema.json',
    title: `Camunda 8 Tutorials — ${title} Process Variables`,
    metadata: {
      convention: repoConfig.convention ?? 'camelCase',
      scope,
      owner: `@${process.env.GITHUB_ACTOR ?? 'HanselIdes'}`,
    },
    variables,
  };
}

function prettifyName(name) {
  return name
    .replace(/_/g, ' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/^./, s => s.toUpperCase());
}
