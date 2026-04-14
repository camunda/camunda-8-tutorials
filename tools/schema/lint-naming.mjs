#!/usr/bin/env node
/**
 * lint-naming.mjs — Naming convention linter for process variable schemas.
 *
 * Usage:
 *   node tools/schema/lint-naming.mjs --group solutions
 *   node tools/schema/lint-naming.mjs --group quick-start
 *
 * Reads the repo-level .variable-schema.config.json for the expected convention.
 * Per-schema metadata.convention overrides the repo default.
 *
 * Emits GitHub Actions annotations for each violation.
 * Exits 1 if enforceNaming is true and violations found; otherwise exits 0.
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, join, relative, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname  = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT  = resolve(__dirname, '../..');

const args     = process.argv.slice(2);
const groupArg = args[args.indexOf('--group') + 1];

if (!groupArg) {
  console.error('Usage: lint-naming.mjs --group solutions|quick-start');
  process.exit(1);
}

const schemaPath = join(REPO_ROOT, groupArg, 'variables.schema.json');

const configPath = join(REPO_ROOT, '.variable-schema.config.json');
const repoConfig = existsSync(configPath)
  ? JSON.parse(readFileSync(configPath, 'utf8'))
  : { convention: 'camelCase', enforceNaming: true };

// When enforceNaming is false, emit notices but don't fail CI.
// Set to true after the snake_case migration PR (issue #96) lands.
const enforce = repoConfig.enforceNaming !== false;

let exitCode = 0;

if (!existsSync(schemaPath)) {
  console.log(`::notice::No schema found at ${relative(REPO_ROOT, schemaPath)} — skipping naming lint.`);
  process.exit(0);
}

const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
const convention = schema.metadata?.convention ?? repoConfig.convention ?? 'camelCase';
const schemaFile = relative(REPO_ROOT, schemaPath);

for (const [name, entry] of Object.entries(schema.variables || {})) {
  if (entry.description?.startsWith('DEAD')) continue;

  const violation = checkConvention(name, convention);
  if (violation) {
    const suggested = toConvention(name, convention);
    const level = enforce ? 'error' : 'notice';
    console.log(`::${level} file=${schemaFile}::Naming violation: '${name}' does not follow ${convention}. Suggested: '${suggested}'. ${violation}`);
    if (enforce) exitCode = 1;
  }
}

process.exit(exitCode);

// ── convention checkers ─────────────────────────────────────────────────────

function checkConvention(name, convention) {
  if (!name) return null;
  switch (convention) {
    case 'camelCase':
      if (!/^[a-z][a-zA-Z0-9]*$/.test(name)) {
        if (name.includes('_')) return 'Contains underscore — use camelCase.';
        if (/^[A-Z]/.test(name)) return 'Starts with uppercase — use camelCase (lowercase first letter).';
        return 'Does not match camelCase pattern.';
      }
      return null;
    case 'snake_case':
      if (!/^[a-z][a-z0-9_]*$/.test(name) || /[A-Z]/.test(name))
        return 'Does not match snake_case pattern (lowercase, underscores only).';
      return null;
    case 'PascalCase':
      if (!/^[A-Z][a-zA-Z0-9]*$/.test(name))
        return 'Does not match PascalCase pattern (uppercase first letter, no underscores).';
      return null;
    default:
      return null;
  }
}

function toConvention(name, convention) {
  const words = name
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .split(/[_\s]+/)
    .filter(Boolean);

  switch (convention) {
    case 'camelCase':
      return words.map((w, i) => i === 0 ? w.toLowerCase() : w[0].toUpperCase() + w.slice(1).toLowerCase()).join('');
    case 'snake_case':
      return words.map(w => w.toLowerCase()).join('_');
    case 'PascalCase':
      return words.map(w => w[0].toUpperCase() + w.slice(1).toLowerCase()).join('');
    default:
      return name;
  }
}
