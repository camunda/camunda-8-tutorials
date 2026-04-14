#!/usr/bin/env node
/**
 * find-similar-variables.mjs — Variable similarity detector.
 *
 * Usage:
 *   node tools/schema/find-similar-variables.mjs
 *
 * Loads both group schemas (solutions/ and quick-start/) and runs:
 *
 * Signal A — Name similarity (within each group):
 *   Normalized Levenshtein distance ≤ 0.20 AND shared prefix ≥ 4 chars.
 *
 * Signal B — Structural similarity (cross-group):
 *   Jaccard similarity of `properties` key sets between object-typed variables ≥ 0.50.
 *   Flags candidates for consolidation into schema/$defs/.
 *
 * All output is advisory — exits 0.
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '../..');

const GROUPS = ['solutions', 'quick-start'];

// ── load all schemas ─────────────────────────────────────────────────────────

/** @type {Array<{group: string, name: string, entry: object}>} */
const allVars = [];

for (const group of GROUPS) {
  const schemaPath = join(REPO_ROOT, group, 'variables.schema.json');
  if (!existsSync(schemaPath)) continue;
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));

  for (const [name, entry] of Object.entries(schema.variables || {})) {
    if (entry.description?.startsWith('DEAD')) continue;
    allVars.push({ group, name, entry });
  }
}

const findings = [];

// ── Signal A: name similarity (within each group) ────────────────────────────

const byGroup = new Map();
for (const v of allVars) {
  if (!byGroup.has(v.group)) byGroup.set(v.group, []);
  byGroup.get(v.group).push(v);
}

for (const [group, vars] of byGroup) {
  const threshold = vars.length < 500 ? 0.20 : 0.15;

  for (let i = 0; i < vars.length; i++) {
    for (let j = i + 1; j < vars.length; j++) {
      const a = vars[i].name;
      const b = vars[j].name;
      const dist = normalizedLevenshtein(a, b);
      const sharedPrefix = commonPrefixLength(a, b);

      if (dist <= threshold && sharedPrefix >= 4) {
        findings.push(
          `**Signal A** (${group}): \`${a}\` and \`${b}\` — name distance ${dist.toFixed(2)}, ${sharedPrefix}-char shared prefix. ` +
          `May represent the same concept under different names.`
        );
      }
    }
  }
}

// ── Signal B: structural similarity (cross-group) ────────────────────────────

const objectVars = allVars.filter(v => v.entry.type === 'object' && v.entry.properties);

for (let i = 0; i < objectVars.length; i++) {
  for (let j = i + 1; j < objectVars.length; j++) {
    const a = objectVars[i];
    const b = objectVars[j];

    const jaccard = jaccardSimilarity(
      new Set(Object.keys(a.entry.properties)),
      new Set(Object.keys(b.entry.properties)),
    );

    if (jaccard >= 0.50) {
      const sharedProps = Object.keys(a.entry.properties).filter(k => b.entry.properties[k]);
      const allProps = new Set([...Object.keys(a.entry.properties), ...Object.keys(b.entry.properties)]);
      const location = a.group === b.group ? a.group : `${a.group} and ${b.group}`;
      findings.push(
        `**Signal B** (${location}): \`${a.name}\` and \`${b.name}\` share ${sharedProps.length} of ${allProps.size} sub-properties ` +
        `(\`${sharedProps.join('`, `')}\`). Jaccard: ${jaccard.toFixed(2)}. ` +
        `Consider consolidating into \`schema/$defs/\`.`
      );
    }
  }
}

// ── output ───────────────────────────────────────────────────────────────────

if (findings.length === 0) {
  console.log('No similar variable pairs found.');
} else {
  console.log('## Variable Similarity Report\n');
  console.log(`Found ${findings.length} similar pair(s). All findings are advisory.\n`);
  for (const f of findings) console.log(`- ${f}`);
}

process.exit(0);

// ── algorithms ───────────────────────────────────────────────────────────────

function normalizedLevenshtein(a, b) {
  const maxLen = Math.max(a.length, b.length);
  return maxLen === 0 ? 0 : levenshtein(a, b) / maxLen;
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[m][n];
}

function commonPrefixLength(a, b) {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return i;
}

function jaccardSimilarity(setA, setB) {
  const intersection = new Set([...setA].filter(x => setB.has(x)));
  const union = new Set([...setA, ...setB]);
  return union.size === 0 ? 0 : intersection.size / union.size;
}
