/**
 * test-json.mjs — CPT test JSON variable reference extraction.
 *
 * References (reads — keep variables alive for dead detection):
 *   All keys from `variables` objects in any instruction step.
 *
 * CPT test files use variables as inputs to instructions and assertions.
 * Their presence confirms the variable is known to the process.
 */

import { readFileSync } from 'fs';

/**
 * @param {string} filePath
 * @returns {{ references: Set<string> }}
 */
export function parseTestJson(filePath) {
  let data;
  try {
    data = JSON.parse(readFileSync(filePath, 'utf8'));
  } catch (err) {
    console.error(`::warning file=${filePath}::Test JSON parse error: ${err.message}`);
    return { references: new Set() };
  }

  const references = new Set();

  function collect(obj) {
    if (!obj || typeof obj !== 'object') return;
    if (Array.isArray(obj)) {
      for (const item of obj) collect(item);
      return;
    }
    if ('variables' in obj && obj.variables && typeof obj.variables === 'object') {
      for (const key of Object.keys(obj.variables)) {
        if (key && !key.includes(' ')) references.add(key);
      }
    }
    for (const val of Object.values(obj)) collect(val);
  }

  collect(data);
  return { references };
}
