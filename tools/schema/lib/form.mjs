/**
 * form.mjs — Camunda Form variable extraction.
 *
 * Definitions (writes):
 *   All `key` values on form components at any nesting depth.
 *   Form keys bind to process variables when the user task submits.
 */

import { readFileSync } from 'fs';

/**
 * @param {string} filePath
 * @returns {{ definitions: Array<{name, line, kind}> }}
 */
export function parseForm(filePath) {
  let form;
  try {
    form = JSON.parse(readFileSync(filePath, 'utf8'));
  } catch (err) {
    console.error(`::warning file=${filePath}::Form parse error: ${err.message}`);
    return { definitions: [] };
  }

  const definitions = [];

  function walk(components) {
    if (!Array.isArray(components)) return;
    for (const component of components) {
      if (component.key && typeof component.key === 'string' && !component.key.includes(' ')) {
        definitions.push({ name: component.key, line: null, kind: 'form-key' });
      }
      if (component.components) walk(component.components);
      // Some form layouts nest inside rows/columns
      if (component.rows) {
        for (const row of component.rows) {
          if (Array.isArray(row)) walk(row);
          else if (row.columns) walk(row.columns);
        }
      }
      if (component.columns) {
        for (const col of component.columns) {
          if (col.components) walk(col.components);
        }
      }
    }
  }

  walk(form.components);
  return { definitions };
}
