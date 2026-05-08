/**
 * dmn.mjs — DMN variable extraction via XML regex.
 *
 * Definitions (writes):
 *   <output name="..."> element names — the variable written by this decision's output column.
 */

import { readFileSync } from 'fs';

/**
 * @param {string} filePath
 * @returns {{ definitions: Array<{name, line, kind}> }}
 */
export function parseDmn(filePath) {
  const xml = readFileSync(filePath, 'utf8');
  const definitions = [];
  const lines = xml.split('\n');

  // Match <output ... name="varName" ...> on any line
  const outputPattern = /<output\b[^>]+\bname="([^"]+)"/g;
  let match;
  while ((match = outputPattern.exec(xml)) !== null) {
    const name = match[1];
    // Find which line this falls on
    const pos = match.index;
    const line = xml.slice(0, pos).split('\n').length;
    if (name && !name.includes(' ')) {
      definitions.push({ name, line, kind: 'dmn-output' });
    }
  }

  return { definitions };
}
