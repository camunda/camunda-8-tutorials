/**
 * glob.mjs — Minimal synchronous glob using Node.js built-ins.
 * Supports ** wildcards. All paths must be absolute.
 */

import { readdirSync, existsSync } from 'fs';
import { join } from 'path';

/**
 * Returns all absolute file paths matching one or more glob patterns.
 * @param {...string} patterns  Absolute glob patterns.
 * @returns {string[]}
 */
export function glob(...patterns) {
  const results = new Set();
  for (const pattern of patterns) {
    for (const f of matchPattern(pattern)) results.add(f);
  }
  return [...results].sort();
}

/**
 * Match a single glob pattern.
 * Handles ** by walking the directory tree from the non-wildcard prefix,
 * then filtering each file path against a regex built from the full pattern.
 */
function matchPattern(pattern) {
  // Find the deepest directory prefix that contains no wildcards
  const parts = pattern.split('/');
  const staticParts = [];
  for (const part of parts) {
    if (part.includes('*')) break;
    staticParts.push(part);
  }
  const baseDir = staticParts.join('/') || '/';

  if (!existsSync(baseDir)) return [];

  // Convert the glob pattern to a regular expression:
  // Process wildcards BEFORE escaping so they don't get caught by the escaper.
  const regexSrc = pattern
    .split('**').join('\x00DSTAR\x00')      // protect ** with placeholder
    .split('*').join('\x00STAR\x00')        // protect * with placeholder
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // escape regex special chars
    .split('\x00DSTAR\x00').join('.*')      // ** → match any path (including /)
    .split('\x00STAR\x00').join('[^/]*');   // * → match any non-separator sequence

  const regex = new RegExp('^' + regexSrc + '$');

  return walkDir(baseDir).filter(f => regex.test(f));
}

function walkDir(dir) {
  const results = [];
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...walkDir(full));
      } else if (entry.isFile()) {
        results.push(full);
      }
    }
  } catch {
    // skip unreadable dirs
  }
  return results;
}
