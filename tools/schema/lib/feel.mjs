/**
 * feel.mjs — Regex-based FEEL expression root identifier extractor.
 *
 * Extracts the root variable references from a FEEL expression.
 * "Root" means the first identifier in a path expression — the process variable name.
 *
 * Example: "=if currentEmail.plainTextBody != null then currentEmail.plainTextBody else currentEmail.htmlBody"
 * → ["currentEmail"]
 *
 * Limitation: only captures the first identifier per path. Multi-variable expressions like
 * "=a + b" produce ["a"] not ["a","b"]. This is sufficient for dead variable detection
 * (any appearance keeps a variable alive) but not for exhaustive reference analysis.
 * Upgrade path: replace with feelin's getVariableReferences().
 */

const FEEL_KEYWORDS = new Set([
  'if', 'then', 'else', 'and', 'or', 'not', 'true', 'false', 'null',
  'instance', 'of', 'in', 'some', 'every', 'satisfies', 'return',
  'function', 'external', 'for', 'between', 'context', 'list', 'filter',
  'duration', 'date', 'time', 'string', 'number', 'boolean',
]);

/**
 * @param {string} expr — A FEEL expression, optionally prefixed with '='.
 * @returns {Set<string>} Root variable identifiers referenced in the expression.
 */
export function feelRootIdents(expr) {
  if (!expr || typeof expr !== 'string') return new Set();

  // Strip leading '=' or whitespace
  let src = expr.replace(/^[=\s]+/, '');

  // Remove string literals to avoid false matches on quoted identifiers
  src = src.replace(/"[^"]*"/g, '""');
  src = src.replace(/'[^']*'/g, "''");

  const results = new Set();

  // Match path expressions: identifier optionally followed by .property or [index]
  // We only want the root — the first identifier segment
  const pathPattern = /\b([a-zA-Z_][a-zA-Z0-9_]*)(?:\s*[.[)])?/g;
  let match;
  while ((match = pathPattern.exec(src)) !== null) {
    const ident = match[1];
    if (!FEEL_KEYWORDS.has(ident) && !/^\d/.test(ident)) {
      results.add(ident);
    }
  }

  return results;
}
