/**
 * bpmn.mjs — BPMN variable extraction using bpmn-moddle + zeebe-bpmn-moddle.
 *
 * Definitions (writes):
 *   zeebe:Output target values
 *   resultVariable attribute values
 *
 * References (reads — keep a variable alive for dead-variable detection):
 *   zeebe:Input source FEEL expressions (root identifiers)
 *   Sequence flow conditionExpression bodies (root identifiers)
 *   Script task / business rule task expression bodies (root identifiers)
 */

import { createRequire } from 'module';
import { readFileSync } from 'fs';
import { feelRootIdents } from './feel.mjs';

const require = createRequire(import.meta.url);
const { BpmnModdle } = require('bpmn-moddle');
const ZeebeModdle   = require('zeebe-bpmn-moddle/resources/zeebe.json');

/**
 * @param {string} filePath
 * @returns {Promise<{ definitions: Array<{name,line,kind}>, references: Set<string> }>}
 */
export async function parseBpmn(filePath) {
  const xml = readFileSync(filePath, 'utf8');
  const moddle = new BpmnModdle({ zeebe: ZeebeModdle });

  let rootElement;
  try {
    ({ rootElement } = await moddle.fromXML(xml));
  } catch (err) {
    console.error(`::warning file=${filePath}::BPMN parse error: ${err.message}`);
    return { definitions: [], references: new Set() };
  }

  const definitions = [];
  const references  = new Set();

  function def(name, kind) {
    if (name && typeof name === 'string' && !name.includes(' ')) {
      definitions.push({ name, line: null, kind });
    }
  }

  function ref(expr) {
    for (const ident of feelRootIdents(expr)) references.add(ident);
  }

  function walk(el) {
    if (!el || typeof el !== 'object') return;

    switch (el.$type) {
      case 'zeebe:Output':
        def(el.target, 'bpmn-output');
        // source is a read reference
        if (el.source?.startsWith('=')) ref(el.source);
        break;

      case 'zeebe:Input':
        // target is connector config — excluded
        // source is a read reference if it's a FEEL expression
        if (el.source?.startsWith('=')) ref(el.source);
        break;

      case 'bpmn:ServiceTask':
      case 'bpmn:SendTask':
      case 'bpmn:BusinessRuleTask':
      case 'bpmn:ScriptTask':
        if (el.resultVariable) def(el.resultVariable, 'result-variable');
        break;

      case 'bpmn:SequenceFlow':
        if (el.conditionExpression?.body) ref(el.conditionExpression.body);
        break;
    }

    // Recurse into all child properties
    for (const val of Object.values(el)) {
      if (Array.isArray(val)) {
        for (const child of val) {
          if (child && typeof child === 'object' && child.$type) walk(child);
        }
      } else if (val && typeof val === 'object' && val.$type) {
        walk(val);
      }
    }
  }

  walk(rootElement);
  return { definitions, references };
}
