// Runs the JavaScript of an n8n Code node, taken straight from the exported
// workflow JSON, with a mocked n8n context. Tests therefore always exercise the
// exact code that ships in the workflow files.
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const cache = new Map();
export function nodeCode(workflowPath, nodeName) {
  if (!cache.has(workflowPath)) cache.set(workflowPath, JSON.parse(readFileSync(workflowPath, 'utf8')));
  const node = cache.get(workflowPath).nodes.find((n) => n.name === nodeName);
  if (!node) throw new Error(`Node "${nodeName}" not found in ${workflowPath}`);
  return node.parameters.jsCode;
}

const asItem = (json) => ({ json });

/**
 * run(code, { json, items, env, nodes, today })
 *   json  - $json for "run once for each item" nodes
 *   items - $input.all() for "run once for all items" nodes
 *   nodes - { 'Node Name': json | [json, ...] } for $('Node Name')
 */
export function run(code, { json = {}, items, env = {}, nodes = {}, today = '2026-10-15' } = {}) {
  const inputItems = (items ?? [json]).map(asItem);
  const ref = (name) => {
    if (!(name in nodes)) throw new Error(`Test did not mock $('${name}')`);
    const list = [].concat(nodes[name]).map(asItem);
    return { item: list[0], first: () => list[0], all: () => list };
  };
  const context = {
    $json: json,
    $input: { first: () => inputItems[0], all: () => inputItems },
    $env: env,
    $: ref,
    $now: { toISODate: () => today, toFormat: () => `${today} 12:00 GMT` },
  };
  const result = new vm.Script(`(() => {\n${code}\n})()`).runInNewContext(context);
  // Objects created inside the sandbox have the sandbox's prototypes; copy them out
  // so strict deep-equality in tests compares values, not realms.
  return JSON.parse(JSON.stringify(result));
}

export const one = (result) => (Array.isArray(result) ? result[0] : result).json;
