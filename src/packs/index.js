'use strict';
// Content packs: installable bundles of detection rules. One file per pack in src/packs/catalog/
// (file name = pack id), the same convention as module manifests, so two people adding two packs
// touch two files. Every pack is validated when it is loaded: a bad pack fails the test run, and
// it is skipped (with a log line) rather than taking the platform down in production.
//
// An installed pack rule is a normal detection_rules row whose builtin_key is
// "pack:<pack id>:<rule key>". That reuses the existing unique (tenant_id, builtin_key) index, so
// installing twice never duplicates, and needs no schema change.
const fs = require('fs');
const path = require('path');
const { normalizeDefinition } = require('../detection/rule-query');
const { BUILTIN_RULES } = require('../detection/rule-runner');

const CATALOG_DIR = path.join(__dirname, 'catalog');
const ID_RE = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const KEY_RE = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const KINDS = ['correlation', 'bioc'];
const MITRE_RE = /^T\d{4}(\.\d{3})?$/;
const PREFIX = 'pack:';

const builtinKey = (packId, ruleKey) => `${PREFIX}${packId}:${ruleKey}`;

// Returns the cleaned pack, or throws Error with a message naming the pack and the problem.
function validatePack(p, fileId) {
  const bad = (m) => { throw new Error(`pack "${fileId}": ${m}`); };
  if (!p || typeof p !== 'object') bad('must export an object');
  if (!ID_RE.test(String(p.id || '')) || p.id.length > 40) bad('id must be lowercase letters, digits and dashes (max 40)');
  if (p.id !== fileId) bad(`id "${p.id}" must equal the file name "${fileId}"`);
  for (const f of ['name', 'description', 'version']) if (typeof p[f] !== 'string' || !p[f].trim()) bad(`${f} is required`);
  if (!/^\d+\.\d+\.\d+$/.test(p.version)) bad('version must look like 1.0.0');
  if (!Array.isArray(p.rules) || !p.rules.length) bad('needs at least one rule');
  if (p.rules.length > 50) bad('at most 50 rules per pack');
  const seen = new Set(); const builtinKeys = new Set(BUILTIN_RULES.map((r) => r.key));
  const rules = p.rules.map((r) => {
    const w = (m) => bad(`rule "${r && r.key}": ${m}`);
    if (!r || !KEY_RE.test(String(r.key || '')) || r.key.length > 50) w('key must be lowercase letters, digits and dashes (max 50)');
    if (seen.has(r.key)) w('duplicate key');
    seen.add(r.key);
    if (builtinKeys.has(r.key)) w('key clashes with a built-in rule');
    if (builtinKey(p.id, r.key).length > 100) w('builtin key longer than 100 characters');
    if (typeof r.name !== 'string' || !r.name.trim() || r.name.length > 255) w('name is required (max 255)');
    if (!KINDS.includes(r.kind)) w('kind must be correlation or bioc');
    if (!SEVERITIES.includes(r.severity)) w('severity must be one of ' + SEVERITIES.join(', '));
    if (!Array.isArray(r.mitre) || r.mitre.some((m) => !MITRE_RE.test(m))) w('mitre must be a list like ["T1110"]');
    const norm = normalizeDefinition(r.definition);
    if (norm.error) w(norm.error);
    return {
      key: r.key, builtin_key: builtinKey(p.id, r.key), kind: r.kind, category: r.category ? String(r.category).slice(0, 100) : null,
      name: r.name.trim(), description: String(r.description || '').slice(0, 2000), severity: r.severity, mitre: r.mitre, definition: norm.def,
    };
  });
  return { id: p.id, name: p.name.trim(), description: p.description.trim(), version: p.version, audience: p.audience || 'residential', sources: Array.isArray(p.sources) ? p.sources.map(String) : [], rules };
}

let cache = null;
function load(dir = CATALOG_DIR, { strict = false } = {}) {
  const out = [];
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.js')).sort()) {
    try { out.push(validatePack(require(path.join(dir, f)), f.slice(0, -3))); } catch (e) {
      if (strict) throw e;
      console.error('[packs] skipped:', e.message);
    }
  }
  return out;
}
const all = () => (cache = cache || load());
const get = (id) => all().find((p) => p.id === id) || null;

// For the "reset to shipped definition" button on the rules page.
function findRuleByBuiltinKey(key) {
  if (typeof key !== 'string' || !key.startsWith(PREFIX)) return null;
  for (const p of all()) { const r = p.rules.find((x) => x.builtin_key === key); if (r) return r; }
  return null;
}

module.exports = { all, get, load, validatePack, findRuleByBuiltinKey, builtinKey, PREFIX };
