'use strict';
// Content packs: installable bundles of detection rules. One file per pack in src/packs/catalog/
// (file name = pack id), the same convention as module manifests, so two people adding two packs
// touch two files. Every pack is validated when it is loaded: a bad pack fails the test run, and
// it is skipped (with a log line) rather than taking the platform down in production.
//
// Manifest v2 (task MK1, docs/product-plan.md "Status of Phase 5"): besides the rules a pack now says who publishes it, whether
// it is certified, who supports it, what it depends on, its version history and whether it is deprecated. Every v2 field is
// optional, so the first three packs work unchanged. A pack carries DATA only, never portal code (docs/portal-shell.md).
// Other kinds of content (parsers, dashboards, playbooks, actions, integrations) are refused until the code that installs them exists.
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
const CERTIFICATIONS = ['certified', 'community'];
const SUPPORTS = ['asix', 'community', 'none'];
const TAG_RE = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const MODULE_ID_RE = /^[a-z][a-z0-9-]{1,40}$/;
const VERSION_RE = /^\d+\.\d+\.\d+$/;
const KNOWN_KEYS = new Set(['id', 'name', 'description', 'version', 'audience', 'sources', 'rules', 'publisher', 'certification', 'supported_by', 'core',
  'deprecated', 'deprecation', 'replaced_by', 'tags', 'license', 'requires', 'history']);
// Content a pack will be able to carry later: refused today, with the task that will make it installable.
const NOT_YET = { parsers: 'no task for it yet', dashboards: 'no task for it yet', playbooks: 'task SR3', actions: 'task SR2', integrations: 'task SR1' };
const cmpVer = (a, b) => { const x = a.split('.').map(Number); const y = b.split('.').map(Number); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i]; return 0; };
const realDate = (d) => typeof d === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(d) && !Number.isNaN(Date.parse(d)) && new Date(d).toISOString().slice(0, 10) === d;

const builtinKey = (packId, ruleKey) => `${PREFIX}${packId}:${ruleKey}`;

// Returns the cleaned pack, or throws Error with a message naming the pack and the problem.
function validatePack(p, fileId) {
  const bad = (m) => { throw new Error(`pack "${fileId}": ${m}`); };
  if (!p || typeof p !== 'object') bad('must export an object');
  if (!ID_RE.test(String(p.id || '')) || p.id.length > 40) bad('id must be lowercase letters, digits and dashes (max 40)');
  if (p.id !== fileId) bad(`id "${p.id}" must equal the file name "${fileId}"`);
  for (const k of Object.keys(p)) {
    if (NOT_YET[k]) bad(`"${k}" cannot be in a pack yet: nothing installs it (${NOT_YET[k]}). A kind of content is allowed together with the code that installs it`);
    if (!KNOWN_KEYS.has(k)) bad(`unknown field "${k}"`);
  }
  for (const f of ['name', 'description', 'version']) if (typeof p[f] !== 'string' || !p[f].trim()) bad(`${f} is required`);
  if (!VERSION_RE.test(p.version)) bad('version must look like 1.0.0');
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
  const v2 = validateV2(p, bad);
  if (v2.history.length && v2.history[0].version !== p.version) bad(`history must start with the current version ${p.version} (newest first)`);
  return {
    id: p.id, name: p.name.trim(), description: p.description.trim(), version: p.version, audience: p.audience || 'residential',
    sources: Array.isArray(p.sources) ? p.sources.map(String) : [], rules, ...v2,
    released: (v2.history[0] && v2.history[0].released) || null,
    contents: { rules: rules.length },   // counts per kind of content; only rules can be installed today
  };
}

// The optional v2 fields, with their defaults. `bad` throws.
function validateV2(p, bad) {
  const str = (v, f, max) => { if (typeof v !== 'string' || !v.trim() || v.length > max) bad(`${f} must be text of 1 to ${max} characters`); return v.trim(); };
  let publisher = { name: 'ASIX', url: null };
  if (p.publisher !== undefined) {
    if (!p.publisher || typeof p.publisher !== 'object' || Array.isArray(p.publisher)) bad('publisher must be { name, url? }');
    publisher = { name: str(p.publisher.name, 'publisher.name', 60), url: null };
    if (p.publisher.url != null) { if (typeof p.publisher.url !== 'string' || !/^https:\/\/[^\s]+$/.test(p.publisher.url) || p.publisher.url.length > 200) bad('publisher.url must be an https address'); publisher.url = p.publisher.url; }
  }
  const certification = p.certification === undefined ? 'certified' : p.certification;
  if (!CERTIFICATIONS.includes(certification)) bad(`certification must be one of ${CERTIFICATIONS.join(', ')}`);
  const supported_by = p.supported_by === undefined ? (certification === 'certified' ? 'asix' : 'community') : p.supported_by;
  if (!SUPPORTS.includes(supported_by)) bad(`supported_by must be one of ${SUPPORTS.join(', ')}`);
  for (const f of ['core', 'deprecated']) if (p[f] !== undefined && typeof p[f] !== 'boolean') bad(`${f} must be true or false`);
  const deprecated = p.deprecated === true;
  let deprecation = null; let replaced_by = null;
  if (deprecated) {
    deprecation = str(p.deprecation, 'deprecation (the reason, required when deprecated)', 300);
    if (p.replaced_by != null) { if (!ID_RE.test(String(p.replaced_by)) || p.replaced_by === p.id) bad('replaced_by must be the id of another pack'); replaced_by = p.replaced_by; }
  } else if (p.deprecation !== undefined || p.replaced_by !== undefined) bad('deprecation and replaced_by only go with deprecated: true');
  const list = (v, f, max, ok, what) => {
    if (v === undefined) return [];
    if (!Array.isArray(v) || v.length > max || v.some((x) => typeof x !== 'string' || !ok.test(x))) bad(`${f} must be a list of at most ${max} ${what}`);
    if (new Set(v).size !== v.length) bad(`${f} has a duplicate`);
    return v.slice();
  };
  const tags = list(p.tags, 'tags', 10, TAG_RE, 'lowercase words such as "linux" or "ssh"');
  if (p.requires !== undefined && (!p.requires || typeof p.requires !== 'object' || Array.isArray(p.requires) || Object.keys(p.requires).some((k) => k !== 'modules' && k !== 'packs'))) bad('requires must be { modules?: [...], packs?: [...] }');
  const rq = p.requires || {};
  const requires = { modules: list(rq.modules, 'requires.modules', 10, MODULE_ID_RE, 'module ids'), packs: list(rq.packs, 'requires.packs', 10, ID_RE, 'pack ids') };
  if (requires.packs.includes(p.id)) bad('a pack cannot require itself');
  const license = p.license === undefined ? null : str(p.license, 'license', 60);
  let history = [];
  if (p.history !== undefined) {
    if (!Array.isArray(p.history) || p.history.length > 50) bad('history must be a list of at most 50 entries');
    history = p.history.map((h, i) => {
      const at = (m) => bad(`history[${i}]: ${m}`);
      if (!h || typeof h !== 'object' || !VERSION_RE.test(String(h.version || ''))) at('version must look like 1.0.0');
      if (h.released !== undefined && !realDate(h.released)) at('released must be a real date like 2026-11-08');
      return { version: h.version, released: h.released || null, notes: str(h.notes, `history[${i}].notes`, 300) };
    });
    for (let i = 1; i < history.length; i++) if (cmpVer(history[i - 1].version, history[i].version) <= 0) bad('history must list versions newest first, each once');
  }
  return { publisher, certification, supported_by, core: p.core === true, deprecated, deprecation, replaced_by, tags, license, requires, history };
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

// ---- State, what the API shows, and what stops an install or a removal ---------------------------------------------
// st = { [packId]: { installed, enabled, open_alerts } } from service.status
const stateOf = (pack, st) => { const s = st && st[pack.id]; return !s ? 'available' : s.installed >= pack.rules.length ? 'installed' : 'partial'; };

// One pack as the API and the Marketplace page see it (no rule definitions: those stay on the server).
function describe(p, st) {
  const s = st && st[p.id];
  return {
    id: p.id, name: p.name, description: p.description, version: p.version, audience: p.audience, sources: p.sources,
    publisher: p.publisher, certification: p.certification, supported_by: p.supported_by, core: p.core,
    deprecated: p.deprecated, deprecation: p.deprecation, replaced_by: p.replaced_by,
    tags: p.tags, license: p.license, requires: p.requires, history: p.history, released: p.released, contents: p.contents,
    rule_count: p.rules.length,
    rules: p.rules.map((r) => ({ key: r.key, name: r.name, description: r.description, severity: r.severity, kind: r.kind, category: r.category, mitre: r.mitre })),
    installed_rules: s ? s.installed : 0, enabled_rules: s ? s.enabled : 0, open_alerts: s ? s.open_alerts : 0,
    state: stateOf(p, st),
  };
}

// null when the pack may be installed, else { status, code, message }.
// enabledModules: Set of module ids that are on. A dependency counts only when it is fully installed.
function installBlockers(pack, { st, allPacks, enabledModules, allowDeprecated = false }) {
  const byId = new Map(allPacks.map((x) => [x.id, x]));
  if (pack.deprecated && !allowDeprecated) {
    const rep = pack.replaced_by && byId.get(pack.replaced_by);
    return { status: 409, code: 'PACK_DEPRECATED', message: `"${pack.name}" is deprecated: ${pack.deprecation}${rep ? ` Use "${rep.name}" instead.` : ''}` };
  }
  const modulesOff = pack.requires.modules.filter((m) => !enabledModules.has(m));
  if (modulesOff.length) return { status: 409, code: 'MODULE_REQUIRED', message: `"${pack.name}" needs these modules switched on first: ${modulesOff.join(', ')}` };
  const packsMissing = pack.requires.packs.filter((id) => { const d = byId.get(id); return !d || stateOf(d, st) !== 'installed'; });
  if (packsMissing.length) return { status: 409, code: 'PACK_REQUIRED', message: `"${pack.name}" needs these packs installed first: ${packsMissing.map((id) => (byId.get(id) ? byId.get(id).name : id)).join(', ')}` };
  return null;
}

// null when the pack may be removed, else { status, code, message }: another installed pack still depends on it.
function removeBlockers(packId, allPacks, st) {
  const users = allPacks.filter((x) => x.id !== packId && x.requires.packs.includes(packId) && st && st[x.id] && st[x.id].installed > 0);
  if (!users.length) return null;
  return { status: 409, code: 'REQUIRED_BY', message: `These installed packs depend on it: ${users.map((x) => x.name).join(', ')}. Remove them first.` };
}

// Problems across the whole catalog (nothing is wrong with one pack alone): unknown modules or packs, loops, a pack that
// requires a deprecated one. tests/packs-v2.test.js runs it on the shipped catalog with the real module ids.
function checkCatalog(list, moduleIds) {
  const out = []; const byId = new Map(list.map((p) => [p.id, p])); const mods = new Set(moduleIds);
  for (const p of list) {
    for (const m of p.requires.modules) if (!mods.has(m)) out.push(`${p.id}: requires unknown module "${m}"`);
    for (const d of p.requires.packs) {
      const dp = byId.get(d);
      if (!dp) out.push(`${p.id}: requires unknown pack "${d}"`);
      else if (dp.deprecated && !p.deprecated) out.push(`${p.id}: requires deprecated pack "${d}"`);
    }
    if (p.replaced_by && !byId.has(p.replaced_by)) out.push(`${p.id}: replaced_by names unknown pack "${p.replaced_by}"`);
  }
  const state = new Map();   // 1 = on the path being walked, 2 = finished
  const walk = (id, path) => {
    if (state.get(id) === 2 || !byId.has(id)) return;
    if (state.get(id) === 1) { out.push(`dependency loop: ${[...path.slice(path.indexOf(id)), id].join(' -> ')}`); return; }
    state.set(id, 1); for (const d of byId.get(id).requires.packs) walk(d, [...path, id]); state.set(id, 2);
  };
  for (const p of list) walk(p.id, []);
  return out;
}

module.exports = { all, get, load, validatePack, findRuleByBuiltinKey, builtinKey, PREFIX, stateOf, describe, installBlockers, removeBlockers, checkCatalog, CERTIFICATIONS, SUPPORTS, NOT_YET };
