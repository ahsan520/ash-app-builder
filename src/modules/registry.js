'use strict';
// Loads and validates module manifests (src/modules/manifests/*.js). Modules register themselves by
// dropping a manifest file in that folder; nothing is hard-coded in the gateway or portal menu.
const fs = require('fs');
const path = require('path');

const TIERS = ['home', 'enterprise'];
const STATUSES = ['available', 'planned'];
const ID_RE = /^[a-z][a-z0-9-]{1,40}$/;

class ManifestError extends Error {}

function validate(m, file) {
  const bad = (msg) => { throw new ManifestError(`${file}: ${msg}`); };
  if (!m || typeof m !== 'object') bad('manifest must export an object');
  if (!ID_RE.test(m.id || '')) bad('id must be lowercase letters, digits and dashes');
  if (path.basename(file, '.js') !== m.id) bad(`file name must match id "${m.id}"`);
  if (typeof m.name !== 'string' || !m.name) bad('name is required');
  if (!TIERS.includes(m.tier)) bad(`tier must be one of ${TIERS.join(', ')}`);
  if (!STATUSES.includes(m.status)) bad(`status must be one of ${STATUSES.join(', ')}`);
  if (m.entitlement != null && typeof m.entitlement !== 'string') bad('entitlement must be a string or null');
  if (m.tier === 'enterprise' && !m.entitlement) bad('enterprise modules must name an entitlement');
  if (m.tier === 'home' && m.entitlement) bad('home modules must not need an entitlement');
  if (!Array.isArray(m.requires) || !m.requires.every((r) => typeof r === 'string')) bad('requires must be an array of module ids');
  if (!Array.isArray(m.permissions) || !m.permissions.every((p) => typeof p === 'string')) bad('permissions must be an array of strings');
  return Object.freeze({ description: '', portal_area: null, ...m });
}

// Checks references and rejects cycles; returns modules in dependency order (requirements first).
function order(list) {
  const byId = new Map(list.map((m) => [m.id, m]));
  for (const m of list) {
    for (const r of m.requires) {
      if (!byId.has(r)) throw new ManifestError(`module "${m.id}" requires unknown module "${r}"`);
      if (byId.get(r).tier === 'enterprise' && m.tier === 'home') throw new ManifestError(`home module "${m.id}" cannot require enterprise module "${r}"`);
    }
  }
  const out = []; const state = new Map();
  const visit = (id, trail) => {
    if (state.get(id) === 2) return;
    if (state.get(id) === 1) throw new ManifestError('dependency cycle: ' + [...trail, id].join(' -> '));
    state.set(id, 1);
    byId.get(id).requires.forEach((r) => visit(r, [...trail, id]));
    state.set(id, 2); out.push(byId.get(id));
  };
  list.forEach((m) => visit(m.id, []));
  return out;
}

function loadDir(dir = path.join(__dirname, 'manifests')) {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.js')).sort();
  const seen = new Set();
  const list = files.map((f) => {
    const m = validate(require(path.join(dir, f)), f);
    if (seen.has(m.id)) throw new ManifestError(`duplicate module id "${m.id}"`);
    seen.add(m.id);
    return m;
  });
  return order(list);
}

module.exports = { loadDir, validate, order, ManifestError, TIERS };
