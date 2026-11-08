'use strict';
// Loads and validates module manifests (src/modules/manifests/*.js). Modules register themselves by
// dropping a manifest file in that folder; nothing is hard-coded in the gateway or portal menu.
const fs = require('fs');
const path = require('path');

const TIERS = ['home', 'enterprise'];
const STATUSES = ['available', 'planned'];
const ID_RE = /^[a-z][a-z0-9-]{1,40}$/;
// Portal page entries (the optional `ui` block, docs/portal-shell.md).
const UI_KINDS = ['builtin', 'native', 'embedded'];
const ENTRY_ID_RE = /^[a-z][a-z0-9-]{0,40}$/;
const PAGE_RE = /^[a-z0-9][a-z0-9-]*\.js$/;          // a file name only: no path separators, no dots to climb out of the folder
const BUILTIN_PATH_RE = /^[a-z][a-z0-9/-]{0,60}$/;   // a menu path that index.html already knows, e.g. 'settings/retention'
const PROXY_ENV_RE = /^ASIX_[A-Z0-9_]{1,60}$/;
const DEFAULT_PORTAL_DIR = path.join(__dirname, '..', 'portal', 'modules');

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
  const out = { description: '', portal_area: null, ...m };
  if (m.ui !== undefined) out.ui = validateUi(m, bad);
  if (m.proxy !== undefined && !(m.ui && m.ui.kind === 'embedded')) bad('proxy is only for a module whose ui.kind is "embedded"');
  return Object.freeze(out);
}

// The optional `ui` block: which portal pages the module brings and how the portal loads them.
// Returns a normalised copy (defaults filled in, menu path computed). `bad` throws a ManifestError.
function validateUi(m, bad) {
  const ui = m.ui;
  if (!ui || typeof ui !== 'object' || Array.isArray(ui)) bad('ui must be an object');
  if (!UI_KINDS.includes(ui.kind)) bad(`ui.kind must be one of ${UI_KINDS.join(', ')}`);
  if (!Array.isArray(ui.entries) || ui.entries.length === 0) bad('ui.entries must be a non-empty array');
  if (ui.kind === 'embedded') {
    const px = m.proxy;
    if (!px || typeof px !== 'object' || !PROXY_ENV_RE.test(px.env || '')) bad('an embedded module must declare proxy: { env: "ASIX_<NAME>_URL" } (the environment variable that holds the tool\'s in-cluster address)');
  }
  const seen = new Set();
  const entries = ui.entries.map((e, i) => {
    const at = `ui.entries[${i}]`;
    if (!e || typeof e !== 'object' || Array.isArray(e)) bad(`${at} must be an object`);
    if (!ENTRY_ID_RE.test(e.id || '')) bad(`${at}.id must be lowercase letters, digits and dashes`);
    if (seen.has(e.id)) bad(`${at}.id "${e.id}" is used twice in this module`);
    seen.add(e.id);
    if (typeof e.label !== 'string' || !e.label.trim() || e.label.length > 60) bad(`${at}.label is required (1 to 60 characters)`);
    if (typeof e.area !== 'string' || !e.area.trim() || e.area.length > 40) bad(`${at}.area is required (1 to 40 characters)`);
    if (e.group != null && (typeof e.group !== 'string' || !e.group.trim() || e.group.length > 40)) bad(`${at}.group must be a string of 1 to 40 characters`);
    if (e.order != null && !(Number.isInteger(e.order) && e.order >= 0 && e.order <= 9999)) bad(`${at}.order must be a whole number from 0 to 9999`);
    if (e.permission != null && (typeof e.permission !== 'string' || !m.permissions.includes(e.permission))) bad(`${at}.permission must be one of this module's own permissions`);
    const base = { id: e.id, label: e.label.trim(), area: e.area.trim(), group: e.group ? e.group.trim() : null, permission: e.permission || null, order: e.order == null ? 100 : e.order };
    if (ui.kind === 'native') {
      if (typeof e.page !== 'string' || !PAGE_RE.test(e.page)) bad(`${at}.page must be a file name such as "marketplace.js" (no folders)`);
      if (e.url != null || e.path != null) bad(`${at}: a native entry takes "page" only`);
      return { ...base, path: `mod/${m.id}/${e.id}`, page: e.page };
    }
    if (ui.kind === 'embedded') {
      if (typeof e.url !== 'string' || !e.url.startsWith(`/app/${m.id}/`) || /\.\.|[\s?#\\]/.test(e.url)) bad(`${at}.url must start with /app/${m.id}/ and have no "..", spaces, "?" or "#"`);
      if (e.page != null || e.path != null) bad(`${at}: an embedded entry takes "url" only`);
      return { ...base, path: `mod/${m.id}/${e.id}`, url: e.url };
    }
    if (typeof e.path !== 'string' || !BUILTIN_PATH_RE.test(e.path)) bad(`${at}.path must be the menu path of a page that is still in index.html (for example "settings/retention")`);
    if (e.page != null || e.url != null) bad(`${at}: a builtin entry takes "path" only`);
    return { ...base, path: e.path };
  });
  return Object.freeze({ kind: ui.kind, entries: Object.freeze(entries.map((x) => Object.freeze(x))) });
}

// Cross-module checks on the portal entries: a native page file must exist; a builtin menu path may only be claimed once.
function checkUi(list, portalDir = DEFAULT_PORTAL_DIR) {
  const claimed = new Map();
  for (const m of list) {
    if (!m.ui) continue;
    for (const e of m.ui.entries) {
      if (m.ui.kind === 'native' && !fs.existsSync(path.join(portalDir, m.id, e.page))) {
        throw new ManifestError(`${m.id}.js: ui entry "${e.id}" names page "${e.page}" but src/portal/modules/${m.id}/${e.page} does not exist`);
      }
      if (m.ui.kind === 'builtin') {
        if (claimed.has(e.path)) throw new ManifestError(`${m.id}.js: menu path "${e.path}" is already used by module "${claimed.get(e.path)}"`);
        claimed.set(e.path, m.id);
      }
    }
  }
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

function loadDir(dir = path.join(__dirname, 'manifests'), opts = {}) {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.js')).sort();
  const seen = new Set();
  const list = files.map((f) => {
    const m = validate(require(path.join(dir, f)), f);
    if (seen.has(m.id)) throw new ManifestError(`duplicate module id "${m.id}"`);
    seen.add(m.id);
    return m;
  });
  checkUi(list, opts.portalDir || DEFAULT_PORTAL_DIR);
  return order(list);
}

module.exports = { loadDir, validate, order, checkUi, ManifestError, TIERS, UI_KINDS };
