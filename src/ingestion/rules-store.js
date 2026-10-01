'use strict';
// Loads the active parsing rules for a tenant: [user-defined, built-in defaults].
// Cached for 30 s per API replica; a save on this replica invalidates immediately.
const db = require('../db');
const { compile } = require('./parsing-rules');
const DEFAULT_SRC = require('./default-parsing-rules');

const TTL_MS = 30000;
const DEFAULT = compile(DEFAULT_SRC);
const cache = new Map();

async function loadUser(tenantId) {
  const r = await db.withTenant(tenantId, (c) => c.query('SELECT content, version, updated_at, updated_by FROM parsing_rules WHERE tenant_id = $1', [tenantId]));
  return r.rows[0] || null;
}

async function getActiveSets(tenantId) {
  const hit = cache.get(tenantId);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.sets;
  let sets = [DEFAULT.rules];
  try {
    const row = await loadUser(tenantId);
    if (row && row.content.trim()) sets = [compile(row.content).rules, DEFAULT.rules];
  } catch (e) {
    // A broken or unreadable user ruleset must never stop ingestion: fall back to defaults.
    console.error('Parsing rules load failed, using defaults:', e.message);
  }
  cache.set(tenantId, { at: Date.now(), sets });
  return sets;
}

const invalidate = (tenantId) => cache.delete(tenantId);

module.exports = { getActiveSets, invalidate, loadUser, DEFAULT_SRC, DEFAULT_INFO: DEFAULT.info, DEFAULT_RULES: DEFAULT.rules };
