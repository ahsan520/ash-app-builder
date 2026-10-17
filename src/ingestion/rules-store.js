'use strict';
// Loads the active rules for a tenant. Two kinds:
//   parsing -> [user-defined, built-in defaults]   (first matching rule wins)
//   model   -> [built-in defaults, user-defined]   (additive; later assignments override earlier)
// Cached for 30 s per API replica; a save on this replica invalidates immediately.
// getActiveSets / getModelSets give compiled rules (inline parsing); getRuleSources gives the text (parser workers).
const crypto = require('crypto');
const db = require('../db');
const { compile } = require('./parsing-rules');

const TTL_MS = 30000;
const KINDS = {
  parsing: { table: 'parsing_rules', engine: 'ingest', src: require('./default-parsing-rules'), userFirst: true },
  model: { table: 'data_model_rules', engine: 'model', src: require('./default-model-rules'), userFirst: false },
};
for (const k of Object.values(KINDS)) k.compiled = compile(k.src, k.engine);
const cache = new Map();
const srcCache = new Map();

// `which` only ever selects a table name from the fixed map above; it is never user input.
async function loadUser(tenantId, which = 'parsing') {
  const t = KINDS[which].table;
  const r = await db.withTenant(tenantId, (c) => c.query(`SELECT content, version, updated_at, updated_by FROM ${t} WHERE tenant_id = $1`, [tenantId]));
  return r.rows[0] || null;
}

async function saveUser(tenantId, which, content, userId) {
  const t = KINDS[which].table;
  const r = await db.withTenant(tenantId, (c) => c.query(
    `INSERT INTO ${t} (tenant_id, content, version, updated_by) VALUES ($1, $2, 1, $3)
     ON CONFLICT (tenant_id) DO UPDATE SET content = EXCLUDED.content, version = ${t}.version + 1,
       updated_by = EXCLUDED.updated_by, updated_at = CURRENT_TIMESTAMP
     RETURNING version, updated_at`, [tenantId, content, userId || null]));
  invalidate(tenantId);
  return r.rows[0];
}

async function getSets(tenantId, which) {
  const key = which + ':' + tenantId, hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.sets;
  const K = KINDS[which]; let sets = [K.compiled.rules];
  try {
    const row = await loadUser(tenantId, which);
    if (row && row.content.trim()) {
      const user = compile(row.content, K.engine).rules;
      sets = K.userFirst ? [user, K.compiled.rules] : [K.compiled.rules, user];
    }
  } catch (e) {
    // A broken or unreadable user ruleset must never stop ingestion: fall back to defaults.
    console.error(`${which} rules load failed, using defaults:`, e.message);
  }
  cache.set(key, { at: Date.now(), sets });
  return sets;
}

// The tenant's own rule TEXT (empty string = none) and a key that changes whenever either text does. The parser workers
// (src/ingestion/parser-pool.js) compile this themselves, so they are sent text, not compiled rules. Same 30 s cache and
// same invalidation as getSets; an unreadable ruleset reads as empty (built-in rules only), as above.
async function getRuleSources(tenantId) {
  const hit = srcCache.get(tenantId);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.value;
  const read = async (which) => {
    try { const row = await loadUser(tenantId, which); return row && row.content.trim() ? row.content : ''; }
    catch (e) { console.error(`${which} rules load failed, using defaults:`, e.message); return ''; }
  };
  const [parsing, model] = await Promise.all([read('parsing'), read('model')]);
  const key = crypto.createHash('sha256').update(parsing).update('\0').update(model).digest('hex').slice(0, 32);
  const value = { key, parsing, model };
  srcCache.set(tenantId, { at: Date.now(), value });
  return value;
}

const getActiveSets = (tenantId) => getSets(tenantId, 'parsing');
const getModelSets = (tenantId) => getSets(tenantId, 'model');
const invalidate = (tenantId) => { for (const w of Object.keys(KINDS)) cache.delete(w + ':' + tenantId); srcCache.delete(tenantId); };

module.exports = {
  getActiveSets, getModelSets, getRuleSources, invalidate, loadUser, saveUser,
  DEFAULT_SRC: KINDS.parsing.src, DEFAULT_INFO: KINDS.parsing.compiled.info, DEFAULT_RULES: KINDS.parsing.compiled.rules,
  DEFAULT_MODEL_SRC: KINDS.model.src, DEFAULT_MODEL_INFO: KINDS.model.compiled.info, DEFAULT_MODEL_RULES: KINDS.model.compiled.rules,
};
