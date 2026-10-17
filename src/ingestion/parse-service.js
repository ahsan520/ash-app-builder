'use strict';
// What the HTTP ingest lane calls to parse a batch. It picks the path:
//   ASIX_PARSER_WORKERS unset or 0  -> inline, in this process, exactly as before (compiled rules cached 30 s per replica)
//   ASIX_PARSER_WORKERS = N         -> on a pool of worker threads (src/ingestion/parser-pool.js), sending the tenant's
//                                      rule TEXT; each worker compiles it once and keeps it.
// Throws on a pool failure (the error `code` says which); the caller decides what to do with the events.
const rulesStore = require('./rules-store');
const { parseItems } = require('./parse-batch');
const { getParserPool } = require('./parser-pool');

// Failures after which the caller should still STORE the events, unparsed. PARSER_BUSY is not one of them: that is back-pressure.
const STORE_UNPARSED = new Set(['PARSE_TIMEOUT', 'PARSE_WORKER_CRASH', 'PARSE_FAILED', 'PARSE_QUARANTINED']);

async function parseForIngest(tenantId, sourceType, items) {
  const pool = getParserPool();
  if (!pool) {
    const sets = await rulesStore.getActiveSets(tenantId);
    const modelSets = await rulesStore.getModelSets(tenantId);
    return parseItems(sets, modelSets, sourceType, items);
  }
  const src = await rulesStore.getRuleSources(tenantId);
  return pool.parse({ scope: tenantId, rulesKey: src.key, rules: { parsing: src.parsing, model: src.model }, sourceType, items });
}

module.exports = { parseForIngest, STORE_UNPARSED };
