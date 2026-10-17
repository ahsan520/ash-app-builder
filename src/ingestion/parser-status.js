'use strict';
// What the "Parser pool" page shows: the settings this API replica runs with, the pool's own counters, and how many
// recent events were stored unparsed (parsed._parse_error, see docs/parser-workers.md). Pure shaping plus one store
// read; nothing here writes.
//
// The counters live in the memory of ONE API replica and restart with it. With several replicas, each request is
// answered by whichever replica the load balancer picked, so the numbers are that replica's, not the whole platform's.
// The unparsed count comes from the event store, so it covers every replica.
const xql = require('../search/xql');

const REASONS = ['PARSE_TIMEOUT', 'PARSE_WORKER_CRASH', 'PARSE_FAILED', 'PARSE_QUARANTINED'];
const WINDOWS = { min: 1, def: 24, max: 168 };   // hours

const envInt = (name) => { const n = Number(process.env[name]); return Number.isFinite(n) && n > 0 ? n : null; };

// Settings as the pool reads them (src/ingestion/parser-pool.js): size from ASIX_PARSER_WORKERS, the rest with defaults.
function settings(pool) {
  if (!pool) return { mode: 'inline', workers: 0, timeout_ms: null, queue: null };
  return { mode: 'workers', workers: pool.size, timeout_ms: pool.timeoutMs, queue: pool.maxQueue };
}

// pool: a ParserPool or null (inline). Returns the counters, or null when parsing runs inline (there is nothing to count).
function counters(pool) {
  if (!pool) return null;
  const s = pool.stats();
  const out = {};
  for (const k of ['workers', 'busy', 'queued', 'completed', 'failed', 'timeouts', 'crashes', 'rejected', 'quarantined', 'rules_resent']) out[k] = Number(s[k]) || 0;
  return out;
}

function clampHours(v) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return WINDOWS.def;
  return Math.min(Math.max(n, WINDOWS.min), WINDOWS.max);
}

// Events stored unparsed in the last `hours` hours, by reason, read through the event store (any engine).
// Reasons the code does not know are kept under their own name, so a new reason is never hidden.
async function unparsedCounts(store, tenantId, hours, now = Date.now()) {
  const from = new Date(now - hours * 3600000).toISOString();
  const plan = xql.parse('filter _parse_error != null | comp count() as n by _parse_error', { from });
  const res = await store.search(tenantId, plan);
  const by = {};
  let total = 0;
  for (const r of res.rows || []) {
    const reason = String(r._parse_error ?? 'UNKNOWN');
    const n = Number(r.n) || 0;
    by[reason] = (by[reason] || 0) + n;
    total += n;
  }
  for (const r of REASONS) if (!(r in by)) by[r] = 0;
  return { hours, total, by_reason: by, truncated: !!res.truncated };
}

async function build({ pool, store, tenantId, hours, now }) {
  const h = clampHours(hours);
  const out = { settings: settings(pool), pool: counters(pool), unparsed: null, unparsed_error: null };
  try { out.unparsed = await unparsedCounts(store, tenantId, h, now); }
  catch (e) { out.unparsed_error = 'Could not count unparsed events'; out.unparsed = { hours: h, total: null, by_reason: {}, truncated: false }; console.error('Parser status: unparsed count failed:', e.message); }
  return out;
}

module.exports = { build, settings, counters, unparsedCounts, clampHours, REASONS, WINDOWS };
