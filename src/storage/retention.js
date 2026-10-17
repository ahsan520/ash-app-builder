'use strict';
// Storage & retention for the events table.
//
//  * events is partitioned by DAY on received_at (see k8s/12-schema-init.yaml). This module
//    keeps partitions created ahead of time, so inserts never land in events_default.
//  * Retention is per tenant: a default number of days plus optional per-source-type overrides
//    (NULL = keep forever). Automatic purging is OFF until the tenant switches it on.
//  * Expired data goes two ways:
//      - the event store deletes rows past their own retention (getEventStore().deleteExpired(): batched
//        DELETEs on PostgreSQL, per-source DELETEs on ClickHouse; needed for per-source rules)
//      - DROP of a whole daily partition once it is older than EVERY tenant's longest
//        retention (getEventStore().dropPartitionsBefore(): instant, and the only way disk is returned to the OS
//        immediately; the rule for WHEN it is safe lives here, the dropping is the engine's)
//  * "What would a purge delete" (preview) also asks the event store (expiredCounts()).
//  * The storage summary's events numbers come from the store (storageStats()). Only creating PostgreSQL's daily
//    partitions ahead of time (ensurePartitions) is Postgres-only; it is skipped when ASIX_EVENT_STORE is not postgres.
//  * Everything runs under one advisory lock, so API replicas never purge concurrently.

const db = require('../db');
const { getEventStore } = require('../events');
const { eventsKind, listPartitions } = require('../events/pg-partitions');

const LOCK_KEY = 7412004;
const DEFAULT_DAYS = Math.min(Math.max(parseInt(process.env.RETENTION_DEFAULT_DAYS, 10) || 90, 1), 3650);
const PARTITIONS_AHEAD = 7;
const MAX_RUN_MS = Math.max(30, Number(process.env.RETENTION_MAX_RUN_SECONDS || 600)) * 1000;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

const nextDay = (day) => new Date(Date.parse(day + 'T00:00:00Z') + 86400000).toISOString().slice(0, 10);
const partName = (day) => 'events_p' + day.replace(/-/g, '');

// ---------------------------------------------------------------- creating partitions (PostgreSQL only)
// eventsKind() and listPartitions() live in src/events/pg-partitions.js (the Postgres adapter needs them too).
const usesPostgres = () => getEventStore().name === 'postgres';

// Creates the partition for one day. If rows for that day already sit in events_default the plain
// CREATE fails, so they are moved into a standalone table which is then attached.
async function ensurePartition(day) {
  if (!DAY_RE.test(day)) throw new Error('bad day');
  const name = partName(day), next = nextDay(day);
  const client = await db.pool.connect();
  try {
    try {
      await client.query(`CREATE TABLE IF NOT EXISTS ${name} PARTITION OF events FOR VALUES FROM ('${day}') TO ('${next}')`);
      return 'created';
    } catch (e) {
      if (!/default partition|23514/.test(`${e.code} ${e.message}`)) throw e;
    }
    await client.query('BEGIN');
    try {
      await client.query(`CREATE TABLE ${name} (LIKE events INCLUDING DEFAULTS)`);
      const moved = await client.query(
        `WITH m AS (DELETE FROM events_default WHERE received_at >= $1 AND received_at < $2 RETURNING *)
         INSERT INTO ${name} SELECT * FROM m`, [day, next]);
      await client.query(`ALTER TABLE events ATTACH PARTITION ${name} FOR VALUES FROM ('${day}') TO ('${next}')`);
      await client.query('COMMIT');
      return `created (moved ${moved.rowCount} rows out of the default partition)`;
    } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  } finally { client.release(); }
}

async function ensurePartitions() {
  if (!usesPostgres()) return { partitioned: false, created: [] };
  if ((await eventsKind(db)) !== 'p') return { partitioned: false, created: [] };
  const have = new Set((await listPartitions(db)).map((p) => p.name));
  const days = (await db.query(`SELECT to_char(CURRENT_DATE + g, 'YYYY-MM-DD') AS day FROM generate_series(-1, ${PARTITIONS_AHEAD}) g`)).rows;
  const created = [];
  for (const { day } of days) if (!have.has(partName(day))) { await ensurePartition(day); created.push(partName(day)); }
  return { partitioned: true, created };
}

// ---------------------------------------------------------------- policy
async function loadPolicy(q, tenantId) {
  const s = (await q.query('SELECT auto_purge, default_days FROM retention_settings WHERE tenant_id = $1', [tenantId])).rows[0];
  const p = (await q.query('SELECT source_type, retention_days FROM retention_policies WHERE tenant_id = $1 ORDER BY source_type', [tenantId])).rows;
  return { configured: !!s, auto_purge: !!(s && s.auto_purge), default_days: s ? s.default_days : DEFAULT_DAYS, overrides: p };
}
const minDaysOf = (pol) => Math.min(pol.default_days, ...pol.overrides.filter((o) => o.retention_days !== null).map((o) => o.retention_days));

// Events that are past their retention right now, by source type (read-only). Asked of the event store.
async function preview(tenantId, pol) {
  const rows = await getEventStore().expiredCounts(tenantId, pol);
  return { total: rows.reduce((a, x) => a + x.events, 0), by_source: rows };
}

// ---------------------------------------------------------------- runs log
async function startRun(trigger, tenantId) {
  return (await db.query("INSERT INTO retention_runs (tenant_id, trigger) VALUES ($1, $2) RETURNING id", [tenantId, trigger])).rows[0].id;
}
const finishRun = (id, status, f = {}) => db.query(
  `UPDATE retention_runs SET status = $2, finished_at = localtimestamp, partitions_dropped = $3, rows_deleted = $4, detail = $5::jsonb, error = $6 WHERE id = $1`,
  [id, status, f.partitions_dropped || 0, f.rows_deleted || 0, JSON.stringify(f.detail || {}), f.error ? String(f.error).slice(0, 500) : null]);

// ---------------------------------------------------------------- purge (row level)
// The event store does the deleting (it knows its own tables); this keeps the policy, the time limit and the result shape.
async function purgeTenant(tenantId, { deadline = Date.now() + MAX_RUN_MS } = {}) {
  const pol = await loadPolicy(db, tenantId);
  const r = await getEventStore().deleteExpired(tenantId, pol, { deadline });
  return { rows_deleted: r.deleted, by_source: r.by_source, truncated: r.truncated,
    ...(r.partitions_scanned === undefined ? {} : { partitions_scanned: r.partitions_scanned }) };
}

// ---------------------------------------------------------------- drop whole partitions
// Only when EVERY tenant has automatic purge on and no "keep forever" rule: then a partition
// whose newest possible event is older than the longest retention contains nothing to keep.
async function dropExpiredPartitions() {
  let maxDays = 0;
  for (const t of (await db.query('SELECT id FROM tenants')).rows) {
    const pol = await loadPolicy(db, t.id);
    if (!pol.auto_purge) return { dropped: [], reason: 'a tenant has automatic purge switched off' };
    if (pol.overrides.some((o) => o.retention_days === null)) return { dropped: [], reason: 'a tenant has a keep-forever rule' };
    maxDays = Math.max(maxDays, pol.default_days, ...pol.overrides.map((o) => o.retention_days));
  }
  if (!maxDays) return { dropped: [], reason: 'no tenants' };
  const cutoff = new Date(Date.now() - maxDays * 86400000).toISOString().slice(0, 10);       // UTC day
  const r = await getEventStore().dropPartitionsBefore(cutoff);                              // the engine drops its own partitions
  return { ...r, max_retention_days: maxDays, cutoff };
}

// ---------------------------------------------------------------- runs
async function withLock(fn) {
  const lock = await db.pool.connect();
  try {
    if (!(await lock.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK_KEY])).rows[0].ok) return { busy: true };
    return await fn();
  } finally {
    await lock.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => {});
    lock.release();
  }
}

// A user pressed "Purge now" for their own tenant (works even when automatic purge is off).
async function runManual(tenantId, { dryRun = true } = {}) {
  const pol = await loadPolicy(db, tenantId);
  if (dryRun) return { dry_run: true, policy: pol, ...(await preview(tenantId, pol)) };
  return withLock(async () => {
    const id = await startRun('manual', tenantId);
    try {
      const r = await purgeTenant(tenantId);
      await finishRun(id, r.truncated ? 'partial' : 'completed', { rows_deleted: r.rows_deleted, detail: r });
      return { dry_run: false, run_id: id, ...r };
    } catch (e) { await finishRun(id, 'failed', { error: e.message }); throw e; }
  });
}

async function runScheduled() {
  return withLock(async () => {
    const out = { partitions: await ensurePartitions(), tenants: 0, rows_deleted: 0, dropped: [], errors: 0 };
    for (const t of (await db.query("SELECT id FROM tenants WHERE status = 'active'")).rows) {
      const pol = await loadPolicy(db, t.id);
      if (!pol.auto_purge) continue;
      const id = await startRun('scheduled', t.id);
      try {
        const r = await purgeTenant(t.id);
        await finishRun(id, r.truncated ? 'partial' : 'completed', { rows_deleted: r.rows_deleted, detail: r });
        out.tenants += 1; out.rows_deleted += r.rows_deleted;
      } catch (e) { out.errors += 1; await finishRun(id, 'failed', { error: e.message }); console.error(`[retention] tenant ${t.id}: ${e.message}`); }
    }
    const id = await startRun('scheduled', null);
    try {
      const d = await dropExpiredPartitions();
      out.dropped = d.dropped;
      if (d.failed && d.failed.length) { out.errors += 1; out.failed = d.failed; console.error('[retention] partitions not dropped:', JSON.stringify(d.failed)); }
      if (d.failed && d.failed.length) await finishRun(id, d.dropped.length ? 'partial' : 'failed', { partitions_dropped: d.dropped.length, detail: d, error: `could not drop: ${d.failed.map((f) => f.name).join(', ')}` });
      else if (d.dropped.length) await finishRun(id, 'completed', { partitions_dropped: d.dropped.length, detail: d });
      else await db.query('DELETE FROM retention_runs WHERE id = $1', [id]);          // nothing happened: keep the history quiet
    } catch (e) { out.errors += 1; await finishRun(id, 'failed', { error: e.message }); console.error('[retention] partition drop failed:', e.message); }
    return out;
  });
}

// Events per UTC day for the last `days` days, today last, zero for a day with none (the storage page chart).
async function dailyCounts(tenantId, days) {
  const now = new Date();
  const start = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - (days - 1));
  const rows = await getEventStore().groupCounts(tenantId, { by: 'day', since: new Date(start).toISOString() });
  const byDay = new Map(rows.map((r) => [r.key, r.events]));
  return Array.from({ length: days }, (_, i) => { const day = new Date(start + i * 86400000).toISOString().slice(0, 10); return { day, n: byDay.get(day) || 0 }; });
}

// ---------------------------------------------------------------- storage summary (read-only)
async function summary(tenantId) {
  const stats = await getEventStore().storageStats();                // the events: layout, sizes, rows (any engine)
  const out = { partitioned: stats.partitioned, database_bytes: Number((await db.query('SELECT pg_database_size(current_database()) AS b')).rows[0].b) };
  const range = await getEventStore().timeRange(tenantId);
  out.oldest = range.oldest; out.newest = range.newest;
  out.partitions = stats.partitions;
  out.default_partition_rows = stats.default_partition_rows;
  out.events_bytes = stats.events_bytes;
  out.events_rows = stats.events_rows;
  out.daily = await dailyCounts(tenantId, 14);
  out.tables = (await db.query(                                      // the control-plane database (PostgreSQL), whatever the events engine
    `SELECT CASE WHEN c.relispartition THEN 'events (all partitions)' ELSE c.relname END AS name, SUM(pg_total_relation_size(c.oid))::bigint AS bytes
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT (c.relkind = 'p' AND c.relname = 'events')
     GROUP BY 1 ORDER BY 2 DESC LIMIT 8`)).rows.map((t) => ({ name: t.name, bytes: Number(t.bytes) }));
  return out;
}

// ---------------------------------------------------------------- scheduler
let timer = null;
function start() {
  if (process.env.RETENTION_WORKER_ENABLED === 'false' || timer) return;
  const every = Math.max(5, Number(process.env.RETENTION_INTERVAL_MINUTES || 60)) * 60000;
  const tick = async () => {
    try {
      const r = await runScheduled();
      if (!r.busy && (r.rows_deleted || (r.dropped && r.dropped.length) || (r.partitions && r.partitions.created.length) || r.errors)) console.log('[retention] cycle', JSON.stringify(r));
    } catch (e) { console.error('[retention] cycle failed:', e.message); }
  };
  setTimeout(tick, 15000).unref();
  timer = setInterval(tick, every); timer.unref();
  console.log(`[retention] worker started (every ${every / 60000} min; automatic purge stays off until enabled per tenant)`);
}

module.exports = { start, ensurePartitions, ensurePartition, listPartitions, loadPolicy, preview, purgeTenant, dropExpiredPartitions,
  runManual, runScheduled, summary, DEFAULT_DAYS };
