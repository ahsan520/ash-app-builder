'use strict';
// Storage & retention for the events table.
//
//  * events is partitioned by DAY on received_at (see k8s/12-schema-init.yaml). This module
//    keeps partitions created ahead of time, so inserts never land in events_default.
//  * Retention is per tenant: a default number of days plus optional per-source-type overrides
//    (NULL = keep forever). Automatic purging is OFF until the tenant switches it on.
//  * Expired data goes two ways:
//      - batched DELETEs of rows past their own retention (needed for per-source rules)
//      - DROP of a whole daily partition once it is older than EVERY tenant's longest
//        retention (instant, and the only way disk is returned to the OS immediately)
//  * Everything runs under one advisory lock, so API replicas never purge concurrently.

const db = require('../db');

const LOCK_KEY = 7412004;
const DEFAULT_DAYS = Math.min(Math.max(parseInt(process.env.RETENTION_DEFAULT_DAYS, 10) || 90, 1), 3650);
const PARTITIONS_AHEAD = 7;
const BATCH = 10000;
const MAX_RUN_MS = Math.max(30, Number(process.env.RETENTION_MAX_RUN_SECONDS || 600)) * 1000;
const PART_RE = /^events_p\d{8}$/;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

const nextDay = (day) => new Date(Date.parse(day + 'T00:00:00Z') + 86400000).toISOString().slice(0, 10);
const partName = (day) => 'events_p' + day.replace(/-/g, '');

// ---------------------------------------------------------------- partitions
async function eventsKind(q) {
  return (await q.query("SELECT c.relkind::text AS k FROM pg_class c WHERE c.oid = 'public.events'::regclass")).rows[0].k;
}

async function listPartitions(q) {
  const r = await q.query(
    `SELECT c.relname AS name, pg_get_expr(c.relpartbound, c.oid) AS bound, pg_total_relation_size(c.oid)::bigint AS bytes,
            pg_relation_size(c.oid)::bigint AS heap_bytes, c.reltuples::bigint AS est_rows
     FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
     WHERE i.inhparent = 'public.events'::regclass ORDER BY c.relname`);
  return r.rows.map((p) => {
    const m = /FROM \('(\d{4}-\d{2}-\d{2})[^']*'\) TO \('(\d{4}-\d{2}-\d{2})/.exec(p.bound || '');
    return { name: p.name, bytes: Number(p.bytes), heap_bytes: Number(p.heap_bytes), est_rows: Number(p.est_rows),
      is_default: p.bound === 'DEFAULT', from: m ? m[1] : null, to: m ? m[2] : null };
  });
}

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

// Events that are past their retention right now, by source type (read-only).
async function preview(q, tenantId, pol) {
  const r = await q.query(
    `SELECT e.source_type, COUNT(*)::bigint AS events, MIN(e.received_at) AS oldest
     FROM events e
     LEFT JOIN unnest($2::text[], $3::int[]) AS pol(source_type, days) ON pol.source_type = e.source_type
     WHERE e.tenant_id = $1
       AND e.received_at < localtimestamp - ($5::int * interval '1 day')              -- lets Postgres prune partitions
       AND (CASE WHEN pol.source_type IS NULL THEN $4::int ELSE pol.days END) IS NOT NULL
       AND e.received_at < localtimestamp - ((CASE WHEN pol.source_type IS NULL THEN $4::int ELSE pol.days END) * interval '1 day')
     GROUP BY e.source_type ORDER BY events DESC`,
    [tenantId, pol.overrides.map((o) => o.source_type), pol.overrides.map((o) => o.retention_days), pol.default_days, minDaysOf(pol)]);
  const rows = r.rows.map((x) => ({ source_type: x.source_type, events: Number(x.events), oldest: x.oldest }));
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
async function purgeTenant(tenantId, { deadline = Date.now() + MAX_RUN_MS } = {}) {
  const pol = await loadPolicy(db, tenantId), minDays = minDaysOf(pol);
  const partitioned = (await eventsKind(db)) === 'p';
  // A partition can hold expired rows if its first day is on or before the day of the shortest cutoff.
  const cutoffDay = (await db.query("SELECT to_char(localtimestamp - ($1::int * interval '1 day'), 'YYYY-MM-DD') AS d", [minDays])).rows[0].d;
  const targets = partitioned
    ? (await listPartitions(db)).filter((p) => p.is_default || (p.from && p.from <= cutoffDay)).map((p) => p.name)
    : ['events'];
  const overrides = pol.overrides.map((o) => o.source_type);
  const rules = [
    ...pol.overrides.filter((o) => o.retention_days !== null).map((o) => ({ label: o.source_type, cond: 'source_type = $2::text', value: o.source_type, days: o.retention_days })),
    { label: '(default)', cond: 'source_type <> ALL($2::text[])', value: overrides, days: pol.default_days },
  ];
  const deleted = {}; let total = 0, truncated = false;
  outer: for (const part of targets.sort()) {
    if (part !== 'events' && !PART_RE.test(part) && part !== 'events_default') continue;
    for (const rule of rules) {
      for (;;) {
        if (Date.now() > deadline) { truncated = true; break outer; }
        const gone = await db.withTenant(tenantId, async (client) => {
          await client.query("SET LOCAL statement_timeout = '60s'");
          return (await client.query(
            `DELETE FROM ${part} WHERE ctid = ANY(ARRAY(
               SELECT ctid FROM ${part} WHERE tenant_id = $1 AND ${rule.cond} AND received_at < localtimestamp - ($3::int * interval '1 day') LIMIT ${BATCH}))
             RETURNING source_type`, [tenantId, rule.value, rule.days])).rows;
        });
        total += gone.length;
        for (const g of gone) deleted[g.source_type] = (deleted[g.source_type] || 0) + 1;
        if (gone.length < BATCH) break;
      }
    }
  }
  return { rows_deleted: total, by_source: deleted, truncated, partitions_scanned: targets.length };
}

// ---------------------------------------------------------------- drop whole partitions
// Only when EVERY tenant has automatic purge on and no "keep forever" rule: then a partition
// whose newest possible event is older than the longest retention contains nothing to keep.
async function dropExpiredPartitions() {
  if ((await eventsKind(db)) !== 'p') return { dropped: [], reason: 'events table is not partitioned' };
  let maxDays = 0;
  for (const t of (await db.query('SELECT id FROM tenants')).rows) {
    const pol = await loadPolicy(db, t.id);
    if (!pol.auto_purge) return { dropped: [], reason: 'a tenant has automatic purge switched off' };
    if (pol.overrides.some((o) => o.retention_days === null)) return { dropped: [], reason: 'a tenant has a keep-forever rule' };
    maxDays = Math.max(maxDays, pol.default_days, ...pol.overrides.map((o) => o.retention_days));
  }
  if (!maxDays) return { dropped: [], reason: 'no tenants' };
  const cutoff = (await db.query("SELECT to_char(localtimestamp - ($1::int * interval '1 day'), 'YYYY-MM-DD') AS d", [maxDays])).rows[0].d;
  const dropped = [];
  for (const p of await listPartitions(db)) {
    if (p.is_default || !p.to || !PART_RE.test(p.name) || p.to > cutoff) continue;
    await db.query(`DROP TABLE ${p.name}`);
    dropped.push(p.name);
  }
  return { dropped, max_retention_days: maxDays, cutoff };
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
  if (dryRun) return { dry_run: true, policy: pol, ...(await preview(db, tenantId, pol)) };
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
      if (d.dropped.length) await finishRun(id, 'completed', { partitions_dropped: d.dropped.length, detail: d });
      else await db.query('DELETE FROM retention_runs WHERE id = $1', [id]);          // nothing happened: keep the history quiet
    } catch (e) { out.errors += 1; await finishRun(id, 'failed', { error: e.message }); console.error('[retention] partition drop failed:', e.message); }
    return out;
  });
}

// ---------------------------------------------------------------- storage summary (read-only)
async function summary(tenantId) {
  const kind = await eventsKind(db);
  const partitions = kind === 'p' ? await listPartitions(db) : [];
  const out = { partitioned: kind === 'p', database_bytes: Number((await db.query('SELECT pg_database_size(current_database()) AS b')).rows[0].b) };
  const range = (await db.query('SELECT MIN(received_at) AS oldest, MAX(received_at) AS newest FROM events WHERE tenant_id = $1', [tenantId])).rows[0];
  out.oldest = range.oldest; out.newest = range.newest;
  const rows = [];
  for (const p of partitions) {                                     // estimates are -1/0 until autovacuum has analysed a new partition
    let n = p.est_rows;
    if ((n <= 0) && p.heap_bytes < 256 * 1048576) n = Number((await db.query(`SELECT COUNT(*)::bigint AS n FROM ${p.name}`)).rows[0].n);
    rows.push({ ...p, rows: Math.max(n, 0) });
  }
  out.partitions = rows.filter((p) => !p.is_default).sort((a, b) => (a.from < b.from ? 1 : -1));
  const def = rows.find((p) => p.is_default); out.default_partition_rows = def ? def.rows : 0;
  out.events_bytes = rows.reduce((a, p) => a + p.bytes, 0);
  if (kind !== 'p') {
    out.events_bytes = Number((await db.query("SELECT pg_total_relation_size('public.events') AS b")).rows[0].b);
    out.events_rows = Number((await db.query('SELECT COUNT(*)::bigint AS n FROM events')).rows[0].n);
  } else out.events_rows = rows.reduce((a, p) => a + p.rows, 0);
  out.daily = (await db.query(
    `SELECT to_char(d.day, 'YYYY-MM-DD') AS day, COALESCE(c.n, 0)::int AS n
     FROM (SELECT CURRENT_DATE - g AS day FROM generate_series(13, 0, -1) g) d
     LEFT JOIN (SELECT received_at::date AS day, COUNT(*) AS n FROM events
                WHERE tenant_id = $1 AND received_at >= CURRENT_DATE - 13 GROUP BY 1) c ON c.day = d.day
     ORDER BY d.day`, [tenantId])).rows;
  out.tables = (await db.query(
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
