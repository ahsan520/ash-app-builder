'use strict';
// Capacity & scaling: gathers VM metrics, database/event growth, cluster state and application
// health, stores a sample every few minutes (for trends) and hands everything to the
// recommendation engine. Read-only: it never changes the cluster.

const db = require('../db');
const hostMetrics = require('./host-metrics');
const kube = require('./kube');
const storage = require('../storage/retention');
const { evaluate } = require('./recommendations');

const LOCK_KEY = 7412005;
const KEEP_DAYS = 30;
const p95 = (arr) => { const a = arr.filter((x) => x != null && !Number.isNaN(x)).sort((x, y) => x - y); return a.length ? a[Math.min(a.length - 1, Math.ceil(0.95 * a.length) - 1)] : null; };

async function dbStats() {
  const r = (await db.query(
    `SELECT (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database())::int AS connections,
            current_setting('max_connections')::int AS max_connections,
            (SELECT CASE WHEN blks_hit + blks_read = 0 THEN NULL ELSE blks_hit::float8 / (blks_hit + blks_read) END FROM pg_stat_database WHERE datname = current_database()) AS cache_hit,
            pg_database_size(current_database())::bigint AS bytes`)).rows[0];
  return { connections: r.connections, max_connections: r.max_connections, cache_hit: r.cache_hit === null ? null : Number(r.cache_hit), bytes: Number(r.bytes) };
}

// retention_days is only set when automatic purge is on AND every rule is bounded (otherwise data is unbounded)
async function eventsInfo(tenantId) {
  const partitioned = (await db.query("SELECT relkind::text AS k FROM pg_class WHERE oid = 'public.events'::regclass")).rows[0].k === 'p';
  const partitions = partitioned ? await storage.listPartitions(db) : [];
  const bytes = partitioned ? partitions.reduce((a, p) => a + p.bytes, 0) : Number((await db.query("SELECT pg_total_relation_size('public.events') AS b")).rows[0].b);
  let auto_purge = false, retention_days = null;
  if (tenantId) {
    const pol = await storage.loadPolicy(db, tenantId);
    auto_purge = pol.auto_purge;
    if (pol.auto_purge && !pol.overrides.some((o) => o.retention_days === null)) retention_days = Math.max(pol.default_days, ...pol.overrides.map((o) => o.retention_days));
  }
  return { partitioned, partitions, bytes, auto_purge, retention_days };
}

async function ingestPerMin() {
  let n = 0;
  for (const t of (await db.query("SELECT id FROM tenants WHERE status = 'active'")).rows) {
    n += Number((await db.query("SELECT COUNT(*)::bigint AS n FROM events WHERE tenant_id = $1 AND received_at > localtimestamp - interval '5 minutes'", [t.id])).rows[0].n);
  }
  return Math.round((n / 5) * 10) / 10;
}

async function appHealth() {
  const d = (await db.query(
    `SELECT COUNT(*) FILTER (WHERE enabled AND COALESCE(last_run_at, created_at) <
              localtimestamp - make_interval(mins => GREATEST(10, 5 * COALESCE(CASE WHEN definition->>'run_every_minutes' ~ '^[0-9]+$' THEN (definition->>'run_every_minutes')::int END, 1))))::int AS behind,
            COUNT(*) FILTER (WHERE enabled AND last_error IS NOT NULL)::int AS errors
     FROM detection_rules`)).rows[0];
  const ioc = (await db.query(
    `SELECT EXTRACT(EPOCH FROM (localtimestamp - s.last_run_at)) / 60 AS lag FROM ioc_scan_state s
     WHERE EXISTS (SELECT 1 FROM threat_indicators i WHERE i.enabled) ORDER BY s.last_run_at DESC NULLS LAST LIMIT 1`)).rows[0];
  const n = (await db.query("SELECT COUNT(*)::int AS n FROM notification_deliveries WHERE status = 'pending' AND next_attempt_at < localtimestamp - interval '10 minutes'")).rows[0].n;
  return { detection: { rules_behind: d.behind, rules_with_errors: d.errors, ioc_lag_minutes: ioc && ioc.lag != null ? Number(ioc.lag) : null }, notifications: { overdue: n } };
}

async function collectLive({ cpuSampleMs = 500, tenantId = null } = {}) {
  const [host, dbs, events, health, ingest, k8s] = await Promise.all([
    hostMetrics.collect({ cpuSampleMs }), dbStats(), eventsInfo(tenantId), appHealth(), ingestPerMin(), kube.snapshot().catch((e) => ({ available: false, error: e.message }))]);
  return { host, db: dbs, events, ...health, ingest_per_min: ingest, k8s };
}

async function history(hours) {
  const rows = (await db.query(
    `SELECT sampled_at, cpu_pct, load1, events_per_min, db_bytes::bigint AS db_bytes,
            100 * (1 - mem_available_bytes::float8 / NULLIF(mem_total_bytes, 0)) AS mem_used_pct,
            100 * (1 - disk_free_bytes::float8 / NULLIF(disk_total_bytes, 0)) AS disk_used_pct
     FROM capacity_samples WHERE sampled_at > localtimestamp - ($1::int * interval '1 hour') ORDER BY sampled_at`, [hours])).rows
    .map((r) => ({ t: r.sampled_at, cpu: r.cpu_pct == null ? null : Number(r.cpu_pct), mem: r.mem_used_pct == null ? null : Math.round(r.mem_used_pct * 10) / 10, disk: r.disk_used_pct == null ? null : Math.round(r.disk_used_pct * 10) / 10,
      load1: r.load1 == null ? null : Number(r.load1), events_per_min: r.events_per_min == null ? null : Number(r.events_per_min), db_bytes: Number(r.db_bytes) }));
  const span = rows.length > 1 ? (new Date(rows.at(-1).t) - new Date(rows[0].t)) / 3600000 : 0;
  const stride = Math.max(1, Math.ceil(rows.length / 240));
  return { samples: rows.length, hours: Math.max(1, Math.round(span)), cpu_p95: p95(rows.map((r) => r.cpu)), mem_p95: p95(rows.map((r) => r.mem)), series: rows.filter((_, i) => i % stride === 0 || i === rows.length - 1) };
}

async function sampleOnce() {
  const l = await collectLive({ cpuSampleMs: 1000 });
  const k = l.k8s.available ? l.k8s : null;
  await db.query(
    `INSERT INTO capacity_samples (cpu_pct, load1, cpu_count, mem_total_bytes, mem_available_bytes, swap_used_bytes, disk_total_bytes, disk_free_bytes, db_bytes, events_bytes, events_per_min,
                                   pg_connections, pg_max_connections, cache_hit_ratio, pods_total, pods_not_ready, restarts_total, oom_kills_24h)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
    [l.host.cpu_pct, l.host.load1, l.host.cpu_count, l.host.mem.total, l.host.mem.available, l.host.mem.swap_used, l.host.disk.total, l.host.disk.free, l.db.bytes, l.events.bytes, l.ingest_per_min,
      l.db.connections, l.db.max_connections, l.db.cache_hit, k ? k.pods.length : null, k ? k.pods.filter((p) => !p.ready).length : null, k ? k.pods.reduce((a, p) => a + p.restarts, 0) : null, k ? k.pods.reduce((a, p) => a + p.oom_killed_24h, 0) : null]);
  await db.query("DELETE FROM capacity_samples WHERE sampled_at < localtimestamp - ($1::int * interval '1 day')", [KEEP_DAYS]);
}

async function report(tenantId, hours = 24) {
  const [live, hist] = await Promise.all([collectLive({ cpuSampleMs: 500, tenantId }), history(hours)]);
  const result = evaluate({ now: Date.now(), host: live.host, history: hist, events: live.events, db: live.db, k8s: live.k8s, detection: live.detection, notifications: live.notifications });
  const { partitions, ...events } = live.events;
  return { generated_at: new Date().toISOString(), host: live.host, db: live.db, events: { ...events, partitions_count: partitions.filter((p) => !p.is_default).length, ingest_per_min: live.ingest_per_min },
    k8s: live.k8s, history: { hours: hist.hours, samples: hist.samples, series: hist.series }, ...result };
}

let timer = null;
function start() {
  if (process.env.CAPACITY_SAMPLER_ENABLED === 'false' || timer) return;
  const every = Math.max(1, Number(process.env.CAPACITY_SAMPLE_MINUTES || 5)) * 60000;
  const tick = async () => {
    const lock = await db.pool.connect();
    try {
      if (!(await lock.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK_KEY])).rows[0].ok) return;
      await sampleOnce();
    } catch (e) { console.error('[capacity] sample failed:', e.message); }
    finally { await lock.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => {}); lock.release(); }
  };
  setTimeout(tick, 30000).unref();
  timer = setInterval(tick, every); timer.unref();
  console.log(`[capacity] sampler started (every ${every / 60000} min, ${KEEP_DAYS} days of history)`);
}

module.exports = { start, report, sampleOnce, collectLive, history, p95 };
