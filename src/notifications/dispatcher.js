'use strict';
// Notification dispatcher. Independent of whoever raises alerts (rule runner, IOC matcher, ...):
//   1. enqueue  - every NEW alert that matches an enabled channel (severity, rule filter) gets one
//                 row in notification_deliveries (UNIQUE per channel+alert, so never duplicated)
//   2. deliver  - due rows are claimed, sent outside any DB transaction, then marked sent / retried
// Retries: 1 min, 5 min, 15 min, 1 h, then the delivery is marked failed (retry button in the portal).

const db = require('../db');
const box = require('./secret-box');
const { buildMessage, sendToChannel } = require('./senders');

const LOCK_KEY = 7412003;
const MAX_ATTEMPTS = 5;
const BACKOFF_SECONDS = [60, 300, 900, 3600];
const BATCH = 50;
const CONCURRENCY = 5;
const rank = (col) => `CASE ${col} WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END`;

async function enqueue(tenantId) {
  return db.withTenant(tenantId, async (client) => (await client.query(
    `INSERT INTO notification_deliveries (tenant_id, channel_id, alert_id)
     SELECT c.tenant_id, c.id, a.id
     FROM notification_channels c
     JOIN alerts a ON a.tenant_id = c.tenant_id
     WHERE c.tenant_id = $1 AND c.enabled
       AND a.created_at >= c.created_at                       -- never back-fill history when a channel is added
       AND a.created_at > localtimestamp - interval '1 day'
       AND a.status IN ('open', 'acknowledged')
       AND ${rank('a.severity')} >= ${rank('c.min_severity')}
       AND (c.rule_filter IS NULL OR a.rule_name ILIKE '%' || c.rule_filter || '%')
     ON CONFLICT (channel_id, alert_id) DO NOTHING
     RETURNING id`, [tenantId])).rowCount);
}

async function claim(tenantId) {
  return db.withTenant(tenantId, async (client) => (await client.query(
    `WITH due AS (
       SELECT id FROM notification_deliveries
       WHERE tenant_id = $1 AND status = 'pending' AND next_attempt_at <= localtimestamp
       ORDER BY next_attempt_at LIMIT ${BATCH} FOR UPDATE SKIP LOCKED)
     UPDATE notification_deliveries d
        SET attempts = d.attempts + 1, next_attempt_at = localtimestamp + interval '2 minutes'   -- lease: a crash mid-send is retried later
       FROM due WHERE d.id = due.id
     RETURNING d.id, d.channel_id, d.alert_id, d.attempts`, [tenantId])).rows);
}

async function load(tenantId, d) {
  return db.withTenant(tenantId, async (client) => {
    const ch = (await client.query('SELECT type, enabled, config_enc FROM notification_channels WHERE id = $1', [d.channel_id])).rows[0];
    const al = (await client.query('SELECT * FROM alerts WHERE id = $1', [d.alert_id])).rows[0];
    const tn = (await client.query('SELECT name FROM tenants WHERE id = $1', [tenantId])).rows[0];
    return { ch, al, tenantName: tn && tn.name };
  });
}

const finish = (tenantId, id, sql, args) => db.withTenant(tenantId, (client) => client.query(sql, [id, ...args]));

async function deliverOne(tenantId, d, deps) {
  try {
    const { ch, al, tenantName } = await load(tenantId, d);
    if (!ch || !al || !ch.enabled) return finish(tenantId, d.id, "UPDATE notification_deliveries SET status = 'skipped', last_error = $2 WHERE id = $1", [ch ? 'channel disabled' : 'channel or alert removed']);
    const message = buildMessage(al, { tenantName, baseUrl: process.env.ASIX_PUBLIC_URL });
    await (deps.send || sendToChannel)(ch.type, box.decrypt(ch.config_enc), message, deps.sendDeps);
    return finish(tenantId, d.id, "UPDATE notification_deliveries SET status = 'sent', sent_at = localtimestamp, last_error = NULL WHERE id = $1", []);
  } catch (err) {
    const msg = String(err && err.message || err).slice(0, 300);
    if (d.attempts >= MAX_ATTEMPTS) return finish(tenantId, d.id, "UPDATE notification_deliveries SET status = 'failed', last_error = $2 WHERE id = $1", [msg]);
    const wait = BACKOFF_SECONDS[Math.min(d.attempts - 1, BACKOFF_SECONDS.length - 1)];
    return finish(tenantId, d.id, 'UPDATE notification_deliveries SET last_error = $2, next_attempt_at = localtimestamp + ($3 * interval \'1 second\') WHERE id = $1', [msg, wait]);
  }
}

async function runTenant(tenantId, deps = {}) {
  const queued = await enqueue(tenantId);
  const due = await claim(tenantId);
  for (let i = 0; i < due.length; i += CONCURRENCY) await Promise.all(due.slice(i, i + CONCURRENCY).map((d) => deliverOne(tenantId, d, deps)));
  return { queued, attempted: due.length };
}

async function runOnce(deps = {}) {
  const lock = await db.pool.connect();
  try {
    if (!(await lock.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK_KEY])).rows[0].ok) return { skipped: true };
    const total = { tenants: 0, queued: 0, attempted: 0, errors: 0 };
    for (const t of (await lock.query("SELECT id FROM tenants WHERE status = 'active'")).rows) {
      try { const r = await runTenant(t.id, deps); total.tenants += 1; total.queued += r.queued; total.attempted += r.attempted; }
      catch (e) { total.errors += 1; console.error(`[notify] tenant ${t.id} failed: ${e.message}`); }
    }
    return total;
  } finally {
    await lock.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => {});
    lock.release();
  }
}

let timer = null, running = false;
function start() {
  if (process.env.NOTIFY_DISPATCHER_ENABLED === 'false' || timer) return;
  if (!box.configured()) console.warn('[notify] NOTIFY_ENCRYPTION_KEY not set - notification channels cannot be saved or delivered');
  const every = Math.max(10, Number(process.env.NOTIFY_INTERVAL_SECONDS || 30)) * 1000;
  const tick = async () => {
    if (running || !box.configured()) return;
    running = true;
    try { const r = await runOnce(); if (r.queued || r.attempted || r.errors) console.log('[notify] cycle', JSON.stringify(r)); }
    catch (e) { console.error('[notify] cycle failed:', e.message); }
    finally { running = false; }
  };
  setTimeout(tick, 20000).unref();
  timer = setInterval(tick, every); timer.unref();
  console.log(`[notify] dispatcher started (every ${every / 1000}s)`);
}

module.exports = { start, runOnce, runTenant, MAX_ATTEMPTS };
