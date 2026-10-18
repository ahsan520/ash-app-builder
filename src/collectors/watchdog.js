'use strict';
// Collector watchdog: raises an alert when a collector you chose to watch goes Disconnected, and closes it when the
// collector is back (or is no longer watched, or was deleted). Notifications need nothing new: they already follow
// new alerts (src/notifications/dispatcher.js), so a channel whose minimum severity allows it sends the message.
//
// Opt-in per collector (collectors.watch_disconnect, default false), so deploying this changes nothing by itself.
// "Disconnected" is exactly what the Collectors page shows: src/collectors/status.js, the collector's own threshold.
//
// plan() is pure (no database, no clock of its own) and holds every rule; run*() only read the rows, call plan() and
// write what it says. One alert per outage: a collector that stays down keeps one alert; if an analyst closes it while
// the collector is still down, no new alert is raised for that same outage (the alert remembers the last_seen it was
// raised for); the next outage raises a new one.

const db = require('../db');
const { statusOf, effectiveMinutes, tsMs } = require('./status');

const RULE_NAME = 'Collector disconnected';
const LOCK_KEY = 7412004;
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const keyOf = (id) => `collector:${id}`;
const isoOf = (v) => { const ms = tsMs(v); return Number.isFinite(ms) ? new Date(ms).toISOString() : null; };

function severity(env = process.env) {
  const s = String(env.ASIX_WATCHDOG_SEVERITY || '').toLowerCase();
  return SEVERITIES.includes(s) ? s : 'high';   // 'high': the default minimum severity of a notification channel
}

// collectors: watched collectors { id, name, last_seen, connected_within_min }
// active:     open or acknowledged alerts of this rule { id, group_key }
// latest:     the newest alert of this rule per group_key { group_key, status, last_seen } (last_seen = what it was raised for)
// opts:       { now, raiseAllowed }  raiseAllowed=false (start-up grace) still closes alerts but raises none
function plan({ collectors, active, latest }, { now = Date.now(), raiseAllowed = true } = {}) {
  const down = new Map();
  for (const c of collectors) {
    const seen = isoOf(c.last_seen);
    if (!seen) continue;                                   // never seen: nothing to be "disconnected from"
    if (statusOf(c.last_seen, c.connected_within_min, now) === 'disconnected') down.set(keyOf(c.id), { c, seen });
  }
  const known = new Map(collectors.map((c) => [keyOf(c.id), c]));
  const newest = new Map(latest.map((a) => [a.group_key, a]));
  const raise = [], close = [];
  if (raiseAllowed) {
    for (const [key, { c, seen }] of down) {
      const prev = newest.get(key);
      if (prev && (prev.status !== 'closed' || prev.last_seen === seen)) continue;   // still active, or the same outage was closed by hand
      const minutes = Math.max(0, Math.round((now - tsMs(c.last_seen)) / 60000));
      raise.push({ collector_id: c.id, name: c.name, group_key: key, last_seen: seen, minutes, threshold: effectiveMinutes(c.connected_within_min) });
    }
  }
  for (const a of active) {
    if (down.has(a.group_key)) continue;
    close.push({ alert_id: a.id, reason: known.has(a.group_key)
      ? 'The collector is connected again.'
      : 'The collector is no longer watched or was removed from the list.' });
  }
  return { raise, close };
}

const raiseText = (r) => ({
  title: `${RULE_NAME}: ${r.name}`,
  summary: `${r.name} has sent nothing for ${r.minutes} minutes (it counts as Connected within ${r.threshold}). Events from it are not arriving.`,
});

async function runTenant(tenantId, { now = Date.now(), raiseAllowed = true, sev = severity() } = {}) {
  return db.withTenant(tenantId, async (client) => {
    await client.query("SET LOCAL statement_timeout = '15s'");
    const collectors = (await client.query(
      'SELECT id, name, last_seen, connected_within_min FROM collectors WHERE tenant_id = $1 AND watch_disconnect', [tenantId])).rows;
    const active = (await client.query(
      "SELECT id, group_key FROM alerts WHERE tenant_id = $1 AND rule_name = $2 AND status IN ('open','acknowledged')", [tenantId, RULE_NAME])).rows;
    const latest = (await client.query(
      `SELECT DISTINCT ON (group_key) group_key, status, details->>'last_seen' AS last_seen
         FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY group_key, created_at DESC, id`, [tenantId, RULE_NAME])).rows;
    const p = plan({ collectors, active, latest }, { now, raiseAllowed });
    for (const r of p.raise) {
      const t = raiseText(r);
      await client.query(
        `INSERT INTO alerts (tenant_id, rule_id, rule_name, severity, title, summary, group_key, event_count, first_event_at, last_event_at, details)
         VALUES ($1, NULL, $2, $3, $4, $5, $6, 0, $7, $7, $8::jsonb)`,
        [tenantId, RULE_NAME, sev, t.title, t.summary, r.group_key, r.last_seen,
          JSON.stringify({ collector_id: r.collector_id, collector: r.name, last_seen: r.last_seen, connected_within_min: r.threshold })]);
    }
    for (const c of p.close) {
      await client.query("UPDATE alerts SET status = 'closed', updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2", [c.alert_id, tenantId]);
      await client.query("INSERT INTO alert_notes (tenant_id, alert_id, author_id, author_name, body) VALUES ($1, $2, NULL, 'ASIX', $3)", [tenantId, c.alert_id, c.reason]);
    }
    return { raised: p.raise.length, closed: p.close.length };
  });
}

async function runOnce(opts = {}) {
  const lock = await db.pool.connect();
  try {
    if (!(await lock.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK_KEY])).rows[0].ok) return { skipped: true };
    const total = { tenants: 0, raised: 0, closed: 0, errors: 0 };
    const silence = require('./silence');        // required here, not at the top: silence.js reads severity() from this file
    for (const t of (await lock.query("SELECT id FROM tenants WHERE status = 'active'")).rows) {
      try { const r = await runTenant(t.id, opts); total.tenants += 1; total.raised += r.raised; total.closed += r.closed; }
      catch (e) { total.errors += 1; console.error(`[watchdog] tenant ${t.id} failed: ${e.message}`); }
      // Silent collectors (events stopped, heartbeat alive). Separate, so a failing event store never stops the disconnect alerts above.
      try { const r = await silence.runTenant(t.id, opts); total.raised += r.raised; total.closed += r.closed; }
      catch (e) { total.errors += 1; console.error(`[watchdog] silence check for tenant ${t.id} failed: ${e.message}`); }
    }
    return total;
  } finally {
    await lock.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => {});
    lock.release();
  }
}

let timer = null, running = false;
function start(env = process.env) {
  if (env.ASIX_WATCHDOG_ENABLED === 'false' || timer) return;
  const every = Math.max(15, Number(env.ASIX_WATCHDOG_INTERVAL_SECONDS || 60)) * 1000;
  // Right after the API (re)starts, collectors could not report while it was down: no new alerts for a few minutes.
  const graceMs = Math.max(0, Number(env.ASIX_WATCHDOG_GRACE_SECONDS === undefined ? 300 : env.ASIX_WATCHDOG_GRACE_SECONDS)) * 1000;
  const graceUntil = Date.now() + graceMs;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      const r = await runOnce({ raiseAllowed: Date.now() >= graceUntil });
      if (r.raised || r.closed || r.errors) console.log('[watchdog] cycle', JSON.stringify(r));
    } catch (e) { console.error('[watchdog] cycle failed:', e.message); }
    finally { running = false; }
  };
  setTimeout(tick, 45000).unref();
  timer = setInterval(tick, every); timer.unref();
  console.log(`[watchdog] started (every ${every / 1000}s, no new alerts for the first ${graceMs / 1000}s)`);
}

module.exports = { RULE_NAME, keyOf, severity, plan, raiseText, runTenant, runOnce, start };
