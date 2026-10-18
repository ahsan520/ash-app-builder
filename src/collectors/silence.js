'use strict';
// Silent-collector watch: raises an alert when a collector you chose to watch is still alive (its heartbeat keeps arriving)
// but no EVENTS have come from it for a while, and closes the alert when events flow again.
//
// Why it exists: the heartbeat (src/ingest/heartbeat.js) keeps an idle broker or the built-in syslog collector Connected, so the
// "Collector disconnected" alert (src/collectors/watchdog.js) cannot see a device that quietly stopped sending behind a healthy
// broker. This one looks at the newest event instead.
//
// Opt-in per collector (collectors.watch_silent_min = minutes of silence before the alert, NULL = off), so deploying this changes
// nothing by itself. The alert goes through the notification channels that already exist (nothing was added there).
//
// plan() is pure (no database, no clock of its own) and holds every rule; runTenant() reads the rows and the event store, calls
// plan() and writes what it says. One alert per silence: a collector that stays silent keeps its one alert; if an analyst closes it
// while the collector is still silent, no new alert is raised for that same silence (the alert remembers the newest event it was
// raised for); the next silence raises a new one.

const db = require('../db');
const { getEventStore } = require('../events');
const { statusOf, tsMs } = require('./status');
const { severity } = require('./watchdog');

const RULE_NAME = 'Collector sending no events';
const MIN_MINUTES = 5;
const MAX_MINUTES = 3 * 24 * 60;                  // 3 days; the event look-back below is 7 days, so a silence this long is still visible
const LOOKBACK_MS = 7 * 24 * 3600 * 1000;
const keyOf = (id) => `silent:${id}`;
const isoOf = (v) => { const ms = tsMs(v); return Number.isFinite(ms) ? new Date(ms).toISOString() : null; };

// Request value -> { value } (whole minutes, or null = off) or { error }.
function checkMinutes(v) {
  if (v === null || v === undefined) return { value: null };
  if (typeof v !== 'number' || !Number.isInteger(v) || v < MIN_MINUTES || v > MAX_MINUTES) {
    return { error: `minutes must be a whole number from ${MIN_MINUTES} to ${MAX_MINUTES}, or null to turn the watch off` };
  }
  return { value: v };
}

// collectors: watched collectors { id, name, last_seen, connected_within_min, watch_silent_min }
// newestEvent: Map of collector name -> time of its newest event in the look-back window (a collector with none is missing)
// active:     open or acknowledged alerts of this rule { id, group_key }
// latest:     the newest alert of this rule per group_key { group_key, status, last_event } (last_event = what it was raised for)
// opts:       { now, raiseAllowed }  raiseAllowed=false (start-up grace) still closes alerts but raises none
function plan({ collectors, newestEvent, active, latest }, { now = Date.now(), raiseAllowed = true } = {}) {
  const silent = new Map(), flowing = new Set();
  for (const c of collectors) {
    const last = isoOf(newestEvent.get(c.name));
    if (!last) continue;                                    // no event in the window: nothing to measure the silence from
    const limit = Number(c.watch_silent_min) * 60000;
    if (!(limit > 0)) continue;
    if (now - tsMs(last) > limit) silent.set(keyOf(c.id), { c, last }); else flowing.add(keyOf(c.id));
  }
  const known = new Set(collectors.map((c) => keyOf(c.id)));
  const newest = new Map(latest.map((a) => [a.group_key, a]));
  const raise = [], close = [];
  if (raiseAllowed) {
    for (const [key, { c, last }] of silent) {
      // A collector that is itself Disconnected is the other alert's business ("Collector disconnected"); this one is for the
      // gap where the collector looks alive but nothing arrives.
      if (statusOf(c.last_seen, c.connected_within_min, now) !== 'connected') continue;
      const prev = newest.get(key);
      if (prev && (prev.status !== 'closed' || prev.last_event === last)) continue;   // still active, or the same silence was closed by hand
      raise.push({ collector_id: c.id, name: c.name, group_key: key, last_event: last,
        minutes: Math.max(0, Math.round((now - tsMs(last)) / 60000)), threshold: Number(c.watch_silent_min) });
    }
  }
  for (const a of active) {
    if (silent.has(a.group_key)) continue;
    if (flowing.has(a.group_key)) { close.push({ alert_id: a.id, reason: 'Events are arriving from the collector again.' }); continue; }
    if (!known.has(a.group_key)) close.push({ alert_id: a.id, reason: 'The collector is no longer watched for silence or was removed from the list.' });
    // watched, but no event at all in the look-back window: still silent, the alert stays
  }
  return { raise, close };
}

const raiseText = (r) => ({
  title: `${RULE_NAME}: ${r.name}`,
  summary: `${r.name} is still reporting in, but no events have come from it for ${r.minutes} minutes (you asked to be told after ${r.threshold}). A device or source behind it may have stopped sending.`,
});

// deps.store lets a test hand in an event store; the real one is used otherwise.
async function runTenant(tenantId, { now = Date.now(), raiseAllowed = true, sev = severity(), store = null } = {}) {
  return db.withTenant(tenantId, async (client) => {
    await client.query("SET LOCAL statement_timeout = '15s'");
    const collectors = (await client.query(
      'SELECT id, name, last_seen, connected_within_min, watch_silent_min FROM collectors WHERE tenant_id = $1 AND watch_silent_min IS NOT NULL', [tenantId])).rows;
    const active = (await client.query(
      "SELECT id, group_key FROM alerts WHERE tenant_id = $1 AND rule_name = $2 AND status IN ('open','acknowledged')", [tenantId, RULE_NAME])).rows;
    if (!collectors.length && !active.length) return { raised: 0, closed: 0 };      // nothing watched, nothing to close: skip the event store
    const latest = (await client.query(
      `SELECT DISTINCT ON (group_key) group_key, status, details->>'last_event' AS last_event
         FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY group_key, created_at DESC, id`, [tenantId, RULE_NAME])).rows;
    const groups = await (store || getEventStore()).groupCounts(tenantId, { by: 'collector_id', since: new Date(now - LOOKBACK_MS).toISOString() });
    const newestEvent = new Map(groups.map((g) => [g.key, g.last_seen]));
    const p = plan({ collectors, newestEvent, active, latest }, { now, raiseAllowed });
    for (const r of p.raise) {
      const t = raiseText(r);
      await client.query(
        `INSERT INTO alerts (tenant_id, rule_id, rule_name, severity, title, summary, group_key, event_count, first_event_at, last_event_at, details)
         VALUES ($1, NULL, $2, $3, $4, $5, $6, 0, $7, $7, $8::jsonb)`,
        [tenantId, RULE_NAME, sev, t.title, t.summary, r.group_key, r.last_event,
          JSON.stringify({ collector_id: r.collector_id, collector: r.name, last_event: r.last_event, silent_after_min: r.threshold })]);
    }
    for (const c of p.close) {
      await client.query("UPDATE alerts SET status = 'closed', updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2", [c.alert_id, tenantId]);
      await client.query("INSERT INTO alert_notes (tenant_id, alert_id, author_id, author_name, body) VALUES ($1, $2, NULL, 'ASIX', $3)", [tenantId, c.alert_id, c.reason]);
    }
    return { raised: p.raise.length, closed: p.close.length };
  });
}

module.exports = { RULE_NAME, MIN_MINUTES, MAX_MINUTES, LOOKBACK_MS, keyOf, checkMinutes, plan, raiseText, runTenant };
