'use strict';
// Parse-failure alert: raises ONE alert per tenant when events are being stored unparsed (parsed._parse_error, see docs/parser-workers.md)
// faster than you allow, and closes it when the rate drops back. Until now the only way to notice was opening Settings, Parser pool.
//
// Off until chosen, with two environment settings on the API (k8s/30-asix-api.yaml), the same style as the watchdog's:
//   ASIX_PARSE_ALERT_MIN_EVENTS    0 or unset = off. N (1 to 1000000) = alert when at least N events were stored unparsed in the window.
//   ASIX_PARSE_ALERT_WINDOW_MIN    5 to 1440, default 15: the look-back window in minutes.
// A tenant can override both from the portal (Settings, Parser pool): a row in parse_alert_settings wins over the environment for that
// tenant (min_events 0 = off for that tenant); no row = the environment, as before (src/ingestion/parse-alert.js).
// It runs inside the collector watchdog cycle (every 60 s, one replica at a time, same start-up grace, same ASIX_WATCHDOG_SEVERITY, same
// notification channels), and reads the count through the event store, so it works on PostgreSQL and ClickHouse. The only schema is the
// optional parse_alert_settings table: if it is missing (schema job not yet run) the environment settings are used.
//
// The window is measured on WHEN ASIX RECEIVED the event (_insert_time), not on the event's own time stamp: a syslog line carries the sender's local
// time without a zone, so an event can say it happened hours ago while it was stored a second ago, and a window on that time never sees a burst of
// failures. XQL cannot filter on _insert_time, so the newest-received events with a parse error are read (the limit, at least 100, at most 5000) and
// counted in the window here; the query is bounded on event time by the window plus LOOKBACK_EXTRA_H hours, which covers every time zone behind UTC
// (an event whose own time is further back is not seen). Past the limit the exact count does not matter, so a big burst is reported as "at least".
// A limit above 5000 cannot be read this way and keeps counting by event time (unparsedCounts), as before.
// The events themselves are never lost: an unparsed event is stored raw. The alert says how many, why (by reason) and where to look.
// One alert at a time: it stays while the count stays at or above the limit, closes (with an "ASIX" note) when it drops below, or when the alert is
// turned off. If an analyst closes it by hand while the count is still above the limit it is not raised again for 60 minutes (COOLDOWN_MIN);
// an alert that ASIX closed itself can be raised again at once. plan() is pure; runTenant() reads, calls plan() and writes.

const db = require('../db');
const { getEventStore } = require('../events');
const { unparsedCounts, REASONS } = require('./parser-status');
const xql = require('../search/xql');
const { tsMs } = require('../collectors/status');
const { severity } = require('../collectors/watchdog');
const parseAlert = require('./parse-alert');

const RULE_NAME = 'Events stored unparsed';
const GROUP_KEY = 'parser:unparsed';
const COOLDOWN_MIN = 60;
const { MAX_EVENTS, MIN_WINDOW, MAX_WINDOW, DEFAULT_WINDOW } = parseAlert.LIMITS;
const LOOKBACK_EXTRA_H = 12;   // see the note at the top
const MIN_READ = 100;          // rows read at least, so the reasons in the alert are a fair sample

function config(env = process.env) {
  const n = Number(env.ASIX_PARSE_ALERT_MIN_EVENTS);
  const w = Number(env.ASIX_PARSE_ALERT_WINDOW_MIN);
  return {
    threshold: Number.isInteger(n) && n >= 1 && n <= MAX_EVENTS ? n : 0,
    windowMin: Number.isInteger(w) && w >= MIN_WINDOW && w <= MAX_WINDOW ? w : DEFAULT_WINDOW,
  };
}

// total/byReason: unparsed events in the window; active: open or acknowledged alerts of this rule { id };
// latest: newest alert of this rule { status, closed_by, age_s } or null (age_s = seconds since it was last updated)
function plan({ total, byReason, active, latest }, cfg, { raiseAllowed = true } = {}) {
  const raise = [], close = [];
  if (!cfg.threshold) {
    for (const a of active) close.push({ alert_id: a.id, reason: 'The unparsed-events alert is turned off.' });
    return { raise, close };
  }
  const over = Number.isFinite(total) && total >= cfg.threshold;
  if (over && !active.length && raiseAllowed) {
    const byHand = latest && latest.status === 'closed' && latest.closed_by !== 'asix';
    const cooling = byHand && Number(latest.age_s) < COOLDOWN_MIN * 60;
    if (!cooling) raise.push({ total, window_min: cfg.windowMin, threshold: cfg.threshold, by_reason: byReason || {} });
  }
  if (!over) for (const a of active) close.push({ alert_id: a.id, reason: 'The number of unparsed events is back below the limit.' });
  return { raise, close };
}

function raiseText(r) {
  const parts = Object.entries(r.by_reason).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k}: ${n}`);
  return {
    title: `${RULE_NAME}: ${r.total} in ${r.window_min} minutes`,
    summary: `${r.total} events were stored unparsed in the last ${r.window_min} minutes (limit ${r.threshold})${parts.length ? ', ' + parts.join(', ') : ''}. They are kept raw, not lost. Open Settings, Parser pool, or search "filter _parse_error != null"; a time limit or crash means a parsing rule is too slow or the workers are short of memory (see docs/parser-workers.md).`,
  };
}

// The limit this tenant runs with: its own row from the portal, else the environment. A database without the table (schema job not run) gets the
// environment settings and one log line per process; any other read failure throws, and the watchdog logs it and tries again next cycle.
let warnedMissing = false;
async function tenantConfig(tenantId, env = process.env) {
  const server = config(env);
  let row = null;
  try { row = await db.withTenant(tenantId, (client) => parseAlert.readRow(client, tenantId)); }
  catch (e) {
    if (!parseAlert.isMissingTable(e)) throw e;
    if (!warnedMissing) { warnedMissing = true; console.warn('[parse-watch] table parse_alert_settings is missing (the schema job has not run): using the server settings'); }
  }
  return parseAlert.resolve(row, server);
}

// Unparsed events RECEIVED in the last `cfg.windowMin` minutes: { total, by_reason, at_least }. Newest received first; when every row read is inside the
// window the real count may be higher (at_least), which only matters for the number shown, since the limit is already reached.
async function countRecent(store, tenantId, cfg, now = Date.now()) {
  if (cfg.threshold > xql.MAX_LIMIT) return { ...(await unparsedCounts(store, tenantId, cfg.windowMin / 60, now)), at_least: false };
  const n = Math.min(Math.max(cfg.threshold, MIN_READ), xql.MAX_LIMIT);
  const from = new Date(now - (cfg.windowMin * 60000 + LOOKBACK_EXTRA_H * 3600000)).toISOString();
  const plan = xql.parse(`filter _parse_error != null | fields _insert_time, _parse_error | sort desc _insert_time | limit ${n}`, { from, limit: n });
  const rows = (await store.search(tenantId, plan)).rows || [];
  const since = now - cfg.windowMin * 60000;
  const by = {}; let total = 0;
  for (const r of rows) {
    const t = typeof r._insert_time === 'string' && !/Z$|[+-]\d\d:?\d\d$/.test(r._insert_time) ? tsMs(r._insert_time) : Date.parse(r._insert_time);   // "2026-10-19 22:44:27" is UTC, as everywhere in ASIX
    if (!(t >= since)) continue;
    const reason = String(r._parse_error ?? 'UNKNOWN');
    by[reason] = (by[reason] || 0) + 1; total += 1;
  }
  for (const k of REASONS) if (!(k in by)) by[k] = 0;
  return { total, by_reason: by, at_least: rows.length >= n && total === rows.length };
}

async function runTenant(tenantId, { now = Date.now(), raiseAllowed = true, sev = severity(), cfg, store = getEventStore() } = {}) {
  if (!cfg) cfg = await tenantConfig(tenantId);
  let counts = { total: 0, by_reason: {} };
  if (cfg.threshold) counts = await countRecent(store, tenantId, cfg, now);   // a count that fails throws: the watchdog logs it and tries again next cycle
  return db.withTenant(tenantId, async (client) => {
    const active = (await client.query(
      "SELECT id FROM alerts WHERE tenant_id = $1 AND rule_name = $2 AND status IN ('open','acknowledged')", [tenantId, RULE_NAME])).rows;
    const latest = (await client.query(
      `SELECT status, details->>'closed_by' AS closed_by, EXTRACT(EPOCH FROM (localtimestamp - updated_at)) AS age_s
         FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at DESC, id LIMIT 1`, [tenantId, RULE_NAME])).rows[0] || null;
    const p = plan({ total: counts.total, byReason: counts.by_reason, active, latest }, cfg, { raiseAllowed });
    for (const r of p.raise) {
      const t = raiseText(r);
      await client.query(
        `INSERT INTO alerts (tenant_id, rule_id, rule_name, severity, title, summary, group_key, event_count, first_event_at, last_event_at, details)
         VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, localtimestamp, localtimestamp, $8::jsonb)`,
        [tenantId, RULE_NAME, sev, t.title, t.summary, GROUP_KEY, r.total, JSON.stringify({ total: r.total, window_min: r.window_min, threshold: r.threshold, by_reason: r.by_reason })]);
    }
    for (const c of p.close) {
      await client.query(
        `UPDATE alerts SET status = 'closed', updated_at = localtimestamp, details = COALESCE(details, '{}'::jsonb) || '{"closed_by":"asix"}'::jsonb WHERE id = $1 AND tenant_id = $2`, [c.alert_id, tenantId]);
      await client.query("INSERT INTO alert_notes (tenant_id, alert_id, author_id, author_name, body) VALUES ($1, $2, NULL, 'ASIX', $3)", [tenantId, c.alert_id, c.reason]);
    }
    return { raised: p.raise.length, closed: p.close.length };
  });
}

module.exports = { RULE_NAME, GROUP_KEY, COOLDOWN_MIN, config, tenantConfig, plan, raiseText, countRecent, runTenant };
