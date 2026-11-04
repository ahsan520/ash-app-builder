'use strict';
// E6k: a daily summary of the tenant's vulnerability findings, kept as ONE event a day in the event store (source type `vuln-summary`).
// Why: the indexer behind the Vulnerabilities tab holds the CURRENT state only (a fixed package takes its findings away), so the tab cannot say
// whether things are getting better or worse. One small event per tenant per UTC day gives a trend (GET /v1/endpoints/vulnerabilities/trend, the
// Trend card) and something the rules can watch (built-in rule "New critical vulnerabilities on endpoints"). The events live in ClickHouse or
// PostgreSQL like every other event, follow the tenant's retention and are searchable with XQL: dataset = "vuln-summary".
//
// Runs inside the collector watchdog cycle (one replica at a time). Per tenant and cycle it does nothing unless ALL of these hold: a central indexer is
// registered for the tenant, the UTC hour is at or after ASIX_VULN_SUMMARY_HOUR (default 3), and no summary exists yet for today's UTC day. Then it reads the
// indexer twice (totals by severity; findings first detected since the previous summary) and writes the event. A failure changes nothing, is logged once
// until it changes, and is retried at most every RETRY_MIN minutes. ASIX_VULN_SUMMARY=false turns it off.
//
// "New" means first DETECTED by the manager since the previous summary (vulnerability.detected_at), not "the count went up": a fixed package and a new one
// in the same day still show as new. Known limit: when a manager re-creates its findings index (or the index was pruned, E6j) every finding gets a new
// detection time and one day shows a large "new" figure.
// plan() and buildEvent() are pure; runTenant() reads, calls them and writes.

const crypto = require('crypto');
const db = require('../db');
const { getEventStore } = require('../events');
const indexer = require('./wazuh-indexer');
const indexerStore = require('./wazuh-indexer-store');

const SOURCE_TYPE = 'vuln-summary';
const COLLECTOR_ID = 'asix-findings-summary';
const DAY_MS = 86400000;
const RETRY_MIN = 15;
const SINCE_MIN_MS = 3600000, SINCE_MAX_MS = 8 * DAY_MS;   // the "new since" window is the time since the previous summary, kept between 1 hour and 8 days
const SEVS = ['critical', 'high', 'medium', 'low', 'unknown'];

function config(env = process.env) {
  const h = env.ASIX_VULN_SUMMARY_HOUR === undefined || env.ASIX_VULN_SUMMARY_HOUR === '' ? 3 : Number(env.ASIX_VULN_SUMMARY_HOUR);
  return { enabled: String(env.ASIX_VULN_SUMMARY || 'true').toLowerCase() !== 'false', hour: Number.isInteger(h) && h >= 0 && h <= 23 ? h : 3 };
}
const dayOf = (ms) => new Date(ms).toISOString().slice(0, 10);

// have: the day of the newest summary already stored (or null); cfg from config(). Returns { record, reason }.
function plan({ registered, haveDay }, cfg, now = Date.now()) {
  if (!cfg.enabled) return { record: false, reason: 'off' };
  if (!registered) return { record: false, reason: 'no indexer' };
  if (new Date(now).getUTCHours() < cfg.hour) return { record: false, reason: 'too early' };
  if (haveDay === dayOf(now)) return { record: false, reason: 'done today' };
  return { record: true, reason: 'due' };
}

// The window for "new since": from the previous summary's time, kept inside the limits.
function sinceFor(prevAtMs, now = Date.now()) {
  const from = Number.isFinite(prevAtMs) ? prevAtMs : now - DAY_MS;
  return new Date(Math.min(Math.max(from, now - SINCE_MAX_MS), now - SINCE_MIN_MS)).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

const n0 = (v) => (Number.isInteger(v) && v >= 0 ? v : 0);
// One event. `summary` = indexer.summary() result, `fresh` = indexer.detectedSince() result, `prev` = parsed fields of the previous summary or null.
function buildEvent(tenantId, summary, fresh, prev, since, now = Date.now()) {
  const day = dayOf(now), sv = summary.severity || {};
  const p = {
    summary_day: day, findings_total: n0(summary.total), machines: n0(summary.machines), distinct_cves: n0(summary.distinct_cves),
    critical: n0(sv.critical), high: n0(sv.high), medium: n0(sv.medium), low: n0(sv.low), unknown: n0(sv.unknown),
    new_total: n0(fresh.total), new_critical: n0(fresh.critical), new_high: n0(fresh.high), new_medium: n0(fresh.medium), new_low: n0(fresh.low),
    new_since: since,
  };
  if (prev && Number.isFinite(Number(prev.findings_total))) {
    p.total_change = p.findings_total - Number(prev.findings_total);
    p.critical_change = p.critical - n0(Number(prev.critical));
  }
  const raw = `Vulnerability findings ${day}: ${p.findings_total} on ${p.machines} machine${p.machines === 1 ? '' : 's'} (critical ${p.critical}, high ${p.high}, medium ${p.medium}, low ${p.low}); `
    + `first detected since ${since}: ${p.new_total} (critical ${p.new_critical}, high ${p.new_high})`;
  // The id is fixed per tenant and day (the day check in runTenant is what stops a second summary; the fixed id is a second guard on a store that sees the same received_at).
  const id = crypto.createHash('sha256').update(`vuln-summary:${tenantId}:${day}`).digest('hex');
  const uuid = `${id.slice(0, 8)}-${id.slice(8, 12)}-5${id.slice(13, 16)}-a${id.slice(17, 20)}-${id.slice(20, 32)}`;
  return { id: uuid, tenant_id: tenantId, source_type: SOURCE_TYPE, collector_id: COLLECTOR_ID, received_at: new Date(now).toISOString(), event_time: new Date(now).toISOString(), raw, parsed: p };
}

const lastProblem = new Map(), nextTry = new Map();
function noteProblem(tenantId, text) {
  if (lastProblem.get(tenantId) === text) return;
  lastProblem.set(tenantId, text);
  console.warn(`[findings-summary] tenant ${tenantId}: ${text}; nothing written, will try again`);
}

// The summaries already stored, newest first (at most the last 9 days).
async function recent(tenantId, now, store) {
  const list = await store.listEvents(tenantId, { source_type: SOURCE_TYPE, from: new Date(now - 9 * DAY_MS).toISOString(), limit: 20 });
  return list.filter((e) => e && e.parsed && typeof e.parsed.summary_day === 'string');
}

async function runTenant(tenantId, { now = Date.now(), raiseAllowed = true, cfg = config(), store = getEventStore(), idx = indexer, registry = indexerStore } = {}) {
  if (!cfg.enabled || !raiseAllowed) return { raised: 0, closed: 0, recorded: 0 };
  if (new Date(now).getUTCHours() < cfg.hour) return { raised: 0, closed: 0, recorded: 0 };
  if ((nextTry.get(tenantId) || 0) > now) return { raised: 0, closed: 0, recorded: 0 };
  let row = null;
  try { row = await db.withTenant(tenantId, (client) => registry.readRow(client, tenantId)); }
  catch (e) { if (registry.isMissingTable(e)) return { raised: 0, closed: 0, recorded: 0 }; throw e; }
  const events = row ? await recent(tenantId, now, store) : [];
  const haveDay = events.length ? events[0].parsed.summary_day : null;
  if (!plan({ registered: !!row, haveDay }, cfg, now).record) return { raised: 0, closed: 0, recorded: 0 };
  try {
    const m = registry.credentials(row);
    const prevEv = events.find((e) => e.parsed.summary_day !== dayOf(now)) || null;
    const since = sinceFor(prevEv ? Date.parse(prevEv.event_time || prevEv.received_at) : NaN, now);
    const summary = await idx.summary(m, {});
    const fresh = await idx.detectedSince(m, since);
    await store.insertBatch(tenantId, [buildEvent(tenantId, summary, fresh, prevEv && prevEv.parsed, since, now)]);
    lastProblem.delete(tenantId); nextTry.delete(tenantId);
    return { raised: 0, closed: 0, recorded: 1 };
  } catch (e) {
    nextTry.set(tenantId, now + RETRY_MIN * 60000);
    noteProblem(tenantId, e && e.code === 'NO_KEY' ? 'NOTIFY_ENCRYPTION_KEY is not configured' : (e && e.message) || 'the indexer could not be read');
    return { raised: 0, closed: 0, recorded: 0 };
  }
}

module.exports = { SOURCE_TYPE, COLLECTOR_ID, RETRY_MIN, SEVS, config, dayOf, plan, sinceFor, buildEvent, recent, runTenant };
