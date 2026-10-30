'use strict';
// E4l: alert when an enrolled endpoint agent has been Disconnected for too long, and close the alert when the agent is back.
// The case it came from (2026-10-30): a Windows 11 machine slept after 10 minutes of power saving, the manager showed its agent as Pending and then
// Disconnected, and nothing in ASIX said so. Collectors and brokers already have this (src/collectors/watchdog.js); endpoint agents did not.
//
// Off until chosen: ASIX_AGENT_WATCH_MIN on the API (k8s/30-asix-api.yaml), 0 or unset = off, otherwise 5 to 10080 minutes. E4m: a tenant can choose its own limit
// (and machines that are never watched) on the Endpoints page; that wins over the environment for the tenant (src/endpoints/agent-alert.js). An agent counts as down when the
// manager reports it Disconnected AND its last keep-alive is at least that old. Choose a value longer than a sleeping laptop is away if sleeping is normal.
// Agents the manager calls Pending (just enrolled, or between handshakes) or Never connected raise nothing.
//
// It runs inside the collector watchdog cycle (every 60 s, one replica at a time, the same start-up grace, the same ASIX_WATCHDOG_SEVERITY and the same
// notification channels, so Resolved messages work for it too). It reads the manager through the E4c client (wazuh-api.js): GET only, the registered
// manager only, nothing the tenant can aim anywhere else. One alert per agent (group key `endpointagent:<id>`), titled with the machine's name.
//
// SAFETY RULES, each tested:
//   - a manager that cannot be reached, answers badly or has no usable password changes NOTHING: alerts are never closed because ASIX cannot see (an outage of
//     the manager must not look like "all agents are back"), and the problem is logged once until it changes;
//   - an alert an analyst closed by hand is not raised again for the same outage (the same last keep-alive), only for a new one (an alert ASIX closed itself,
//     because the check was turned off or the manager unregistered, is raised again if the agent is still down);
//   - at most MAX_RAISE new alerts per cycle, oldest outage first, so a manager restart or a network cut that shows 400 agents as down cannot flood the alert list
//     (the rest follow on the next cycles; the cap is per cycle, not per tenant, and is a flood guard, not a limit on coverage);
//   - an open alert is closed only on evidence: the agent is listed as not Disconnected, or the manager no longer has it, or no manager is registered, or the
//     check is turned off. An agent that is Disconnected but beyond the pages read keeps its alert.
// plan() is pure; runTenant() reads, calls plan() and writes.

const db = require('../db');
const wazuhApi = require('./wazuh-api');
const agentAlert = require('./agent-alert');
const managerStore = require('./wazuh-manager-store');
const { severity } = require('../collectors/watchdog');

const RULE_NAME = 'Endpoint agent disconnected';
const KEY_PREFIX = 'endpointagent:';
const MIN_MINUTES = 5, MAX_MINUTES = 10080;
const MAX_RAISE = 25;     // new alerts per tenant per cycle
const PAGE = 500, MAX_PAGES = 4;   // up to 2,000 disconnected agents are read per cycle

const keyOf = (id) => KEY_PREFIX + id;
const idOf = (key) => (typeof key === 'string' && key.startsWith(KEY_PREFIX) ? key.slice(KEY_PREFIX.length) : null);

function config(env = process.env) {
  const n = Number(env.ASIX_AGENT_WATCH_MIN);
  return { minutes: Number.isInteger(n) && n >= MIN_MINUTES && n <= MAX_MINUTES ? n : 0 };
}

// The manager writes times as ISO text ("2026-10-30T05:52:23Z"); anything else is "unknown" and never raises.
function ageMin(lastKeepAlive, now) {
  const t = typeof lastKeepAlive === 'string' ? Date.parse(lastKeepAlive) : NaN;
  return Number.isFinite(t) ? Math.max(0, Math.floor((now - t) / 60000)) : null;
}

// disconnected: shaped agents the manager lists as Disconnected (wazuh-api.js shapeAgent); active: open or acknowledged alerts { id, group_key };
// latest: newest alert per group key { group_key, status, closed_by, last_keep_alive }; lookups: for open alerts whose agent is not in `disconnected`,
// { [agent id]: shaped agent | null } (null = the manager has no such agent).
// skip: agent ids the tenant chose not to watch (E4m): they raise nothing and an open alert of one is closed.
function plan({ disconnected = [], active = [], latest = [], lookups = {}, registered = true }, cfg, { now = Date.now(), raiseAllowed = true, skip = [] } = {}) {
  const raise = [], close = [];
  if (!cfg.minutes) {
    for (const a of active) close.push({ alert_id: a.id, reason: 'The endpoint agent disconnected alert is turned off.' });
    return { raise, close };
  }
  if (!registered) {
    for (const a of active) close.push({ alert_id: a.id, reason: 'No endpoint manager is registered for this tenant any more.' });
    return { raise, close };
  }
  const skipped = new Set(skip.map(String));
  const down = new Map();
  for (const a of disconnected) if (a && a.id) down.set(a.id, a);
  const activeKeys = new Set(active.map((a) => a.group_key));
  const newest = new Map(latest.map((a) => [a.group_key, a]));

  if (raiseAllowed) {
    const due = [];
    for (const a of down.values()) {
      const minutes = ageMin(a.last_keep_alive, now);
      if (minutes === null || minutes < cfg.minutes) continue;
      if (skipped.has(String(a.id))) continue;
      const key = keyOf(a.id);
      if (activeKeys.has(key)) continue;
      const prev = newest.get(key);
      if (prev && prev.status === 'closed' && prev.closed_by !== 'asix' && prev.last_keep_alive === a.last_keep_alive) continue;   // the same outage, closed by hand (an alert ASIX closed itself can come back)
      due.push({ agent: a, key, minutes });
    }
    due.sort((x, y) => y.minutes - x.minutes || (x.agent.id < y.agent.id ? -1 : 1));
    for (const d of due.slice(0, MAX_RAISE)) {
      raise.push({ agent_id: d.agent.id, name: d.agent.name, ip: d.agent.ip, group_key: d.key, last_keep_alive: d.agent.last_keep_alive, minutes: d.minutes, threshold: cfg.minutes,
        os: d.agent.os && d.agent.os.name ? d.agent.os.name : null, version: d.agent.version || null, groups: d.agent.groups || [] });
    }
  }
  for (const a of active) {
    const id = idOf(a.group_key);
    if (id && skipped.has(id)) { close.push({ alert_id: a.id, reason: 'This machine was set not to raise this alert (Endpoints, Agents).' }); continue; }
    if (id && down.has(id)) continue;                                  // still down
    if (!id || !Object.prototype.hasOwnProperty.call(lookups, id)) continue;   // not looked up: no evidence, keep it
    const now_ = lookups[id];
    if (now_ === null) close.push({ alert_id: a.id, reason: 'The endpoint manager no longer has this agent (it was removed).' });
    else if (now_ && now_.status !== 'disconnected') close.push({ alert_id: a.id, reason: now_.status === 'active' ? 'The agent is connected (Active) again.' : `The agent is no longer Disconnected (the manager now says ${now_.status || 'unknown'}).` });
    // still Disconnected but not on the pages read: keep the alert
  }
  return { raise, close };
}

function raiseText(r) {
  const who = r.name || r.agent_id;
  const hrs = r.minutes >= 120 ? `${Math.floor(r.minutes / 60)} hours` : `${r.minutes} minutes`;
  return {
    title: `${RULE_NAME}: ${who}${r.ip && r.ip !== 'any' ? ' (' + r.ip + ')' : ''}`,
    summary: `The endpoint agent on ${who} (agent ${r.agent_id}${r.os ? ', ' + r.os : ''}) has not reported for ${hrs} (alert limit ${r.threshold} minutes). Its events and file, configuration and alert data are not arriving. A machine that is asleep or off shows the same way: check power saving first, then the agent service and the network path to the manager on ports 1514 and 1515.`,
  };
}

const lastProblem = new Map();   // tenant id -> the last problem logged, so a manager that is down is reported once, not every minute
function noteProblem(tenantId, text) {
  if (lastProblem.get(tenantId) === text) return;
  lastProblem.set(tenantId, text);
  console.warn(`[agent-watch] tenant ${tenantId}: ${text}; nothing changed, will try again`);
}

async function readDisconnected(m, api) {
  const out = [];
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const parsed = api.parseAgentQuery({ status: 'disconnected', limit: String(PAGE), offset: String(page * PAGE), sort: 'lastKeepAlive' });
    if (parsed.error) throw new Error(parsed.error);
    const r = await api.listAgents(m, parsed);
    out.push(...r.agents);
    if (out.length >= r.total || r.agents.length < PAGE) break;
  }
  return out;
}

// The tenant's own settings (E4m), or none. A database without the table (schema job not run) means none: the server setting decides, as before.
let warnedMissing = false;
async function readSettings(tenantId) {
  try { return await db.withTenant(tenantId, (client) => agentAlert.readRow(client, tenantId)); }
  catch (e) {
    if (!agentAlert.isMissingTable(e)) throw e;
    if (!warnedMissing) { warnedMissing = true; console.warn('[agent-watch] table agent_watch_settings is missing (the schema job has not run): using the server setting'); }
    return null;
  }
}

// cfg = the SERVER setting ({ minutes }); the tenant's saved setting, if any, wins over it.
async function runTenant(tenantId, { now = Date.now(), raiseAllowed = true, sev = severity(), cfg: serverCfg = config(), api = wazuhApi, store = managerStore } = {}) {
  const eff = agentAlert.resolve(await readSettings(tenantId), serverCfg);
  const cfg = { minutes: eff.minutes };
  // 1. what ASIX holds: the alerts of this rule, and whether a manager is registered (a database without the table has none to read)
  const held = await db.withTenant(tenantId, async (client) => {
    const active = (await client.query(
      "SELECT id, group_key FROM alerts WHERE tenant_id = $1 AND rule_name = $2 AND status IN ('open','acknowledged')", [tenantId, RULE_NAME])).rows;
    const latest = (await client.query(
      `SELECT DISTINCT ON (group_key) group_key, status, details->>'closed_by' AS closed_by, details->>'last_keep_alive' AS last_keep_alive
         FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY group_key, created_at DESC, id`, [tenantId, RULE_NAME])).rows;
    let row = null, tableMissing = false;
    if (cfg.minutes) {
      try { row = await store.readRow(client, tenantId); }
      catch (e) { if (!store.isMissingTable(e)) throw e; tableMissing = true; }
    }
    return { active, latest, row, tableMissing };
  });
  if (!cfg.minutes && !held.active.length) return { raised: 0, closed: 0 };
  if (cfg.minutes && held.tableMissing) return { raised: 0, closed: 0 };
  if (cfg.minutes && !held.row && !held.active.length) return { raised: 0, closed: 0 };

  // 2. what the manager says (not inside a transaction: this waits on the network). Any failure leaves everything as it is.
  let disconnected = [], lookups = {};
  if (cfg.minutes && held.row) {
    try {
      const m = store.credentials(held.row);
      disconnected = await readDisconnected(m, api);
      const downIds = new Set(disconnected.map((a) => a.id));
      for (const a of held.active) {
        const id = idOf(a.group_key);
        if (id && !downIds.has(id)) lookups[id] = await api.getAgent(m, id);
      }
      lastProblem.delete(tenantId);
    } catch (e) {
      noteProblem(tenantId, e && e.code === 'NO_KEY' ? 'NOTIFY_ENCRYPTION_KEY is not configured' : (e && e.message) || 'the manager could not be read');
      return { raised: 0, closed: 0 };
    }
  }

  // 3. decide and write
  const p = plan({ disconnected, active: held.active, latest: held.latest, lookups, registered: !!held.row }, cfg, { now, raiseAllowed, skip: eff.skip });
  if (!p.raise.length && !p.close.length) return { raised: 0, closed: 0 };
  return db.withTenant(tenantId, async (client) => {
    for (const r of p.raise) {
      const t = raiseText(r);
      await client.query(
        `INSERT INTO alerts (tenant_id, rule_id, rule_name, severity, title, summary, group_key, event_count, first_event_at, last_event_at, details)
         VALUES ($1, NULL, $2, $3, $4, $5, $6, 0, localtimestamp, localtimestamp, $7::jsonb)`,
        [tenantId, RULE_NAME, sev, t.title, t.summary, r.group_key,
          JSON.stringify({ agent_id: r.agent_id, agent: r.name, ip: r.ip, os: r.os, version: r.version, groups: r.groups, last_keep_alive: r.last_keep_alive, minutes: r.minutes, threshold_min: r.threshold })]);
    }
    for (const c of p.close) {
      await client.query(
        `UPDATE alerts SET status = 'closed', updated_at = localtimestamp, details = COALESCE(details, '{}'::jsonb) || '{"closed_by":"asix"}'::jsonb WHERE id = $1 AND tenant_id = $2`, [c.alert_id, tenantId]);
      await client.query("INSERT INTO alert_notes (tenant_id, alert_id, author_id, author_name, body) VALUES ($1, $2, NULL, 'ASIX', $3)", [tenantId, c.alert_id, c.reason]);
    }
    return { raised: p.raise.length, closed: p.close.length };
  });
}

module.exports = { RULE_NAME, KEY_PREFIX, MIN_MINUTES, MAX_MINUTES, MAX_RAISE, config, ageMin, plan, raiseText, readDisconnected, runTenant, keyOf, idOf };
