'use strict';
// Broker pause watch: raises an alert when a watched broker REJECTED the list of paused inputs ASIX asked it to run
// (Brokers page, Inputs; src/brokers/paused.js). The broker took the new list through its own checks (vector validate, restart, health check),
// something failed, it put its old settings back and said so in its report (collectors.config_rejected_paused). Until then the input an operator meant to
// stop (a noisy log file, an HTTP listener that should be closed) is still running, or one they meant to start again is still off, and the Brokers page
// shows it only in the Paused column.
//
// No new setting and no schema change. Which brokers: the same rule as the broker key and signature alerts (src/collectors/key-watch.js): a collector whose
// version reads "vector-<version>" that is watched ("Alert if down" on it, or the tenant-wide "Watch everything" switch and not left out).
// The state comes from pausedState() in src/brokers/paused.js, so this alert and the Brokers page cannot disagree.
//
// Only a rejection is a problem. Not raised: `pending` (a broker asks every 5 minutes, so asked-but-not-yet-applied is normal for a while),
// `stale` (it stopped reporting: the disconnect alert covers a dead broker), `unknown` (never reported: it did not opt in with --accept-config, or its
// script is older; ASIX cannot tell that from a broker that has not pulled yet) and `applied`. It is the broker describing itself, not proof.
//
// plan() is pure and holds every rule; runTenant() reads the rows, calls plan() and writes what it says. One alert per rejected list: it stays while the
// broker keeps rejecting the same ask, closes when the broker applies it, the ask changes, the broker is no longer watched or was deleted; if an analyst
// closes it while the same list is still rejected it is not raised again for that list. Another rejected list raises a new one.

const db = require('../db');
const { isBroker, BROKER_VERSION_SQL } = require('../brokers/broker-view');
const paused = require('../brokers/paused');
const { severity } = require('./watchdog');
const watchAll = require('./watch-all');

const RULE_NAME = 'Broker input pause not applied';
const keyOf = (id) => `brokerpause:${id}`;

// What is wrong with what this broker says about the pause list? null = nothing; else a reference that changes when the asked list does.
function badPause(row, now) {
  const s = paused.pausedState(row, now);
  if (s.state !== 'rejected') return null;
  const names = s.asked.length ? s.asked.join(', ') : 'none';
  return { ref: `rejected:${s.asked.join(',')}`, asked: s.asked, names };
}

// brokers: watched brokers { id, name, version, inputs_paused, config_paused_inputs, config_rejected_paused, config_reported_at }
// active:  open or acknowledged alerts of this rule { id, group_key }
// latest:  newest alert of this rule per group_key { group_key, status, pause_ref }
// opts:    { now, raiseAllowed }  false (start-up grace) still closes alerts but raises none
function plan({ brokers, active, latest }, { now = Date.now(), raiseAllowed = true } = {}) {
  const bad = new Map(), known = new Set();
  for (const b of brokers) {
    if (!isBroker(b)) continue;
    known.add(keyOf(b.id));
    const k = badPause(b, now);
    if (k) bad.set(keyOf(b.id), { b, k });
  }
  const newest = new Map(latest.map((a) => [a.group_key, a]));
  const raise = [], close = [];
  if (raiseAllowed) {
    for (const [key, { b, k }] of bad) {
      const prev = newest.get(key);
      if (prev && (prev.status !== 'closed' || prev.pause_ref === k.ref)) continue;   // still active, or this same list was closed by hand
      raise.push({ broker_id: b.id, name: b.name, group_key: key, pause_ref: k.ref, asked: k.asked, names: k.names });
    }
  }
  for (const a of active) {
    const cur = bad.get(a.group_key);
    if (cur) {
      const prev = newest.get(a.group_key);
      if (!prev || prev.pause_ref === cur.k.ref) continue;   // the same problem: keep it
      // the ask changed to another list that is also rejected: the open alert describes the old list, so it is closed and a new one raised next cycle
      close.push({ alert_id: a.id, reason: 'ASIX now asks this broker for a different list of inputs, which it also rejected.' });
      continue;
    }
    close.push({ alert_id: a.id, reason: known.has(a.group_key)
      ? 'The broker applied the list of inputs ASIX asks for, or ASIX no longer asks for it.'
      : 'The broker is no longer watched or was removed from the list.' });
  }
  return { raise, close };
}

const raiseText = (r) => ({
  title: `${RULE_NAME}: ${r.name}`,
  summary: r.asked.length
    ? `${r.name} was asked to pause ${r.names} and rejected it: it put its old settings back, so those inputs are still running. See "journalctl -u asix-broker-config" on the broker for why (a failed Vector validate, restart or health check).`
    : `${r.name} was asked to resume its paused inputs and rejected it: it put its old settings back, so they are still paused. See "journalctl -u asix-broker-config" on the broker for why (a failed Vector validate, restart or health check).`,
});

async function runTenant(tenantId, { now = Date.now(), raiseAllowed = true, sev = severity() } = {}) {
  return db.withTenant(tenantId, async (client) => {
    await client.query("SET LOCAL statement_timeout = '15s'");
    const all = await watchAll.read(client, tenantId);
    const brokers = (await client.query(
      `SELECT c.id, c.name, c.version, c.inputs_paused, c.config_paused_inputs, c.config_rejected_paused, c.config_reported_at
         FROM collectors c
        WHERE c.tenant_id = $1 AND c.version ILIKE $2
          AND (c.watch_disconnect OR ($3::boolean AND NOT c.watch_exclude AND c.last_seen >= $4::timestamp))`,
      [tenantId, BROKER_VERSION_SQL, all.disconnect, watchAll.cutoffOf(now)])).rows;
    const active = (await client.query(
      "SELECT id, group_key FROM alerts WHERE tenant_id = $1 AND rule_name = $2 AND status IN ('open','acknowledged')", [tenantId, RULE_NAME])).rows;
    const latest = (await client.query(
      `SELECT DISTINCT ON (group_key) group_key, status, details->>'pause_ref' AS pause_ref
         FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY group_key, created_at DESC, id`, [tenantId, RULE_NAME])).rows;
    const p = plan({ brokers, active, latest }, { now, raiseAllowed });
    for (const r of p.raise) {
      const t = raiseText(r);
      await client.query(
        `INSERT INTO alerts (tenant_id, rule_id, rule_name, severity, title, summary, group_key, event_count, first_event_at, last_event_at, details)
         VALUES ($1, NULL, $2, $3, $4, $5, $6, 0, localtimestamp, localtimestamp, $7::jsonb)`,
        [tenantId, RULE_NAME, sev, t.title, t.summary, r.group_key, JSON.stringify({ broker_id: r.broker_id, broker: r.name, pause_ref: r.pause_ref, asked: r.asked })]);
    }
    for (const c of p.close) {
      await client.query("UPDATE alerts SET status = 'closed', updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2", [c.alert_id, tenantId]);
      await client.query("INSERT INTO alert_notes (tenant_id, alert_id, author_id, author_name, body) VALUES ($1, $2, NULL, 'ASIX', $3)", [tenantId, c.alert_id, c.reason]);
    }
    return { raised: p.raise.length, closed: p.close.length };
  });
}

module.exports = { RULE_NAME, keyOf, badPause, plan, raiseText, runTenant };
