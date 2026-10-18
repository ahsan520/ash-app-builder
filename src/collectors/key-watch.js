'use strict';
// Broker key watch: raises an alert when a broker you watch ("Alert if down", collectors.watch_disconnect) is still tied to an
// installer key that was revoked or deleted. ASIX rejects what such a broker sends, so it would only show up later as
// "Collector disconnected" after its threshold; this alert is immediate and says the cause and what to do.
//
// No new setting and no schema change: a broker is a collector whose version reads "vector-<version>" (src/brokers/broker-view.js),
// and watching it is the existing opt-in. Rotating a key is safe: the new key is active and the heartbeat moves the broker onto it
// before the old one is revoked, so a revoked key with no broker on it raises nothing.
//
// plan() is pure and holds every rule; runTenant() reads the rows, calls plan() and writes what it says. One alert per problem:
// it stays while the problem stays, closes when the broker is on an active key again (or is no longer watched, or was deleted),
// and if an analyst closes it while the same key is still bad, it is not raised again for that same key.

const db = require('../db');
const { isBroker, BROKER_VERSION_SQL } = require('../brokers/broker-view');
const { severity } = require('./watchdog');
const watchAll = require('./watch-all');

const RULE_NAME = 'Broker installer key unusable';
const keyOf = (id) => `brokerkey:${id}`;

// What is wrong with the key this broker is tied to? null = nothing; else a reference that changes when the problem does.
function badKey(b) {
  if (!b.key_id) return { ref: 'deleted', why: 'its installer key was deleted' };
  if (b.key_status === 'revoked') return { ref: `revoked:${b.key_id}`, why: `its installer key (${b.key_name || b.key_prefix || b.key_id}) is revoked` };
  return null;
}

// brokers: watched brokers { id, name, version, key_id, key_status, key_name, key_prefix }
// active:  open or acknowledged alerts of this rule { id, group_key }
// latest:  newest alert of this rule per group_key { group_key, status, key_ref }
// opts:    { raiseAllowed }  false (start-up grace) still closes alerts but raises none
function plan({ brokers, active, latest }, { raiseAllowed = true } = {}) {
  const bad = new Map(), known = new Set();
  for (const b of brokers) {
    if (!isBroker(b)) continue;
    known.add(keyOf(b.id));
    const k = badKey(b);
    if (k) bad.set(keyOf(b.id), { b, k });
  }
  const newest = new Map(latest.map((a) => [a.group_key, a]));
  const raise = [], close = [];
  if (raiseAllowed) {
    for (const [key, { b, k }] of bad) {
      const prev = newest.get(key);
      if (prev && (prev.status !== 'closed' || prev.key_ref === k.ref)) continue;   // still active, or this same key problem was closed by hand
      raise.push({ broker_id: b.id, name: b.name, group_key: key, key_ref: k.ref, why: k.why });
    }
  }
  for (const a of active) {
    if (bad.has(a.group_key)) continue;
    close.push({ alert_id: a.id, reason: known.has(a.group_key)
      ? 'The broker is on an active installer key again.'
      : 'The broker is no longer watched or was removed from the list.' });
  }
  return { raise, close };
}

const raiseText = (r) => ({
  title: `${RULE_NAME}: ${r.name}`,
  summary: `${r.name} cannot send to ASIX: ${r.why}. On the Brokers page press Rotate key, then re-run the bootstrap script on the broker with the new key.`,
});

async function runTenant(tenantId, { now = Date.now(), raiseAllowed = true, sev = severity() } = {}) {
  return db.withTenant(tenantId, async (client) => {
    await client.query("SET LOCAL statement_timeout = '15s'");
    // Watched = "Alert if down" on by hand, or the tenant-wide "watch everything" switch is on and the broker is not retired.
    const all = await watchAll.read(client, tenantId);
    const brokers = (await client.query(
      `SELECT c.id, c.name, c.version, c.key_id, k.status AS key_status, k.name AS key_name, k.key_prefix
         FROM collectors c LEFT JOIN ingestion_keys k ON k.id = c.key_id
        WHERE c.tenant_id = $1 AND c.version ILIKE $2
          AND (c.watch_disconnect OR ($3::boolean AND c.last_seen >= $4::timestamp))`,
      [tenantId, BROKER_VERSION_SQL, all.disconnect, watchAll.cutoffOf(now)])).rows;
    const active = (await client.query(
      "SELECT id, group_key FROM alerts WHERE tenant_id = $1 AND rule_name = $2 AND status IN ('open','acknowledged')", [tenantId, RULE_NAME])).rows;
    const latest = (await client.query(
      `SELECT DISTINCT ON (group_key) group_key, status, details->>'key_ref' AS key_ref
         FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY group_key, created_at DESC, id`, [tenantId, RULE_NAME])).rows;
    const p = plan({ brokers, active, latest }, { raiseAllowed });
    for (const r of p.raise) {
      const t = raiseText(r);
      await client.query(
        `INSERT INTO alerts (tenant_id, rule_id, rule_name, severity, title, summary, group_key, event_count, first_event_at, last_event_at, details)
         VALUES ($1, NULL, $2, $3, $4, $5, $6, 0, localtimestamp, localtimestamp, $7::jsonb)`,
        [tenantId, RULE_NAME, sev, t.title, t.summary, r.group_key, JSON.stringify({ broker_id: r.broker_id, broker: r.name, key_ref: r.key_ref })]);
    }
    for (const c of p.close) {
      await client.query("UPDATE alerts SET status = 'closed', updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2", [c.alert_id, tenantId]);
      await client.query("INSERT INTO alert_notes (tenant_id, alert_id, author_id, author_name, body) VALUES ($1, $2, NULL, 'ASIX', $3)", [tenantId, c.alert_id, c.reason]);
    }
    return { raised: p.raise.length, closed: p.close.length };
  });
}

module.exports = { RULE_NAME, keyOf, badKey, plan, raiseText, runTenant };
