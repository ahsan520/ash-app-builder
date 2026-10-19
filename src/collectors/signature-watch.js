'use strict';
// Broker signature watch: raises an alert when ASIX signs its broker config answers (ASIX_CONFIG_SIGNING_KEY, src/brokers/config-signing.js)
// but a broker you watch does not check the signature: it has no public key (`not_verifying`), or it refuses ASIX's answer (`refused`).
// The Brokers page already shows both in its Config check column; this alert is for the operator who is not looking at that page.
//
// No new setting and no schema change. Which brokers: the same rule as the broker key alert (src/collectors/key-watch.js), a collector whose
// version reads "vector-<version>" that is watched ("Alert if down" on it, or the tenant-wide "Watch everything" switch and not left out).
// What a broker says comes from the report it already sends after every config pull (collectors.config_signature) and is read with
// signatureState() in src/brokers/config.js, so this alert and the Brokers page can never disagree.
//
// Only the broker's own words count, and only while ASIX signs:
//   - signing off on ASIX (no key, or an unusable one): nothing to check, so nothing is raised and open alerts are closed
//   - `unknown` (never reported: the broker did not opt in with --accept-config, or its script is older), `waiting`, `verifying`, `stale`: not a problem
// It is the broker describing itself, not proof (an old or edited script can say anything), exactly as the Brokers page says.
//
// plan() is pure and holds every rule; runTenant() reads the rows, calls plan() and writes what it says. One alert per problem: it stays while the
// problem stays, closes when the broker checks again (or is no longer watched, was deleted, or ASIX stopped signing), and if an analyst closes it
// while the same problem is still there it is not raised again for that same problem. A different problem (a refusal for another reason) raises a new one.

const db = require('../db');
const { isBroker, BROKER_VERSION_SQL } = require('../brokers/broker-view');
const { signatureState, SIGNATURE_HELP } = require('../brokers/config');
const signing = require('../brokers/config-signing');
const { severity } = require('./watchdog');
const watchAll = require('./watch-all');

const RULE_NAME = 'Broker not checking config signature';
const keyOf = (id) => `brokersig:${id}`;

const NOT_VERIFYING_HELP = 'Copy the public key from the Syslog port card on the Brokers page and re-run the bootstrap script on the broker with --accept-config --config-pubkey <file>.';

// What is wrong with what this broker says about the signature? null = nothing; else a reference that changes when the problem does.
function badSignature(row, now) {
  const s = signatureState(true, row, now);
  if (s.state === 'not_verifying') return { ref: 'not_verifying', why: 'it has no public key, so it acts on config answers without checking who signed them', help: NOT_VERIFYING_HELP };
  if (s.state === 'refused') return { ref: `refused:${s.problem}`, why: `it refuses ASIX's signed config answer (${s.problem})`, help: SIGNATURE_HELP[s.problem] || 'See Signed config in docs/broker-vm.md.' };
  return null;
}

// brokers:    watched brokers { id, name, version, config_signature, config_reported_at }
// active:     open or acknowledged alerts of this rule { id, group_key }
// latest:     newest alert of this rule per group_key { group_key, status, sig_ref }
// signingOn:  ASIX has a usable signing key
// opts:       { now, raiseAllowed }  false (start-up grace) still closes alerts but raises none
function plan({ brokers, active, latest, signingOn }, { now = Date.now(), raiseAllowed = true } = {}) {
  const bad = new Map(), known = new Set();
  for (const b of brokers) {
    if (!isBroker(b)) continue;
    known.add(keyOf(b.id));
    if (!signingOn) continue;
    const k = badSignature(b, now);
    if (k) bad.set(keyOf(b.id), { b, k });
  }
  const newest = new Map(latest.map((a) => [a.group_key, a]));
  const raise = [], close = [];
  if (raiseAllowed) {
    for (const [key, { b, k }] of bad) {
      const prev = newest.get(key);
      if (prev && (prev.status !== 'closed' || prev.sig_ref === k.ref)) continue;   // still active, or this same problem was closed by hand
      raise.push({ broker_id: b.id, name: b.name, group_key: key, sig_ref: k.ref, why: k.why, help: k.help });
    }
  }
  for (const a of active) {
    if (bad.has(a.group_key)) continue;
    close.push({ alert_id: a.id, reason: !signingOn
      ? 'ASIX does not sign its config answers any more, so there is nothing to check.'
      : known.has(a.group_key)
        ? 'The broker checks ASIX\'s signature again, or no longer reports a signature problem.'
        : 'The broker is no longer watched or was removed from the list.' });
  }
  return { raise, close };
}

const raiseText = (r) => ({
  title: `${RULE_NAME}: ${r.name}`,
  summary: `ASIX signs its broker config answers, but ${r.name} does not check them: ${r.why}. ${r.help}`,
});

async function runTenant(tenantId, { now = Date.now(), raiseAllowed = true, sev = severity(), signingOn } = {}) {
  const on = signingOn === undefined ? signing.status().enabled === true : signingOn === true;
  return db.withTenant(tenantId, async (client) => {
    await client.query("SET LOCAL statement_timeout = '15s'");
    // Watched = "Alert if down" on by hand, or the tenant-wide "watch everything" switch is on and the broker is not retired and not left out.
    const all = await watchAll.read(client, tenantId);
    const brokers = (await client.query(
      `SELECT c.id, c.name, c.version, c.config_signature, c.config_reported_at
         FROM collectors c
        WHERE c.tenant_id = $1 AND c.version ILIKE $2
          AND (c.watch_disconnect OR ($3::boolean AND NOT c.watch_exclude AND c.last_seen >= $4::timestamp))`,
      [tenantId, BROKER_VERSION_SQL, all.disconnect, watchAll.cutoffOf(now)])).rows;
    const active = (await client.query(
      "SELECT id, group_key FROM alerts WHERE tenant_id = $1 AND rule_name = $2 AND status IN ('open','acknowledged')", [tenantId, RULE_NAME])).rows;
    const latest = (await client.query(
      `SELECT DISTINCT ON (group_key) group_key, status, details->>'sig_ref' AS sig_ref
         FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY group_key, created_at DESC, id`, [tenantId, RULE_NAME])).rows;
    const p = plan({ brokers, active, latest, signingOn: on }, { now, raiseAllowed });
    for (const r of p.raise) {
      const t = raiseText(r);
      await client.query(
        `INSERT INTO alerts (tenant_id, rule_id, rule_name, severity, title, summary, group_key, event_count, first_event_at, last_event_at, details)
         VALUES ($1, NULL, $2, $3, $4, $5, $6, 0, localtimestamp, localtimestamp, $7::jsonb)`,
        [tenantId, RULE_NAME, sev, t.title, t.summary, r.group_key, JSON.stringify({ broker_id: r.broker_id, broker: r.name, sig_ref: r.sig_ref })]);
    }
    for (const c of p.close) {
      await client.query("UPDATE alerts SET status = 'closed', updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2", [c.alert_id, tenantId]);
      await client.query("INSERT INTO alert_notes (tenant_id, alert_id, author_id, author_name, body) VALUES ($1, $2, NULL, 'ASIX', $3)", [tenantId, c.alert_id, c.reason]);
    }
    return { raised: p.raise.length, closed: p.close.length };
  });
}

module.exports = { RULE_NAME, keyOf, badSignature, plan, raiseText, runTenant };
