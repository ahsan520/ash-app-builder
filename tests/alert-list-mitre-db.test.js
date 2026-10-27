'use strict';
// E4g: ATT&CK on the alert list and the technique filter, against a real PostgreSQL with the platform schema applied (docs/endpoints.md, "E4g as built"):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/alert-list-mitre-db.test.js
// The real route and the real SQL run; only the sign-in chain is replaced. Skips itself without ASIX_TEST_DB, so `npm test` is unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const { getEventStore } = require('../src/events');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = null; next(); }],
};
const routes = require('../src/gateway/routes/alerts');

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['alert-mitre-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['alert-mitre-b-' + stamp])).rows[0].id;
  const app = express(); app.use(routes);
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const get = async (q) => { const r = await fetch(base + '/v1/alerts?' + new URLSearchParams(q)); return { status: r.status, json: await r.json() }; };
  const ins = async (tenant, title, details, o = {}) => (await db.query(
    `INSERT INTO alerts (tenant_id, rule_name, severity, status, title, group_key, event_count, first_event_at, last_event_at, details)
     VALUES ($1,'r',$2,$3,$4,$4,1, localtimestamp, localtimestamp, $5::jsonb) RETURNING id`,
    [tenant, o.sev || 'high', o.status || 'open', title, details === undefined ? undefined : JSON.stringify(details)])).rows[0].id;
  const titles = (r) => r.json.alerts.map((a) => a.title).sort();

  try {
    const brute = await ins(TENANT, 'brute', { mitre: { techniques: [{ id: 'T1110', name: 'Brute Force' }], tactics: ['Credential Access'] } });
    await ins(TENANT, 'sub', { mitre: { techniques: [{ id: 'T1110.003', name: 'Password Spraying' }, { id: 'T1078', name: 'Valid Accounts' }], tactics: ['Credential Access', 'Initial Access'] } });
    await ins(TENANT, 'fim', { mitre: { techniques: [{ id: 'T1565.001', name: 'Stored Data Manipulation' }], tactics: ['Impact'] } });
    await ins(TENANT, 'lookalike', { mitre: { techniques: [{ id: 'T1111', name: 'MFA Interception' }], tactics: [] } });
    await ins(TENANT, 'none', { threshold: 3 });
    await ins(TENANT, 'empty-details', {});
    await ins(TENANT, 'null-mitre', { mitre: null });
    await ins(TENANT, 'odd-shape', { mitre: { techniques: 'T1110' } });
    await ins(TENANT, 'odd-elements', { mitre: { techniques: [7, null, { name: 'no id' }, 'T1110', { id: 'T1059', name: 'Command Interpreter' }] } });
    await ins(TENANT, 'closed-brute', { mitre: { techniques: [{ id: 'T1110', name: 'Brute Force' }], tactics: [] } }, { status: 'closed' });
    await ins(OTHER, 'other tenant brute', { mitre: { techniques: [{ id: 'T1110', name: 'Brute Force' }], tactics: [] } });

    // Alerts raised before E4f: nothing stored, the techniques come from the sample events (real PostgreSQL event store)
    const evs = [{ source_type: 'endpoint-alert', collector_id: 'c-old', raw: 'a', parsed: { mitre_ids: 'T1548.003,T1059', mitre_techniques: 'Sudo and Sudo Caching,Command Interpreter', mitre_tactics: 'Privilege Escalation' }, received_at: new Date().toISOString() },
      { source_type: 'syslog', collector_id: 'c-old', raw: 'b', parsed: { host: 'x' }, received_at: new Date().toISOString() }];
    await getEventStore().insertBatch(TENANT, evs);
    const eid = (await db.query("SELECT id, source_type FROM events WHERE tenant_id = $1 AND collector_id = 'c-old'", [TENANT])).rows;
    const mitreEv = eid.find((e) => e.source_type === 'endpoint-alert').id, plainEv = eid.find((e) => e.source_type === 'syslog').id;
    await ins(TENANT, 'old-from-events', { sample_event_ids: [mitreEv, plainEv] });
    await ins(TENANT, 'old-plain-events', { sample_event_ids: [plainEv] });
    await ins(TENANT, 'old-gone-events', { sample_event_ids: ['00000000-0000-4000-8000-000000000000', 'not-an-id', 7] });
    await ins(OTHER, 'other-old', { sample_event_ids: [mitreEv] });

    let r = await get({ status: 'all' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.alerts.length, 13, 'the unfiltered list is unchanged: every alert of the tenant and no other tenant');
    assert.ok(r.json.alerts.every((a) => !('mitre_stored' in a) && !('details' in a)), 'the raw column and the details are not returned');
    const by = Object.fromEntries(r.json.alerts.map((a) => [a.title, a.mitre]));
    assert.deepStrictEqual(by.brute, { techniques: [{ id: 'T1110', name: 'Brute Force', url: 'https://attack.mitre.org/techniques/T1110/' }], tactics: ['Credential Access'] });
    assert.deepStrictEqual(by.sub.techniques.map((t) => t.id), ['T1110.003', 'T1078']);
    assert.strictEqual(by.sub.techniques[0].url, 'https://attack.mitre.org/techniques/T1110/003/');
    for (const t of ['none', 'empty-details', 'null-mitre', 'odd-shape']) assert.deepStrictEqual(by[t], { techniques: [], tactics: [] }, t + ' has an empty ATT&CK, not a crash');
    assert.deepStrictEqual(by['odd-elements'].techniques.map((t) => t.id), ['T1059'], 'only the well-formed element survives');

    assert.deepStrictEqual(by['old-from-events'], { techniques: [{ id: 'T1548.003', name: 'Sudo and Sudo Caching', url: 'https://attack.mitre.org/techniques/T1548/003/' }, { id: 'T1059', name: 'Command Interpreter', url: 'https://attack.mitre.org/techniques/T1059/' }], tactics: ['Privilege Escalation'] }, 'an old alert takes its ATT&CK from its sample events');
    for (const t of ['old-plain-events', 'old-gone-events']) assert.deepStrictEqual(by[t], { techniques: [], tactics: [] }, t);
    r = await get({ status: 'all', mitre: 'T1110' });
    assert.deepStrictEqual(titles(r), ['brute', 'closed-brute', 'sub'], 'T1110 finds itself and its sub-technique, not T1111, not another tenant');
    r = await get({ status: 'all', mitre: 'T15*' });
    assert.deepStrictEqual(titles(r), ['fim', 'old-from-events'], 'a prefix with a star finds T1565.001 and the event-backed T1548.003');
    r = await get({ status: 'all', mitre: 't15' });
    assert.deepStrictEqual(titles(r), ['fim', 'old-from-events'], 'lower case, no star');
    r = await get({ status: 'all', mitre: 'T11' });
    assert.deepStrictEqual(titles(r), ['brute', 'closed-brute', 'lookalike', 'sub'], 'T11 finds T1110, T1110.003, T1111, not T1078');
    r = await get({ status: 'all', mitre: 'T1548' });
    assert.deepStrictEqual(titles(r), ['old-from-events'], 'an alert with no stored ATT&CK is found through its events');
    r = await get({ status: 'all', mitre: 'T1110.0' });
    assert.deepStrictEqual(titles(r), ['sub'], 'a partial sub-technique');
    r = await get({ status: 'all', mitre: 'T11', limit: '2', offset: '1' });
    assert.strictEqual(r.json.alerts.length, 2, 'offset and limit are applied after the filter'); assert.strictEqual(r.json.count, 2);
    r = await get({ mitre: 't1110' });
    assert.deepStrictEqual(titles(r), ['brute', 'sub'], 'lower case is accepted; the default status hides closed alerts');
    r = await get({ status: 'all', mitre: 'T1110.003' });
    assert.deepStrictEqual(titles(r), ['sub'], 'a sub-technique finds only itself');
    r = await get({ status: 'all', mitre: 'T1078' });
    assert.deepStrictEqual(titles(r), ['sub'], 'the second technique of an alert is found too');
    r = await get({ status: 'all', mitre: 'T1059' });
    assert.deepStrictEqual(titles(r), ['odd-elements', 'old-from-events'], 'a malformed neighbour element does not stop the filter');
    r = await get({ status: 'all', mitre: 'T1565.001' });
    assert.deepStrictEqual(titles(r), ['fim']);
    r = await get({ status: 'all', mitre: 'T9999' });
    assert.deepStrictEqual(r.json.alerts, [], 'a well-formed id nothing carries gives an empty list');
    r = await get({ status: 'all', mitre: 'T1110', severity: 'low' });
    assert.deepStrictEqual(r.json.alerts, [], 'the technique filter combines with the others (all alerts are high)');

    for (const bad of ['', 'T', '*', 'T11100', "T1110' OR '1'='1", 'T1110%', 'x', 'T1110.003.001', 'T1110.', ' ', 'T1*0']) {
      r = await get({ mitre: bad });
      assert.strictEqual(r.status, 400, JSON.stringify(bad) + ' is refused'); assert.strictEqual(r.json.error && r.json.error.code || r.json.code, 'INVALID_MITRE');
    }
    r = await fetch(base + '/v1/alerts?mitre=T1110&mitre=T1078'); assert.strictEqual(r.status, 400, 'a repeated parameter is refused');
    assert.ok(brute);
    console.log('alert-list-mitre-db: all checks passed');
  } finally {
    srv.close();
    await db.query('DELETE FROM events WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM alerts WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]);
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]);
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
