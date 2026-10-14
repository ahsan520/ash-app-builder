'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/alert-dedupe-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT; let USER;
// Replace only the auth chain; every query stays real.
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = USER; next(); }],
};
const dedupeRoutes = require('../src/gateway/routes/alert-dedupe');
const alertRoutes = require('../src/gateway/routes/alerts');
const triageRoutes = require('../src/gateway/routes/alert-triage');

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['dedupe-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['dedupe-b-' + stamp])).rows[0].id;
  USER = (await db.query("INSERT INTO users (tenant_id, username, email) VALUES ($1,$2,'a@example.test') RETURNING id", [TENANT, 'alice-' + stamp])).rows[0].id;
  const rule = (await db.query("INSERT INTO detection_rules (tenant_id, name, severity, definition) VALUES ($1,'SSH brute force','medium','{}'::jsonb) RETURNING id", [TENANT])).rows[0].id;

  const app = express(); app.use(express.json()); app.use(alertRoutes); app.use(triageRoutes); app.use(dedupeRoutes);
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const ins = async (tenant, o) => (await db.query(
    `INSERT INTO alerts (tenant_id, rule_id, rule_name, severity, status, title, group_key, event_count, first_event_at, last_event_at, assignee_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8, localtimestamp - ($9 || ' hours')::interval, localtimestamp - ($10 || ' hours')::interval, $11) RETURNING id`,
    [tenant, o.rule === undefined ? rule : o.rule, o.name || 'SSH brute force', o.sev || 'medium', o.status || 'open', o.title || 'SSH brute force: ' + (o.group || 'g1'),
     o.group || 'g1', o.n || 1, String(o.first), String(o.last), o.assignee || null])).rows[0].id;
  const get = async (id) => (await db.query('SELECT * FROM alerts WHERE id = $1', [id])).rows[0];

  try {
    // group g1: three repeats (oldest first = a1); group g2: a single alert; group g3: two repeats; closed one is ignored
    const a1 = await ins(TENANT, { group: 'g1', n: 5, first: 30, last: 29, sev: 'low', status: 'acknowledged' });
    const a2 = await ins(TENANT, { group: 'g1', n: 7, first: 20, last: 19, sev: 'high', assignee: USER });
    const a3 = await ins(TENANT, { group: 'g1', n: 2, first: 10, last: 1 });
    await ins(TENANT, { group: 'g2', n: 1, first: 5, last: 4 });
    const c1 = await ins(TENANT, { group: 'g3', n: 3, first: 9, last: 8 });
    const c2 = await ins(TENANT, { group: 'g3', n: 4, first: 7, last: 6 });
    await ins(TENANT, { group: 'g1', n: 99, first: 40, last: 39, status: 'closed' });
    const foreign = await ins(OTHER, { rule: null, name: 'SSH brute force', group: 'g1', n: 1, first: 3, last: 2 });
    await call('POST', `/v1/alerts/${a2}/notes`, { body: 'looking at this' });

    // listing
    let r = await call('GET', '/v1/alert-duplicates');
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.group_count, 2); assert.strictEqual(r.json.alert_count, 5);
    const g1 = r.json.groups.find((g) => g.group_key === 'g1');
    assert.strictEqual(g1.count, 3); assert.strictEqual(g1.total_events, 14);
    assert.deepStrictEqual(g1.alerts.map((a) => a.id), [a1, a2, a3], 'oldest first');
    assert.strictEqual(g1.alerts[1].assignee_name.startsWith('alice-'), true);

    // validation against the database
    assert.strictEqual((await call('POST', '/v1/alerts/merge', { primary_id: a1, ids: [c1] })).json.error.code, 'NOT_DUPLICATES');
    assert.strictEqual((await call('POST', '/v1/alerts/merge', { primary_id: a1, ids: [foreign] })).status, 404, 'other tenant alerts are not found');
    assert.strictEqual((await call('POST', '/v1/alerts/merge', { primary_id: a1, ids: [a1] })).json.error.code, 'INVALID_BODY');
    assert.strictEqual((await call('POST', '/v1/alerts/merge', { primary_id: a1, ids: ['99999999-9999-4999-8999-999999999999'] })).status, 404);
    assert.strictEqual((await get(foreign)).status, 'open');

    // manual merge of a2 + a3 into a1
    r = await call('POST', '/v1/alerts/merge', { primary_id: a1, ids: [a2, a3] });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.merged, 2); assert.strictEqual(r.json.event_count, 14);
    let p = await get(a1);
    assert.strictEqual(p.event_count, 14); assert.strictEqual(p.severity, 'high'); assert.strictEqual(p.status, 'open', 'open repeat wins over acknowledged primary');
    assert.strictEqual(p.assignee_id, USER, 'owner carried over from a duplicate'); assert.strictEqual(p.merged_count, 2);
    assert.ok(new Date(p.first_event_at) <= new Date((await get(a2)).first_event_at));
    assert.ok(new Date(p.last_event_at) >= new Date((await get(a3)).last_event_at));
    for (const id of [a2, a3]) { const d = await get(id); assert.strictEqual(d.status, 'closed'); assert.strictEqual(d.merged_into_id, a1); }
    const notes = (await call('GET', `/v1/alerts/${a1}/notes`)).json.notes;
    assert.ok(notes.some((n) => n.body === 'looking at this'), 'notes moved to the primary');
    assert.ok(notes.some((n) => n.author_name === 'ASIX' && /Merged 2 repeat alerts/.test(n.body)), 'audit note added');
    assert.strictEqual((await call('GET', `/v1/alerts/${a1}/merged`)).json.merged.length, 2);

    // merged alerts are closed, so they leave the active list and the duplicate scan
    const list = (await call('GET', '/v1/alerts?limit=200')).json.alerts;
    assert.ok(!list.some((a) => a.id === a2 || a.id === a3));
    assert.strictEqual(list.find((a) => a.id === a1).merged_count, 2);
    // merging again with an already-merged alert is refused
    assert.strictEqual((await call('POST', '/v1/alerts/merge', { primary_id: a1, ids: [a2] })).json.error.code, 'NOT_ACTIVE');

    // merge-all picks up the remaining group and is a no-op the second time
    r = await call('POST', '/v1/alert-duplicates/merge', {});
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.groups, 1); assert.strictEqual(r.json.merged, 1);
    assert.strictEqual((await get(c1)).merged_count, 1); assert.strictEqual((await get(c1)).event_count, 7);
    assert.strictEqual((await get(c2)).merged_into_id, c1);
    r = await call('POST', '/v1/alert-duplicates/merge', {});
    assert.strictEqual(r.json.merged, 0); assert.strictEqual((await call('GET', '/v1/alert-duplicates')).json.group_count, 0);

    // a second-level merge repoints earlier children at the new primary
    const b1 = await ins(TENANT, { group: 'g1', n: 1, first: 50, last: 49 });
    r = await call('POST', '/v1/alerts/merge', { primary_id: b1, ids: [a1] });
    assert.strictEqual(r.status, 200);
    assert.strictEqual((await get(a2)).merged_into_id, b1, 'children follow their parent');
    assert.strictEqual((await get(b1)).merged_count, 3, 'a1 plus the two it had absorbed');
    assert.strictEqual((await get(b1)).event_count, 15);

    // another tenant's data was never touched
    assert.strictEqual((await get(foreign)).merged_count, 0);
    console.log('alert-dedupe-db: all checks passed');
  } finally {
    srv.close();
    await db.query('DELETE FROM alert_notes WHERE tenant_id = ANY($1::uuid[])', [[TENANT, OTHER]]);
    await db.query('UPDATE alerts SET merged_into_id = NULL WHERE tenant_id = ANY($1::uuid[])', [[TENANT, OTHER]]);
    await db.query('DELETE FROM alerts WHERE tenant_id = ANY($1::uuid[])', [[TENANT, OTHER]]);
    await db.query('DELETE FROM detection_rules WHERE tenant_id = $1', [TENANT]);
    await db.query('DELETE FROM users WHERE tenant_id = $1', [TENANT]);
    await db.query('DELETE FROM tenants WHERE id = ANY($1::uuid[])', [[TENANT, OTHER]]);
    await db.close();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
