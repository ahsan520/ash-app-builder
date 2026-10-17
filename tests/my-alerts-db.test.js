'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/my-alerts-db.test.js
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
const routes = require('../src/gateway/routes/my-alerts');

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['mine-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['mine-b-' + stamp])).rows[0].id;
  USER = (await db.query("INSERT INTO users (tenant_id, username, email) VALUES ($1,$2,'a@example.test') RETURNING id", [TENANT, 'alice-' + stamp])).rows[0].id;
  const COLLEAGUE = (await db.query("INSERT INTO users (tenant_id, username, email) VALUES ($1,$2,'b@example.test') RETURNING id", [TENANT, 'bob-' + stamp])).rows[0].id;
  const FOREIGN_USER = (await db.query("INSERT INTO users (tenant_id, username, email) VALUES ($1,$2,'c@example.test') RETURNING id", [OTHER, 'carol-' + stamp])).rows[0].id;

  const app = express(); app.use(routes);
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const get = async () => { const r = await fetch(base + '/v1/my-alerts'); return { status: r.status, json: await r.json() }; };
  const ins = async (tenant, o) => (await db.query(
    `INSERT INTO alerts (tenant_id, rule_name, severity, status, title, group_key, event_count, first_event_at, last_event_at, assignee_id)
     VALUES ($1,'r',$2,$3,$4,$5,$6, localtimestamp - ($7 || ' hours')::interval, localtimestamp - ($8 || ' hours')::interval, $9) RETURNING id`,
    [tenant, o.sev, o.status || 'open', o.title, o.title, o.n || 1, String(o.first || 5), String(o.last || 1), o.assignee])).rows[0].id;

  try {
    // empty first
    let r = await get();
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.applicable, true); assert.strictEqual(r.json.active_total, 0); assert.deepStrictEqual(r.json.alerts, []); assert.strictEqual(r.json.oldest_open_at, null);

    const low = await ins(TENANT, { sev: 'low', title: 'low open', assignee: USER, last: 3 });
    const hiAck = await ins(TENANT, { sev: 'high', status: 'acknowledged', title: 'high acknowledged', assignee: USER, last: 2 });
    const hiOpen = await ins(TENANT, { sev: 'high', title: 'high open', assignee: USER, last: 4 });
    const crit = await ins(TENANT, { sev: 'critical', title: 'critical open', assignee: USER, last: 6 });
    await ins(TENANT, { sev: 'critical', status: 'closed', title: 'closed is ignored', assignee: USER });
    await ins(TENANT, { sev: 'critical', title: 'colleague alert', assignee: COLLEAGUE });
    await ins(TENANT, { sev: 'critical', title: 'unassigned', assignee: null });
    await ins(OTHER, { sev: 'critical', title: 'other tenant', assignee: FOREIGN_USER });
    for (let i = 0; i < 4; i++) await ins(TENANT, { sev: 'medium', title: 'medium ' + i, assignee: USER, last: 10 + i });   // 8 active in total, only 5 listed

    r = await get();
    assert.strictEqual(r.json.active_total, 8, 'closed, colleague, unassigned and other-tenant alerts are not mine');
    assert.deepStrictEqual(r.json.active, { critical: 1, high: 2, medium: 4, low: 1 });
    assert.strictEqual(r.json.open, 7); assert.strictEqual(r.json.acknowledged, 1);
    assert.ok(r.json.oldest_open_at, 'oldest open alert is reported');
    assert.strictEqual(r.json.alerts.length, 5);
    assert.deepStrictEqual(r.json.alerts.slice(0, 4).map((a) => a.title), ['critical open', 'high open', 'high acknowledged', 'medium 0'], 'worst severity first, open before acknowledged, newest first');
    assert.strictEqual(r.json.alerts[0].id, crit); assert.ok(r.json.alerts.every((a) => [low, hiAck, hiOpen, crit].includes(a.id) || /^medium/.test(a.title)));
    console.log('my-alerts-db: all checks passed');
  } finally {
    srv.close();
    await db.query('DELETE FROM alerts WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]);
    await db.query('DELETE FROM users WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]);
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]);
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
