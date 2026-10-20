'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/parse-alert-db.test.js
// Skips itself otherwise. The unparsed-events alert limit saved from the portal: the real routes, the real settings table, the real event store, the
// real alerts table and the watchdog's real cycle. Only the sign-in chain is replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };
const { getEventStore } = require('../src/events');
const pw = require('../src/ingestion/parse-watch');
const wd = require('../src/collectors/watchdog');

const MIN = 60000;
const bad = (age, reason) => ({ source_type: 'syslog', collector_id: null, raw: 'line', parsed: { _parse_error: reason }, received_at: new Date(Date.now() - age).toISOString() });

async function main() {
  const stamp = Date.now();
  const A = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['pa-a-' + stamp])).rows[0].id;
  const B = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['pa-b-' + stamp])).rows[0].id;
  TENANT = A;
  const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/parser-alert'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const alerts = async (t) => (await db.query('SELECT id, status, title, details FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at, id', [t, pw.RULE_NAME])).rows;
  const notes = async (id) => (await db.query('SELECT author_name, body FROM alert_notes WHERE alert_id = $1', [id])).rows;
  const store = getEventStore();
  const savedEnv = { m: process.env.ASIX_PARSE_ALERT_MIN_EVENTS, w: process.env.ASIX_PARSE_ALERT_WINDOW_MIN };
  delete process.env.ASIX_PARSE_ALERT_MIN_EVENTS; delete process.env.ASIX_PARSE_ALERT_WINDOW_MIN;
  try {
    // 6 unparsed events in the last 10 minutes for both tenants
    for (const t of [A, B]) await store.insertBatch(t, Array.from({ length: 6 }, (_, i) => bad((i + 1) * MIN, 'PARSE_TIMEOUT')));

    // nothing saved, server off: follows the server, raises nothing
    let r = await call('GET', '/v1/parser/alert'); assert.strictEqual(r.json.settings.source, 'server'); assert.strictEqual(r.json.settings.enabled, false);
    assert.deepStrictEqual(await pw.runTenant(A), { raised: 0, closed: 0 });

    // save a limit of 5 in 15 minutes for A only: A raises one alert, B (no row, server off) nothing
    r = await call('PUT', '/v1/parser/alert', { min_events: 5, window_min: 15 }); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.settings.source, 'tenant');
    assert.strictEqual((await db.query('SELECT count(*)::int AS n FROM parse_alert_settings WHERE tenant_id = $1', [A])).rows[0].n, 1);
    assert.strictEqual((await db.query('SELECT updated_by FROM parse_alert_settings WHERE tenant_id = $1', [A])).rows[0].updated_by, 'tester');
    assert.deepStrictEqual(await pw.runTenant(A), { raised: 1, closed: 0 });
    assert.deepStrictEqual(await pw.runTenant(B), { raised: 0, closed: 0 });
    let al = await alerts(A); assert.strictEqual(al.length, 1); assert.strictEqual(al[0].title, 'Events stored unparsed: 6 in 15 minutes'); assert.strictEqual(al[0].details.threshold, 5);
    assert.strictEqual((await alerts(B)).length, 0);

    // another tenant does not see it; a second save updates the same row
    TENANT = B; assert.strictEqual((await call('GET', '/v1/parser/alert')).json.settings.source, 'server');
    TENANT = A; r = await call('PUT', '/v1/parser/alert', { min_events: 8 }); assert.strictEqual(r.json.settings.window_min, 15, 'window kept');
    assert.strictEqual((await db.query('SELECT count(*)::int AS n FROM parse_alert_settings WHERE tenant_id = $1', [A])).rows[0].n, 1);
    // a limit above the count closes the open alert with an ASIX note
    assert.deepStrictEqual(await pw.runTenant(A), { raised: 0, closed: 1 });
    al = await alerts(A); assert.strictEqual(al[0].status, 'closed'); assert.strictEqual(al[0].details.closed_by, 'asix');
    const n = await notes(al[0].id); assert.strictEqual(n[0].author_name, 'ASIX'); assert.match(n[0].body, /below the limit/);

    // the saved limit wins over a server setting that is on, and 0 means off for this tenant only
    process.env.ASIX_PARSE_ALERT_MIN_EVENTS = '3';
    assert.deepStrictEqual(await pw.runTenant(B), { raised: 1, closed: 0 }, 'B follows the server setting (3)');
    assert.deepStrictEqual(await pw.runTenant(A), { raised: 0, closed: 0 }, 'A has its own limit (8), not the server 3');
    await call('PUT', '/v1/parser/alert', { min_events: 0 });
    assert.deepStrictEqual(await pw.runTenant(A), { raised: 0, closed: 0 }, 'off for A although the server is on');
    r = await call('GET', '/v1/parser/alert'); assert.strictEqual(r.json.settings.enabled, false); assert.strictEqual(r.json.settings.server.enabled, true);

    // follow the server again: A's 6 events reach the server's 3, and the older alert was closed by ASIX, so one is raised at once
    r = await call('PUT', '/v1/parser/alert', { follow_server: true }); assert.strictEqual(r.json.settings.source, 'server');
    assert.strictEqual((await db.query('SELECT count(*)::int AS n FROM parse_alert_settings WHERE tenant_id = $1', [A])).rows[0].n, 0);
    assert.deepStrictEqual(await pw.runTenant(A), { raised: 1, closed: 0 });
    // turning it off from the portal closes the open one
    await call('PUT', '/v1/parser/alert', { min_events: 0 });
    assert.deepStrictEqual(await pw.runTenant(A), { raised: 0, closed: 1 });

    // refused bodies write nothing, and the database itself refuses out-of-range values
    for (const b of [{ min_events: -1 }, { min_events: 5, window_min: 4 }, { min_events: 1000001 }, { follow_server: true, min_events: 1 }]) assert.strictEqual((await call('PUT', '/v1/parser/alert', b)).status, 400, JSON.stringify(b));
    await assert.rejects(() => db.withTenant(A, (c) => c.query('UPDATE parse_alert_settings SET min_events = -1 WHERE tenant_id = $1', [A])), /violates check/);
    await assert.rejects(() => db.withTenant(A, (c) => c.query('UPDATE parse_alert_settings SET window_min = 4 WHERE tenant_id = $1', [A])), /violates check/);
    assert.strictEqual((await db.query('SELECT min_events FROM parse_alert_settings WHERE tenant_id = $1', [A])).rows[0].min_events, 0, 'still the last good save');

    // the watchdog's real cycle reads the saved limit without error
    await call('PUT', '/v1/parser/alert', { min_events: 5, window_min: 15 });
    const t1 = await wd.runOnce({ raiseAllowed: true }); assert.strictEqual(t1.errors, 0);
    assert.ok((await alerts(A)).some((a) => a.status === 'open'), 'raised through the real cycle');

    // a database without the table: the page says so, the watchdog carries on with the server setting and logs nothing fatal
    await db.query('ALTER TABLE parse_alert_settings RENAME TO parse_alert_settings_away');
    try {
      r = await call('GET', '/v1/parser/alert'); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.settings.available, false);
      assert.strictEqual((await call('PUT', '/v1/parser/alert', { min_events: 5 })).status, 503);
      assert.strictEqual((await wd.runOnce({ raiseAllowed: true })).errors, 0);
      assert.strictEqual((await pw.tenantConfig(A)).source, 'server');
    } finally { await db.query('ALTER TABLE parse_alert_settings_away RENAME TO parse_alert_settings'); }
    console.log('parse-alert-db: all checks passed');
  } finally {
    srv.close();
    if (savedEnv.m === undefined) delete process.env.ASIX_PARSE_ALERT_MIN_EVENTS; else process.env.ASIX_PARSE_ALERT_MIN_EVENTS = savedEnv.m;
    if (savedEnv.w === undefined) delete process.env.ASIX_PARSE_ALERT_WINDOW_MIN; else process.env.ASIX_PARSE_ALERT_WINDOW_MIN = savedEnv.w;
    await db.query('ALTER TABLE IF EXISTS parse_alert_settings_away RENAME TO parse_alert_settings').catch(() => {});
    for (const t of ['alert_notes', 'alerts', 'parse_alert_settings', 'events']) await db.query(`DELETE FROM ${t} WHERE tenant_id = ANY($1)`, [[A, B]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[A, B]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
