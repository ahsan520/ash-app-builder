'use strict';
// Detection rules, the IOC matcher and the alert detail page read events through the event store. This runs them
// end to end on real Postgres (the alerts, rules and scan state live there whichever engine holds the events).
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/detection-store-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const T_ID = { current: null };
const shared = require('../src/gateway/shared');
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = T_ID.current; next(); }] };
const alertRoutes = require('../src/gateway/routes/alerts');
const detectionRoutes = require('../src/gateway/routes/detections');
const { getEventStore } = require('../src/events');
const ioc = require('../src/detection/ioc-matcher');
const rules = require('../src/detection/rule-runner');

const ago = (min) => new Date(Date.now() - min * 60000).toISOString();

async function main() {
  const stamp = Date.now();
  const mk = async (n) => (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', [`detect-store-${n}-${stamp}`])).rows[0].id;
  const T = await mk('a'); const OTHER = await mk('b');
  T_ID.current = T;
  const store = getEventStore();
  const put = (tenant, ...evs) => store.insertBatch(tenant, evs.map((e) => (typeof e === 'string' ? { source_type: 'syslog', raw: e } : { source_type: 'syslog', ...e })));
  const alerts = async (name) => (await db.withTenant(T, (c) => c.query('SELECT * FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY group_key', [T, name]))).rows;
  const app = express(); app.use(express.json()); app.use(alertRoutes); app.use(detectionRoutes);
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, path, body) => { const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json' }, body: body && JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };

  try {
    // ---------------- detection rules ----------------
    const definition = { regex: 'Failed password', group_by: 'source_ip', threshold: 3, window_minutes: 30, run_every_minutes: 1, filters: [{ field: 'host', op: 'not_equals', value: 'bastion' }] };
    const rule = (await db.withTenant(T, (c) => c.query(
      "INSERT INTO detection_rules (tenant_id, name, severity, definition, kind, category) VALUES ($1, 'ssh test rule', 'high', $2::jsonb, 'correlation', 'Credential Access') RETURNING id", [T, JSON.stringify(definition)]))).rows[0];
    const failed = (ip, min, host) => ({ raw: `Failed password for root from ${ip} port 22`, received_at: ago(min), parsed: { host } });
    await put(T,
      failed('203.0.113.9', 1, 'web01'), failed('203.0.113.9', 2, 'web01'), failed('203.0.113.9', 3, 'web02'), failed('203.0.113.9', 4, 'web01'),   // 4 events: above the threshold
      failed('198.51.100.7', 2, 'web01'), failed('198.51.100.7', 3, 'web01'),                                   // 2 events: below
      failed('192.0.2.1', 1, 'bastion'), failed('192.0.2.1', 2, 'bastion'), failed('192.0.2.1', 3, 'bastion'),   // excluded by the not_equals filter
      failed('203.0.113.9', 90, 'web01'),                                                                         // outside the 30 minute window
      { raw: 'Accepted publickey from 203.0.113.9', received_at: ago(1), parsed: { host: 'web01' } });
    await put(OTHER, failed('203.0.113.9', 1, 'web01'), failed('203.0.113.9', 2, 'web01'), failed('203.0.113.9', 3, 'web01'), failed('10.9.9.9', 1, 'web01'));

    let r = await rules.runTenant(T);
    assert.strictEqual(r.errors, 0, 'no rule failed');
    let a = await alerts('ssh test rule');
    assert.strictEqual(a.length, 1, 'only the 203.0.113.9 group reaches the threshold');
    assert.strictEqual(a[0].group_key, '203.0.113.9'); assert.strictEqual(a[0].event_count, 4);
    assert.strictEqual(a[0].details.sample_event_ids.length, 4);
    assert.ok(/Failed password/.test(a[0].details.sample_raw));
    assert.ok(a[0].first_event_at && a[0].last_event_at);
    assert.strictEqual((await db.query('SELECT last_error FROM detection_rules WHERE id = $1', [rule.id])).rows[0].last_error, null);

    // the alert detail page loads the sample events through the store, newest first
    const detail = await call('GET', '/v1/alerts/' + a[0].id);
    assert.strictEqual(detail.status, 200);
    assert.deepStrictEqual(detail.json.events.map((e) => e.id).sort(), [...a[0].details.sample_event_ids].sort());
    const times = detail.json.events.map((e) => Date.parse(e.event_time || e.received_at));
    assert.deepStrictEqual(times, [...times].sort((x, y) => y - x), 'newest first');
    assert.deepStrictEqual(Object.keys(detail.json.events[0]).sort(), ['collector_id', 'event_time', 'id', 'raw', 'received_at', 'source_type']);

    // the rule test endpoint (what the portal's "Test" button calls)
    const test = await call('POST', '/v1/detections/rules/test', { definition });
    assert.strictEqual(test.status, 200); assert.strictEqual(test.json.alerts_would_raise, 1);
    assert.deepStrictEqual(test.json.groups.map((g) => [g.group, g.events]), [['203.0.113.9', 4]]);
    const bad = await call('POST', '/v1/detections/rules/test', { definition: { regex: '(a)\\1', threshold: 1 } });
    assert.strictEqual(bad.status, 400);

    // nothing leaks across tenants: the other tenant has its own 3 + 1 events and no rule of ours
    assert.strictEqual((await db.withTenant(OTHER, (c) => c.query("SELECT * FROM alerts WHERE tenant_id = $1 AND rule_name = 'ssh test rule'", [OTHER]))).rows.length, 0);

    // ---------------- IOC matcher ----------------
    await db.withTenant(T, (c) => c.query("INSERT INTO threat_indicators (tenant_id, type, value, source, severity) VALUES ($1,'ip','203.0.113.77','test','critical')", [T]));
    await put(OTHER, 'tenant B mentions 203.0.113.77');                       // must never be scanned for tenant A
    await put(T, 'sshd: connection from 203.0.113.77 port 22', 'nothing to see here', 'again 203.0.113.77 connected');
    const state = async () => (await db.query('SELECT * FROM ioc_scan_state WHERE tenant_id = $1', [T])).rows[0];

    let i = await ioc.runTenant(T);
    assert.ok(i.scanned >= 3, 'first run looks back over recent events of this tenant');
    assert.strictEqual(i.created, 1); assert.strictEqual(i.matches, 2);
    let ia = await alerts('IOC match');
    assert.strictEqual(ia.length, 1); assert.strictEqual(ia[0].event_count, 2); assert.strictEqual(ia[0].severity, 'critical');
    assert.strictEqual(ia[0].details.sample.event_ids.length, 2);
    assert.ok((await state()).last_event_id, 'place saved');

    assert.strictEqual((await ioc.runTenant(T)).scanned, 0, 'each event is examined exactly once');
    await put(T, 'late: 203.0.113.77 seen again', 'unrelated');
    i = await ioc.runTenant(T);
    assert.strictEqual(i.scanned, 2); assert.strictEqual(i.updated, 1); assert.strictEqual(i.created, 0);
    ia = await alerts('IOC match');
    assert.strictEqual(ia.length, 1); assert.strictEqual(ia[0].event_count, 3, 'the open alert absorbs the new match');

    // more events than one store page (1000): every one is read, in order, once
    await put(T, ...Array.from({ length: 2300 }, (_, k) => (k % 500 === 0 ? `bulk ${k} 203.0.113.77` : `bulk ${k}`)));
    i = await ioc.runTenant(T);
    assert.strictEqual(i.scanned, 2300); assert.strictEqual(i.matches, 5);
    assert.strictEqual((await alerts('IOC match'))[0].event_count, 8);
    assert.strictEqual((await ioc.runTenant(T)).scanned, 0);

    // an unreadable event store is an error for this tenant, and the saved place does not move
    const before = await state();
    const { setEventStore } = require('../src/events');
    const real = getEventStore();
    setEventStore({ scan: async () => { throw new Error('event store down'); } });
    await assert.rejects(ioc.runTenant(T), /event store down/);
    setEventStore(real);
    const after = await state();
    assert.strictEqual(String(after.last_event_id), String(before.last_event_id));
    console.log('detection reads through the event store (db): ok');
  } finally {
    srv.close();
    for (const t of [T, OTHER]) {
      await db.withTenant(t, (c) => c.query('DELETE FROM events WHERE tenant_id = $1', [t])).catch(() => {});
      for (const tbl of ['alerts', 'detection_rules', 'threat_indicators']) await db.withTenant(t, (c) => c.query(`DELETE FROM ${tbl} WHERE tenant_id = $1`, [t])).catch(() => {});
      await db.query('DELETE FROM ioc_scan_state WHERE tenant_id = $1', [t]).catch(() => {});
      await db.query('DELETE FROM tenants WHERE id = $1', [t]).catch(() => {});
    }
    await db.close();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
