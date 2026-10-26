'use strict';
// Unit tests (no database): merge planning rules and the request validation of the dedupe routes.
// The database behaviour is covered by tests/alert-dedupe-db.test.js (needs ASIX_TEST_DB=1).
const test = require('node:test');
const assert = require('assert');
const path = require('path');
const express = require('express');

const D = require('../src/alerts/dedupe');

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';
const U1 = '44444444-4444-4444-8444-444444444444';
const U2 = '55555555-5555-4555-8555-555555555555';
const RULE = '66666666-6666-4666-8666-666666666666';
const alert = (o) => ({ id: A, rule_id: RULE, rule_name: 'SSH brute force', group_key: '203.0.113.9', severity: 'medium',
  status: 'open', event_count: 5, merged_count: 0, assignee_id: null, last_event_at: '2026-10-13T10:00:00Z', ...o });

test('identity: same rule + group match, anything else does not', () => {
  assert.strictEqual(D.identity(alert()), D.identity(alert({ id: B, title: 'other' })));
  assert.notStrictEqual(D.identity(alert()), D.identity(alert({ group_key: '203.0.113.10' })));
  assert.notStrictEqual(D.identity(alert()), D.identity(alert({ rule_id: B })));
  // renamed rule keeps the same identity because rule_id wins over rule_name
  assert.strictEqual(D.identity(alert()), D.identity(alert({ rule_name: 'Renamed' })));
  // IOC alerts have no rule_id: fall back to the name, and never collide with a rule_id alert
  const ioc = alert({ rule_id: null, rule_name: 'IOC match', group_key: 'ioc:ip:1.2.3.4' });
  assert.strictEqual(D.identity(ioc), D.identity({ ...ioc, id: B }));
  assert.notStrictEqual(D.identity(ioc), D.identity(alert({ rule_id: null, rule_name: 'IOC match', group_key: 'ioc:ip:1.2.3.5' })));
});

test('severity: the worst one wins, unknown values never beat a known one', () => {
  assert.strictEqual(D.worstSeverity([alert({ severity: 'low' }), alert({ severity: 'high' }), alert({ severity: 'medium' })]), 'high');
  assert.strictEqual(D.worstSeverity([alert({ severity: 'critical' }), alert({ severity: 'low' })]), 'critical');
  assert.strictEqual(D.worstSeverity([alert({ severity: 'low' })]), 'low');
  assert.strictEqual(D.worstSeverity([alert({ severity: 'weird' }), alert({ severity: 'low' })]), 'low');
});

test('status: an open repeat is never hidden behind an acknowledged primary', () => {
  assert.strictEqual(D.mergedStatus([alert({ status: 'acknowledged' }), alert({ status: 'open' })]), 'open');
  assert.strictEqual(D.mergedStatus([alert({ status: 'acknowledged' }), alert({ status: 'acknowledged' })]), 'acknowledged');
  assert.strictEqual(D.mergedStatus([alert({ status: 'open' }), alert({ status: 'open' })]), 'open');
});

test('assignee: primary keeps its owner, otherwise the most recently active owner', () => {
  const p = alert({ assignee_id: U1 });
  assert.strictEqual(D.mergedAssignee(p, [alert({ id: B, assignee_id: U2 })]), U1);
  const none = alert();
  assert.strictEqual(D.mergedAssignee(none, [alert({ id: B })]), null);
  const older = alert({ id: B, assignee_id: U1, last_event_at: '2026-10-13T09:00:00Z' });
  const newer = alert({ id: C, assignee_id: U2, last_event_at: '2026-10-13T11:00:00Z' });
  assert.strictEqual(D.mergedAssignee(none, [older, newer]), U2);
});

test('planMerge: merged_count counts each absorbed alert plus what it had absorbed', () => {
  const primary = alert({ merged_count: 2 });
  const plan = D.planMerge(primary, [alert({ id: B, merged_count: 0 }), alert({ id: C, merged_count: 3, severity: 'critical', status: 'acknowledged' })]);
  assert.strictEqual(plan.merged_count, 2 + 1 + (1 + 3));
  assert.strictEqual(plan.severity, 'critical');
  assert.strictEqual(plan.status, 'open');
  assert.strictEqual(D.planMerge(alert(), [alert({ id: B })]).merged_count, 1);
});

// ---- route validation: every rejection happens before the database is touched ---------------------
// Replace the shared helpers so the routes need no Keycloak, and make any database access fail loudly.
const sharedPath = path.resolve(__dirname, '..', 'src', 'gateway', 'shared.js');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
let dbTouched = 0;
require.cache[sharedPath] = {
  id: sharedPath, filename: sharedPath, loaded: true,
  exports: {
    db: { withTenant: async () => { dbTouched += 1; throw new Error('database must not be reached'); } },
    guarded: () => [(req, res, next) => { req.tenant_id = 'tenant'; next(); }],
    UUID_RE,
    apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }),
  },
};
const router = require('../src/gateway/routes/alert-dedupe');

test('merge route rejects bad input before touching the database', async () => {
  const app = express(); app.use(express.json()); app.use(router);
  const srv = app.listen(0);
  const base = 'http://127.0.0.1:' + srv.address().port;
  const post = async (body) => { const r = await fetch(base + '/v1/alerts/merge', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return [r.status, (await r.json()).error]; };
  try {
    assert.strictEqual((await post({}))[0], 400);
    assert.strictEqual((await post({ primary_id: 'nope', ids: [B] }))[0], 400);
    assert.strictEqual((await post({ primary_id: A }))[0], 400);
    assert.strictEqual((await post({ primary_id: A, ids: [] }))[0], 400);
    assert.strictEqual((await post({ primary_id: A, ids: ['x'] }))[0], 400);
    assert.strictEqual((await post({ primary_id: A, ids: [B, 7] }))[0], 400);
    const many = Array.from({ length: 201 }, (_, i) => '00000000-0000-4000-8000-' + String(i).padStart(12, '0'));
    const [status, err] = await post({ primary_id: A, ids: many });
    assert.strictEqual(status, 400); assert.strictEqual(err.code, 'TOO_MANY');
    const r = await fetch(base + '/v1/alerts/not-a-uuid/merged'); assert.strictEqual(r.status, 400);
    assert.strictEqual(dbTouched, 0);
  } finally { srv.close(); }
});
