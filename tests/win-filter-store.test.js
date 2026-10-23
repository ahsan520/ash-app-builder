'use strict';
// The saved Windows filter policy (src/endpoints/win-filter-store.js, src/gateway/routes/win-filter.js, docs/endpoints.md task E2): the request rules, the view, the preview, and
// the three routes with the sign-in chain and the database replaced by a recorder. The real table is covered by tests/win-filter-db.test.js (needs Postgres).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const store = require('../src/endpoints/win-filter-store');
const wf = require('../src/endpoints/win-filter');

const POLICY = { rules: [{ id: 'a', action: 'drop', channel: 'Security', event_ids: [4656, ' 4700-4710 ', '4720-4720'] }], strip_message: true };

describe('parseBody', () => {
  it('clear on its own removes the policy', () => assert.deepStrictEqual(store.parseBody({ clear: true }), { clear: true }));
  it('a policy is validated, normalised and returned in the stored shape', () => {
    const b = store.parseBody({ policy: POLICY, if_revision: '3' });
    assert.strictEqual(b.if_revision, 3);
    assert.deepStrictEqual(b.canonical.rules[0].event_ids, [4656, '4700-4710', 4720]);
    assert.deepStrictEqual(wf.validate(b.canonical).policy, b.policy);               // reading it back gives the same policy
    assert.strictEqual(store.parseBody({ policy: {} }).if_revision, null);
    for (const x of [null, undefined, '']) assert.strictEqual(store.parseBody({ policy: {}, if_revision: x }).if_revision, null);
    assert.strictEqual(store.parseBody({ policy: {}, if_revision: 0 }).if_revision, 0);
  });
  it('refuses everything else, with a reason', () => {
    for (const x of [null, undefined, [], 'x', {}, { other: 1 }]) assert.match(store.parseBody(x).error, /Send \{ "policy"/);
    assert.match(store.parseBody({ clear: false }).error, /clear can only be true/);
    assert.match(store.parseBody({ clear: true, policy: {} }).error, /on its own/); assert.match(store.parseBody({ clear: true, if_revision: 1 }).error, /on its own/);
    for (const x of [-1, 1.5, 'abc', '01', true, {}, 2147483648]) assert.match(store.parseBody({ policy: {}, if_revision: x }).error, /if_revision/, String(x));
    assert.match(store.parseBody({ policy: { rules: [{ id: 'A', action: 'x' }] } }).error, /rule 1: id.*rule 1: action/);
    assert.match(store.parseBody({ policy: { rules: Array.from({ length: 8 }, () => ({ id: 'A', action: 'drop' })) } }).error, /and \d+ more\)$/);   // long lists are cut
    assert.match(store.parseBody({ policy: 5 }).error, /must be an object/);
  });
});

describe('parseEvents', () => {
  it('accepts sample events and fills the missing parts', () => {
    assert.deepStrictEqual(store.parseEvents(undefined), { events: [] });
    assert.deepStrictEqual(store.parseEvents([{ channel: 'Security', event_id: 4624 }]), { events: [{ channel: 'Security', event_id: 4624, fields: {}, message: undefined }] });
    assert.deepStrictEqual(store.parseEvents([{ channel: 'S', event_id: 1, fields: { A: 'x', B: 2 }, message: 'm' }]).events[0].fields, { A: 'x', B: 2 });
  });
  it('refuses bad ones and says which', () => {
    const e = (x) => store.parseEvents(x).error;
    assert.match(e({}), /list of at most 50/); assert.match(e(Array(51).fill({ channel: 'S', event_id: 1 })), /at most 50/);
    assert.match(e([null]), /event 1 must be an object/); assert.match(e([{ channel: 5, event_id: 1 }]), /event 1: channel/); assert.match(e([{ channel: 'a'.repeat(65), event_id: 1 }]), /channel/);
    for (const id of [-1, 65536, 1.5, '4624', null]) assert.match(e([{ channel: 'S', event_id: id }]), /event_id/, String(id));
    assert.match(e([{ channel: 'S', event_id: 1 }, { channel: 'S', event_id: 1, fields: [] }]), /event 2: fields/);
    assert.match(e([{ channel: 'S', event_id: 1, fields: { A: {} } }]), /field A/); assert.match(e([{ channel: 'S', event_id: 1, message: 5 }]), /message/);
    assert.match(e([{ channel: 'S', event_id: 1, message: 'x'.repeat(20001) }]), /20000/);
  });
});

describe('view, outputs, preview', () => {
  it('no row: not configured, revision 0, the empty policy, and the suggested preset', () => {
    const v = store.view(null);
    assert.deepStrictEqual([v.available, v.configured, v.invalid, v.revision, v.updated_at], [true, false, false, 0, null]);
    assert.deepStrictEqual(v.policy, { version: 1, default: 'keep', channels: {}, strip_message: false, rules: [], message_strip: [] });
    assert.strictEqual(v.preset.rules[0].id, 'noisy-security'); assert.strictEqual(v.limits.rules, 200);
    assert.strictEqual(store.view(null, true).available, false);
  });
  it('a row: the stored policy, its revision and time; a stored policy that no longer validates is flagged, not shown', () => {
    const b = store.parseBody({ policy: POLICY });
    const v = store.view({ policy: b.canonical, revision: 4, updated_at: '2026-10-23T10:00:00Z' });
    assert.deepStrictEqual([v.configured, v.invalid, v.revision, v.updated_at, v.policy], [true, false, 4, '2026-10-23T10:00:00.000Z', b.canonical]);
    const x = store.view({ policy: { default: 'maybe' }, revision: 2, updated_at: null });
    assert.deepStrictEqual([x.configured, x.invalid, x.revision, x.policy.rules], [true, true, 2, []]);
  });
  it('the agent.conf covers the usual channels plus every channel the policy names, without repeating one', () => {
    const p = wf.validate({ channels: { 'application': { default: 'keep' } }, rules: [{ id: 'a', action: 'drop', channel: 'Microsoft-Windows-Sysmon/Operational' }, { id: 'b', action: 'drop', channel: 'security' }], message_strip: [{ channel: 'Setup', regex: 'x' }] }).policy;
    assert.deepStrictEqual(store.channelsOf(p), ['Security', 'System', 'Application', 'Microsoft-Windows-Sysmon/Operational', 'Setup']);
    const o = store.outputs(wf.validate(POLICY).policy);
    assert.match(o.vector, /^\[transforms\.asix_win_filter\]/); assert.match(o.agent_conf, /<location>Security<\/location>[\s\S]*<query>Event\/System\[/);
    assert.deepStrictEqual(Object.keys(o.xpath), ['Security', 'System', 'Application']); assert.strictEqual(o.xpath.System.query, null);
  });
  it('preview gives the outputs and what each sample event would do', () => {
    const ev = store.parseEvents([{ channel: 'Security', event_id: 4705, message: 'm' }, { channel: 'Security', event_id: 4624, message: 'm' }, { channel: 'System', event_id: 1 }]).events;
    const r = store.preview(wf.validate(POLICY).policy, ev);
    assert.deepStrictEqual(r.results, [{ channel: 'Security', event_id: 4705, keep: false, rule_id: 'a', message: null }, { channel: 'Security', event_id: 4624, keep: true, rule_id: null, message: null },
      { channel: 'System', event_id: 1, keep: true, rule_id: null, message: null }]);
    assert.strictEqual(r.ok, true); assert.deepStrictEqual(wf.validate(r.policy).errors, []);
  });
});

describe('the routes', () => {
  const TENANT = '11111111-1111-1111-1111-111111111111', perms = [], sqls = [], writes = [], clears = [];
  let row = null, srv, base, failWith = null;
  const fakeDb = { withTenant: async (t, fn) => { if (failWith) throw failWith; return fn({ query: async (sql, args) => {
    sqls.push(sql);
    if (/^SELECT .* FROM win_filter_policy/.test(sql)) return { rows: row ? [{ ...row }] : [] };
    if (/^INSERT INTO win_filter_policy/.test(sql)) { writes.push({ args }); row = { policy: JSON.parse(args[1]), revision: row ? row.revision + 1 : 1, updated_at: new Date('2026-10-23T10:00:00Z'), by: args[2] }; return { rows: [] }; }
    if (/^DELETE FROM win_filter_policy/.test(sql)) { clears.push(args); row = null; return { rows: [] }; }
    throw new Error('unexpected sql ' + sql);
  } }); }, query: async () => ({ rows: [] }) };
  const shared = require('../src/gateway/shared'), saved = require.cache[require.resolve('../src/gateway/shared')].exports;
  before(async () => {
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: fakeDb, guarded: (p) => { perms.push(p); return [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'u1'; next(); }]; } };
    delete require.cache[require.resolve('../src/gateway/routes/win-filter')];
    const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/win-filter'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = saved; delete require.cache[require.resolve('../src/gateway/routes/win-filter')]; });
  const call = async (method, p, body) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const put = (b) => call('PUT', '/v1/endpoints/win-filter', b), get = () => call('GET', '/v1/endpoints/win-filter');

  it('each route asks for the permission it should: read and preview capacity:read, save parsing:rules:write', () => {
    assert.deepStrictEqual([...perms].sort(), ['capacity:read', 'capacity:read', 'parsing:rules:write']);
  });
  it('nothing saved: GET says so; saving stores the policy in the shown shape and counts the revision up', async () => {
    let r = await get(); assert.deepStrictEqual([r.status, r.json.settings.configured, r.json.settings.revision], [200, false, 0]);
    r = await put({ policy: POLICY }); assert.strictEqual(r.status, 200);
    assert.deepStrictEqual([r.json.settings.configured, r.json.settings.revision, r.json.settings.policy.rules[0].event_ids], [true, 1, [4656, '4700-4710', 4720]]);
    assert.deepStrictEqual([writes.length, writes[0].args[0], writes[0].args[2]], [1, TENANT, 'u1']);
    r = await put({ policy: { default: 'keep' } }); assert.strictEqual(r.json.settings.revision, 2); assert.strictEqual(r.json.settings.policy.rules.length, 0);
    assert.strictEqual((await get()).json.settings.revision, 2);
  });
  it('a save based on an old revision is refused with 409 and writes nothing; the right one, or none, goes through', async () => {
    const n = writes.length, rev = row.revision;
    let r = await put({ policy: POLICY, if_revision: rev - 1 }); assert.deepStrictEqual([r.status, r.json.error.code], [409, 'WIN_FILTER_CHANGED']); assert.strictEqual(writes.length, n);
    r = await put({ policy: POLICY, if_revision: 0 }); assert.strictEqual(r.status, 409);                       // 0 means "none saved yet" and one is
    r = await put({ policy: POLICY, if_revision: rev }); assert.deepStrictEqual([r.status, r.json.settings.revision], [200, rev + 1]);
    await put({ clear: true }); r = await put({ policy: POLICY, if_revision: 0 }); assert.deepStrictEqual([r.status, r.json.settings.revision], [200, 1]);   // none saved, 0 is right
    r = await put({ policy: POLICY, if_revision: 5 }); assert.strictEqual(r.status, 409);
  });
  it('a save reads the row under lock first', async () => { sqls.length = 0; await put({ policy: POLICY }); assert.match(sqls[0], /FOR UPDATE$/); });
  it('an invalid policy is a 400 with the reasons and writes nothing', async () => {
    const n = writes.length, r = await put({ policy: { rules: [{ id: 'a', action: 'drop', match: { regex: '(?=x)' } }] } });
    assert.deepStrictEqual([r.status, r.json.error.code], [400, 'INVALID_WIN_FILTER']); assert.match(r.json.error.message, /rule 1: match.regex/); assert.strictEqual(writes.length, n);
    assert.strictEqual((await put({})).status, 400);
  });
  it('clear removes the policy: back to keeping everything', async () => {
    await put({ policy: POLICY }); const r = await put({ clear: true });
    assert.deepStrictEqual([r.status, r.json.settings.configured, r.json.settings.revision, clears.length > 0], [200, false, 0, true]);
  });
  it('preview: problems come back as data, a good policy gives the outputs and the sample results, bad samples are a 400, and the database is not touched', async () => {
    const n = sqls.length;
    let r = await call('POST', '/v1/endpoints/win-filter/preview', { policy: { rules: [{ id: 'A', action: 'drop' }] } });
    assert.deepStrictEqual([r.status, r.json.preview.ok], [200, false]); assert.match(r.json.preview.errors[0], /rule 1: id/);
    r = await call('POST', '/v1/endpoints/win-filter/preview', { policy: POLICY, events: [{ channel: 'Security', event_id: 4656 }] });
    assert.deepStrictEqual([r.json.preview.ok, r.json.preview.results[0].keep, r.json.preview.results[0].rule_id], [true, false, 'a']); assert.match(r.json.preview.outputs.vector, /abort/);
    r = await call('POST', '/v1/endpoints/win-filter/preview', { policy: POLICY, events: [{ channel: 'Security', event_id: 'x' }] }); assert.deepStrictEqual([r.status, r.json.error.code], [400, 'INVALID_WIN_FILTER']);
    r = await call('POST', '/v1/endpoints/win-filter/preview'); assert.strictEqual(r.json.preview.ok, true);       // no body: the empty policy
    assert.strictEqual(sqls.length, n);
  });
  it('a missing table is a notice on GET, a 503 on save; any other failure is a 500 that does not leak the cause', async () => {
    const e = new Error('no table'); e.code = '42P01'; failWith = e;
    let r = await get(); assert.deepStrictEqual([r.status, r.json.settings.available], [200, false]);
    r = await put({ policy: POLICY }); assert.deepStrictEqual([r.status, r.json.error.code], [503, 'WIN_FILTER_NOT_READY']);
    failWith = new Error('connection to 10.1.2.3 reset'); const log = console.error; console.error = () => {};
    try { r = await get(); assert.strictEqual(r.status, 500); assert.ok(!JSON.stringify(r.json).includes('10.1.2.3')); r = await put({ policy: POLICY }); assert.strictEqual(r.status, 500); assert.ok(!JSON.stringify(r.json).includes('10.1.2.3')); } finally { console.error = log; failWith = null; }
  });
});
