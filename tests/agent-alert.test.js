'use strict';
// E4m: the settings rules (src/endpoints/agent-alert.js), the skip list in agent-watch's plan(), and the wiring. No database.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const aa = require('../src/endpoints/agent-alert');
const w = require('../src/endpoints/agent-watch');

const NOW = Date.parse('2026-10-30T12:00:00Z');
const ago = (m) => new Date(NOW - m * 60000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const agent = (id, min) => ({ id, name: 'pc-' + id, ip: '10.0.0.' + Number(id), status: 'disconnected', last_keep_alive: ago(min), os: { name: 'Windows 11' }, groups: [] });
const cfg = { minutes: 30 };

describe('checkMinutes', () => {
  it('accepts 0 and 5 to 10080, as a number or digits; refuses everything else', () => {
    for (const v of [0, '0', 5, '5', ' 60 ', 10080]) assert.strictEqual(aa.checkMinutes(v).value, Number(v), String(v));
    for (const v of [1, 4, 10081, -5, 5.5, '5.5', '', null, undefined, 'abc', '05', '1e3', [30], {}, true]) assert.ok(aa.checkMinutes(v).error, String(v));
  });
});

describe('parseBody', () => {
  it('knows exactly three shapes', () => {
    assert.deepStrictEqual(aa.parseBody({ minutes: 60 }), { minutes: 60 });
    assert.deepStrictEqual(aa.parseBody({ minutes: '0' }), { minutes: 0 });
    assert.deepStrictEqual(aa.parseBody({ follow_server: true }), { follow: true });
    assert.deepStrictEqual(aa.parseBody({ skip_agent: '002', skip: true }), { agent: '002', skip: true });
    assert.deepStrictEqual(aa.parseBody({ skip_agent: '12345678', skip: false }), { agent: '12345678', skip: false });
  });
  it('refuses mixes, wrong types and bad ids', () => {
    for (const b of [null, [], 'x', {}, { follow_server: false }, { follow_server: true, minutes: 5 }, { minutes: 60, skip_agent: '002', skip: true }, { minutes: 3 },
      { skip_agent: '2', skip: true }, { skip_agent: '123456789', skip: true }, { skip_agent: 2, skip: true }, { skip_agent: '0a2', skip: true }, { skip_agent: "002'; DROP", skip: true },
      { skip_agent: '002' }, { skip_agent: '002', skip: 'true' }, { skip: true }]) assert.ok(aa.parseBody(b).error, JSON.stringify(b));
  });
});

describe('resolve and view', () => {
  it('no row follows the server; a row with minutes wins (0 = off); a row with minutes null follows the server but keeps its list', () => {
    assert.deepStrictEqual(aa.resolve(null, { minutes: 45 }), { minutes: 45, source: 'server', skip: [] });
    assert.deepStrictEqual(aa.resolve({ minutes: 0, skip_agents: [] }, { minutes: 45 }), { minutes: 0, source: 'tenant', skip: [] });
    assert.deepStrictEqual(aa.resolve({ minutes: 90, skip_agents: ['002'] }, { minutes: 0 }), { minutes: 90, source: 'tenant', skip: ['002'] });
    assert.deepStrictEqual(aa.resolve({ minutes: null, skip_agents: ['002', '003'] }, { minutes: 45 }), { minutes: 45, source: 'server', skip: ['002', '003'] });
  });
  it('drops ids that are not agent ids from a stored list', () => {
    assert.deepStrictEqual(aa.resolve({ minutes: null, skip_agents: ['002', 'x', '', '1'] }, { minutes: 0 }).skip, ['002']);
  });
  it('view reports the source, whether it is on, the server value, the limits and a missing table', () => {
    const v = aa.view({ minutes: 60, skip_agents: ['002'], updated_at: '2026-10-30T10:00:00Z' }, { minutes: 0 });
    assert.deepStrictEqual([v.available, v.source, v.minutes, v.enabled, v.skip_agents, v.updated_at, v.server, v.limits], [true, 'tenant', 60, true, ['002'], '2026-10-30T10:00:00.000Z', { minutes: 0, enabled: false }, { minutes: [5, 10080], max_skip: 200 }]);
    assert.strictEqual(aa.view(null, { minutes: 0 }, true).available, false);
    assert.strictEqual(aa.view(null, { minutes: 0 }).enabled, false);
  });
});

describe('plan with a skip list', () => {
  it('a skipped agent raises nothing, the others still do', () => {
    const p = w.plan({ disconnected: [agent('002', 90), agent('003', 90)] }, cfg, { now: NOW, skip: ['002'] });
    assert.deepStrictEqual(p.raise.map((r) => r.agent_id), ['003']);
  });
  it('an open alert of a skipped agent is closed with a reason, even while the agent is still down', () => {
    const active = [{ id: 'a1', group_key: 'endpointagent:002' }, { id: 'a2', group_key: 'endpointagent:003' }];
    const p = w.plan({ disconnected: [agent('002', 90), agent('003', 90)], active }, cfg, { now: NOW, skip: ['002'] });
    assert.deepStrictEqual(p.raise, []);
    assert.strictEqual(p.close.length, 1); assert.strictEqual(p.close[0].alert_id, 'a1'); assert.match(p.close[0].reason, /set not to raise/);
  });
  it('no skip list behaves as before', () => {
    assert.strictEqual(w.plan({ disconnected: [agent('002', 90)] }, cfg, { now: NOW }).raise.length, 1);
    assert.strictEqual(w.plan({ disconnected: [agent('002', 90)] }, cfg, { now: NOW, skip: [] }).raise.length, 1);
  });
  it('off still closes everything, skip list or not', () => {
    const p = w.plan({ active: [{ id: 'a1', group_key: 'endpointagent:002' }] }, { minutes: 0 }, { now: NOW, skip: ['002'] });
    assert.match(p.close[0].reason, /turned off/);
  });
});

describe('wiring', () => {
  const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
  it('the route is registered, the schema has the table with row security, CI runs the database test', () => {
    assert.match(read('src/gateway/index.js'), /routes\/agent-alert/);
    const schema = read('k8s/12-schema-init.yaml');
    for (const t of ['CREATE TABLE IF NOT EXISTS agent_watch_settings', 'ALTER TABLE agent_watch_settings ENABLE ROW LEVEL SECURITY', 'GRANT SELECT, INSERT, UPDATE, DELETE ON agent_watch_settings']) assert.ok(schema.includes(t), t);
    assert.match(read('.github/workflows/ci.yml'), /agent-alert-db/);
  });
  it('the route reads with capacity:read and writes with parsing:rules:write', () => {
    const r = read('src/gateway/routes/agent-alert.js');
    assert.match(r, /router\.get\('\/v1\/endpoints\/agent-alert', \.\.\.guarded\('capacity:read'\)/);
    assert.match(r, /router\.put\('\/v1\/endpoints\/agent-alert', \.\.\.guarded\('parsing:rules:write'\)/);
  });
});
