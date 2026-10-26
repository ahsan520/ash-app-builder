'use strict';
// Broker key watch (src/collectors/key-watch.js): the pure planning rules and the SQL it sends (database replaced by a recorder).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const kw = require('../src/collectors/key-watch');

const br = (o = {}) => ({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', key_id: 'k1', key_status: 'active', key_name: 'broker-1-key', key_prefix: 'asix_ik_abc', ...o });
const P = (o, opts) => kw.plan({ brokers: [br()], active: [], latest: [], ...o }, opts);

describe('plan: raising', () => {
  it('raises nothing for a broker on an active key', () => assert.deepStrictEqual(P(), { raise: [], close: [] }));
  it('raises one alert for a revoked key, naming the key', () => {
    const p = P({ brokers: [br({ key_status: 'revoked' })] });
    assert.strictEqual(p.raise.length, 1);
    assert.deepStrictEqual(p.raise[0], { broker_id: 'b1', name: 'broker-1', group_key: 'brokerkey:b1', key_ref: 'revoked:k1', why: 'its installer key (broker-1-key) is revoked' });
  });
  it('raises one alert for a deleted key (no key_id)', () => {
    const p = P({ brokers: [br({ key_id: null, key_status: null })] });
    assert.strictEqual(p.raise[0].key_ref, 'deleted'); assert.match(p.raise[0].why, /deleted/);
  });
  it('ignores a collector that is not a broker', () => {
    assert.deepStrictEqual(P({ brokers: [br({ version: '1.2.3', key_status: 'revoked' })] }), { raise: [], close: [] });
  });
  it('does not raise while an alert is open or acknowledged', () => {
    for (const status of ['open', 'acknowledged']) {
      const p = P({ brokers: [br({ key_status: 'revoked' })], active: [{ id: 'a1', group_key: 'brokerkey:b1' }], latest: [{ group_key: 'brokerkey:b1', status, key_ref: 'revoked:k1' }] });
      assert.deepStrictEqual(p, { raise: [], close: [] }, status);
    }
  });
  it('does not raise again for the same key after an analyst closed the alert', () => {
    assert.deepStrictEqual(P({ brokers: [br({ key_status: 'revoked' })], latest: [{ group_key: 'brokerkey:b1', status: 'closed', key_ref: 'revoked:k1' }] }), { raise: [], close: [] });
  });
  it('raises again when it is a different key problem (new key revoked, or the key was deleted)', () => {
    const closed = [{ group_key: 'brokerkey:b1', status: 'closed', key_ref: 'revoked:old' }];
    assert.strictEqual(P({ brokers: [br({ key_status: 'revoked' })], latest: closed }).raise.length, 1);
    assert.strictEqual(P({ brokers: [br({ key_id: null, key_status: null })], latest: closed }).raise.length, 1);
  });
  it('raises nothing during the start-up grace, but still closes', () => {
    const p = P({ brokers: [br({ key_status: 'revoked' }), br({ id: 'b2', name: 'b2' })], active: [{ id: 'a2', group_key: 'brokerkey:b2' }] }, { raiseAllowed: false });
    assert.strictEqual(p.raise.length, 0); assert.deepStrictEqual(p.close.map((c) => c.alert_id), ['a2']);
  });
});

describe('plan: closing', () => {
  it('closes when the broker is on an active key again (rotation finished)', () => {
    const p = P({ active: [{ id: 'a1', group_key: 'brokerkey:b1' }] });
    assert.deepStrictEqual(p.close, [{ alert_id: 'a1', reason: 'The broker is on an active installer key again.' }]);
  });
  it('closes when the broker is no longer watched or was deleted (not in the watched list)', () => {
    const p = P({ brokers: [], active: [{ id: 'a1', group_key: 'brokerkey:gone' }] });
    assert.match(p.close[0].reason, /no longer watched or was removed/);
  });
  it('keeps the alert while the key is still bad', () => {
    const p = P({ brokers: [br({ key_status: 'revoked' })], active: [{ id: 'a1', group_key: 'brokerkey:b1' }], latest: [{ group_key: 'brokerkey:b1', status: 'open', key_ref: 'revoked:k1' }] });
    assert.deepStrictEqual(p, { raise: [], close: [] });
  });
});

describe('runTenant (database replaced)', () => {
  const dbPath = require.resolve('../src/db');
  const saved = require.cache[dbPath].exports;
  let calls, rows;
  before(() => {
    require.cache[dbPath].exports = { ...saved, withTenant: async (t, fn) => fn({ query: async (sql, args) => {
      calls.push({ sql, args });
      if (/FROM collectors/.test(sql)) return { rows: rows.brokers };
      if (/status IN \('open','acknowledged'\)/.test(sql)) return { rows: rows.active };
      if (/DISTINCT ON/.test(sql)) return { rows: rows.latest };
      return { rows: [] };
    } }) };
    delete require.cache[require.resolve('../src/collectors/key-watch')];
  });
  after(() => { require.cache[dbPath].exports = saved; delete require.cache[require.resolve('../src/collectors/key-watch')]; });

  it('only reads watched brokers, then raises and closes what plan() says', async () => {
    calls = []; rows = { brokers: [br({ key_status: 'revoked' })], active: [{ id: 'old', group_key: 'brokerkey:gone' }], latest: [] };
    const r = await require('../src/collectors/key-watch').runTenant('t1', { sev: 'high' });
    assert.deepStrictEqual(r, { raised: 1, closed: 1 });
    const sel = calls.find((c) => /FROM collectors/.test(c.sql));
    assert.match(sel.sql, /c\.watch_disconnect/); assert.strictEqual(sel.args.length, 4); assert.deepStrictEqual(sel.args.slice(0, 3), ['t1', 'vector-%', false]);   // tenant, broker pattern, watch-everything off, then the age cutoff
    const ins = calls.find((c) => /INSERT INTO alerts/.test(c.sql));
    assert.strictEqual(ins.args[1], 'Broker installer key unusable'); assert.strictEqual(ins.args[2], 'high'); assert.strictEqual(ins.args[5], 'brokerkey:b1');
    assert.deepStrictEqual(JSON.parse(ins.args[6]), { broker_id: 'b1', broker: 'broker-1', key_ref: 'revoked:k1' });
    assert.ok(calls.some((c) => /SET status = 'closed'/.test(c.sql) && c.args[0] === 'old'));
  });
});
