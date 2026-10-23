'use strict';
// Broker pause watch (src/collectors/pause-watch.js): the pure planning rules and the SQL it sends (database replaced by a recorder).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const pw = require('../src/collectors/pause-watch');

const NOW = Date.parse('2026-10-23T12:00:00Z');
const fresh = '2026-10-23T11:58:00Z', old = '2026-10-23T11:00:00Z';
const br = (o = {}) => ({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', inputs_paused: null, config_paused_inputs: null, config_rejected_paused: null, config_reported_at: fresh, ...o });
const rejected = (o = {}) => br({ inputs_paused: 'journald', config_paused_inputs: '', config_rejected_paused: 'journald', ...o });
const P = (o, opts) => pw.plan({ brokers: [br()], active: [], latest: [], ...o }, { now: NOW, ...opts });
const KEY = 'brokerpause:b1';

describe('plan: raising', () => {
  it('raises nothing for a broker with no pause at all', () => assert.deepStrictEqual(P(), { raise: [], close: [] }));
  it('raises one alert for a broker that rejected the list it was asked for', () => {
    const p = P({ brokers: [rejected()] });
    assert.strictEqual(p.raise.length, 1);
    assert.strictEqual(p.raise[0].group_key, KEY); assert.strictEqual(p.raise[0].pause_ref, 'rejected:journald'); assert.deepStrictEqual(p.raise[0].asked, ['journald']);
  });
  it('a rejection does not go stale: an old report still raises (the broker said it, and nothing has changed)', () => {
    assert.strictEqual(P({ brokers: [rejected({ config_reported_at: old })] }).raise.length, 1);
  });
  it('raises nothing for the states that are not a rejection: applied, pending, stale, never reported', () => {
    for (const row of [
      { inputs_paused: 'file', config_paused_inputs: 'file' },                              // applied
      { inputs_paused: 'file', config_paused_inputs: '' },                                   // pending
      { inputs_paused: 'file', config_paused_inputs: '', config_reported_at: old },          // stale
      { inputs_paused: 'file' },                                                             // never reported (did not opt in, or an older script)
      { inputs_paused: null, config_paused_inputs: 'file' },                                 // resume asked, not yet applied
      { inputs_paused: 'file', config_paused_inputs: '', config_rejected_paused: 'http' }]) { // it rejected ANOTHER list than the one asked now
      assert.deepStrictEqual(P({ brokers: [br(row)] }), { raise: [], close: [] }, JSON.stringify(row));
    }
  });
  it('ignores a collector that is not a broker', () => assert.deepStrictEqual(P({ brokers: [rejected({ version: '1.2.3' })] }), { raise: [], close: [] }));
  it('does not raise while an alert is open or acknowledged', () => {
    for (const status of ['open', 'acknowledged']) {
      assert.deepStrictEqual(P({ brokers: [rejected()], active: [{ id: 'a1', group_key: KEY }], latest: [{ group_key: KEY, status, pause_ref: 'rejected:journald' }] }), { raise: [], close: [] }, status);
    }
  });
  it('does not raise again for the same list after an analyst closed the alert', () => {
    assert.deepStrictEqual(P({ brokers: [rejected()], latest: [{ group_key: KEY, status: 'closed', pause_ref: 'rejected:journald' }] }), { raise: [], close: [] });
  });
  it('raises again for a different rejected list than the one closed', () => {
    const p = P({ brokers: [rejected({ inputs_paused: 'file,journald', config_rejected_paused: 'file,journald' })], latest: [{ group_key: KEY, status: 'closed', pause_ref: 'rejected:journald' }] });
    assert.strictEqual(p.raise.length, 1); assert.strictEqual(p.raise[0].pause_ref, 'rejected:file,journald');
  });
  it('names several inputs in the fixed order', () => {
    assert.strictEqual(pw.badPause(rejected({ inputs_paused: 'journald,file', config_rejected_paused: 'journald,file' }), NOW).names, 'file, journald');
  });
  it('raises nothing during the start-up grace, but still closes', () => {
    const p = P({ brokers: [rejected(), rejected({ id: 'b2', name: 'b2' }), br({ id: 'b3', name: 'b3' })], active: [{ id: 'a3', group_key: 'brokerpause:b3' }] }, { raiseAllowed: false });
    assert.strictEqual(p.raise.length, 0); assert.deepStrictEqual(p.close.map((c) => c.alert_id), ['a3']);
  });
});

describe('plan: closing', () => {
  it('closes when the broker applies the list', () => {
    const p = P({ brokers: [br({ inputs_paused: 'journald', config_paused_inputs: 'journald' })], active: [{ id: 'a1', group_key: KEY }] });
    assert.strictEqual(p.close.length, 1); assert.match(p.close[0].reason, /applied the list/);
  });
  it('closes when the operator changes the ask (resume, or a list the broker has not rejected)', () => {
    assert.strictEqual(P({ brokers: [br({ inputs_paused: null, config_paused_inputs: '', config_rejected_paused: 'journald' })], active: [{ id: 'a1', group_key: KEY }] }).close.length, 1);
    assert.strictEqual(P({ brokers: [rejected({ inputs_paused: 'http' })], active: [{ id: 'a1', group_key: KEY }] }).close.length, 1);
  });
  it('closes when the broker is no longer watched or was deleted', () => {
    assert.match(P({ brokers: [], active: [{ id: 'a1', group_key: 'brokerpause:gone' }] }).close[0].reason, /no longer watched or was removed/);
  });
  it('keeps the alert while the same list is still rejected', () => {
    assert.deepStrictEqual(P({ brokers: [rejected()], active: [{ id: 'a1', group_key: KEY }], latest: [{ group_key: KEY, status: 'open', pause_ref: 'rejected:journald' }] }), { raise: [], close: [] });
  });
  it('an open alert for one rejected list is closed when the ask moves to another rejected list (the new one is raised next cycle)', () => {
    const p = P({ brokers: [rejected({ inputs_paused: 'http', config_rejected_paused: 'http' })], active: [{ id: 'a1', group_key: KEY }], latest: [{ group_key: KEY, status: 'open', pause_ref: 'rejected:journald' }] });
    assert.deepStrictEqual(p.close.map((c) => c.alert_id), ['a1']); assert.match(p.close[0].reason, /different list/); assert.strictEqual(p.raise.length, 0);
  });
});

describe('raiseText', () => {
  it('names the broker, the inputs and where to look', () => {
    const t = pw.raiseText({ name: 'broker-1', asked: ['file', 'journald'], names: 'file, journald' });
    assert.strictEqual(t.title, 'Broker input pause not applied: broker-1');
    assert.match(t.summary, /broker-1 was asked to pause file, journald and rejected it/); assert.match(t.summary, /still running/); assert.match(t.summary, /journalctl -u asix-broker-config/);
  });
  it('says it differently when the rejected ask was a resume', () => {
    const t = pw.raiseText({ name: 'broker-1', asked: [], names: 'none' });
    assert.match(t.summary, /asked to resume/); assert.match(t.summary, /still paused/);
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
    delete require.cache[require.resolve('../src/collectors/pause-watch')];
  });
  after(() => { require.cache[dbPath].exports = saved; delete require.cache[require.resolve('../src/collectors/pause-watch')]; });

  it('only reads watched brokers, then raises and closes what plan() says', async () => {
    calls = []; rows = { brokers: [rejected()], active: [{ id: 'old', group_key: 'brokerpause:gone' }], latest: [] };
    const r = await require('../src/collectors/pause-watch').runTenant('t1', { sev: 'high', now: NOW });
    assert.deepStrictEqual(r, { raised: 1, closed: 1 });
    const sel = calls.find((c) => /FROM collectors/.test(c.sql));
    assert.match(sel.sql, /c\.watch_disconnect/); assert.match(sel.sql, /NOT c\.watch_exclude/); assert.match(sel.sql, /c\.config_rejected_paused/); assert.strictEqual(sel.args.length, 4);
    assert.deepStrictEqual(sel.args.slice(0, 3), ['t1', 'vector-%', false]);
    const ins = calls.find((c) => /INSERT INTO alerts/.test(c.sql));
    assert.strictEqual(ins.args[1], 'Broker input pause not applied'); assert.strictEqual(ins.args[2], 'high'); assert.strictEqual(ins.args[5], 'brokerpause:b1');
    assert.deepStrictEqual(JSON.parse(ins.args[6]), { broker_id: 'b1', broker: 'broker-1', pause_ref: 'rejected:journald', asked: ['journald'] });
    assert.ok(calls.some((c) => /SET status = 'closed'/.test(c.sql) && c.args[0] === 'old'));
  });
  it('a database without the pause columns makes the query throw, which the watchdog catches per tenant', async () => {
    const dbp = require.cache[dbPath].exports; const orig = dbp.withTenant;
    dbp.withTenant = async () => { throw new Error('column "inputs_paused" does not exist'); };
    try { await assert.rejects(require('../src/collectors/pause-watch').runTenant('t1', { now: NOW }), /inputs_paused/); } finally { dbp.withTenant = orig; }
  });
});
