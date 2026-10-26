'use strict';
// Broker signature watch (src/collectors/signature-watch.js): the pure planning rules and the SQL it sends (database replaced by a recorder).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const sw = require('../src/collectors/signature-watch');
const config = require('../src/brokers/config');

const NOW = Date.parse('2026-10-19T12:00:00Z');
const fresh = '2026-10-19T11:58:00Z', old = '2026-10-19T11:00:00Z';
const br = (o = {}) => ({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', config_signature: 'ok', config_reported_at: fresh, ...o });
const P = (o, opts) => sw.plan({ brokers: [br()], active: [], latest: [], signingOn: true, ...o }, { now: NOW, ...opts });
const KEY = 'brokersig:b1';

describe('plan: raising', () => {
  it('raises nothing for a broker that checks and passes', () => assert.deepStrictEqual(P(), { raise: [], close: [] }));
  it('raises one alert for a broker with no public key while ASIX signs', () => {
    const p = P({ brokers: [br({ config_signature: 'off' })] });
    assert.strictEqual(p.raise.length, 1);
    assert.strictEqual(p.raise[0].group_key, KEY); assert.strictEqual(p.raise[0].sig_ref, 'not_verifying');
    assert.match(p.raise[0].why, /no public key/); assert.match(p.raise[0].help, /--config-pubkey/);
  });
  it('raises one alert for a broker that refuses ASIX\'s answer, naming the reason and its fix', () => {
    const p = P({ brokers: [br({ config_signature: 'bad_signature' })] });
    assert.strictEqual(p.raise[0].sig_ref, 'refused:bad_signature'); assert.match(p.raise[0].why, /bad_signature/);
    assert.strictEqual(p.raise[0].help, config.SIGNATURE_HELP.bad_signature);
  });
  it('has help text for every refusal reason a broker can send', () => {
    for (const reason of config.SIGNATURE_PROBLEMS) { const k = sw.badSignature(br({ config_signature: reason }), NOW); assert.ok(k && k.help, reason); }
  });
  it('raises nothing when ASIX does not sign, whatever the broker says', () => {
    for (const s of ['off', 'unsigned', 'bad_signature']) assert.deepStrictEqual(P({ signingOn: false, brokers: [br({ config_signature: s })] }), { raise: [], close: [] }, s);
  });
  it('raises nothing for states that are not a problem: never reported, waiting, verifying, stale', () => {
    for (const row of [{ config_signature: null, config_reported_at: null }, { config_signature: 'unchecked' }, { config_signature: 'ok' },
      { config_signature: 'ok', config_reported_at: old }, { config_signature: 'bad_signature', config_reported_at: old }, { config_signature: 'unchecked', config_reported_at: old }]) {
      assert.deepStrictEqual(P({ brokers: [br(row)] }), { raise: [], close: [] }, JSON.stringify(row));
    }
  });
  it('treats a stale "off" report as still not checking (no public key does not go stale)', () => {
    assert.strictEqual(P({ brokers: [br({ config_signature: 'off', config_reported_at: old })] }).raise.length, 1);
  });
  it('ignores a collector that is not a broker', () => {
    assert.deepStrictEqual(P({ brokers: [br({ version: '1.2.3', config_signature: 'off' })] }), { raise: [], close: [] });
  });
  it('does not raise while an alert is open or acknowledged', () => {
    for (const status of ['open', 'acknowledged']) {
      const p = P({ brokers: [br({ config_signature: 'off' })], active: [{ id: 'a1', group_key: KEY }], latest: [{ group_key: KEY, status, sig_ref: 'not_verifying' }] });
      assert.deepStrictEqual(p, { raise: [], close: [] }, status);
    }
  });
  it('does not raise again for the same problem after an analyst closed the alert', () => {
    assert.deepStrictEqual(P({ brokers: [br({ config_signature: 'off' })], latest: [{ group_key: KEY, status: 'closed', sig_ref: 'not_verifying' }] }), { raise: [], close: [] });
  });
  it('raises again when it is a different problem than the one that was closed', () => {
    assert.strictEqual(P({ brokers: [br({ config_signature: 'clock_skew' })], latest: [{ group_key: KEY, status: 'closed', sig_ref: 'not_verifying' }] }).raise.length, 1);
    assert.strictEqual(P({ brokers: [br({ config_signature: 'off' })], latest: [{ group_key: KEY, status: 'closed', sig_ref: 'refused:clock_skew' }] }).raise.length, 1);
  });
  it('keeps the open alert when the reason of a refusal changes (it is still the same alert)', () => {
    const p = P({ brokers: [br({ config_signature: 'clock_skew' })], active: [{ id: 'a1', group_key: KEY }], latest: [{ group_key: KEY, status: 'open', sig_ref: 'refused:bad_signature' }] });
    assert.deepStrictEqual(p, { raise: [], close: [] });
  });
  it('raises nothing during the start-up grace, but still closes', () => {
    const p = P({ brokers: [br({ config_signature: 'off' }), br({ id: 'b2', name: 'b2' })], active: [{ id: 'a2', group_key: 'brokersig:b2' }] }, { raiseAllowed: false });
    assert.strictEqual(p.raise.length, 0); assert.deepStrictEqual(p.close.map((c) => c.alert_id), ['a2']);
  });
});

describe('plan: closing', () => {
  it('closes when the broker checks again', () => {
    const p = P({ active: [{ id: 'a1', group_key: KEY }] });
    assert.strictEqual(p.close.length, 1); assert.match(p.close[0].reason, /checks ASIX's signature again/);
  });
  it('closes when the broker stops reporting a problem (stale report)', () => {
    assert.strictEqual(P({ brokers: [br({ config_signature: 'bad_signature', config_reported_at: old })], active: [{ id: 'a1', group_key: KEY }] }).close.length, 1);
  });
  it('closes when the broker is no longer watched or was deleted', () => {
    const p = P({ brokers: [], active: [{ id: 'a1', group_key: 'brokersig:gone' }] });
    assert.match(p.close[0].reason, /no longer watched or was removed/);
  });
  it('closes everything, with its own note, when ASIX stops signing', () => {
    const p = P({ signingOn: false, brokers: [br({ config_signature: 'off' })], active: [{ id: 'a1', group_key: KEY }, { id: 'a2', group_key: 'brokersig:gone' }] });
    assert.deepStrictEqual(p.close.map((c) => c.alert_id), ['a1', 'a2']); assert.ok(p.close.every((c) => /does not sign/.test(c.reason)));
  });
  it('keeps the alert while the problem is still there', () => {
    assert.deepStrictEqual(P({ brokers: [br({ config_signature: 'off' })], active: [{ id: 'a1', group_key: KEY }], latest: [{ group_key: KEY, status: 'open', sig_ref: 'not_verifying' }] }), { raise: [], close: [] });
  });
});

describe('raiseText', () => {
  it('names the broker and tells the operator what to do', () => {
    const t = sw.raiseText({ name: 'broker-1', why: 'it has no public key', help: 'Do the thing.' });
    assert.strictEqual(t.title, 'Broker not checking config signature: broker-1'); assert.match(t.summary, /broker-1 does not check them: it has no public key\. Do the thing\./);
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
    delete require.cache[require.resolve('../src/collectors/signature-watch')];
  });
  after(() => { require.cache[dbPath].exports = saved; delete require.cache[require.resolve('../src/collectors/signature-watch')]; });

  it('only reads watched brokers, then raises and closes what plan() says', async () => {
    calls = []; rows = { brokers: [br({ config_signature: 'off' })], active: [{ id: 'old', group_key: 'brokersig:gone' }], latest: [] };
    const r = await require('../src/collectors/signature-watch').runTenant('t1', { sev: 'high', now: NOW, signingOn: true });
    assert.deepStrictEqual(r, { raised: 1, closed: 1 });
    const sel = calls.find((c) => /FROM collectors/.test(c.sql));
    assert.match(sel.sql, /c\.watch_disconnect/); assert.match(sel.sql, /NOT c\.watch_exclude/); assert.strictEqual(sel.args.length, 4);
    assert.deepStrictEqual(sel.args.slice(0, 3), ['t1', 'vector-%', false]);
    const ins = calls.find((c) => /INSERT INTO alerts/.test(c.sql));
    assert.strictEqual(ins.args[1], 'Broker not checking config signature'); assert.strictEqual(ins.args[2], 'high'); assert.strictEqual(ins.args[5], 'brokersig:b1');
    assert.deepStrictEqual(JSON.parse(ins.args[6]), { broker_id: 'b1', broker: 'broker-1', sig_ref: 'not_verifying' });
    assert.ok(calls.some((c) => /SET status = 'closed'/.test(c.sql) && c.args[0] === 'old'));
  });
  it('raises nothing and closes the open alert when ASIX does not sign', async () => {
    calls = []; rows = { brokers: [br({ config_signature: 'off' })], active: [{ id: 'a1', group_key: 'brokersig:b1' }], latest: [] };
    const r = await require('../src/collectors/signature-watch').runTenant('t1', { now: NOW, signingOn: false });
    assert.deepStrictEqual(r, { raised: 0, closed: 1 });
  });
  it('asks the signing module when signingOn is not given (no key set: off)', async () => {
    const saveKey = process.env.ASIX_CONFIG_SIGNING_KEY; delete process.env.ASIX_CONFIG_SIGNING_KEY;
    try {
      calls = []; rows = { brokers: [br({ config_signature: 'off' })], active: [], latest: [] };
      assert.deepStrictEqual(await require('../src/collectors/signature-watch').runTenant('t1', { now: NOW }), { raised: 0, closed: 0 });
    } finally { if (saveKey !== undefined) process.env.ASIX_CONFIG_SIGNING_KEY = saveKey; }
  });
});
