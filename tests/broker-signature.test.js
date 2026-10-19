'use strict';
// Which brokers check ASIX's signature on their config (src/brokers/config.js signatureState, the `signature` field of the broker's report,
// and what GET /v1/brokers returns for it). Pure rules, then the real listing route with the sign-in chain, the database and the event store replaced.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const express = require('express');
const config = require('../src/brokers/config');
const view = require('../src/brokers/broker-view');

const NOW = Date.UTC(2026, 9, 18, 12, 0, 0);
const ago = (m) => new Date(NOW - m * 60000);
const row = (o = {}) => ({ id: 'id-' + (o.name || 'b'), name: 'broker-1', alias: null, os: 'Ubuntu', version: 'vector-0.59.0', last_ip: '10.0.0.5', first_seen: ago(5000), last_seen: ago(1),
  events_total: '10', connected_within_min: null, key_id: 'k1', installer_name: 'home', key_status: 'active', key_prefix: 'asix_ik_abcd', key_last_used_at: ago(1), ...o });

describe('the signature field of a broker report', () => {
  const body = (extra) => ({ collector: 'broker-1', syslog_port: 514, rejected_port: null, ...extra });
  it('every value in the list is accepted and stored as sent', () => {
    for (const v of config.SIGNATURE_VALUES) assert.strictEqual(config.checkReport(body({ signature: v })).signature, v, v);
    assert.deepStrictEqual(config.SIGNATURE_VALUES.slice(0, 3), ['off', 'unchecked', 'ok']);
    assert.deepStrictEqual(config.SIGNATURE_VALUES.slice(3), config.SIGNATURE_PROBLEMS);
  });
  it('left out or null means the broker did not say (an older script): stored as null', () => {
    assert.strictEqual(config.checkReport(body()).signature, null);
    assert.strictEqual(config.checkReport(body({ signature: null })).signature, null);
  });
  it('anything else is refused with a reason that lists the allowed values, and nothing is returned', () => {
    for (const v of ['maybe', 'OK', ' ok', 'ok ', '', 5, true, ['ok'], { v: 'ok' }, 'ok; DROP TABLE collectors', "ok'--", 'verifying', 'refused']) {
      const r = config.checkReport(body({ signature: v })); assert.ok(r.error, JSON.stringify(v)); assert.match(r.error, /signature must be one of: off, unchecked, ok/); assert.strictEqual(r.name, undefined);
    }
  });
  it('recordReport writes it on the row of the sending key and broker, as the sixth argument, and nulls it when the broker did not say', async () => {
    const seen = []; const q = { query: async (sql, args) => { seen.push({ sql, args }); return { rowCount: 1 }; } };
    await config.recordReport(q, 't', 'k', config.checkReport(body({ signature: 'bad_signature' })));
    await config.recordReport(q, 't', 'k', config.checkReport(body()));
    assert.match(seen[0].sql, /config_signature = \$6/); assert.match(seen[0].sql, /WHERE tenant_id = \$1 AND key_id = \$2 AND name = \$3/);
    assert.deepStrictEqual(seen[0].args, ['t', 'k', 'broker-1', 514, null, 'bad_signature']);
    assert.strictEqual(seen[1].args[5], null, 'an older script that does not send it clears an old value instead of leaving it');
  });
});

describe('signatureState', () => {
  const at = (sig, min = 1) => ({ config_signature: sig, config_reported_at: ago(min) });
  it('never reported, or a value outside the list: unknown, with no problem', () => {
    for (const r of [null, undefined, {}, { config_signature: null }, { config_signature: 'banana', config_reported_at: ago(1) }, { config_signature: 5 }])
      { const g = config.signatureState(true, r, NOW); assert.strictEqual(g.state, 'unknown', JSON.stringify(r)); assert.strictEqual(g.problem, null); assert.strictEqual(g.signing_on, true); }
  });
  it('off: not verifying, whatever the age (it has no key to check with, so there is nothing to go stale)', () => {
    assert.strictEqual(config.signatureState(true, at('off'), NOW).state, 'not_verifying');
    assert.strictEqual(config.signatureState(false, at('off', 5000), NOW).state, 'not_verifying');
  });
  it('ok: verifying; unchecked: waiting; each refusal: refused with its reason', () => {
    assert.strictEqual(config.signatureState(true, at('ok'), NOW).state, 'verifying');
    assert.strictEqual(config.signatureState(true, at('unchecked'), NOW).state, 'waiting');
    for (const p of config.SIGNATURE_PROBLEMS) { const s = config.signatureState(true, at(p), NOW); assert.strictEqual(s.state, 'refused', p); assert.strictEqual(s.problem, p); }
  });
  it('a report older than 15 minutes is stale for ok, unchecked and refused (a refusal keeps its reason); 15 minutes exactly is still fresh', () => {
    assert.strictEqual(config.signatureState(true, at('ok', 15), NOW).state, 'verifying');
    assert.strictEqual(config.signatureState(true, at('ok', 16), NOW).state, 'stale');
    assert.strictEqual(config.signatureState(true, at('unchecked', 16), NOW).state, 'stale');
    const s = config.signatureState(true, at('bad_signature', 60), NOW); assert.strictEqual(s.state, 'stale'); assert.strictEqual(s.problem, 'bad_signature');
  });
  it('says whether ASIX signs, and an unreadable time is treated as fresh (the same rule as the port state)', () => {
    assert.strictEqual(config.signatureState(true, at('ok'), NOW).signing_on, true);
    assert.strictEqual(config.signatureState(false, at('ok'), NOW).signing_on, false);
    assert.strictEqual(config.signatureState(undefined, at('ok'), NOW).signing_on, false);
    assert.strictEqual(config.signatureState(true, { config_signature: 'ok', config_reported_at: 'not a time' }, NOW).state, 'verifying');
  });
  it('every refusal reason has one line of help, and there is no help for anything else', () => {
    assert.deepStrictEqual(Object.keys(config.SIGNATURE_HELP).sort(), [...config.SIGNATURE_PROBLEMS].sort());
    for (const t of Object.values(config.SIGNATURE_HELP)) assert.ok(t.length > 20 && !/\n/.test(t));
  });
});

describe('on each broker and in the summary', () => {
  it('shape carries the state, the reason and the help for a refusal, and ASIX\'s own signing state', () => {
    const b = view.shape(row({ config_signature: 'wrong_broker', config_reported_at: ago(2) }), { now: NOW, signingOn: true });
    assert.strictEqual(b.signature.state, 'refused'); assert.strictEqual(b.signature.problem, 'wrong_broker'); assert.match(b.signature.help, /ASIX_BROKER_NAME/); assert.strictEqual(b.signature.signing_on, true);
    const ok = view.shape(row({ config_signature: 'ok', config_reported_at: ago(2) }), { now: NOW });
    assert.strictEqual(ok.signature.state, 'verifying'); assert.strictEqual(ok.signature.help, null); assert.strictEqual(ok.signature.signing_on, false, 'signingOn defaults to off');
    assert.strictEqual(view.shape(row(), { now: NOW }).signature.state, 'unknown');
  });
  it('is information, not a problem: no entry in problems and no change to with_problems', () => {
    const bs = ['bad_signature', 'unsigned', 'ok', 'off'].map((sig, i) => view.shape(row({ name: 'b' + i, config_signature: sig, config_reported_at: ago(1) }), { now: NOW, signingOn: true }));
    for (const b of bs) assert.deepStrictEqual(b.problems, [], b.signature.state);
    assert.strictEqual(view.summarize(bs).with_problems, 0);
  });
  it('summarize counts the brokers that verify, that do not, and that refused (stale and unknown are none of these)', () => {
    const mk = (sig, min = 1) => view.shape(row({ name: sig + min, config_signature: sig, config_reported_at: ago(min) }), { now: NOW, signingOn: true });
    const bs = [mk('ok'), mk('ok', 2), mk('ok', 99), mk('off'), mk('unsigned'), mk('bad_signature'), mk('unchecked'), view.shape(row({ name: 'old' }), { now: NOW })];
    const s = view.summarize(bs);
    assert.strictEqual(s.signature_verifying, 2); assert.strictEqual(s.signature_not_verifying, 1); assert.strictEqual(s.signature_refused, 2);
    assert.strictEqual(s.total, 8);
  });
});

describe('GET /v1/brokers and signing', () => {
  const TENANT = '11111111-1111-4111-8111-111111111111';
  let rows; let seen;
  const fakeDb = { withTenant: async (t, fn) => fn({ query: async (sql, args) => {
    if (/syslog_port FROM broker_settings/.test(sql)) return { rows: [] };
    if (/FROM collectors/.test(sql)) seen = { sql, args }; return { rows }; } }), query: async () => ({ rows: [] }) };
  const shared = require('../src/gateway/shared');
  const savedShared = require.cache[require.resolve('../src/gateway/shared')].exports;
  const signing = require('../src/brokers/config-signing');
  const savedEnv = process.env.ASIX_CONFIG_SIGNING_KEY;
  let srv; let base;
  before(async () => {
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: fakeDb, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };
    delete require.cache[require.resolve('../src/gateway/routes/brokers')];
    require('../src/events').setEventStore({ groupCounts: async () => [] });
    const app = express(); app.use(require('../src/gateway/routes/brokers'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = savedShared; if (savedEnv === undefined) delete process.env.ASIX_CONFIG_SIGNING_KEY; else process.env.ASIX_CONFIG_SIGNING_KEY = savedEnv; signing.reset(); });
  const get = async () => { const r = await fetch(base + '/v1/brokers'); return { status: r.status, json: await r.json() }; };
  const fresh = (o) => row({ last_seen: new Date(), config_reported_at: new Date(), ...o });

  it('selects the column and returns the state; ASIX without a signing key says so on every broker', async () => {
    delete process.env.ASIX_CONFIG_SIGNING_KEY; signing.reset();
    rows = [fresh({ config_signature: 'off' }), fresh({ name: 'b2', config_signature: 'ok' }), fresh({ name: 'b3' })];
    const r = await get();
    assert.match(seen.sql, /c\.config_reported_at, c\.config_signature,/);
    assert.deepStrictEqual(r.json.brokers.map((b) => b.signature.state), ['not_verifying', 'verifying', 'unknown']);
    assert.deepStrictEqual(r.json.brokers.map((b) => b.signature.signing_on), [false, false, false]);
    assert.strictEqual(r.json.summary.signature_verifying, 1); assert.strictEqual(r.json.summary.signature_not_verifying, 1);
  });
  it('with a usable signing key on ASIX, signing_on is true', async () => {
    process.env.ASIX_CONFIG_SIGNING_KEY = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' }); signing.reset();
    rows = [fresh({ config_signature: 'off' })];
    const r = await get(); assert.strictEqual(r.json.brokers[0].signature.signing_on, true); assert.strictEqual(r.json.brokers[0].signature.state, 'not_verifying');
  });
  it('an unusable signing key does not break the listing: signing_on is false', async () => {
    process.env.ASIX_CONFIG_SIGNING_KEY = 'not a key'; signing.reset();
    const quiet = console.error; console.error = () => {};
    try { rows = [fresh({ config_signature: 'unsigned' })]; const r = await get(); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.brokers[0].signature.signing_on, false); assert.strictEqual(r.json.brokers[0].signature.state, 'refused'); }
    finally { console.error = quiet; }
  });
  it('a refusal comes with its reason and help, and the broker is not listed as having a problem', async () => {
    delete process.env.ASIX_CONFIG_SIGNING_KEY; signing.reset();
    rows = [fresh({ config_signature: 'bad_signature' })];
    const b = (await get()).json.brokers[0];
    assert.strictEqual(b.signature.state, 'refused'); assert.strictEqual(b.signature.problem, 'bad_signature'); assert.match(b.signature.help, /public key/); assert.deepStrictEqual(b.problems, []);
  });
});
