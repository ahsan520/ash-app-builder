'use strict';
// Pausing optional inputs on one broker (src/brokers/paused.js, collectors.inputs_paused), server side without a database: the rules, the Brokers page shape, the signed text,
// the portal route and the broker's pull and report.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const paused = require('../src/brokers/paused');
const config = require('../src/brokers/config');
const view = require('../src/brokers/broker-view');
const signing = require('../src/brokers/config-signing');

describe('rules', () => {
  it('checkPaused: known names in the fixed order, each once; empty clears; anything else is refused with the allowed list', () => {
    assert.deepStrictEqual(paused.checkPaused(['journald', 'file', 'file']), { value: ['file', 'journald'] });
    assert.deepStrictEqual(paused.checkPaused(' HTTP , file '), { value: ['file', 'http'] });
    for (const empty of [null, undefined, '', [], ' ', [' ']]) assert.deepStrictEqual(paused.checkPaused(empty), { value: [] });
    for (const bad of ['syslog', ['file', 'syslog-tls'], ['journald;x'], 5, {}, true, ['file', 7]]) { const r = paused.checkPaused(bad); assert.ok(r.error, JSON.stringify(bad)); assert.match(r.error, /file, http, journald/); }
  });
  it('syslog and syslog over TLS can never be paused', () => { for (const k of ['syslog', 'syslog-tls', 'https', 'all']) assert.ok(paused.checkPaused([k]).error, k); });
  it('parseText and toText: unknown names dropped, fixed order, null when not text', () => {
    assert.deepStrictEqual(paused.parseText('journald,file,bogus'), ['file', 'journald']); assert.deepStrictEqual(paused.parseText(''), []); assert.strictEqual(paused.parseText(null), null); assert.strictEqual(paused.parseText(5), null);
    assert.strictEqual(paused.toText(['journald', 'file']), 'file,journald');
  });
  it('checkReportText accepts only what the broker script sends', () => {
    assert.deepStrictEqual(paused.checkReportText(''), { value: '' }); assert.deepStrictEqual(paused.checkReportText('http,journald'), { value: 'http,journald' });
    for (const bad of ['file,file', 'syslog', 'File', 'file;', 'file,', ',file', 'x'.repeat(41), 5, null, ['file']]) assert.ok(paused.checkReportText(bad).error, JSON.stringify(bad));
  });
  it('checkReport carries the optional fields and leaves them undefined for an older script; a bad one is a 400 reason and the port report is not trusted', () => {
    const base = { collector: 'broker-1', syslog_port: 514, rejected_port: null };
    let r = config.checkReport(base); assert.strictEqual(r.paused, undefined); assert.strictEqual(r.pausedRejected, undefined);
    r = config.checkReport({ ...base, paused_inputs: 'file', rejected_paused_inputs: '' }); assert.strictEqual(r.paused, 'file'); assert.strictEqual(r.pausedRejected, '');
    r = config.checkReport({ ...base, paused_inputs: '' }); assert.strictEqual(r.paused, ''); assert.strictEqual(r.pausedRejected, undefined);
    assert.match(config.checkReport({ ...base, paused_inputs: 'syslog' }).error, /paused_inputs/); assert.match(config.checkReport({ ...base, paused_inputs: 'file', rejected_paused_inputs: 'x' }).error, /rejected_paused_inputs/);
  });
});

describe('what the pull says', () => {
  const rec = (rows) => { const seen = []; return { seen, query: async (sql, args) => { seen.push({ sql, args }); return { rows }; } }; };
  it('asked: the list; nothing asked but the broker still has something paused: "" (resume); nothing either way or no row: no opinion', async () => {
    assert.strictEqual(await paused.readForPull(rec([{ inputs_paused: 'journald,file', config_paused_inputs: null }]), 't1', 'k1', 'broker-1'), 'file,journald');
    assert.strictEqual(await paused.readForPull(rec([{ inputs_paused: null, config_paused_inputs: 'file' }]), 't1', 'k1', 'broker-1'), '');
    assert.strictEqual(await paused.readForPull(rec([{ inputs_paused: null, config_paused_inputs: '' }]), 't1', 'k1', 'broker-1'), undefined);
    assert.strictEqual(await paused.readForPull(rec([{ inputs_paused: null, config_paused_inputs: null }]), 't1', 'k1', 'broker-1'), undefined);
    assert.strictEqual(await paused.readForPull(rec([]), 't1', 'k1', 'broker-1'), undefined);
  });
  it('is read by key AND name', async () => {
    const q = rec([{ inputs_paused: 'file', config_paused_inputs: null }]); await paused.readForPull(q, 't1', 'k1', 'broker-1');
    assert.match(q.seen[0].sql, /WHERE tenant_id = \$1 AND key_id = \$2 AND name = \$3/); assert.deepStrictEqual(q.seen[0].args, ['t1', 'k1', 'broker-1']);
  });
  it('writePaused touches one broker of this tenant only, never a non-broker collector; an empty list stores NULL', async () => {
    let q = rec([{ id: 'b1', name: 'broker-1', inputs_paused: 'file,http' }]);
    assert.deepStrictEqual(await paused.writePaused(q, 't1', 'b1', ['http', 'file']), { id: 'b1', name: 'broker-1', paused: ['file', 'http'] });
    assert.match(q.seen[0].sql, /^UPDATE collectors SET inputs_paused = \$3 WHERE id = \$1 AND tenant_id = \$2 AND version ILIKE 'vector-%'/); assert.deepStrictEqual(q.seen[0].args, ['b1', 't1', 'file,http']);
    q = rec([{ id: 'b1', name: 'broker-1', inputs_paused: null }]); assert.deepStrictEqual((await paused.writePaused(q, 't1', 'b1', [])).paused, []); assert.strictEqual(q.seen[0].args[2], null);
    assert.strictEqual(await paused.writePaused(rec([]), 't1', 'nope', ['file']), null);
  });
  it('recordReport writes on the key\'s own broker only', async () => {
    const q = rec([]); q.query = async (sql, args) => { q.seen.push({ sql, args }); return { rowCount: 1 }; };
    assert.strictEqual(await paused.recordReport(q, 't1', 'k1', 'broker-1', 'file', ''), true);
    assert.match(q.seen[0].sql, /WHERE tenant_id = \$1 AND key_id = \$2 AND name = \$3/); assert.deepStrictEqual(q.seen[0].args, ['t1', 'k1', 'broker-1', 'file', null]);
  });
});

describe('the state on the Brokers page', () => {
  const NOW = Date.parse('2026-10-22T12:00:00Z'), fresh = new Date(NOW - 60000), old = new Date(NOW - 20 * 60000);
  const row = (o = {}) => ({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', last_seen: fresh, key_id: 'k1', installer_name: 'k', key_status: 'active', inputs_paused: null, config_paused_inputs: null, config_rejected_paused: null, config_reported_at: null, ...o });
  const st = (o) => paused.pausedState(row(o), NOW).state;
  it('none / unknown / applied / pending / stale / rejected', () => {
    assert.strictEqual(st({}), 'none'); assert.strictEqual(st({ config_paused_inputs: '', config_reported_at: fresh }), 'none');
    assert.strictEqual(st({ inputs_paused: 'file' }), 'unknown');
    assert.strictEqual(st({ inputs_paused: 'file', config_paused_inputs: 'file', config_reported_at: fresh }), 'applied');
    assert.strictEqual(st({ inputs_paused: 'file,journald', config_paused_inputs: 'journald,file', config_reported_at: fresh }), 'applied', 'order does not matter');
    assert.strictEqual(st({ inputs_paused: 'file', config_paused_inputs: '', config_reported_at: fresh }), 'pending');
    assert.strictEqual(st({ inputs_paused: 'file', config_paused_inputs: '', config_reported_at: old }), 'stale');
    assert.strictEqual(st({ inputs_paused: 'file', config_paused_inputs: '', config_rejected_paused: 'file', config_reported_at: fresh }), 'rejected');
    assert.strictEqual(st({ inputs_paused: 'file', config_paused_inputs: '', config_rejected_paused: 'http', config_reported_at: fresh }), 'pending', 'a different list was the rejected one');
  });
  it('resume asked (nothing listed) while the broker still reports something paused is pending, and applied once it reports none', () => {
    assert.strictEqual(st({ inputs_paused: null, config_paused_inputs: 'file', config_reported_at: fresh }), 'pending');
    assert.strictEqual(st({ inputs_paused: null, config_paused_inputs: '', config_reported_at: fresh }), 'none');
  });
  it('shape and summary', () => {
    const a = view.shape(row({ inputs_paused: 'file', config_paused_inputs: 'file', config_reported_at: fresh }), { now: NOW });
    assert.deepStrictEqual(a.inputs_paused.asked, ['file']); assert.strictEqual(a.inputs_paused.state, 'applied'); assert.deepStrictEqual(a.problems, [], 'never a problem');
    const b = view.shape(row({ id: 'b2', inputs_paused: 'http' }), { now: NOW }), c = view.shape(row({ id: 'b3' }), { now: NOW });
    const s = view.summarize([a, b, c]); assert.strictEqual(s.paused_asked, 2); assert.strictEqual(s.paused_not_applied, 1);
  });
});

describe('the signed text', () => {
  it('paused_inputs is appended after tls_port only when given, so every existing text is unchanged', () => {
    assert.strictEqual(signing.payloadText('broker-1', 514, 1000000, 6514), '{"v":1,"collector":"broker-1","issued_at":1000,"syslog_port":514,"tls_port":6514}');
    assert.strictEqual(signing.payloadText('broker-1', null, 1000000, null, 'file,journald'), '{"v":1,"collector":"broker-1","issued_at":1000,"syslog_port":null,"tls_port":null,"paused_inputs":"file,journald"}');
    assert.match(signing.payloadText('broker-1', null, 1000000, null, ''), /"paused_inputs":""\}$/);
  });
  it('verify returns it, and refuses a payload where it is not a short comma list', () => {
    const k = require('crypto').generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const key = { privateKey: k.privateKey, keyId: 'x' }, pem = k.publicKey.export({ type: 'spki', format: 'pem' });
    const doc = signing.signedDocument(key, 'broker-1', 514, Date.now(), null, 'file');
    assert.deepStrictEqual(signing.verify(pem, doc, { expectCollector: 'broker-1' }), { ok: true, port: 514, tls_port: null, paused_inputs: 'file' });
    assert.ok(!('paused_inputs' in signing.verify(pem, signing.signedDocument(key, 'broker-1', 514, Date.now(), null), { expectCollector: 'broker-1' })), 'a payload without the field gives a result without it');
    assert.strictEqual(signing.verify(pem, signing.signedDocument(key, 'broker-1', 514, Date.now(), null, 'FILE;rm'), { expectCollector: 'broker-1' }).ok, false);
  });
});

describe('routes', () => {
  let srv, base, failDb = false, failRead = false, failRecord = false, row = { inputs_paused: null, config_paused_inputs: null }, writes = [], reports = [], found = true;
  const ID = '11111111-1111-4111-8111-111111111111';
  before(() => {
    const dbPath = require.resolve('../src/db');
    require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: {
      withTenant: async (tenant, fn) => { if (failDb) throw new Error('boom'); return fn({ query: async (sql, args) => {
        if (/^UPDATE collectors SET inputs_paused/.test(sql)) { writes.push({ sql, args }); return { rows: found ? [{ id: args[0], name: 'broker-1', inputs_paused: args[2] }] : [] }; }
        if (/SELECT inputs_paused, config_paused_inputs/.test(sql)) { if (failRead) throw new Error('column "inputs_paused" does not exist'); return { rows: [row] }; }
        if (/SET config_paused_inputs/.test(sql)) { if (failRecord) throw new Error('column "config_paused_inputs" does not exist'); reports.push(args); return { rowCount: 1, rows: [] }; }
        if (/UPDATE collectors SET config_syslog_port/.test(sql)) return { rowCount: 1, rows: [] };
        return { rows: [{ syslog_port: null, tls_port: null }] }; } }); },
      query: async () => ({ rows: [{ id: 'k1', tenant_id: 't1', name: 'broker-1', platform: 'linux' }] }),
    } };
    const shared = require('../src/gateway/shared');
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: require('../src/db'), guarded: () => [(req, res, next) => { req.tenant_id = 't1'; req.user_id = 'u1'; next(); }] };
    const app = express(); app.use(require('../src/ingest/broker-config').router); app.use(express.json()); app.use(require('../src/gateway/routes/broker-inputs'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => srv.close());
  const call = async (method, p, body, headers = {}) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json().catch(() => null) }; };
  const KEY = { authorization: 'Bearer asix_ik_' + 'a'.repeat(40) };
  const put = (id, body) => call('PUT', '/v1/brokers/' + id + '/inputs-paused', body);
  const pull = (q = '?collector=broker-1') => call('GET', '/v1/ingest/broker-config' + q, undefined, KEY);

  it('the portal route pauses, and resumes with an empty list or null', async () => {
    let r = await put(ID, { paused: ['journald', 'file'] }); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json, { success: true, broker: { id: ID, name: 'broker-1' }, paused: ['file', 'journald'] }); assert.deepStrictEqual(writes.at(-1).args, [ID, 't1', 'file,journald']);
    r = await put(ID, { paused: [] }); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json.paused, []); assert.strictEqual(writes.at(-1).args[2], null);
    r = await put(ID, { paused: null }); assert.strictEqual(r.status, 200); assert.strictEqual(writes.at(-1).args[2], null);
  });
  it('a missing body field, an input that cannot be paused or a bad id writes nothing', async () => {
    const n = writes.length;
    let r = await put(ID, {}); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_BODY');
    r = await put(ID, { paused: ['syslog'] }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_INPUT');
    r = await put('not-a-uuid', { paused: ['file'] }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_ID');
    assert.strictEqual(writes.length, n);
  });
  it('an unknown or non-broker row is a 404 and a database failure a 500', async () => {
    found = false; try { assert.strictEqual((await put(ID, { paused: ['file'] })).status, 404); } finally { found = true; }
    failDb = true; try { assert.strictEqual((await put(ID, { paused: ['file'] })).status, 500); } finally { failDb = false; }
  });
  it('the pull: field present only when it matters, and the answer stays as it was otherwise', async () => {
    row = { inputs_paused: null, config_paused_inputs: null }; assert.deepStrictEqual((await pull()).json.config, { syslog_port: null, tls_port: null });
    row = { inputs_paused: 'journald,file', config_paused_inputs: null }; assert.deepStrictEqual((await pull()).json.config, { syslog_port: null, tls_port: null, paused_inputs: 'file,journald' });
    row = { inputs_paused: null, config_paused_inputs: 'file' }; assert.strictEqual((await pull()).json.config.paused_inputs, '');
    row = { inputs_paused: 'file', config_paused_inputs: null };
    assert.strictEqual((await pull('')).json.config.paused_inputs, undefined, 'a script that sends no name is told nothing about it');
    assert.strictEqual((await pull('?collector=a%20b')).json.config.paused_inputs, undefined);
  });
  it('if the columns are not there yet the answer is the one from before; a signed answer carries the list', async () => {
    row = { inputs_paused: 'file', config_paused_inputs: null }; failRead = true; try { const r = await pull(); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json.config, { syslog_port: null, tls_port: null }); } finally { failRead = false; }
    const crypto = require('crypto'); const k = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    process.env.ASIX_CONFIG_SIGNING_KEY = k.privateKey.export({ type: 'pkcs8', format: 'pem' }); signing.reset();
    try { const r = await pull(); const v = signing.verify(k.publicKey.export({ type: 'spki', format: 'pem' }), r.json.signed, { expectCollector: 'broker-1' }); assert.strictEqual(v.ok, true); assert.strictEqual(v.paused_inputs, 'file'); }
    finally { delete process.env.ASIX_CONFIG_SIGNING_KEY; signing.reset(); }
  });
  it('the report stores the paused list in its own statement; a failure there does not fail the report', async () => {
    const body = { collector: 'broker-1', syslog_port: 514, rejected_port: null, paused_inputs: 'file', rejected_paused_inputs: '' };
    let r = await call('POST', '/v1/ingest/broker-config/report', body, KEY); assert.strictEqual(r.status, 200); assert.deepStrictEqual(reports.at(-1), ['t1', 'k1', 'broker-1', 'file', null]);
    const n = reports.length; r = await call('POST', '/v1/ingest/broker-config/report', { ...body, paused_inputs: undefined }, KEY); assert.strictEqual(r.status, 200); assert.strictEqual(reports.length, n, 'an older script writes nothing here');
    failRecord = true; try { r = await call('POST', '/v1/ingest/broker-config/report', body, KEY); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.recorded, true); } finally { failRecord = false; }
    r = await call('POST', '/v1/ingest/broker-config/report', { ...body, paused_inputs: 'syslog' }, KEY); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'BROKER_REPORT_INVALID');
  });
});
