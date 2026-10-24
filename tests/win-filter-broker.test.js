'use strict';
// The Windows event filter on a broker, server side without a database (docs/endpoints.md, task E3): the program and its hash, what the config pull announces, the report,
// the signed payload, the two routes (announce and download) and the save-time size limit. The broker script is in tests/broker-win-filter-script.test.js; the real
// database in tests/win-filter-broker-db.test.js (gated).
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const express = require('express');
const wf = require('../src/endpoints/win-filter');
const store = require('../src/endpoints/win-filter-store');
const wb = require('../src/endpoints/win-filter-broker');
const signing = require('../src/brokers/config-signing');
const config = require('../src/brokers/config');

const POLICY = wf.validate(wf.presetNoisySecurity()).policy;
const POLICY_INPUT = wf.toInput(POLICY);
const sha = (t) => crypto.createHash('sha256').update(t, 'utf8').digest('hex');
const HEX = 'a'.repeat(64), HEX2 = 'b'.repeat(64);

describe('the program', () => {
  it('is a header comment, the generated VRL and a newline; its hash is the SHA-256 of exactly that text', () => {
    const p = wb.program(POLICY_INPUT);
    assert.strictEqual(p.text, wb.HEADER + wf.toVrl(POLICY) + '\n');
    assert.strictEqual(p.sha256, sha(p.text)); assert.strictEqual(p.bytes, Buffer.byteLength(p.text));
    assert.match(p.text, /^# ASIX Windows event filter/); assert.match(p.text, /\nif !keep \{ abort \}\n/);
  });
  it('is the same for the same policy and different for a different one (the hash names the content, not a revision)', () => {
    assert.strictEqual(wb.program(POLICY_INPUT).sha256, wb.program(JSON.parse(JSON.stringify(POLICY_INPUT))).sha256);
    const other = { ...POLICY_INPUT, rules: [{ ...POLICY_INPUT.rules[0], event_ids: [4656] }] };
    assert.notStrictEqual(wb.program(other).sha256, wb.program(POLICY_INPUT).sha256);
  });
  it('NO POLICY is the program "." (keep everything, change nothing); its hash is a fixed, public value', () => {
    const i = wb.identity();
    assert.strictEqual(i.text, wb.IDENTITY_TEXT); assert.match(i.text, /\n\.\n$/); assert.strictEqual(i.sha256, wb.IDENTITY_SHA); assert.strictEqual(wb.IDENTITY_SHA, sha(wb.IDENTITY_TEXT));
    assert.match(wb.IDENTITY_SHA, wb.SHA_RE);
  });
  it('a stored policy that is no longer valid is not turned into a program', () => {
    const r = wb.program({ version: 1, rules: [{ id: 'x', action: 'maybe' }] }); assert.match(r.error, /not valid/); assert.strictEqual(r.text, undefined);
    assert.match(wb.program(null).error, /not valid/);
  });
  it('a program bigger than the limit is not offered (the limit is read live)', () => {
    const was = wf.MAX_PROGRAM_BYTES; wf.MAX_PROGRAM_BYTES = 100;
    try { assert.match(wb.program(POLICY_INPUT).error, /more than the 100 a broker takes/); } finally { wf.MAX_PROGRAM_BYTES = was; }
    assert.ok(wb.program(POLICY_INPUT).text);
  });
  it('the LARGEST policy validate() accepts still fits the limit (if the limits are raised this fails and says so)', () => {
    const ids = Array.from({ length: 100 }, (_, i) => (i % 2 ? (1000 + i * 10) + '-' + (1005 + i * 10) : 2000 + i));
    const big = { version: 1, default: 'drop', channels: Object.fromEntries(Array.from({ length: 20 }, (_, i) => ['Chan' + i, { default: 'keep' }])),
      rules: Array.from({ length: wf.MAX_RULES }, (_, i) => ({ id: 'r' + i, action: i % 2 ? 'keep' : 'drop', channel: 'Microsoft-Windows-Sysmon/Operational', event_ids: ids, match: { field: 'CommandLine', regex: 'a'.repeat(wf.MAX_REGEX) } })),
      message_strip: Array.from({ length: wf.MAX_STRIPS }, () => ({ channel: 'Security', event_ids: ids, regex: 'b'.repeat(wf.MAX_REGEX) })) };
    const v = wf.validate(big); assert.ok(v.ok, v.errors.join('; '));
    const p = wb.program(wf.toInput(v.policy)); assert.ok(!p.error, p.error);
    assert.ok(p.bytes < wf.MAX_PROGRAM_BYTES, 'program is ' + p.bytes + ' bytes against a limit of ' + wf.MAX_PROGRAM_BYTES + ': raise the limit or lower the policy limits');
  });
});

describe('saving refuses a policy that could never be delivered', () => {
  it('parseBody checks the size of the program (read live), with a plain message, and saves nothing', () => {
    assert.ok(store.parseBody({ policy: POLICY_INPUT }).policy);
    const was = wf.MAX_PROGRAM_BYTES; wf.MAX_PROGRAM_BYTES = 400;
    try { const r = store.parseBody({ policy: POLICY_INPUT, if_revision: 0 }); assert.match(r.error, /too large to send to a broker/); assert.strictEqual(r.policy, undefined); } finally { wf.MAX_PROGRAM_BYTES = was; }
    assert.ok(store.parseBody({ policy: POLICY_INPUT }).policy, 'back to normal');
  });
});

// A fake client: `policy` is the win_filter_policy row (or null), `reported` the broker's config_win_filter (undefined = no collector row).
const client = ({ policy = null, reported, missing = false, seen = [] } = {}) => ({ query: async (sql, args) => {
  seen.push({ sql, args });
  if (/FROM win_filter_policy/.test(sql)) { if (missing) { const e = new Error('no table'); e.code = '42P01'; throw e; } return { rows: policy ? [policy] : [] }; }
  if (/config_win_filter FROM collectors/.test(sql)) return { rows: reported === undefined ? [] : [{ config_win_filter: reported }] };
  return { rows: [] };
} });

describe('what the pull announces (readForPull)', () => {
  const row = { policy: POLICY_INPUT, revision: 3, updated_at: new Date() };
  it('a tenant WITH a policy: the hash of its program, every pull, whatever the broker reported', async () => {
    const want = wb.program(POLICY_INPUT).sha256;
    assert.strictEqual(await wb.readForPull(client({ policy: row }), 't1', 'k1', 'broker-1'), want);
    assert.strictEqual(await wb.readForPull(client({ policy: row, reported: want }), 't1', 'k1', 'broker-1'), want);
    assert.strictEqual(await wb.readForPull(client({ policy: row }), 't1', 'k1', null), want, 'a broker script that sends no name gets it too');
  });
  it('a tenant WITHOUT a policy says nothing to a broker that never had a program (the answer keeps the shape it had)', async () => {
    for (const reported of [undefined, null, '', wb.IDENTITY_SHA]) assert.strictEqual(await wb.readForPull(client({ reported }), 't1', 'k1', 'broker-1'), undefined, String(reported));
    assert.strictEqual(await wb.readForPull(client({ reported: HEX }), 't1', 'k1', null), undefined, 'no name: cannot tell which broker, says nothing');
  });
  it('a tenant that REMOVED its policy tells a broker that still has a program to take it away (the keep-everything program)', async () => {
    assert.strictEqual(await wb.readForPull(client({ reported: HEX }), 't1', 'k1', 'broker-1'), wb.IDENTITY_SHA);
  });
  it('the broker is looked up by tenant AND key AND name (one key cannot read another broker\'s report)', async () => {
    const seen = []; await wb.readForPull(client({ seen, reported: HEX }), 't1', 'k1', 'broker-1');
    const q = seen.find((s) => /FROM collectors/.test(s.sql)); assert.match(q.sql, /tenant_id = \$1 AND key_id = \$2 AND name = \$3/); assert.deepStrictEqual(q.args, ['t1', 'k1', 'broker-1']);
  });
  it('a stored policy that is invalid is not announced and the problem is logged, not thrown', async () => {
    const orig = console.error, logged = []; console.error = (...a) => logged.push(a.join(' '));
    try { assert.strictEqual(await wb.readForPull(client({ policy: { policy: { rules: [{ id: 'x', action: 'no' }] }, revision: 2 } }), 't1', 'k1', 'broker-1'), undefined); } finally { console.error = orig; }
    assert.match(logged.join('\n'), /Windows filter not sent to brokers/);
  });
  it('a database without the table throws (the route catches it and leaves the field out)', async () => {
    await assert.rejects(() => wb.readForPull(client({ missing: true }), 't1', 'k1', 'broker-1'), (e) => e.code === '42P01');
  });
  it('current(): revision 0 and the keep-everything program with no policy, the revision and program with one, an error for an invalid one', async () => {
    const none = await wb.current(client(), 't1'); assert.strictEqual(none.revision, 0); assert.strictEqual(none.sha256, wb.IDENTITY_SHA); assert.strictEqual(none.policy, false);
    const some = await wb.current(client({ policy: row }), 't1'); assert.strictEqual(some.revision, 3); assert.strictEqual(some.policy, true); assert.strictEqual(some.sha256, wb.program(POLICY_INPUT).sha256);
    assert.ok((await wb.current(client({ policy: { policy: 5, revision: 1 } }), 't1')).error);
  });
});

describe('the report', () => {
  it('a report without the fields is what it always was; with them it carries the hashes', () => {
    assert.deepStrictEqual(wb.checkReport({ collector: 'broker-1' }), {});
    assert.deepStrictEqual(wb.checkReport({ win_filter: HEX }), { winFilter: HEX, winFilterRejected: '' });
    assert.deepStrictEqual(wb.checkReport({ win_filter: '', rejected_win_filter: HEX2 }), { winFilter: '', winFilterRejected: HEX2 });
    assert.deepStrictEqual(wb.checkReport({ win_filter: HEX, rejected_win_filter: null }), { winFilter: HEX, winFilterRejected: '' });
  });
  it('refuses anything that is not empty or a lower-case 64-character hash', () => {
    for (const v of ['abc', 'A'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), 5, null, {}, 'a'.repeat(63) + ';']) assert.ok(wb.checkReport({ win_filter: v }).error, JSON.stringify(v));
    for (const v of ['abc', 7, {}, 'G'.repeat(64)]) assert.ok(wb.checkReport({ win_filter: HEX, rejected_win_filter: v }).error, JSON.stringify(v));
  });
  it('config.checkReport adds them only when the broker sent them (the shape of every other report is unchanged)', () => {
    const base = { collector: 'broker-1', syslog_port: 514, rejected_port: null };
    const plain = config.checkReport(base); assert.strictEqual(plain.winFilter, undefined); assert.ok(!('winFilter' in plain)); assert.ok(!('winFilterRejected' in plain));
    const full = config.checkReport({ ...base, win_filter: HEX, rejected_win_filter: '' }); assert.strictEqual(full.winFilter, HEX); assert.strictEqual(full.winFilterRejected, '');
    assert.match(config.checkReport({ ...base, win_filter: 'nope' }).error, /win_filter/);
  });
  it('recordReport writes the two columns on the broker\'s own row (tenant AND key AND name) and says whether a row was there', async () => {
    const seen = []; const c = (n) => ({ query: async (sql, args) => { seen.push({ sql, args }); return { rowCount: n }; } });
    assert.strictEqual(await wb.recordReport(c(1), 't1', 'k1', 'broker-1', HEX, ''), true);
    assert.match(seen[0].sql, /SET config_win_filter = \$4, config_rejected_win_filter = \$5 WHERE tenant_id = \$1 AND key_id = \$2 AND name = \$3/); assert.deepStrictEqual(seen[0].args, ['t1', 'k1', 'broker-1', HEX, null]);
    assert.strictEqual(await wb.recordReport(c(0), 't1', 'k1', 'broker-1', '', HEX2), false); assert.deepStrictEqual(seen[1].args, ['t1', 'k1', 'broker-1', '', HEX2]);
  });
});

describe('the signed payload', () => {
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const key = signing.load({ ASIX_CONFIG_SIGNING_KEY: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }) });
  const NOW = Date.UTC(2026, 9, 23, 12, 0, 0);
  it('without a filter the text is exactly what it was before; with one, "win_filter" comes last (after paused_inputs)', () => {
    assert.strictEqual(signing.payloadText('broker-1', 514, NOW, null), '{"v":1,"collector":"broker-1","issued_at":1792756800,"syslog_port":514,"tls_port":null}');
    assert.strictEqual(signing.payloadText('broker-1', 514, NOW, null, undefined, undefined), signing.payloadText('broker-1', 514, NOW, null));
    assert.strictEqual(signing.payloadText('broker-1', 514, NOW, null, undefined, HEX), '{"v":1,"collector":"broker-1","issued_at":1792756800,"syslog_port":514,"tls_port":null,"win_filter":"' + HEX + '"}');
    assert.match(signing.payloadText('broker-1', 514, NOW, null, 'file', HEX), /"paused_inputs":"file","win_filter":"a{64}"\}$/);
  });
  it('the signature covers the hash: verify returns it, and one changed character fails', () => {
    const doc = signing.signedDocument(key, 'broker-1', 514, NOW, null, undefined, HEX);
    const ok = signing.verify(key.publicPem, doc, { expectCollector: 'broker-1', nowMs: NOW }); assert.strictEqual(ok.ok, true); assert.strictEqual(ok.win_filter, HEX);
    assert.strictEqual(signing.verify(key.publicPem, signing.signedDocument(key, 'broker-1', 514, NOW, null), { expectCollector: 'broker-1', nowMs: NOW }).win_filter, undefined, 'nothing said, nothing returned');
    const swapped = { ...doc, payload: Buffer.from(Buffer.from(doc.payload, 'base64').toString().replace(HEX, HEX2)).toString('base64') };
    assert.strictEqual(signing.verify(key.publicPem, swapped, { expectCollector: 'broker-1', nowMs: NOW }).reason, 'bad signature');
  });
  it('a signed hash that is not 64 hex is refused even when the signature is good', () => {
    for (const bad of ['xyz', 'A'.repeat(64), 5]) {
      const doc = signing.signedDocument(key, 'broker-1', 514, NOW, null, undefined, bad);
      assert.strictEqual(signing.verify(key.publicPem, doc, { expectCollector: 'broker-1', nowMs: NOW }).reason, 'unreadable Windows filter hash', String(bad));
    }
  });
  it('the signed payload stays far below the 2000-character limit the broker script puts on it', () => {
    const doc = signing.signedDocument(key, 'x'.repeat(100), 65535, NOW, 65535, 'file,http,journald', HEX);
    assert.ok(doc.payload.length < 700, String(doc.payload.length)); assert.ok(doc.signature.length < 200);
  });
});

describe('routes', () => {
  let srv, base, policyRow = null, reported, missing = false, failDb = false, updates = [], wfUpdates = [], logged = [];
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  before(() => {
    const dbPath = require.resolve('../src/db');
    require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: {
      withTenant: async (tenant, fn) => { if (failDb) throw new Error('boom'); return fn({ query: async (sql, args) => {
        if (/FROM win_filter_policy/.test(sql)) { if (missing) { const e = new Error('no table'); e.code = '42P01'; throw e; } return { rows: policyRow ? [policyRow] : [] }; }
        if (/config_win_filter FROM collectors/.test(sql)) return { rows: reported === undefined ? [] : [{ config_win_filter: reported }] };
        if (/^\s*UPDATE collectors SET config_win_filter/.test(sql)) { wfUpdates.push({ sql, args }); return { rowCount: 1, rows: [] }; }
        if (/^\s*UPDATE collectors/.test(sql)) { updates.push({ sql, args }); return { rowCount: 1, rows: [] }; }
        return { rows: [{ syslog_port: null, tls_port: null }] }; } }); },
      query: async () => ({ rows: [{ id: 'k1', tenant_id: 't1', name: 'broker-1', platform: 'linux' }] }),
    } };
    const shared = require('../src/gateway/shared');
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: require('../src/db'), guarded: () => [(req, res, next) => { req.tenant_id = 't1'; req.user_id = 'u1'; next(); }] };
    const app = express(); app.use(require('../src/ingest/broker-config').router); app.use(express.json());
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); delete process.env.ASIX_CONFIG_SIGNING_KEY; signing.reset(); });
  beforeEach(() => { policyRow = null; reported = undefined; missing = false; failDb = false; updates = []; wfUpdates = []; logged = []; delete process.env.ASIX_CONFIG_SIGNING_KEY; signing.reset(); });
  const KEY = 'Bearer asix_ik_' + 'a'.repeat(40);
  const get = async (p, headers = {}) => { const r = await fetch(base + p, { headers: { authorization: KEY, ...headers } }); const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch (e) { /* plain text */ } return { status: r.status, text, json, headers: r.headers }; };
  const post = async (body) => { const r = await fetch(base + '/v1/ingest/broker-config/report', { method: 'POST', headers: { authorization: KEY, 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };

  it('the pull announces the hash when the tenant has a policy; nothing otherwise (the answer keeps its old shape)', async () => {
    let r = await get('/v1/ingest/broker-config?collector=broker-1'); assert.deepStrictEqual(r.json.config, { syslog_port: null, tls_port: null });
    policyRow = { policy: POLICY_INPUT, revision: 2, updated_at: new Date() };
    r = await get('/v1/ingest/broker-config?collector=broker-1'); assert.strictEqual(r.json.config.win_filter, wb.program(POLICY_INPUT).sha256); assert.strictEqual(r.json.config.syslog_port, null);
    policyRow = null; reported = HEX;
    r = await get('/v1/ingest/broker-config?collector=broker-1'); assert.strictEqual(r.json.config.win_filter, wb.IDENTITY_SHA, 'removed policy: take the filter away');
  });
  it('with a signing key the same hash is inside the signed payload, and a broker that checks it gets the same value', async () => {
    process.env.ASIX_CONFIG_SIGNING_KEY = kp.privateKey.export({ type: 'pkcs8', format: 'pem' }); signing.reset();
    policyRow = { policy: POLICY_INPUT, revision: 2, updated_at: new Date() };
    const r = await get('/v1/ingest/broker-config?collector=broker-1'); const v = signing.verify(signing.current().publicPem, r.json.signed, { expectCollector: 'broker-1' });
    assert.strictEqual(v.ok, true, v.reason); assert.strictEqual(v.win_filter, r.json.config.win_filter);
    policyRow = null; reported = undefined;
    const r2 = await get('/v1/ingest/broker-config?collector=broker-1'); assert.strictEqual(signing.verify(signing.current().publicPem, r2.json.signed, { expectCollector: 'broker-1' }).win_filter, undefined);
  });
  it('a missing table or a failing read leaves the field out and the pull still answers', async () => {
    policyRow = { policy: POLICY_INPUT, revision: 1, updated_at: new Date() }; missing = true;
    let r = await get('/v1/ingest/broker-config?collector=broker-1'); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json.config, { syslog_port: null, tls_port: null });
  });
  it('the download serves the program for the CURRENT policy as plain text with the hash in a header', async () => {
    policyRow = { policy: POLICY_INPUT, revision: 4, updated_at: new Date() };
    const r = await get('/v1/ingest/broker-config/win-filter'); const p = wb.program(POLICY_INPUT);
    assert.strictEqual(r.status, 200); assert.match(r.headers.get('content-type'), /^text\/plain/); assert.strictEqual(r.text, p.text); assert.strictEqual(sha(r.text), p.sha256);
    assert.strictEqual(r.headers.get('x-asix-win-filter-sha256'), p.sha256); assert.strictEqual(r.headers.get('x-asix-win-filter-revision'), '4'); assert.strictEqual(r.headers.get('cache-control'), 'no-store');
  });
  it('with no policy the download is the keep-everything program (how a broker takes a filter away)', async () => {
    const r = await get('/v1/ingest/broker-config/win-filter'); assert.strictEqual(r.status, 200); assert.strictEqual(r.text, wb.IDENTITY_TEXT); assert.strictEqual(r.headers.get('x-asix-win-filter-revision'), '0');
  });
  it('an invalid stored policy is 404 with a code, a missing table 503, a database failure 500; none is a crash', async () => {
    policyRow = { policy: { rules: [{ id: 'x', action: 'no' }] }, revision: 2, updated_at: new Date() };
    let r = await get('/v1/ingest/broker-config/win-filter'); assert.strictEqual(r.status, 404); assert.strictEqual(r.json.error.code, 'WIN_FILTER_UNAVAILABLE');
    policyRow = null; missing = true; r = await get('/v1/ingest/broker-config/win-filter'); assert.strictEqual(r.status, 503); assert.strictEqual(r.json.error.code, 'WIN_FILTER_NOT_READY');
    missing = false; failDb = true; const orig = console.error; console.error = () => {}; try { r = await get('/v1/ingest/broker-config/win-filter'); } finally { console.error = orig; }
    assert.strictEqual(r.status, 500); assert.strictEqual(r.json.error.code, 'BROKER_CONFIG_ERROR');
  });
  it('the download needs the broker\'s key like every ingest route', async () => {
    const r = await fetch(base + '/v1/ingest/broker-config/win-filter'); assert.ok([401, 403].includes(r.status), String(r.status));
  });
  it('the report stores the hashes; without them the Windows filter columns are never touched', async () => {
    let r = await post({ collector: 'broker-1', syslog_port: 514, rejected_port: null }); assert.strictEqual(r.json.recorded, true); assert.strictEqual(wfUpdates.length, 0); assert.strictEqual(updates.length, 1);
    r = await post({ collector: 'broker-1', syslog_port: 514, rejected_port: null, win_filter: HEX, rejected_win_filter: HEX2 }); assert.strictEqual(r.status, 200);
    assert.strictEqual(wfUpdates.length, 1); assert.deepStrictEqual(wfUpdates[0].args, ['t1', 'k1', 'broker-1', HEX, HEX2]); assert.strictEqual(updates.length, 2, 'the port report is stored as well');
    r = await post({ collector: 'broker-1', syslog_port: 514, rejected_port: null, win_filter: 'zzz' }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'BROKER_REPORT_INVALID');
  });
});

describe('what the Brokers page shows (winFilterState)', () => {
  const NOW = Date.parse('2026-10-23T12:00:00Z'), at = (min) => new Date(NOW - min * 60000).toISOString().replace('Z', '');
  const cur = { policy: true, revision: 3, sha256: HEX };
  const none = { policy: false, revision: 0, sha256: wb.IDENTITY_SHA };
  const st = (row, c) => wb.winFilterState({ config_reported_at: at(2), ...row }, c, NOW);
  it('the same fresh-report line as the other config states', () => { assert.strictEqual(wb.FRESH_MS, config.REPORT_FRESH_MS); });
  it('a policy is set: unknown, applied, rejected, pending, stale', () => {
    assert.strictEqual(st({}, cur).state, 'unknown');
    assert.deepStrictEqual({ ...st({ config_win_filter: HEX }, cur) }, { state: 'applied', revision: 3, reported_at: at(2), removing: false });
    assert.strictEqual(st({ config_win_filter: HEX2, config_rejected_win_filter: HEX }, cur).state, 'rejected');
    assert.strictEqual(st({ config_win_filter: HEX2 }, cur).state, 'pending');
    assert.strictEqual(st({ config_win_filter: '' }, cur).state, 'pending', 'a broker with no file yet is waiting for it');
    assert.strictEqual(st({ config_win_filter: HEX2, config_reported_at: at(16) }, cur).state, 'stale');
    assert.strictEqual(st({ config_win_filter: HEX2, config_reported_at: at(15) }, cur).state, 'pending', 'exactly 15 minutes is still fresh');
  });
  it('a rejection of an older program does not show: the state follows the program ASIX wants now', () => {
    assert.strictEqual(st({ config_win_filter: HEX2, config_rejected_win_filter: 'c'.repeat(64) }, cur).state, 'pending');
  });
  it('no policy: nothing to show, unless the broker still has the old program (removing)', () => {
    for (const has of [undefined, null, '', wb.IDENTITY_SHA]) assert.strictEqual(st({ config_win_filter: has }, none).state, 'none', String(has));
    const r = st({ config_win_filter: HEX2 }, none); assert.strictEqual(r.state, 'pending'); assert.strictEqual(r.removing, true);
    assert.strictEqual(st({ config_win_filter: HEX2, config_reported_at: at(30) }, none).state, 'stale');
  });
  it('the policy could not be read: nothing is claimed', () => {
    assert.strictEqual(st({ config_win_filter: HEX }, null).state, 'none'); assert.strictEqual(st({ config_win_filter: HEX }, { error: 'x' }).state, 'none');
  });
  it('broker-view puts it on each broker and counts it in the summary; without a program to compare the broker shows none', () => {
    const view = require('../src/brokers/broker-view');
    const row = (name, extra) => ({ id: name, name, version: 'vector-0.59.0', last_seen: new Date(NOW).toISOString(), first_seen: new Date(NOW).toISOString(), events_total: 0, key_id: 'k1', installer_name: 'k', key_status: 'active', config_reported_at: at(1), ...extra });
    const bs = [row('a', { config_win_filter: HEX }), row('b', {}), row('c', { config_win_filter: HEX2 })].map((r) => view.shape(r, { now: NOW, winFilter: cur }));
    assert.deepStrictEqual(bs.map((b) => b.win_filter.state), ['applied', 'unknown', 'pending']);
    const sum = view.summarize(bs); assert.strictEqual(sum.win_filter_applied, 1); assert.strictEqual(sum.win_filter_not_applied, 2);
    assert.strictEqual(view.shape(row('d', {}), { now: NOW }).win_filter.state, 'none'); assert.deepStrictEqual(bs.map((b) => b.problems), [[], [], []], 'never a problem');
  });
});
