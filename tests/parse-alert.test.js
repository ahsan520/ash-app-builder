'use strict';
// Unparsed-events alert limit chosen in the portal (src/ingestion/parse-alert.js, src/gateway/routes/parser-alert.js, parse-watch tenantConfig):
// the rules, and the two routes and the watchdog's read with the sign-in chain and the database replaced by a recorder.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const pa = require('../src/ingestion/parse-alert');

const server = { threshold: 0, windowMin: 15 };

describe('checkMinEvents / checkWindow', () => {
  it('accept whole numbers in range, as numbers or digit strings', () => {
    for (const [v, n] of [[0, 0], ['0', 0], [1, 1], [' 25 ', 25], ['1000000', 1000000], [1000000, 1000000]]) assert.deepStrictEqual(pa.checkMinEvents(v), { value: n }, String(v));
    for (const [v, n] of [[5, 5], ['15', 15], [1440, 1440]]) assert.deepStrictEqual(pa.checkWindow(v), { value: n }, String(v));
  });
  it('refuse everything else, with a reason', () => {
    for (const v of [-1, '-1', 1000001, '1000001', 1.5, '1.5', 'abc', '', '  ', null, undefined, true, {}, [], '010', '1e3', '٣', '99999999999']) assert.ok(pa.checkMinEvents(v).error, 'events ' + JSON.stringify(v));
    for (const v of [0, 4, '4', 1441, '1441', 7.5, 'x', '', null, undefined, false, '0015']) assert.ok(pa.checkWindow(v).error, 'window ' + JSON.stringify(v));
    assert.match(pa.checkMinEvents('x').error, /^Limit \(events\) must be a whole number from 0 to 1000000/);
    assert.match(pa.checkWindow('x').error, /^Window \(minutes\) must be a whole number from 5 to 1440/);
  });
});

describe('parseBody', () => {
  it('follow_server alone goes back to the server settings', () => assert.deepStrictEqual(pa.parseBody({ follow_server: true }), { follow: true }));
  it('a limit, with or without a window', () => {
    assert.deepStrictEqual(pa.parseBody({ min_events: 20 }), { min_events: 20, window_min: null });
    assert.deepStrictEqual(pa.parseBody({ min_events: '20', window_min: '60' }), { min_events: 20, window_min: 60 });
    assert.deepStrictEqual(pa.parseBody({ min_events: 0 }), { min_events: 0, window_min: null });
    for (const w of [null, undefined, '']) assert.deepStrictEqual(pa.parseBody({ min_events: 3, window_min: w }), { min_events: 3, window_min: null });
  });
  it('refuses a bad body', () => {
    for (const b of [null, undefined, [], 'x', 5, {}, { other: 1 }, { follow_server: false }, { follow_server: 'true' }, { follow_server: true, min_events: 5 }, { follow_server: true, window_min: 15 },
      { min_events: -1 }, { min_events: 'many' }, { min_events: 5, window_min: 4 }, { min_events: 5, window_min: 'x' }, { min_events: null }]) assert.ok(pa.parseBody(b).error, JSON.stringify(b));
  });
});

describe('resolve and view', () => {
  it('no row follows the server; a row wins, including 0 = off over a server that is on', () => {
    assert.deepStrictEqual(pa.resolve(null, { threshold: 30, windowMin: 60 }), { threshold: 30, windowMin: 60, source: 'server' });
    assert.deepStrictEqual(pa.resolve({ min_events: 5, window_min: 10 }, { threshold: 30, windowMin: 60 }), { threshold: 5, windowMin: 10, source: 'tenant' });
    assert.deepStrictEqual(pa.resolve({ min_events: 0, window_min: 15 }, { threshold: 30, windowMin: 60 }), { threshold: 0, windowMin: 15, source: 'tenant' });
  });
  it('a malformed row is ignored rather than trusted', () => {
    for (const row of [{ min_events: null, window_min: 15 }, { min_events: '5', window_min: 15 }, {}, { min_events: 5 }]) assert.strictEqual(pa.resolve(row, server).source, 'server');
  });
  it('view says where the limit comes from, what the server has and the allowed ranges', () => {
    const v = pa.view({ min_events: 20, window_min: 30, updated_at: '2026-10-19T10:00:00Z' }, { threshold: 0, windowMin: 15 });
    assert.deepStrictEqual(v, { available: true, source: 'tenant', min_events: 20, window_min: 30, enabled: true, updated_at: '2026-10-19T10:00:00.000Z',
      server: { min_events: 0, window_min: 15, enabled: false }, limits: { min_events: [0, 1000000], window_min: [5, 1440] } });
    assert.strictEqual(pa.view(null, server).source, 'server'); assert.strictEqual(pa.view(null, server).enabled, false);
    assert.strictEqual(pa.view({ min_events: 0, window_min: 15 }, { threshold: 9, windowMin: 15 }).enabled, false, 'off for the tenant even though the server is on');
    assert.strictEqual(pa.view(null, server, true).available, false);
  });
  it('isMissingTable is the PostgreSQL undefined_table code only', () => {
    assert.strictEqual(pa.isMissingTable({ code: '42P01' }), true);
    for (const e of [null, undefined, new Error('x'), { code: '23505' }]) assert.strictEqual(pa.isMissingTable(e), false);
  });
});

describe('routes', () => {
  const TENANT = '11111111-1111-4111-8111-111111111111';
  let row; let writes; let clears; let mode;   // mode: 'ok' | 'missing' | 'broken'
  const fakeDb = { withTenant: async (t, fn) => fn({ query: async (sql, args) => {
    if (mode === 'missing') { const e = new Error('relation "parse_alert_settings" does not exist'); e.code = '42P01'; throw e; }
    if (mode === 'broken') throw new Error('connection reset');
    if (/^SELECT .* FROM parse_alert_settings/.test(sql)) return { rows: row ? [row] : [] };
    if (/^INSERT INTO parse_alert_settings/.test(sql)) { writes.push(args); row = { min_events: args[1], window_min: args[2], updated_at: new Date('2026-10-19T10:00:00Z') }; return { rows: [] }; }
    if (/^DELETE FROM parse_alert_settings/.test(sql)) { clears.push(args); row = null; return { rows: [] }; }
    throw new Error('unexpected SQL ' + sql);
  } }), query: async () => ({ rows: [] }) };
  const shared = require('../src/gateway/shared');
  const savedShared = require.cache[require.resolve('../src/gateway/shared')].exports;
  const perms = [];
  let srv; let base;
  const savedEnv = { m: process.env.ASIX_PARSE_ALERT_MIN_EVENTS, w: process.env.ASIX_PARSE_ALERT_WINDOW_MIN };
  before(() => {
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: fakeDb, guarded: (p) => { perms.push(p); return [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'u1'; next(); }]; } };
    delete require.cache[require.resolve('../src/gateway/routes/parser-alert')];
    delete process.env.ASIX_PARSE_ALERT_MIN_EVENTS; delete process.env.ASIX_PARSE_ALERT_WINDOW_MIN;
    const app = express(); app.use(express.json());
    app.use(require('../src/gateway/routes/parser-alert'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => {
    srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = savedShared;
    if (savedEnv.m !== undefined) process.env.ASIX_PARSE_ALERT_MIN_EVENTS = savedEnv.m; if (savedEnv.w !== undefined) process.env.ASIX_PARSE_ALERT_WINDOW_MIN = savedEnv.w;
  });
  const call = async (method, p, body, raw) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: raw !== undefined ? raw : body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const reset = (m = 'ok') => { row = null; writes = []; clears = []; mode = m; };

  it('uses the existing permissions: capacity:read to read, parsing:rules:write to change', () => {
    assert.deepStrictEqual([...new Set(perms)].sort(), ['capacity:read', 'parsing:rules:write']);
  });
  it('GET with nothing saved follows the server (off here)', async () => {
    reset();
    const r = await call('GET', '/v1/parser/alert'); assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.settings.source, 'server'); assert.strictEqual(r.json.settings.enabled, false); assert.strictEqual(r.json.settings.window_min, 15);
  });
  it('GET shows the server setting from the environment', async () => {
    reset(); process.env.ASIX_PARSE_ALERT_MIN_EVENTS = '40'; process.env.ASIX_PARSE_ALERT_WINDOW_MIN = '30';
    try { const s = (await call('GET', '/v1/parser/alert')).json.settings; assert.strictEqual(s.min_events, 40); assert.strictEqual(s.window_min, 30); assert.strictEqual(s.source, 'server'); assert.strictEqual(s.enabled, true); }
    finally { delete process.env.ASIX_PARSE_ALERT_MIN_EVENTS; delete process.env.ASIX_PARSE_ALERT_WINDOW_MIN; }
  });
  it('PUT saves the limit for this tenant and GET returns it', async () => {
    reset();
    const r = await call('PUT', '/v1/parser/alert', { min_events: 20, window_min: 30 });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.settings.source, 'tenant'); assert.strictEqual(r.json.settings.min_events, 20); assert.strictEqual(r.json.settings.window_min, 30);
    assert.deepStrictEqual(writes, [[TENANT, 20, 30, 'u1']]);
    assert.strictEqual((await call('GET', '/v1/parser/alert')).json.settings.min_events, 20);
  });
  it('a window left out keeps the saved window, or the server window when nothing is saved', async () => {
    reset(); process.env.ASIX_PARSE_ALERT_WINDOW_MIN = '45';
    try {
      await call('PUT', '/v1/parser/alert', { min_events: 10 }); assert.strictEqual(writes[0][2], 45, 'server window when nothing saved');
      await call('PUT', '/v1/parser/alert', { min_events: 10, window_min: 90 });
      await call('PUT', '/v1/parser/alert', { min_events: 12 }); assert.strictEqual(writes[2][2], 90, 'the saved window');
    } finally { delete process.env.ASIX_PARSE_ALERT_WINDOW_MIN; }
  });
  it('0 saves "off for this tenant"', async () => {
    reset(); const r = await call('PUT', '/v1/parser/alert', { min_events: 0 });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.settings.enabled, false); assert.strictEqual(r.json.settings.source, 'tenant');
  });
  it('follow_server deletes the saved limit', async () => {
    reset(); await call('PUT', '/v1/parser/alert', { min_events: 20 });
    const r = await call('PUT', '/v1/parser/alert', { follow_server: true });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.settings.source, 'server'); assert.deepStrictEqual(clears, [[TENANT]]);
  });
  it('PUT refuses a bad body and writes nothing', async () => {
    reset();
    for (const b of [{}, { min_events: -1 }, { min_events: 'x' }, { min_events: 5, window_min: 2 }, { follow_server: false }, { follow_server: true, min_events: 1 }, []]) {
      const r = await call('PUT', '/v1/parser/alert', b); assert.strictEqual(r.status, 400, JSON.stringify(b)); assert.strictEqual(r.json.error.code, 'INVALID_PARSER_ALERT');
    }
    assert.deepStrictEqual(writes, []); assert.deepStrictEqual(clears, []);
  });
  it('malformed JSON is a 400 from the body parser, never a save', async () => {
    reset(); const r = await fetch(base + '/v1/parser/alert', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: '{"min_events": ' });
    assert.ok(r.status >= 400 && r.status < 500); assert.deepStrictEqual(writes, []);
  });
  it('a database without the table: GET says not available, PUT says run the schema job', async () => {
    reset('missing');
    const g = await call('GET', '/v1/parser/alert'); assert.strictEqual(g.status, 200); assert.strictEqual(g.json.settings.available, false); assert.strictEqual(g.json.settings.source, 'server');
    const p = await call('PUT', '/v1/parser/alert', { min_events: 5 }); assert.strictEqual(p.status, 503); assert.strictEqual(p.json.error.code, 'PARSER_ALERT_NOT_READY');
  });
  it('any other database failure is a 500 with no detail leaked', async () => {
    reset('broken');
    for (const [m, b] of [['GET'], ['PUT', { min_events: 5 }]]) { const r = await call(m, '/v1/parser/alert', b); assert.strictEqual(r.status, 500); assert.strictEqual(r.json.error.code, 'PARSER_ALERT_ERROR'); assert.ok(!/connection reset/.test(JSON.stringify(r.json))); }
  });
});

describe('parse-watch tenantConfig (the watchdog\'s read)', () => {
  const db = require('../src/db');
  const pw = require('../src/ingestion/parse-watch');
  const realWithTenant = db.withTenant;
  after(() => { db.withTenant = realWithTenant; });
  const env = { ASIX_PARSE_ALERT_MIN_EVENTS: '30', ASIX_PARSE_ALERT_WINDOW_MIN: '60' };
  const withRow = (row) => { db.withTenant = async (t, fn) => fn({ query: async () => ({ rows: row ? [row] : [] }) }); };
  it('no row: the environment', async () => { withRow(null); assert.deepStrictEqual(await pw.tenantConfig('t1', env), { threshold: 30, windowMin: 60, source: 'server' }); });
  it('a row wins over the environment, and 0 turns it off', async () => {
    withRow({ min_events: 5, window_min: 10 }); assert.deepStrictEqual(await pw.tenantConfig('t1', env), { threshold: 5, windowMin: 10, source: 'tenant' });
    withRow({ min_events: 0, window_min: 15 }); assert.strictEqual((await pw.tenantConfig('t1', env)).threshold, 0);
  });
  it('a database without the table falls back to the environment; another failure throws (the watchdog logs it and tries again)', async () => {
    const warn = console.warn; const lines = []; console.warn = (m) => lines.push(m);
    try {
      db.withTenant = async () => { const e = new Error('no table'); e.code = '42P01'; throw e; };
      assert.strictEqual((await pw.tenantConfig('t1', env)).source, 'server'); await pw.tenantConfig('t1', env);
      assert.strictEqual(lines.length, 1, 'logged once per process');
    } finally { console.warn = warn; }
    db.withTenant = async () => { throw new Error('connection reset'); };
    await assert.rejects(() => pw.tenantConfig('t1', env), /connection reset/);
  });
  it('runTenant with an explicit cfg never reads the settings table', async () => {
    const sqls = []; db.withTenant = async (t, fn) => fn({ query: async (sql) => { sqls.push(sql); return { rows: [] }; } });
    await pw.runTenant('t1', { cfg: { threshold: 0, windowMin: 15 }, sev: 'high', store: { search: async () => { throw new Error('must not count while off'); } } });
    assert.ok(sqls.length > 0 && sqls.every((q) => !/parse_alert_settings/.test(q)), 'only the alert queries');
  });
});
