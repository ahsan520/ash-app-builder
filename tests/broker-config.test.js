'use strict';
// Broker config pull, server side without a database: the port rules (src/brokers/config.js) and the two routes with the
// sign-in chain, the key lookup and the database replaced.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const config = require('../src/brokers/config');

describe('checkSyslogPort', () => {
  it('accepts plain ports as numbers or digit strings', () => {
    assert.deepStrictEqual(config.checkSyslogPort(1514), { value: 1514 });
    assert.deepStrictEqual(config.checkSyslogPort(' 1514 '), { value: 1514 });
    assert.deepStrictEqual(config.checkSyslogPort('1'), { value: 1 });
    assert.deepStrictEqual(config.checkSyslogPort('65535'), { value: 65535 });
  });
  it('empty, null and undefined clear it', () => {
    for (const v of [null, undefined, '', '   ']) assert.deepStrictEqual(config.checkSyslogPort(v), { value: null });
  });
  it('refuses everything else, with a reason', () => {
    for (const v of [0, '0', 65536, '65536', -1, '-1', '1.5', 1.5, '0514', '514; rm -rf /', 'abc', '1e3', true, {}, [], '١٥١٤']) {
      const r = config.checkSyslogPort(v); assert.ok(r.error, JSON.stringify(v)); assert.strictEqual(r.value, undefined);
    }
  });
  it('refuses the reserved ports by name', () => {
    for (const [p, what] of [[22, /SSH/], [443, /HTTPS/], [8686, /health/], [30443, /ASIX HTTPS/]]) assert.match(config.checkSyslogPort(p).error, what);
    assert.deepStrictEqual(config.view(1514), { syslog_port: 1514, reserved_ports: [22, 443, 8686, 30443] });
  });
});

describe('database helpers', () => {
  it('read: no row and a null column both mean no opinion; a number comes back as a number', async () => {
    const q = (rows) => ({ query: async () => ({ rows }) });
    assert.strictEqual(await config.readSyslogPort(q([]), 't'), null);
    assert.strictEqual(await config.readSyslogPort(q([{ syslog_port: null }]), 't'), null);
    assert.strictEqual(await config.readSyslogPort(q([{ syslog_port: 1514 }]), 't'), 1514);
  });
  it('write: touches only syslog_port', async () => {
    const seen = []; await config.writeSyslogPort({ query: async (sql, args) => { seen.push({ sql, args }); } }, 'tenant-1', 1514, 'u1');
    assert.match(seen[0].sql, /ON CONFLICT \(tenant_id\) DO UPDATE SET syslog_port = EXCLUDED\.syslog_port/); assert.doesNotMatch(seen[0].sql, /vector_target/);
    assert.deepStrictEqual(seen[0].args, ['tenant-1', 1514, 'u1']);
  });
});

describe('routes', () => {
  let srv, base, stored = null, failDb = false, failKey = false;
  before(() => {
    const dbPath = require.resolve('../src/db');
    require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: {
      withTenant: async (tenant, fn) => { if (failDb) throw new Error('boom'); return fn({ query: async (sql, args) => {
        if (/^SELECT/.test(sql)) return { rows: [{ syslog_port: stored }] };
        stored = args[1]; return { rows: [] }; } }); },
      query: async () => ({ rows: failKey ? [] : [{ id: 'k1', tenant_id: 't1', name: 'broker-1', platform: 'linux' }] }),
    } };
    const shared = require('../src/gateway/shared');
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: require('../src/db'), guarded: () => [(req, res, next) => { req.tenant_id = 't1'; req.user_id = 'u1'; next(); }] };
    const app = express(); app.use(express.json());
    app.use(require('../src/ingest/broker-config').router); app.use(require('../src/gateway/routes/broker-config'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => srv.close());
  const call = async (method, p, body, headers = {}) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const KEY = 'Bearer asix_ik_' + 'a'.repeat(40);

  it('the portal route reads, saves, validates and clears', async () => {
    assert.strictEqual((await call('GET', '/v1/broker-config')).json.config.syslog_port, null);
    let r = await call('PUT', '/v1/broker-config', { syslog_port: 1514 }); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.config.syslog_port, 1514); assert.strictEqual(stored, 1514);
    assert.strictEqual((await call('GET', '/v1/broker-config')).json.config.syslog_port, 1514);
    for (const bad of [{}, { syslog_port: 22 }, { syslog_port: 'x' }, { syslog_port: 70000 }]) { r = await call('PUT', '/v1/broker-config', bad); assert.strictEqual(r.status, 400, JSON.stringify(bad)); }
    assert.strictEqual(stored, 1514, 'a refused value changes nothing');
    r = await call('PUT', '/v1/broker-config', { syslog_port: null }); assert.strictEqual(r.status, 200); assert.strictEqual(stored, null);
  });
  it('a database failure is a 500 with a code, not a crash', async () => {
    failDb = true; try { const r = await call('PUT', '/v1/broker-config', { syslog_port: 1514 }); assert.strictEqual(r.status, 500); assert.strictEqual(r.json.error.code, 'BROKER_CONFIG_ERROR'); } finally { failDb = false; }
  });
  it('the broker route needs a valid key and answers with the port or null', async () => {
    assert.strictEqual((await call('GET', '/v1/ingest/broker-config')).status, 401);
    failKey = true; assert.strictEqual((await call('GET', '/v1/ingest/broker-config', undefined, { authorization: KEY })).status, 401); failKey = false;
    stored = null; let r = await call('GET', '/v1/ingest/broker-config', undefined, { authorization: KEY });
    assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json.config, { syslog_port: null }); assert.strictEqual(r.json.interval_seconds, 300);
    stored = 1514; r = await call('GET', '/v1/ingest/broker-config', undefined, { authorization: KEY }); assert.deepStrictEqual(r.json.config, { syslog_port: 1514 });
  });
  it('the broker route is read only and a database failure is a 500', async () => {
    assert.ok([404, 405].includes((await fetch(base + '/v1/ingest/broker-config', { method: 'POST', headers: { authorization: KEY } })).status));
    failDb = true; try { assert.strictEqual((await call('GET', '/v1/ingest/broker-config', undefined, { authorization: KEY })).status, 500); } finally { failDb = false; }
  });
});
