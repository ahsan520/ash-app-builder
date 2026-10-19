'use strict';
// A broker's syslog port and its TLS port must differ, from both directions and for the tenant-wide saves, without a database.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const config = require('../src/brokers/config');

describe('clash helpers', () => {
  const q = (rows, seen) => ({ query: async (sql, args) => { seen.push({ sql, args }); return { rows }; } });
  it('the tenant-wide reads look only at brokers that would follow the new value, and return names', async () => {
    const seen = [];
    assert.deepStrictEqual(await config.brokersClashingWithSyslog(q([{ name: 'a' }, { name: 'b' }, {}], seen), 't1', 6515), ['a', 'b']);
    assert.match(seen[0].sql, /syslog_port_override IS NULL AND syslog_port_exclude = false AND tls_port_override = \$2/); assert.deepStrictEqual(seen[0].args, ['t1', 6515]);
    assert.deepStrictEqual(await config.brokersClashingWithTls(q([{ name: 'a' }], seen), 't1', 2514), ['a']);
    assert.match(seen[1].sql, /tls_port_override IS NULL AND syslog_port_exclude = false AND syslog_port_override = \$2/);
    assert.deepStrictEqual(await config.brokersClashingWithTls(q([], seen), 't1', 1), []);
  });
  it('readBrokerTlsPort: own wins, left out means none, else the tenant-wide port, no broker is null', async () => {
    const mk = (row, tenant) => ({ query: async (sql) => (/FROM collectors/.test(sql) ? { rows: row ? [row] : [] } : { rows: [{ tls_port: tenant }] }) });
    assert.deepStrictEqual(await config.readBrokerTlsPort(mk({ tls_port_override: 6515, syslog_port_exclude: true }, 6514), 't', 'b'), { port: 6515 });
    assert.deepStrictEqual(await config.readBrokerTlsPort(mk({ tls_port_override: null, syslog_port_exclude: true }, 6514), 't', 'b'), { port: null });
    assert.deepStrictEqual(await config.readBrokerTlsPort(mk({ tls_port_override: null, syslog_port_exclude: false }, 6514), 't', 'b'), { port: 6514 });
    assert.strictEqual(await config.readBrokerTlsPort(mk(null, 6514), 't', 'b'), null);
  });
});

describe('routes', () => {
  let srv, base, rows = {}, tlsFails = false;
  const ID = '11111111-1111-4111-8111-111111111111';
  const writes = [];
  before(() => {
    const dbPath = require.resolve('../src/db');
    require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: { withTenant: async (t, fn) => fn({ query: async (sql, args) => {
      if (/^\s*UPDATE collectors SET syslog_port_override/.test(sql)) { writes.push('own'); return { rows: [{ id: ID, name: 'broker-1' }] }; }
      if (/INSERT INTO broker_settings/.test(sql)) { writes.push('tenant'); return { rows: [] }; }
      if (/SELECT tls_port_override, syslog_port_exclude FROM collectors/.test(sql)) { if (tlsFails) throw new Error('column does not exist'); return { rows: [rows.broker || { tls_port_override: null, syslog_port_exclude: false }] }; }
      if (/tls_port_override = \$2/.test(sql)) return { rows: rows.clashSyslog || [] };
      if (/syslog_port_override = \$2/.test(sql)) return { rows: rows.clashTls || [] };
      if (/SELECT tls_port FROM broker_settings/.test(sql)) return { rows: [{ tls_port: rows.tenantTls ?? null }] };
      if (/SELECT syslog_port FROM broker_settings/.test(sql)) return { rows: [{ syslog_port: null }] };
      return { rows: [] }; } }) } };
    const shared = require('../src/gateway/shared');
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: require('../src/db'), guarded: () => [(req, res, next) => { req.tenant_id = 't1'; req.user_id = 'u1'; next(); }] };
    const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/broker-port')); app.use(require('../src/gateway/routes/broker-config'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => srv.close());
  const call = async (method, p, body) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const own = (v) => call('PUT', '/v1/brokers/' + ID + '/syslog-port', { syslog_port: v });
  const reset = () => { rows = {}; tlsFails = false; writes.length = 0; };

  it('an own syslog port equal to the TLS port this broker is asked for is refused, nothing written', async () => {
    reset(); rows.tenantTls = 6514; let r = await own(6514); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_SYSLOG_PORT'); assert.match(r.json.error.message, /TLS port/);
    rows.broker = { tls_port_override: 6515, syslog_port_exclude: false }; assert.strictEqual((await own(6515)).status, 400, 'its own TLS port');
    assert.strictEqual((await own(6514)).status, 200, 'the tenant-wide TLS port is not its own while it has one');
    rows.broker = { tls_port_override: null, syslog_port_exclude: true }; assert.strictEqual((await own(6514)).status, 200, 'left out: asked for no TLS port');
    assert.deepStrictEqual(writes, ['own', 'own']);
  });
  it('clearing the port, and a database without the TLS column, are not blocked', async () => {
    reset(); rows.tenantTls = 6514; assert.strictEqual((await own(null)).status, 200);
    tlsFails = true; assert.strictEqual((await own(6514)).status, 200); reset();
  });
  it('a tenant-wide syslog port that would clash with a following broker\'s own TLS port is refused with the names', async () => {
    reset(); rows.clashSyslog = [{ name: 'broker-a' }, { name: 'broker-c' }];
    const r = await call('PUT', '/v1/broker-config', { syslog_port: 6515 }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_SYSLOG_PORT'); assert.match(r.json.error.message, /broker-a, broker-c/);
    assert.deepStrictEqual(writes, []); rows.clashSyslog = []; assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: 6515 })).status, 200); assert.deepStrictEqual(writes, ['tenant']);
  });
  it('a tenant-wide TLS port that would clash with a following broker\'s own syslog port is refused with the names', async () => {
    reset(); rows.clashTls = [{ name: 'broker-b' }];
    const r = await call('PUT', '/v1/broker-config', { tls_port: 2514 }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_TLS_PORT'); assert.match(r.json.error.message, /broker-b/);
    assert.deepStrictEqual(writes, []); assert.strictEqual((await call('PUT', '/v1/broker-config', { tls_port: null })).status, 200); reset();
  });
});
