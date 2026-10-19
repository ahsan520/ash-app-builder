'use strict';
// A syslog port for ONE broker (collectors.syslog_port_override), server side without a database: the rules in src/brokers/config.js,
// how the Brokers page shapes it (src/brokers/broker-view.js), the portal route and the broker's pull with ?collector=.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const config = require('../src/brokers/config');
const view = require('../src/brokers/broker-view');

describe('which port a broker is asked for', () => {
  it('its own port wins over the tenant-wide one, which wins over nothing', () => {
    assert.strictEqual(config.effectivePort(1514, 2514), 2514);
    assert.strictEqual(config.effectivePort(1514, null), 1514);
    assert.strictEqual(config.effectivePort(null, 2514), 2514, 'an own port works with no tenant-wide port');
    assert.strictEqual(config.effectivePort(null, null), null);
    assert.strictEqual(config.effectivePort(undefined, undefined), null);
    assert.strictEqual(config.effectivePort('1514', '2514'), 2514, 'a column that comes back as text is still a number');
  });
  it('says where the port came from', () => {
    assert.strictEqual(config.portSource(1514, 2514), 'broker');
    assert.strictEqual(config.portSource(1514, null), 'tenant');
    assert.strictEqual(config.portSource(null, null), 'none');
  });
  it('nameOrNull accepts only a plain broker name (it goes into a URL)', () => {
    assert.strictEqual(config.nameOrNull('broker-1'), 'broker-1');
    assert.strictEqual(config.nameOrNull('b.2:x_y'), 'b.2:x_y');
    for (const v of [undefined, null, '', 'a b', 'a/b', 'a&b=c', 'a?b', 'x'.repeat(101), ['broker-1'], { a: 1 }, 5]) assert.strictEqual(config.nameOrNull(v), null, JSON.stringify(v));
  });
});

describe('database helpers', () => {
  it('readOverride finds the row by key AND name, and no row or a null column means no override', async () => {
    const seen = []; const q = (rows) => ({ query: async (sql, args) => { seen.push({ sql, args }); return { rows }; } });
    assert.strictEqual(await config.readOverride(q([{ syslog_port_override: 2514 }]), 't1', 'k1', 'broker-1'), 2514);
    assert.strictEqual(await config.readOverride(q([{ syslog_port_override: null }]), 't1', 'k1', 'broker-1'), null);
    assert.strictEqual(await config.readOverride(q([]), 't1', 'k1', 'ghost'), null);
    assert.match(seen[0].sql, /WHERE tenant_id = \$1 AND key_id = \$2 AND name = \$3/);
    assert.deepStrictEqual(seen[0].args, ['t1', 'k1', 'broker-1']);
  });
  it('writeOverride updates one broker of this tenant only, never a non-broker collector, and says if it found one', async () => {
    const seen = []; const q = (rows) => ({ query: async (sql, args) => { seen.push({ sql, args }); return { rows }; } });
    assert.deepStrictEqual(await config.writeOverride(q([{ id: 'b1', name: 'broker-1', extra: 'x' }]), 't1', 'b1', 2514), { id: 'b1', name: 'broker-1' });
    assert.strictEqual(await config.writeOverride(q([]), 't1', 'nope', null), null);
    assert.match(seen[0].sql, /^\s*UPDATE collectors SET syslog_port_override = \$3 WHERE id = \$1 AND tenant_id = \$2 AND version ILIKE 'vector-%'/);
    assert.deepStrictEqual(seen[0].args, ['b1', 't1', 2514]); assert.deepStrictEqual(seen[1].args, ['nope', 't1', null]);
  });
});

describe('the Brokers page shape', () => {
  const NOW = Date.parse('2026-10-18T12:00:00Z');
  const row = (o = {}) => ({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', last_seen: new Date(NOW - 60000), key_id: 'k1', installer_name: 'k', key_status: 'active',
    config_syslog_port: null, config_rejected_port: null, config_reported_at: null, syslog_port_override: null, ...o });
  it('with no own port nothing changes: it follows the tenant-wide port', () => {
    const b = view.shape(row({ config_syslog_port: 1514, config_reported_at: new Date(NOW - 60000) }), { now: NOW, syslogPort: 1514 });
    assert.strictEqual(b.config.state, 'applied'); assert.strictEqual(b.config.source, 'tenant'); assert.strictEqual(b.config.override_port, null); assert.strictEqual(b.config.configured_port, 1514);
  });
  it('an own port is the one compared with what the broker reports, whatever the tenant-wide port is', () => {
    let b = view.shape(row({ syslog_port_override: 2514, config_syslog_port: 1514, config_reported_at: new Date(NOW - 60000) }), { now: NOW, syslogPort: 1514 });
    assert.strictEqual(b.config.state, 'pending'); assert.strictEqual(b.config.configured_port, 2514); assert.strictEqual(b.config.source, 'broker'); assert.strictEqual(b.config.override_port, 2514);
    b = view.shape(row({ syslog_port_override: 2514, config_syslog_port: 2514, config_reported_at: new Date(NOW - 60000) }), { now: NOW, syslogPort: 1514 });
    assert.strictEqual(b.config.state, 'applied');
    b = view.shape(row({ syslog_port_override: 2514, config_syslog_port: 514, config_rejected_port: 2514, config_reported_at: new Date(NOW - 60000) }), { now: NOW, syslogPort: null });
    assert.strictEqual(b.config.state, 'rejected', 'works with no tenant-wide port at all');
    b = view.shape(row({ syslog_port_override: 2514 }), { now: NOW, syslogPort: null }); assert.strictEqual(b.config.state, 'unknown');
  });
  it('a row from a database without the column behaves as before', () => {
    const r = row(); delete r.syslog_port_override;
    const b = view.shape(r, { now: NOW, syslogPort: null }); assert.strictEqual(b.config.state, 'none'); assert.strictEqual(b.config.source, 'none'); assert.strictEqual(b.config.override_port, null);
  });
  it('the summary counts brokers with their own port, and applied / not applied follow the effective port', () => {
    const fresh = new Date(NOW - 60000);
    const list = [view.shape(row({ id: 'a', syslog_port_override: 2514, config_syslog_port: 2514, config_reported_at: fresh }), { now: NOW, syslogPort: 1514 }),
      view.shape(row({ id: 'b', config_syslog_port: 514, config_reported_at: fresh }), { now: NOW, syslogPort: 1514 }),
      view.shape(row({ id: 'c' }), { now: NOW, syslogPort: null })];
    const s = view.summarize(list); assert.strictEqual(s.port_overrides, 1); assert.strictEqual(s.config_applied, 1); assert.strictEqual(s.config_not_applied, 1);
  });
});

describe('routes', () => {
  let srv, base, failDb = false, failKey = false, tenantPort = null, ownPort = null, ownFails = false, writes = [], found = true;
  const ID = '11111111-1111-4111-8111-111111111111';
  before(() => {
    const dbPath = require.resolve('../src/db');
    require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: {
      withTenant: async (tenant, fn) => { if (failDb) throw new Error('boom'); return fn({ query: async (sql, args) => {
        if (/^\s*UPDATE collectors SET syslog_port_override/.test(sql)) { writes.push({ sql, args }); return { rows: found ? [{ id: args[0], name: 'broker-1' }] : [] }; }
        if (/FROM collectors/.test(sql)) { if (ownFails) throw new Error('column "syslog_port_override" does not exist'); return { rows: [{ syslog_port_override: ownPort }] }; }
        return { rows: [{ syslog_port: tenantPort }] }; } }); },
      query: async () => ({ rows: failKey ? [] : [{ id: 'k1', tenant_id: 't1', name: 'broker-1', platform: 'linux' }] }),
    } };
    const shared = require('../src/gateway/shared');
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: require('../src/db'), guarded: () => [(req, res, next) => { req.tenant_id = 't1'; req.user_id = 'u1'; next(); }] };
    const app = express();
    app.use(require('../src/ingest/broker-config').router); app.use(express.json()); app.use(require('../src/gateway/routes/broker-port'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => srv.close());
  const call = async (method, p, body, headers = {}) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const KEY = { authorization: 'Bearer asix_ik_' + 'a'.repeat(40) };
  const put = (id, body) => call('PUT', '/v1/brokers/' + id + '/syslog-port', body);

  it('the portal route saves, clears and validates', async () => {
    let r = await put(ID, { syslog_port: 2514 }); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json, { success: true, broker: { id: ID, name: 'broker-1' }, syslog_port: 2514 });
    assert.deepStrictEqual(writes.at(-1).args, [ID, 't1', 2514]);
    r = await put(ID, { syslog_port: '2515' }); assert.strictEqual(r.json.syslog_port, 2515);
    r = await put(ID, { syslog_port: null }); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.syslog_port, null); assert.deepStrictEqual(writes.at(-1).args, [ID, 't1', null]);
    r = await put(ID, { syslog_port: '' }); assert.strictEqual(r.json.syslog_port, null);
    const n = writes.length;
    for (const bad of [{}, { syslog_port: 22 }, { syslog_port: 30443 }, { syslog_port: 0 }, { syslog_port: 65536 }, { syslog_port: 'x' }, { syslog_port: '514; ls' }]) {
      r = await put(ID, bad); assert.strictEqual(r.status, 400, JSON.stringify(bad)); assert.ok(['INVALID_BODY', 'INVALID_SYSLOG_PORT'].includes(r.json.error.code));
    }
    assert.strictEqual(writes.length, n, 'refused values write nothing');
  });
  it('a bad id is a 400, an unknown or non-broker row a 404, a database failure a 500', async () => {
    let r = await put('not-a-uuid', { syslog_port: 2514 }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_ID');
    found = false; try { r = await put(ID, { syslog_port: 2514 }); assert.strictEqual(r.status, 404); } finally { found = true; }
    failDb = true; try { r = await put(ID, { syslog_port: 2514 }); assert.strictEqual(r.status, 500); assert.strictEqual(r.json.error.code, 'BROKER_CONFIG_ERROR'); } finally { failDb = false; }
  });
  it('the pull without a name answers the tenant-wide port exactly as before', async () => {
    tenantPort = 1514; ownPort = 2514;
    let r = await call('GET', '/v1/ingest/broker-config', undefined, KEY); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json.config, { syslog_port: 1514, tls_port: null });
    tenantPort = null; r = await call('GET', '/v1/ingest/broker-config', undefined, KEY); assert.deepStrictEqual(r.json.config, { syslog_port: null, tls_port: null });
  });
  it('the pull with its name answers its own port, else the tenant-wide one, else null', async () => {
    const get = () => call('GET', '/v1/ingest/broker-config?collector=broker-1', undefined, KEY);
    tenantPort = 1514; ownPort = 2514; assert.deepStrictEqual((await get()).json.config, { syslog_port: 2514, tls_port: null });
    ownPort = null; assert.deepStrictEqual((await get()).json.config, { syslog_port: 1514, tls_port: null });
    tenantPort = null; assert.deepStrictEqual((await get()).json.config, { syslog_port: null, tls_port: null });
    tenantPort = null; ownPort = 2514; assert.deepStrictEqual((await get()).json.config, { syslog_port: 2514, tls_port: null }, 'an own port needs no tenant-wide port');
  });
  it('a name that is not a plain name is ignored, and so is a repeated one', async () => {
    tenantPort = 1514; ownPort = 2514;
    for (const q of ['collector=a%20b', 'collector=a%2Fb', 'collector=', 'collector=broker-1&collector=broker-2']) {
      const r = await call('GET', '/v1/ingest/broker-config?' + q, undefined, KEY); assert.strictEqual(r.status, 200, q); assert.deepStrictEqual(r.json.config, { syslog_port: 1514, tls_port: null }, q);
    }
  });
  it('if the column is not there yet the tenant-wide port still answers; a key still has to be valid', async () => {
    tenantPort = 1514; ownFails = true; try {
      const r = await call('GET', '/v1/ingest/broker-config?collector=broker-1', undefined, KEY); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json.config, { syslog_port: 1514, tls_port: null });
    } finally { ownFails = false; }
    assert.strictEqual((await call('GET', '/v1/ingest/broker-config?collector=broker-1')).status, 401);
    failKey = true; try { assert.strictEqual((await call('GET', '/v1/ingest/broker-config?collector=broker-1', undefined, KEY)).status, 401); } finally { failKey = false; }
    failDb = true; try { assert.strictEqual((await call('GET', '/v1/ingest/broker-config?collector=broker-1', undefined, KEY)).status, 500); } finally { failDb = false; }
  });
});
