'use strict';
// A syslog-over-TLS port for ONE broker (collectors.tls_port_override), server side without a database: the rules in src/brokers/config.js,
// how the Brokers page shapes it (src/brokers/broker-view.js), the portal route and the broker's pull with ?collector=.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const config = require('../src/brokers/config');
const view = require('../src/brokers/broker-view');

describe('which TLS port a broker is asked for', () => {
  it('its own port wins over the tenant-wide one, which wins over nothing', () => {
    assert.strictEqual(config.effectiveTlsPort(6514, 6515), 6515);
    assert.strictEqual(config.effectiveTlsPort(6514, null), 6514);
    assert.strictEqual(config.effectiveTlsPort(null, 6515), 6515, 'an own port works with no tenant-wide port');
    assert.strictEqual(config.effectiveTlsPort(null, null), null);
    assert.strictEqual(config.effectiveTlsPort(undefined, undefined), null);
    assert.strictEqual(config.effectiveTlsPort('6514', '6515'), 6515, 'a column that comes back as text is still a number');
  });
  it('a broker left out of the tenant-wide ports is told no tenant-wide TLS port, but its own still applies', () => {
    assert.strictEqual(config.effectiveTlsPort(6514, null, true), null);
    assert.strictEqual(config.effectiveTlsPort(6514, 6515, true), 6515);
  });
  it('says where the port came from', () => {
    assert.strictEqual(config.tlsSource(6514, 6515), 'broker');
    assert.strictEqual(config.tlsSource(6514, null), 'tenant');
    assert.strictEqual(config.tlsSource(6514, null, true), 'excluded');
    assert.strictEqual(config.tlsSource(6514, 6515, true), 'broker');
    assert.strictEqual(config.tlsSource(null, null), 'none');
  });
});

describe('database helpers', () => {
  const q = (rows, seen) => ({ query: async (sql, args) => { seen.push({ sql, args }); return { rows }; } });
  it('readTlsOverride finds the row by key AND name, and no row or a null column means none', async () => {
    const seen = [];
    assert.strictEqual(await config.readTlsOverride(q([{ tls_port_override: 6515 }], seen), 't1', 'k1', 'broker-1'), 6515);
    assert.strictEqual(await config.readTlsOverride(q([{ tls_port_override: null }], seen), 't1', 'k1', 'broker-1'), null);
    assert.strictEqual(await config.readTlsOverride(q([], seen), 't1', 'k1', 'ghost'), null);
    assert.match(seen[0].sql, /WHERE tenant_id = \$1 AND key_id = \$2 AND name = \$3/);
    assert.deepStrictEqual(seen[0].args, ['t1', 'k1', 'broker-1']);
  });
  it('writeTlsOverride updates one broker of this tenant only, never a non-broker collector, and says if it found one', async () => {
    const seen = [];
    assert.deepStrictEqual(await config.writeTlsOverride(q([{ id: 'b1', name: 'broker-1', extra: 'x' }], seen), 't1', 'b1', 6515), { id: 'b1', name: 'broker-1' });
    assert.strictEqual(await config.writeTlsOverride(q([], seen), 't1', 'nope', null), null);
    assert.match(seen[0].sql, /^\s*UPDATE collectors SET tls_port_override = \$3 WHERE id = \$1 AND tenant_id = \$2 AND version ILIKE 'vector-%'/);
    assert.deepStrictEqual(seen[0].args, ['b1', 't1', 6515]);
  });
  it('readBrokerPorts reads the broker\'s own syslog port and flag, or null for no such broker', async () => {
    const seen = [];
    assert.deepStrictEqual(await config.readBrokerPorts(q([{ syslog_port_override: 2514, syslog_port_exclude: true }], seen), 't1', 'b1'), { own: 2514, excluded: true });
    assert.deepStrictEqual(await config.readBrokerPorts(q([{ syslog_port_override: null, syslog_port_exclude: false }], seen), 't1', 'b1'), { own: null, excluded: false });
    assert.strictEqual(await config.readBrokerPorts(q([], seen), 't1', 'nope'), null);
    assert.match(seen[0].sql, /WHERE id = \$1 AND tenant_id = \$2 AND version ILIKE 'vector-%'/);
  });
});

describe('the Brokers page shape', () => {
  const NOW = Date.parse('2026-10-19T12:00:00Z');
  const fresh = new Date(NOW - 60000);
  const row = (o = {}) => ({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', last_seen: new Date(NOW - 60000), key_id: 'k1', installer_name: 'k', key_status: 'active',
    config_syslog_port: null, config_rejected_port: null, config_reported_at: null, config_tls_port: null, config_rejected_tls_port: null, syslog_port_override: null, tls_port_override: null, ...o });
  it('with no own TLS port nothing changes: it follows the tenant-wide TLS port', () => {
    const b = view.shape(row({ config_tls_port: 6514, config_reported_at: fresh }), { now: NOW, tlsPort: 6514 });
    assert.strictEqual(b.tls.state, 'applied'); assert.strictEqual(b.tls.source, 'tenant'); assert.strictEqual(b.tls.override_port, null); assert.strictEqual(b.tls.configured_port, 6514);
  });
  it('an own TLS port is the one compared with what the broker reports, whatever the tenant-wide port is', () => {
    let b = view.shape(row({ tls_port_override: 6515, config_tls_port: 6514, config_reported_at: fresh }), { now: NOW, tlsPort: 6514 });
    assert.strictEqual(b.tls.state, 'pending'); assert.strictEqual(b.tls.configured_port, 6515); assert.strictEqual(b.tls.source, 'broker'); assert.strictEqual(b.tls.override_port, 6515);
    b = view.shape(row({ tls_port_override: 6515, config_tls_port: 6515, config_reported_at: fresh }), { now: NOW, tlsPort: 6514 });
    assert.strictEqual(b.tls.state, 'applied');
    b = view.shape(row({ tls_port_override: 6515, config_tls_port: 6514, config_rejected_tls_port: 6515, config_reported_at: fresh }), { now: NOW, tlsPort: null });
    assert.strictEqual(b.tls.state, 'rejected', 'works with no tenant-wide TLS port at all');
    b = view.shape(row({ tls_port_override: 6515 }), { now: NOW, tlsPort: null }); assert.strictEqual(b.tls.state, 'unknown');
    b = view.shape(row({ tls_port_override: 6515, config_tls_port: 0, config_reported_at: fresh }), { now: NOW, tlsPort: null }); assert.strictEqual(b.tls.state, 'no_listener');
  });
  it('a broker left out of the tenant-wide ports is asked for nothing, unless it has its own TLS port', () => {
    let b = view.shape(row({ syslog_port_exclude: true, config_tls_port: 6514, config_reported_at: fresh }), { now: NOW, tlsPort: 6515 });
    assert.strictEqual(b.tls.state, 'none'); assert.strictEqual(b.tls.source, 'excluded');
    b = view.shape(row({ syslog_port_exclude: true, tls_port_override: 6515, config_tls_port: 6515, config_reported_at: fresh }), { now: NOW, tlsPort: 6514 });
    assert.strictEqual(b.tls.state, 'applied'); assert.strictEqual(b.tls.source, 'broker');
  });
  it('a row from a database without the column behaves as before', () => {
    const r = row(); delete r.tls_port_override;
    const b = view.shape(r, { now: NOW, tlsPort: null }); assert.strictEqual(b.tls.state, 'none'); assert.strictEqual(b.tls.source, 'none'); assert.strictEqual(b.tls.override_port, null);
  });
  it('the summary counts brokers with their own TLS port, and applied / not applied follow the effective port', () => {
    const list = [view.shape(row({ id: 'a', tls_port_override: 6515, config_tls_port: 6515, config_reported_at: fresh }), { now: NOW, tlsPort: 6514 }),
      view.shape(row({ id: 'b', config_tls_port: 6513, config_reported_at: fresh }), { now: NOW, tlsPort: 6514 }),
      view.shape(row({ id: 'c' }), { now: NOW, tlsPort: null })];
    const s = view.summarize(list); assert.strictEqual(s.tls_port_overrides, 1); assert.strictEqual(s.tls_applied, 1); assert.strictEqual(s.tls_not_applied, 1);
  });
});

describe('routes', () => {
  let srv, base, failDb = false, failKey = false, tenantSyslog = null, tenantTls = null, ownTls = null, ownTlsFails = false, writes = [], found = true, brokerRow = { syslog_port_override: null, syslog_port_exclude: false };
  const ID = '11111111-1111-4111-8111-111111111111';
  before(() => {
    const dbPath = require.resolve('../src/db');
    require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: {
      withTenant: async (tenant, fn) => { if (failDb) throw new Error('boom'); return fn({ query: async (sql, args) => {
        if (/^\s*UPDATE collectors SET tls_port_override/.test(sql)) { writes.push({ sql, args }); return { rows: found ? [{ id: args[0], name: 'broker-1' }] : [] }; }
        if (/SELECT syslog_port_override, syslog_port_exclude FROM collectors/.test(sql)) return { rows: found ? [brokerRow] : [] };
        if (/SELECT tls_port_override FROM collectors/.test(sql)) { if (ownTlsFails) throw new Error('column "tls_port_override" does not exist'); return { rows: [{ tls_port_override: ownTls }] }; }
        if (/FROM collectors/.test(sql)) return { rows: [{ syslog_port_override: null, syslog_port_exclude: false }] };
        if (/SELECT tls_port FROM broker_settings/.test(sql)) return { rows: [{ tls_port: tenantTls }] };
        return { rows: [{ syslog_port: tenantSyslog }] }; } }); },
      query: async () => ({ rows: failKey ? [] : [{ id: 'k1', tenant_id: 't1', name: 'broker-1', platform: 'linux' }] }),
    } };
    const shared = require('../src/gateway/shared');
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: require('../src/db'), guarded: () => [(req, res, next) => { req.tenant_id = 't1'; req.user_id = 'u1'; next(); }] };
    const app = express();
    app.use(require('../src/ingest/broker-config').router); app.use(express.json()); app.use(require('../src/gateway/routes/broker-tls-port'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => srv.close());
  const call = async (method, p, body, headers = {}) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const KEY = { authorization: 'Bearer asix_ik_' + 'a'.repeat(40) };
  const put = (id, body) => call('PUT', '/v1/brokers/' + id + '/tls-port', body);
  const reset = () => { tenantSyslog = null; tenantTls = null; ownTls = null; brokerRow = { syslog_port_override: null, syslog_port_exclude: false }; };

  it('the portal route saves, clears and validates', async () => {
    reset();
    let r = await put(ID, { tls_port: 6515 }); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json, { success: true, broker: { id: ID, name: 'broker-1' }, tls_port: 6515 });
    assert.deepStrictEqual(writes.at(-1).args, [ID, 't1', 6515]);
    r = await put(ID, { tls_port: '6516' }); assert.strictEqual(r.json.tls_port, 6516);
    r = await put(ID, { tls_port: null }); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.tls_port, null); assert.deepStrictEqual(writes.at(-1).args, [ID, 't1', null]);
    r = await put(ID, { tls_port: '' }); assert.strictEqual(r.json.tls_port, null);
    const n = writes.length;
    for (const bad of [{}, { tls_port: 22 }, { tls_port: 443 }, { tls_port: 30443 }, { tls_port: 0 }, { tls_port: 65536 }, { tls_port: 'x' }, { tls_port: '6514; ls' }]) {
      r = await put(ID, bad); assert.strictEqual(r.status, 400, JSON.stringify(bad)); assert.ok(['INVALID_BODY', 'INVALID_TLS_PORT'].includes(r.json.error.code));
    }
    assert.match((await put(ID, { tls_port: 443 })).json.error.message, /Port 443 is used for HTTPS and cannot be a TLS port/);
    assert.strictEqual(writes.length, n, 'refused values write nothing');
  });
  it('it must differ from the syslog port THIS broker is asked for', async () => {
    reset(); const n = writes.length;
    tenantSyslog = 1514; let r = await put(ID, { tls_port: 1514 }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_TLS_PORT'); assert.match(r.json.error.message, /same as the syslog port/);
    assert.strictEqual((await put(ID, { tls_port: 6515 })).status, 200);
    brokerRow = { syslog_port_override: 2514, syslog_port_exclude: false };
    assert.strictEqual((await put(ID, { tls_port: 2514 })).status, 400, 'its own syslog port wins over the tenant-wide one');
    assert.strictEqual((await put(ID, { tls_port: 1514 })).status, 200, 'the tenant-wide syslog port is not this broker\'s');
    brokerRow = { syslog_port_override: null, syslog_port_exclude: true };
    assert.strictEqual((await put(ID, { tls_port: 1514 })).status, 200, 'left out and no own syslog port: it is asked for none, so there is nothing to clash with');
    assert.strictEqual(writes.length - n, 3, 'only the three accepted values were written');
    reset();
  });
  it('a bad id is a 400, an unknown or non-broker row a 404, a database failure a 500', async () => {
    reset();
    let r = await put('not-a-uuid', { tls_port: 6515 }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_ID');
    const n = writes.length;
    found = false; try { r = await put(ID, { tls_port: 6515 }); assert.strictEqual(r.status, 404); assert.strictEqual(r.json.error.code, 'NOT_FOUND'); r = await put(ID, { tls_port: null }); assert.strictEqual(r.status, 404); } finally { found = true; }
    assert.strictEqual(writes.length, n);
    failDb = true; try { r = await put(ID, { tls_port: 6515 }); assert.strictEqual(r.status, 500); assert.strictEqual(r.json.error.code, 'BROKER_CONFIG_ERROR'); } finally { failDb = false; }
  });
  it('the pull without a name answers the tenant-wide TLS port exactly as before', async () => {
    reset(); tenantSyslog = 1514; tenantTls = 6514; ownTls = 6515;
    let r = await call('GET', '/v1/ingest/broker-config', undefined, KEY); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json.config, { syslog_port: 1514, tls_port: 6514 });
    tenantTls = null; r = await call('GET', '/v1/ingest/broker-config', undefined, KEY); assert.deepStrictEqual(r.json.config, { syslog_port: 1514, tls_port: null });
    reset();
  });
  it('the pull with its name answers its own TLS port, else the tenant-wide one, else null', async () => {
    reset();
    const get = () => call('GET', '/v1/ingest/broker-config?collector=broker-1', undefined, KEY);
    tenantTls = 6514; ownTls = 6515; assert.deepStrictEqual((await get()).json.config, { syslog_port: null, tls_port: 6515 });
    ownTls = null; assert.deepStrictEqual((await get()).json.config, { syslog_port: null, tls_port: 6514 });
    tenantTls = null; assert.deepStrictEqual((await get()).json.config, { syslog_port: null, tls_port: null });
    ownTls = 6515; assert.deepStrictEqual((await get()).json.config, { syslog_port: null, tls_port: 6515 }, 'an own TLS port needs no tenant-wide one');
    reset();
  });
  it('a name that is not a plain name is ignored, and so is a repeated one', async () => {
    reset(); tenantTls = 6514; ownTls = 6515;
    for (const q of ['collector=a%20b', 'collector=a%2Fb', 'collector=', 'collector=broker-1&collector=broker-2']) {
      const r = await call('GET', '/v1/ingest/broker-config?' + q, undefined, KEY); assert.strictEqual(r.status, 200, q); assert.deepStrictEqual(r.json.config, { syslog_port: null, tls_port: 6514 }, q);
    }
    reset();
  });
  it('if the column is not there yet the tenant-wide TLS port still answers; a key still has to be valid', async () => {
    reset(); tenantSyslog = 1514; tenantTls = 6514; ownTlsFails = true; try {
      const r = await call('GET', '/v1/ingest/broker-config?collector=broker-1', undefined, KEY); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json.config, { syslog_port: 1514, tls_port: 6514 });
    } finally { ownTlsFails = false; }
    assert.strictEqual((await call('GET', '/v1/ingest/broker-config?collector=broker-1')).status, 401);
    failKey = true; try { assert.strictEqual((await call('GET', '/v1/ingest/broker-config?collector=broker-1', undefined, KEY)).status, 401); } finally { failKey = false; }
    failDb = true; try { assert.strictEqual((await call('GET', '/v1/ingest/broker-config?collector=broker-1', undefined, KEY)).status, 500); } finally { failDb = false; }
    reset();
  });
});
