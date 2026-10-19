'use strict';
// Leaving ONE broker out of the tenant-wide syslog port (collectors.syslog_port_exclude), server side without a database: the rules in
// src/brokers/config.js, how the Brokers page shapes it (src/brokers/broker-view.js), the portal route and the broker's pull with ?collector=.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const config = require('../src/brokers/config');
const view = require('../src/brokers/broker-view');

describe('which port a broker is asked for when it can be left out', () => {
  it('left out: no tenant-wide port, so null (keep what it has); an own port still applies', () => {
    assert.strictEqual(config.effectivePort(1514, null, true), null);
    assert.strictEqual(config.effectivePort(1514, 2514, true), 2514, 'the own port was chosen for this broker alone');
    assert.strictEqual(config.effectivePort(null, null, true), null);
    assert.strictEqual(config.effectivePort(null, 2514, true), 2514);
  });
  it('not left out (or the argument missing) nothing changes', () => {
    assert.strictEqual(config.effectivePort(1514, null, false), 1514);
    assert.strictEqual(config.effectivePort(1514, null), 1514);
    assert.strictEqual(config.effectivePort('1514', null, undefined), 1514);
    assert.strictEqual(config.effectivePort(1514, 2514, false), 2514);
  });
  it('says where the port came from, and "excluded" only when a tenant-wide port is being held back', () => {
    assert.strictEqual(config.portSource(1514, null, true), 'excluded');
    assert.strictEqual(config.portSource(1514, 2514, true), 'broker');
    assert.strictEqual(config.portSource(1514, null, false), 'tenant');
    assert.strictEqual(config.portSource(1514, null), 'tenant');
    assert.strictEqual(config.portSource(null, null, true), 'none', 'with no tenant-wide port there is nothing to be left out of');
    assert.strictEqual(config.portSource(null, 2514, true), 'broker');
  });
});

describe('database helpers', () => {
  const rec = (rows) => { const seen = []; return { seen, query: async (sql, args) => { seen.push({ sql, args }); return { rows }; } }; };
  it('readExclude finds the row by key AND name; no row, null or a non-true value means not left out', async () => {
    let q = rec([{ syslog_port_exclude: true }]);
    assert.strictEqual(await config.readExclude(q, 't1', 'k1', 'broker-1'), true);
    assert.match(q.seen[0].sql, /WHERE tenant_id = \$1 AND key_id = \$2 AND name = \$3/); assert.deepStrictEqual(q.seen[0].args, ['t1', 'k1', 'broker-1']);
    for (const rows of [[{ syslog_port_exclude: false }], [{ syslog_port_exclude: null }], [{}], [], [{ syslog_port_exclude: 't' }]]) assert.strictEqual(await config.readExclude(rec(rows), 't1', 'k1', 'x'), false, JSON.stringify(rows));
  });
  it('writeExclude updates one broker of this tenant only, never a non-broker collector, and says if it found one', async () => {
    let q = rec([{ id: 'b1', name: 'broker-1', syslog_port_exclude: true, extra: 'x' }]);
    assert.deepStrictEqual(await config.writeExclude(q, 't1', 'b1', true), { id: 'b1', name: 'broker-1', syslog_port_exclude: true });
    assert.match(q.seen[0].sql, /^\s*UPDATE collectors SET syslog_port_exclude = \$3 WHERE id = \$1 AND tenant_id = \$2 AND version ILIKE 'vector-%'/);
    assert.deepStrictEqual(q.seen[0].args, ['b1', 't1', true]);
    q = rec([]); assert.strictEqual(await config.writeExclude(q, 't1', 'nope', false), null); assert.deepStrictEqual(q.seen[0].args, ['nope', 't1', false]);
  });
});

describe('the Brokers page shape', () => {
  const NOW = Date.parse('2026-10-18T12:00:00Z');
  const fresh = new Date(NOW - 60000);
  const row = (o = {}) => ({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', last_seen: fresh, key_id: 'k1', installer_name: 'k', key_status: 'active',
    config_syslog_port: null, config_rejected_port: null, config_reported_at: null, syslog_port_override: null, syslog_port_exclude: false, ...o });
  it('left out of a tenant-wide port: nothing is asked, the state is none, the source says excluded', () => {
    const b = view.shape(row({ syslog_port_exclude: true, config_syslog_port: 514, config_reported_at: fresh }), { now: NOW, syslogPort: 1514 });
    assert.strictEqual(b.config.state, 'none'); assert.strictEqual(b.config.configured_port, null); assert.strictEqual(b.config.source, 'excluded');
    assert.strictEqual(b.config.excluded, true); assert.strictEqual(b.config.reported_port, 514, 'what it listens on is still shown');
  });
  it('with an own port the flag changes nothing it is asked for, and the source stays broker', () => {
    const b = view.shape(row({ syslog_port_exclude: true, syslog_port_override: 2514, config_syslog_port: 2514, config_reported_at: fresh }), { now: NOW, syslogPort: 1514 });
    assert.strictEqual(b.config.state, 'applied'); assert.strictEqual(b.config.configured_port, 2514); assert.strictEqual(b.config.source, 'broker'); assert.strictEqual(b.config.excluded, true);
  });
  it('not left out, or a row from a database without the column, behaves as before', () => {
    let b = view.shape(row({ config_syslog_port: 1514, config_reported_at: fresh }), { now: NOW, syslogPort: 1514 });
    assert.strictEqual(b.config.state, 'applied'); assert.strictEqual(b.config.source, 'tenant'); assert.strictEqual(b.config.excluded, false);
    const r = row(); delete r.syslog_port_exclude;
    b = view.shape(r, { now: NOW, syslogPort: 1514 }); assert.strictEqual(b.config.excluded, false); assert.strictEqual(b.config.state, 'unknown'); assert.strictEqual(b.config.configured_port, 1514);
  });
  it('a flag with no tenant-wide port set is kept but dormant', () => {
    const b = view.shape(row({ syslog_port_exclude: true }), { now: NOW, syslogPort: null });
    assert.strictEqual(b.config.excluded, true); assert.strictEqual(b.config.source, 'none'); assert.strictEqual(b.config.state, 'none');
  });
  it('the summary counts left-out brokers (not those with their own port), and they are neither applied nor not applied', () => {
    const list = [view.shape(row({ id: 'a', syslog_port_exclude: true }), { now: NOW, syslogPort: 1514 }),
      view.shape(row({ id: 'b', syslog_port_exclude: true, syslog_port_override: 2514, config_syslog_port: 2514, config_reported_at: fresh }), { now: NOW, syslogPort: 1514 }),
      view.shape(row({ id: 'c', config_syslog_port: 1514, config_reported_at: fresh }), { now: NOW, syslogPort: 1514 })];
    const s = view.summarize(list);
    assert.strictEqual(s.port_excluded, 1); assert.strictEqual(s.port_overrides, 1); assert.strictEqual(s.config_applied, 2); assert.strictEqual(s.config_not_applied, 0);
  });
});

describe('routes', () => {
  let srv, base, failDb = false, failKey = false, tenantPort = null, ownPort = null, excluded = false, excludeFails = false, writes = [], found = true;
  const ID = '11111111-1111-4111-8111-111111111111';
  before(() => {
    const dbPath = require.resolve('../src/db');
    require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: {
      withTenant: async (tenant, fn) => { if (failDb) throw new Error('boom'); return fn({ query: async (sql, args) => {
        if (/^\s*UPDATE collectors SET syslog_port_exclude/.test(sql)) { writes.push({ sql, args }); return { rows: found ? [{ id: args[0], name: 'broker-1', syslog_port_exclude: args[2] }] : [] }; }
        if (/SELECT syslog_port_exclude FROM collectors/.test(sql)) { if (excludeFails) throw new Error('column "syslog_port_exclude" does not exist'); return { rows: [{ syslog_port_exclude: excluded }] }; }
        if (/SELECT syslog_port_override FROM collectors/.test(sql)) return { rows: [{ syslog_port_override: ownPort }] };
        return { rows: [{ syslog_port: tenantPort }] }; } }); },
      query: async () => ({ rows: failKey ? [] : [{ id: 'k1', tenant_id: 't1', name: 'broker-1', platform: 'linux' }] }),
    } };
    const shared = require('../src/gateway/shared');
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: require('../src/db'), guarded: () => [(req, res, next) => { req.tenant_id = 't1'; req.user_id = 'u1'; next(); }] };
    const app = express();
    app.use(require('../src/ingest/broker-config').router); app.use(express.json()); app.use(require('../src/gateway/routes/broker-port-exclude'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => srv.close());
  const call = async (method, p, body, headers = {}) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const KEY = { authorization: 'Bearer asix_ik_' + 'a'.repeat(40) };
  const put = (id, body) => call('PUT', '/v1/brokers/' + id + '/syslog-port-exclude', body);
  const pull = (q = '?collector=broker-1') => call('GET', '/v1/ingest/broker-config' + q, undefined, KEY);

  it('the portal route leaves a broker out and puts it back', async () => {
    let r = await put(ID, { exclude: true }); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json, { success: true, broker: { id: ID, name: 'broker-1', syslog_port_exclude: true } });
    assert.deepStrictEqual(writes.at(-1).args, [ID, 't1', true]);
    r = await put(ID, { exclude: false }); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.broker.syslog_port_exclude, false); assert.deepStrictEqual(writes.at(-1).args, [ID, 't1', false]);
  });
  it('it needs a real true or false and a real id; nothing is written otherwise', async () => {
    const n = writes.length;
    for (const bad of [{}, { exclude: 'true' }, { exclude: 1 }, { exclude: null }, { syslog_port: 1514 }]) { const r = await put(ID, bad); assert.strictEqual(r.status, 400, JSON.stringify(bad)); assert.strictEqual(r.json.error.code, 'INVALID_BODY'); }
    const r = await put('not-a-uuid', { exclude: true }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_ID');
    assert.strictEqual(writes.length, n);
  });
  it('an unknown or non-broker row is a 404 and a database failure a 500', async () => {
    found = false; try { assert.strictEqual((await put(ID, { exclude: true })).status, 404); } finally { found = true; }
    failDb = true; try { const r = await put(ID, { exclude: true }); assert.strictEqual(r.status, 500); assert.strictEqual(r.json.error.code, 'BROKER_CONFIG_ERROR'); } finally { failDb = false; }
  });
  it('the pull: a left-out broker is told null, one that is not still gets the tenant-wide port', async () => {
    tenantPort = 1514; ownPort = null; excluded = true; assert.deepStrictEqual((await pull()).json.config, { syslog_port: null, tls_port: null });
    excluded = false; assert.deepStrictEqual((await pull()).json.config, { syslog_port: 1514, tls_port: null });
  });
  it('the pull: an own port wins over being left out, and the flag is not even read then', async () => {
    tenantPort = 1514; ownPort = 2514; excluded = true;
    excludeFails = true; try { assert.deepStrictEqual((await pull()).json.config, { syslog_port: 2514, tls_port: null }); } finally { excludeFails = false; }
  });
  it('the pull: nothing to be left out of (no tenant-wide port), or no name, is answered as before', async () => {
    tenantPort = null; ownPort = null; excluded = true; assert.deepStrictEqual((await pull()).json.config, { syslog_port: null, tls_port: null });
    tenantPort = 1514; assert.deepStrictEqual((await pull('')).json.config, { syslog_port: 1514, tls_port: null }, 'an older script that sends no name is told the tenant-wide port');
    assert.deepStrictEqual((await pull('?collector=a%20b')).json.config, { syslog_port: 1514, tls_port: null }, 'a name that is not a plain name is ignored');
  });
  it('if the column is not there yet the tenant-wide port still answers; a key still has to be valid', async () => {
    tenantPort = 1514; ownPort = null; excluded = true; excludeFails = true; try { assert.deepStrictEqual((await pull()).json.config, { syslog_port: 1514, tls_port: null }); } finally { excludeFails = false; }
    assert.strictEqual((await call('GET', '/v1/ingest/broker-config?collector=broker-1')).status, 401);
    failKey = true; try { assert.strictEqual((await pull()).status, 401); } finally { failKey = false; }
    failDb = true; try { assert.strictEqual((await pull()).status, 500); } finally { failDb = false; }
  });
});
