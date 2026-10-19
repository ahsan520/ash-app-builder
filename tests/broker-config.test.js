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

describe('checkTlsPort', () => {
  it('same port rules as the syslog port, with its own wording', () => {
    assert.deepStrictEqual(config.checkTlsPort(6514), { value: 6514 });
    assert.deepStrictEqual(config.checkTlsPort(' 6515 '), { value: 6515 });
    for (const v of [null, undefined, '', '  ']) assert.deepStrictEqual(config.checkTlsPort(v, 514), { value: null });
    for (const v of [0, 65536, '0514', '6514; ls', 'x', 1.5, true, {}]) assert.ok(config.checkTlsPort(v).error, JSON.stringify(v));
    for (const p of [22, 443, 8686, 30443]) { const r = config.checkTlsPort(p); assert.match(r.error, /TLS port/); assert.match(r.error, new RegExp('Port ' + p)); }
    assert.match(config.checkTlsPort('x').error, /^Syslog-over-TLS port must be a whole number/);
  });
  it('refuses the same number as the syslog port, but only when one is given', () => {
    assert.match(config.checkTlsPort(1514, 1514).error, /same as the syslog port/);
    assert.deepStrictEqual(config.checkTlsPort(1514, 514), { value: 1514 });
    assert.deepStrictEqual(config.checkTlsPort(1514, null), { value: 1514 });
    assert.deepStrictEqual(config.checkTlsPort(null, 1514), { value: null }, 'clearing is always fine');
  });
  it('read and write touch only tls_port', async () => {
    const q = (rows) => ({ query: async () => ({ rows }) });
    assert.strictEqual(await config.readTlsPort(q([]), 't'), null); assert.strictEqual(await config.readTlsPort(q([{ tls_port: null }]), 't'), null); assert.strictEqual(await config.readTlsPort(q([{ tls_port: 6514 }]), 't'), 6514);
    const seen = []; await config.writeTlsPort({ query: async (sql, args) => { seen.push({ sql, args }); } }, 'tenant-1', 6514, 'u1');
    assert.match(seen[0].sql, /DO UPDATE SET tls_port = EXCLUDED\.tls_port/); assert.doesNotMatch(seen[0].sql, /syslog_port|vector_target/); assert.deepStrictEqual(seen[0].args, ['tenant-1', 6514, 'u1']);
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

describe('broker reports (what a broker says it applied)', () => {
  it('checkReport accepts a name, the port in use, and a rejected port or null', () => {
    assert.deepStrictEqual(config.checkReport({ collector: 'broker-1', syslog_port: 1514, rejected_port: null }), { name: 'broker-1', port: 1514, rejected: null, signature: null });
    assert.deepStrictEqual(config.checkReport({ collector: 'b.2:x_y', syslog_port: '514', rejected_port: 1514 }), { name: 'b.2:x_y', port: 514, rejected: 1514, signature: null });
    assert.deepStrictEqual(config.checkReport({ collector: 'b', syslog_port: 514 }), { name: 'b', port: 514, rejected: null, signature: null }, 'rejected_port may be left out');
  });
  it('checkReport refuses everything else with a reason', () => {
    for (const b of [null, undefined, [], 'x', 5, {}, { syslog_port: 514 }, { collector: '', syslog_port: 514 }, { collector: 'a b', syslog_port: 514 }, { collector: 'x'.repeat(101), syslog_port: 514 },
      { collector: 5, syslog_port: 514 }, { collector: 'b' }, { collector: 'b', syslog_port: null }, { collector: 'b', syslog_port: 0 }, { collector: 'b', syslog_port: 65536 },
      { collector: 'b', syslog_port: '514; ls' }, { collector: 'b', syslog_port: 1.5 }, { collector: 'b', syslog_port: 514, rejected_port: 0 }, { collector: 'b', syslog_port: 514, rejected_port: 'x' }]) {
      const r = config.checkReport(b); assert.ok(r.error, JSON.stringify(b)); assert.strictEqual(r.name, undefined);
    }
  });
  it('recordReport updates only the row of the sending key and broker, and says whether one was found', async () => {
    const seen = []; const q = (n) => ({ query: async (sql, args) => { seen.push({ sql, args }); return { rowCount: n }; } });
    assert.strictEqual(await config.recordReport(q(1), 'tenant-1', 'key-1', { name: 'broker-1', port: 1514, rejected: null }), true);
    assert.strictEqual(await config.recordReport(q(0), 'tenant-1', 'key-1', { name: 'ghost', port: 514, rejected: 1514 }), false);
    assert.match(seen[0].sql, /^\s*UPDATE collectors SET/); assert.doesNotMatch(seen[0].sql, /INSERT/i);
    assert.match(seen[0].sql, /WHERE tenant_id = \$1 AND key_id = \$2 AND name = \$3/);
    assert.deepStrictEqual(seen[0].args, ['tenant-1', 'key-1', 'broker-1', 1514, null, null]); assert.deepStrictEqual(seen[1].args, ['tenant-1', 'key-1', 'ghost', 514, 1514, null]);
  });
  describe('configState', () => {
    const NOW = Date.parse('2026-10-18T12:00:00Z'), ago = (min) => new Date(NOW - min * 60000);
    const row = (o = {}) => ({ config_syslog_port: null, config_rejected_port: null, config_reported_at: null, ...o });
    it('none: ASIX has no port, whatever the broker says', () => {
      assert.strictEqual(config.configState(null, row(), NOW).state, 'none');
      const s = config.configState(null, row({ config_syslog_port: 514, config_reported_at: ago(1) }), NOW);
      assert.strictEqual(s.state, 'none'); assert.strictEqual(s.reported_port, 514); assert.strictEqual(s.configured_port, null);
      assert.strictEqual(config.configState(undefined, row(), NOW).state, 'none');
    });
    it('unknown: a port is set and this broker never reported', () => {
      const s = config.configState(1514, row(), NOW); assert.strictEqual(s.state, 'unknown'); assert.strictEqual(s.reported_port, null); assert.strictEqual(s.configured_port, 1514);
    });
    it('applied: the broker reports the port ASIX asks for, however old the report is', () => {
      assert.strictEqual(config.configState(1514, row({ config_syslog_port: 1514, config_reported_at: ago(1) }), NOW).state, 'applied');
      assert.strictEqual(config.configState(1514, row({ config_syslog_port: '1514', config_reported_at: ago(600) }), NOW).state, 'applied', 'a column that comes back as text still compares as a number');
    });
    it('rejected: it reports the old port and says it rejected the one asked for; a different rejected port is only pending', () => {
      const r = config.configState(1514, row({ config_syslog_port: 514, config_rejected_port: 1514, config_reported_at: ago(2) }), NOW);
      assert.strictEqual(r.state, 'rejected'); assert.strictEqual(r.rejected_port, 1514); assert.strictEqual(r.reported_port, 514);
      assert.strictEqual(config.configState(2514, row({ config_syslog_port: 514, config_rejected_port: 1514, config_reported_at: ago(2) }), NOW).state, 'pending', 'ASIX moved on to another port');
    });
    it('pending, then stale once the last report is older than 15 minutes', () => {
      assert.strictEqual(config.configState(1514, row({ config_syslog_port: 514, config_reported_at: ago(5) }), NOW).state, 'pending');
      assert.strictEqual(config.configState(1514, row({ config_syslog_port: 514, config_reported_at: ago(15) }), NOW).state, 'pending', 'exactly 15 minutes is still fresh');
      assert.strictEqual(config.configState(1514, row({ config_syslog_port: 514, config_reported_at: ago(16) }), NOW).state, 'stale');
      assert.strictEqual(config.configState(1514, row({ config_syslog_port: 514, config_reported_at: '2026-10-18 11:59:00' }), NOW).state, 'pending', 'a timestamp string is read as UTC like last_seen');
      assert.strictEqual(config.REPORT_FRESH_MS, 15 * 60 * 1000);
    });
    it('a rejection that is no longer asked for does not show: the state follows ASIX\'s current port', () => {
      assert.strictEqual(config.configState(514, row({ config_syslog_port: 514, config_rejected_port: 1514, config_reported_at: ago(1) }), NOW).state, 'applied');
    });
  });
});

describe('routes', () => {
  let srv, base, stored = null, storedTls = null, failDb = false, failKey = false, updates = [], reportRows = 1;
  before(() => {
    const dbPath = require.resolve('../src/db');
    require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: {
      withTenant: async (tenant, fn) => { if (failDb) throw new Error('boom'); return fn({ query: async (sql, args) => {
        if (/^\s*UPDATE collectors/.test(sql)) { updates.push({ sql, args }); return { rowCount: reportRows, rows: [] }; }
        if (/^SELECT/.test(sql)) return { rows: [{ syslog_port: stored, tls_port: storedTls }] };
        if (/tls_port/.test(sql)) { storedTls = args[1]; return { rows: [] }; }
        stored = args[1]; return { rows: [] }; } }); },
      query: async () => ({ rows: failKey ? [] : [{ id: 'k1', tenant_id: 't1', name: 'broker-1', platform: 'linux' }] }),
    } };
    const shared = require('../src/gateway/shared');
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: require('../src/db'), guarded: () => [(req, res, next) => { req.tenant_id = 't1'; req.user_id = 'u1'; next(); }] };
    const app = express();   // same order as src/gateway/index.js: the ingest lane before the global JSON parser
    app.use(require('../src/ingest/broker-config').router); app.use(express.json()); app.use(require('../src/gateway/routes/broker-config'));
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
  it('the portal route saves the TLS port alone, with the syslog port alone, or both; keys left out are not touched', async () => {
    stored = null; storedTls = null;
    let r = await call('PUT', '/v1/broker-config', { tls_port: 6514 }); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.config.tls_port, 6514); assert.strictEqual(r.json.config.syslog_port, null); assert.strictEqual(storedTls, 6514); assert.strictEqual(stored, null);
    r = await call('PUT', '/v1/broker-config', { syslog_port: 1514 }); assert.strictEqual(r.status, 200); assert.strictEqual(stored, 1514); assert.strictEqual(storedTls, 6514, 'a syslog-only save keeps the TLS port'); assert.strictEqual(r.json.config.tls_port, 6514);
    r = await call('PUT', '/v1/broker-config', { syslog_port: 2514, tls_port: 7514 }); assert.strictEqual(r.status, 200); assert.strictEqual(stored, 2514); assert.strictEqual(storedTls, 7514);
    assert.strictEqual((await call('GET', '/v1/broker-config')).json.config.tls_port, 7514);
    r = await call('PUT', '/v1/broker-config', { tls_port: null }); assert.strictEqual(r.status, 200); assert.strictEqual(storedTls, null); assert.strictEqual(stored, 2514, 'clearing one leaves the other');
    stored = null; storedTls = null;
  });
  it('the portal route refuses a bad TLS port, a TLS port equal to the syslog port, and the reverse, writing nothing', async () => {
    stored = 1514; storedTls = 6514;
    for (const bad of [{ tls_port: 22 }, { tls_port: 'x' }, { tls_port: 70000 }, { tls_port: 1514 }, { syslog_port: 6514 }, { syslog_port: 2514, tls_port: 2514 }]) {
      const r = await call('PUT', '/v1/broker-config', bad); assert.strictEqual(r.status, 400, JSON.stringify(bad));
      assert.ok(['INVALID_TLS_PORT', 'INVALID_SYSLOG_PORT'].includes(r.json.error.code), JSON.stringify(bad));
    }
    assert.strictEqual(stored, 1514); assert.strictEqual(storedTls, 6514, 'a refused value changes nothing');
    const r = await call('PUT', '/v1/broker-config', {}); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_BODY');
    stored = null; storedTls = null;
  });
  it('the broker route answers with the TLS port next to the syslog port', async () => {
    stored = 1514; storedTls = 6514; const r = await call('GET', '/v1/ingest/broker-config', undefined, { authorization: KEY });
    assert.deepStrictEqual(r.json.config, { syslog_port: 1514, tls_port: 6514 }); stored = null; storedTls = null;
  });
  it('a database failure is a 500 with a code, not a crash', async () => {
    failDb = true; try { const r = await call('PUT', '/v1/broker-config', { syslog_port: 1514 }); assert.strictEqual(r.status, 500); assert.strictEqual(r.json.error.code, 'BROKER_CONFIG_ERROR'); } finally { failDb = false; }
  });
  it('the broker route needs a valid key and answers with the port or null', async () => {
    assert.strictEqual((await call('GET', '/v1/ingest/broker-config')).status, 401);
    failKey = true; assert.strictEqual((await call('GET', '/v1/ingest/broker-config', undefined, { authorization: KEY })).status, 401); failKey = false;
    stored = null; let r = await call('GET', '/v1/ingest/broker-config', undefined, { authorization: KEY });
    assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json.config, { syslog_port: null, tls_port: null }); assert.strictEqual(r.json.interval_seconds, 300);
    stored = 1514; r = await call('GET', '/v1/ingest/broker-config', undefined, { authorization: KEY }); assert.deepStrictEqual(r.json.config, { syslog_port: 1514, tls_port: null });
  });
  it('the broker route is read only and a database failure is a 500', async () => {
    assert.ok([404, 405].includes((await fetch(base + '/v1/ingest/broker-config', { method: 'POST', headers: { authorization: KEY } })).status));
    failDb = true; try { assert.strictEqual((await call('GET', '/v1/ingest/broker-config', undefined, { authorization: KEY })).status, 500); } finally { failDb = false; }
  });
  it('the report route needs a valid key, validates the body and records on the key\'s own broker', async () => {
    const post = (body, headers = { authorization: KEY }) => call('POST', '/v1/ingest/broker-config/report', body, headers);
    assert.strictEqual((await post({ collector: 'broker-1', syslog_port: 514 }, {})).status, 401);
    failKey = true; assert.strictEqual((await post({ collector: 'broker-1', syslog_port: 514 })).status, 401); failKey = false;
    assert.strictEqual(updates.length, 0, 'nothing written without a valid key');
    for (const bad of [{}, { collector: 'broker-1' }, { collector: 'bad name', syslog_port: 514 }, { collector: 'broker-1', syslog_port: 70000 }, [1]]) {
      const r = await post(bad); assert.strictEqual(r.status, 400, JSON.stringify(bad)); assert.strictEqual(r.json.error.code, 'BROKER_REPORT_INVALID');
    }
    assert.strictEqual(updates.length, 0, 'refused bodies write nothing');
    stored = 1514; reportRows = 1;
    let r = await post({ collector: 'broker-1', syslog_port: 514, rejected_port: 1514 }); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json, { success: true, recorded: true });
    assert.deepStrictEqual(updates[0].args, ['t1', 'k1', 'broker-1', 514, 1514, null], 'tenant and key come from the key lookup, not from the body');
    assert.strictEqual(stored, 1514, 'a report never changes the setting');
    reportRows = 0; r = await post({ collector: 'ghost', syslog_port: 514 }); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.recorded, false); reportRows = 1;
  });
  it('the report route: malformed or oversized JSON is a 400 with a code, a database failure is a 500', async () => {
    const raw = (body) => fetch(base + '/v1/ingest/broker-config/report', { method: 'POST', headers: { authorization: KEY, 'content-type': 'application/json' }, body });
    let r = await raw('{not json'); assert.strictEqual(r.status, 400); assert.strictEqual((await r.json()).error.code, 'BROKER_REPORT_BAD_BODY');
    r = await raw(JSON.stringify({ collector: 'b', syslog_port: 514, pad: 'x'.repeat(6000) })); assert.strictEqual(r.status, 413); assert.strictEqual((await r.json()).error.code, 'BROKER_REPORT_BAD_BODY');
    failDb = true; try { r = await raw(JSON.stringify({ collector: 'broker-1', syslog_port: 514 })); assert.strictEqual(r.status, 500); assert.strictEqual((await r.json()).error.code, 'BROKER_CONFIG_ERROR'); } finally { failDb = false; }
  });
});
