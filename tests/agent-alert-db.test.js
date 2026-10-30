'use strict';
// E4m against a real PostgreSQL (platform schema applied): the real routes, the real agent_watch_settings table, the real wazuh_managers / alerts / alert_notes tables and
// agent-watch's real runTenant, with the manager's API replaced by a recorder. Only the sign-in chain is replaced.
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/agent-alert-db.test.js
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };
const w = require('../src/endpoints/agent-watch');
const managerStore = require('../src/endpoints/wazuh-manager-store');
const wazuhApi = require('../src/endpoints/wazuh-api');

const NOW = Date.now();
const iso = (minAgo) => new Date(NOW - minAgo * 60000).toISOString().replace(/\.\d{3}Z$/, 'Z');

async function main() {
  const stamp = NOW;
  const mk = async (n) => (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['agentalert-' + n + '-' + stamp])).rows[0].id;
  const A = await mk('a'), B = await mk('b');
  for (const t of [A, B]) await db.query(`INSERT INTO wazuh_managers (tenant_id, api_url, api_user, api_secret_enc, ca_pem, cert_sha256) VALUES ($1, 'https://10.0.0.1:55000', 'u', 'sealed', 'pem', $2)`, [t, 'a'.repeat(64)]);
  TENANT = A;
  const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/agent-alert'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const U = '/v1/endpoints/agent-alert';

  const mgr = { agents: [], calls: 0 };
  const api = {
    parseAgentQuery: wazuhApi.parseAgentQuery,
    listAgents: async (m, parsed) => { mgr.calls += 1; const d = mgr.agents.filter((a) => a.status === 'disconnected'); return { total: d.length, limit: parsed.limit, offset: parsed.offset, agents: d }; },
    getAgent: async (m, id) => { mgr.calls += 1; return mgr.agents.find((a) => a.id === id) || null; },
  };
  const store = { readRow: managerStore.readRow, isMissingTable: managerStore.isMissingTable, credentials: () => ({ stub: true }) };
  const agent = (id, minAgo, status = 'disconnected') => ({ id, name: 'pc-' + id, ip: '192.168.68.' + Number(id), status, version: 'Wazuh v4.14.9', groups: [], last_keep_alive: iso(minAgo), os: { name: 'Windows 11' } });
  const run = (t, server) => w.runTenant(t, { now: NOW, cfg: { minutes: server }, api, store });
  const alerts = async (t, extra = '') => (await db.query(`SELECT id, status, group_key, details FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ${extra} ORDER BY created_at, id`, [t, w.RULE_NAME])).rows;
  const notes = async (id) => (await db.query('SELECT author_name, body FROM alert_notes WHERE alert_id = $1', [id])).rows;
  const rows = async (t) => (await db.query('SELECT minutes, skip_agents, updated_by FROM agent_watch_settings WHERE tenant_id = $1', [t])).rows;

  try {
    mgr.agents = [agent('002', 120), agent('003', 120)];

    // 1. nothing saved and the server off: follows the server, reads nothing from the manager, raises nothing
    let r = await call('GET', U); assert.strictEqual(r.json.settings.source, 'server'); assert.strictEqual(r.json.settings.enabled, false); assert.deepStrictEqual(r.json.settings.skip_agents, []);
    assert.deepStrictEqual(await run(A, 0), { raised: 0, closed: 0 }); assert.strictEqual(mgr.calls, 0);

    // 2. a limit saved for A turns the alert on although the server is off; B (nothing saved) stays off
    r = await call('PUT', U, { minutes: 30 }); assert.strictEqual(r.status, 200); assert.deepStrictEqual([r.json.settings.source, r.json.settings.minutes, r.json.settings.enabled], ['tenant', 30, true]);
    assert.strictEqual((await rows(A))[0].updated_by, 'tester');
    assert.deepStrictEqual(await run(A, 0), { raised: 2, closed: 0 });
    assert.deepStrictEqual(await run(B, 0), { raised: 0, closed: 0 }); assert.strictEqual((await alerts(B)).length, 0);
    TENANT = B; assert.strictEqual((await call('GET', U)).json.settings.source, 'server'); TENANT = A;

    // 3. leaving one machine out closes its open alert with an ASIX note and never raises it again; the other stays
    r = await call('PUT', U, { skip_agent: '002', skip: true }); assert.deepStrictEqual(r.json.settings.skip_agents, ['002']); assert.strictEqual(r.json.settings.minutes, 30, 'the limit is kept');
    assert.deepStrictEqual(await run(A, 0), { raised: 0, closed: 1 });
    let al = await alerts(A); const a2 = al.find((x) => x.group_key === 'endpointagent:002'), a3 = al.find((x) => x.group_key === 'endpointagent:003');
    assert.strictEqual(a2.status, 'closed'); assert.strictEqual(a2.details.closed_by, 'asix'); assert.strictEqual(a3.status, 'open');
    assert.match((await notes(a2.id))[0].body, /set not to raise/); assert.strictEqual((await notes(a2.id))[0].author_name, 'ASIX');
    assert.deepStrictEqual(await run(A, 0), { raised: 0, closed: 0 });

    // 4. adding the same id twice keeps one copy; watching it again raises it again on the next cycle (ASIX closed it itself)
    await call('PUT', U, { skip_agent: '002', skip: true }); assert.deepStrictEqual((await rows(A))[0].skip_agents, ['002']);
    r = await call('PUT', U, { skip_agent: '002', skip: false }); assert.deepStrictEqual(r.json.settings.skip_agents, []);
    assert.deepStrictEqual(await run(A, 0), { raised: 1, closed: 0 });

    // 5. the limit off for this tenant closes what is open even while the server is on; following the server then raises again
    r = await call('PUT', U, { minutes: 0 }); assert.strictEqual(r.json.settings.enabled, false);
    assert.deepStrictEqual(await run(A, 45), { raised: 0, closed: 2 });
    r = await call('PUT', U, { follow_server: true }); assert.deepStrictEqual([r.json.settings.source, r.json.settings.minutes], ['server', 0]);
    assert.strictEqual((await rows(A)).length, 0, 'following the server with nobody left out leaves no row');
    assert.deepStrictEqual(await run(A, 45), { raised: 2, closed: 0 }, 'the server setting (45) applies again');

    // 6. following the server keeps the list of machines left out
    await call('PUT', U, { skip_agent: '003', skip: true }); await call('PUT', U, { minutes: 90 });
    r = await call('PUT', U, { follow_server: true }); assert.deepStrictEqual([r.json.settings.source, r.json.settings.skip_agents], ['server', ['003']]);
    assert.strictEqual((await rows(A)).length, 1);
    r = await call('PUT', U, { skip_agent: '003', skip: false }); assert.strictEqual((await rows(A)).length, 0, 'the last entry gone and following the server: the row is removed');

    // 7. the list holds 200 ids; the 201st is refused and writes nothing; an id already there is still accepted
    for (let i = 0; i < 200; i += 1) assert.strictEqual((await call('PUT', U, { skip_agent: String(1000 + i), skip: true })).status, 200);
    r = await call('PUT', U, { skip_agent: '9999', skip: true }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'AGENT_ALERT_LIST_FULL');
    assert.strictEqual((await rows(A))[0].skip_agents.length, 200);
    assert.strictEqual((await call('PUT', U, { skip_agent: '1000', skip: true })).status, 200);
    await db.query('DELETE FROM agent_watch_settings WHERE tenant_id = $1', [A]);

    // 8. refused bodies change nothing; the database CHECKs refuse what the route would
    for (const b of [{ minutes: 3 }, { minutes: 10081 }, { skip_agent: '2', skip: true }, {}, { follow_server: true, minutes: 5 }]) { r = await call('PUT', U, b); assert.strictEqual(r.status, 400, JSON.stringify(b)); }
    assert.strictEqual((await rows(A)).length, 0);
    await assert.rejects(db.query('INSERT INTO agent_watch_settings (tenant_id, minutes) VALUES ($1, 3)', [A]), /check/i);
    await assert.rejects(db.query('INSERT INTO agent_watch_settings (tenant_id, minutes) VALUES ($1, 20000)', [A]), /check/i);

    // 9. a tenant never sees or changes another's row (row security through the real tenant scope)
    await call('PUT', U, { minutes: 15 }); TENANT = B;
    r = await call('GET', U); assert.strictEqual(r.json.settings.source, 'server');
    assert.strictEqual((await call('PUT', U, { skip_agent: '002', skip: false })).status, 200); assert.strictEqual((await rows(A))[0].minutes, 15);
    TENANT = A;

    // 10. a database without the table: the route says so, the alert falls back to the server setting
    await db.query('ALTER TABLE agent_watch_settings RENAME TO agent_watch_settings_off');
    try {
      r = await call('GET', U); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.settings.available, false);
      r = await call('PUT', U, { minutes: 30 }); assert.strictEqual(r.status, 503); assert.strictEqual(r.json.error.code, 'AGENT_ALERT_NOT_READY');
      const warn = console.warn; console.warn = () => {};
      try { assert.deepStrictEqual(await run(A, 45), { raised: 0, closed: 0 }, 'server 45: the two alerts from step 5 are still open'); } finally { console.warn = warn; }
    } finally { await db.query('ALTER TABLE agent_watch_settings_off RENAME TO agent_watch_settings'); }

    console.log('agent-alert-db: ok');
  } finally {
    srv.close();
    for (const t of [A, B]) {
      await db.query('DELETE FROM alert_notes WHERE tenant_id = $1', [t]).catch(() => {});
      await db.query('DELETE FROM alerts WHERE tenant_id = $1', [t]).catch(() => {});
      await db.query('DELETE FROM agent_watch_settings WHERE tenant_id = $1', [t]).catch(() => {});
      await db.query('DELETE FROM wazuh_managers WHERE tenant_id = $1', [t]).catch(() => {});
    }
  }
}
main().then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });
