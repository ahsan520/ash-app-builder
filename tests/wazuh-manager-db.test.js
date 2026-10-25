'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/wazuh-manager-db.test.js
// Skips itself otherwise. The central Wazuh manager of a tenant (docs/endpoints.md task E4c): the REAL routes, the REAL wazuh_managers table with its row security (checked as
// a role that is not a superuser, because a superuser bypasses it), the REAL operator CLI, and two stand-in manager APIs over HTTPS (tests/fixtures/fake-wazuh-api.js, a
// documented shape, not a real Wazuh). Only the sign-in chain is replaced. The point: a tenant reaches ITS manager and no other, and no route can change where that is.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
process.env.ASIX_WAZUH_API_TIMEOUT_MS = '1500';
process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true';
process.env.NOTIFY_ENCRYPTION_KEY = require('crypto').randomBytes(32).toString('base64');

const assert = require('assert');
const express = require('express');
const { Readable } = require('stream');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const fake = require('./fixtures/fake-wazuh-api');

let TENANT, PERMS = [];
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: (p) => [(req, res, next) => { PERMS.push(p); req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };
const cli = require('../src/endpoints/wazuh-manager-cli');
const wazuhApi = require('../src/endpoints/wazuh-api');

const reg = (m, extra = {}) => JSON.stringify({ url: m.url, user: m.user, password: m.password, ca_pem: m.cert, label: 'manager ' + m.tag, ...extra });
async function runCli(args, stdin = '') { const out = [], err = []; const code = await cli.run(args, { stdin: Readable.from([stdin]), out: (l) => out.push(l), err: (l) => err.push(l) }); return { code, out: out.join('\n'), err: err.join('\n') }; }

async function main() {
  const stamp = Date.now();
  const A = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wz-a-' + stamp])).rows[0].id;
  const B = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wz-b-' + stamp])).rows[0].id;
  const C = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wz-c-' + stamp])).rows[0].id;
  const MA = await fake.start({ tag: 'A', password: 'A-Passw0rd!x' }), MB = await fake.start({ tag: 'B', cn: 'wazuh-b', password: 'B-Passw0rd!x', agents: fake.AGENTS.slice(0, 2) });
  const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/wazuh-manager'));
  const srv = app.listen(0), base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (as, method, p, body) => { TENANT = as; const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json().catch(() => null) }; };
  const rowOf = async (t) => (await db.query('SELECT * FROM wazuh_managers WHERE tenant_id = $1', [t])).rows[0];
  try {
    // nothing registered
    let r = await call(A, 'GET', '/v1/endpoints/manager'); assert.deepStrictEqual([r.status, r.json.manager], [200, { available: true, registered: false }]);
    for (const p of ['/v1/endpoints/agents', '/v1/endpoints/agents/summary', '/v1/endpoints/agents/001']) { r = await call(A, 'GET', p); assert.deepStrictEqual([r.status, r.json.error.code], [404, 'WAZUH_NO_MANAGER'], p); }

    // the CLI registers (after signing in to the manager); the row holds a sealed password
    let c = await runCli(['register', '--tenant', 'wz-a-' + stamp], reg(MA)); assert.strictEqual(c.code, 0, c.err); assert.match(c.out, /The manager answered: Wazuh v4\.14\.9/); assert.match(c.out, /Registered for tenant/);
    await runCli(['register', '--tenant', B], reg(MB));                       // by id
    const row = await rowOf(A); assert.strictEqual(row.api_url, MA.url); assert.strictEqual(row.api_user, 'asix-readonly'); assert.ok(!JSON.stringify(row).includes('A-Passw0rd'), 'the password is not in the row'); assert.ok(row.api_secret_enc.startsWith('v1.'));
    assert.strictEqual(row.cert_sha256.length, 64); assert.strictEqual(row.updated_by, 'cli');

    // reading: each tenant reaches its OWN manager
    r = await call(A, 'GET', '/v1/endpoints/manager'); assert.strictEqual(r.status, 200); assert.deepStrictEqual([r.json.manager.registered, r.json.manager.label, r.json.manager.host, r.json.manager.port, r.json.manager.status.reachable, r.json.manager.status.version], [true, 'manager A', '127.0.0.1', MA.port, true, 'v4.14.9']);
    const shown = JSON.stringify(r.json); for (const s of ['A-Passw0rd', 'api_secret_enc', 'BEGIN CERTIFICATE']) assert.ok(!shown.includes(s), s + ' in the view');
    r = await call(A, 'GET', '/v1/endpoints/agents'); assert.deepStrictEqual([r.status, r.json.total, r.json.agents.length], [200, 4, 4]);
    r = await call(B, 'GET', '/v1/endpoints/agents'); assert.deepStrictEqual([r.status, r.json.total, r.json.agents.length], [200, 2, 2], 'tenant B sees ITS manager (two agents)');
    r = await call(B, 'GET', '/v1/endpoints/agents/summary'); assert.strictEqual(r.json.summary.total, 2);
    r = await call(A, 'GET', '/v1/endpoints/agents/001'); assert.strictEqual(r.json.agent.name, 'WIN-DC01'); assert.ok(!JSON.stringify(r.json).includes('MDAxIFdJTi1'), 'no agent key');
    r = await call(B, 'GET', '/v1/endpoints/agents/001'); assert.strictEqual(r.status, 200);
    r = await call(B, 'GET', '/v1/endpoints/agents/002'); assert.deepStrictEqual([r.status, r.json.error.code], [404, 'WAZUH_NO_AGENT'], 'B\'s manager has no agent 002 (A\'s has)');
    assert.ok(MA.state.requests.every((q) => q.method === 'GET' || q.path.startsWith('/security/user/authenticate')), 'A\'s manager only ever saw reads');
    const sawA = MA.state.requests.length, sawB = MB.state.requests.length;
    r = await call(C, 'GET', '/v1/endpoints/agents'); assert.deepStrictEqual([r.status, r.json.error.code], [404, 'WAZUH_NO_MANAGER'], 'a tenant with no row reaches nothing');
    assert.deepStrictEqual([MA.state.requests.length, MB.state.requests.length], [sawA, sawB], 'and neither manager was called for it');

    // bad requests never reach the manager
    const n = MA.state.requests.length;
    for (const p of ['/v1/endpoints/agents?agents_list=000', '/v1/endpoints/agents?q=id%3D000', '/v1/endpoints/agents?select=key', '/v1/endpoints/agents?limit=9999', '/v1/endpoints/agents?status=bogus']) { r = await call(A, 'GET', p); assert.deepStrictEqual([r.status, r.json.error.code], [400, 'INVALID_AGENT_QUERY'], p); }
    for (const p of ['/v1/endpoints/agents/1', '/v1/endpoints/agents/001%2F..%2Fmanager', '/v1/endpoints/agents/abc']) { r = await call(A, 'GET', p); assert.strictEqual(r.status, 400, p); }
    assert.strictEqual(MA.state.requests.length, n, 'nothing was sent for a bad request');
    r = await call(A, 'GET', '/v1/endpoints/agents?status=active&sort=-name&limit=1'); assert.deepStrictEqual([r.status, r.json.agents.length, r.json.total], [200, 1, 2]);

    // NO route changes where a manager is: every other method answers 404 (no handler) and the row is untouched
    for (const [m, p, body] of [['PUT', '/v1/endpoints/manager', { url: MB.url }], ['POST', '/v1/endpoints/manager', { url: MB.url }], ['DELETE', '/v1/endpoints/manager'], ['POST', '/v1/endpoints/agents', {}], ['DELETE', '/v1/endpoints/agents/001'], ['PUT', '/v1/endpoints/agents/001', {}]]) { r = await call(A, m, p, body); assert.strictEqual(r.status, 404, m + ' ' + p); }
    assert.strictEqual((await rowOf(A)).api_url, MA.url);
    assert.ok(PERMS.length > 0 && PERMS.every((p) => p === 'capacity:read'), 'every route asks for capacity:read only');

    // states of the manager are shown, not thrown
    MA.state.failAuth = true; wazuhApi.forget(A);
    r = await call(A, 'GET', '/v1/endpoints/manager'); assert.deepStrictEqual([r.status, r.json.manager.status.reachable, r.json.manager.status.code], [200, false, 'AUTH_FAILED']);
    r = await call(A, 'GET', '/v1/endpoints/agents'); assert.deepStrictEqual([r.status, r.json.error.code], [502, 'WAZUH_AUTH_FAILED']);
    MA.state.failAuth = false; MA.state.delayMs = 2500; wazuhApi.forget(A);
    r = await call(A, 'GET', '/v1/endpoints/agents/summary'); assert.deepStrictEqual([r.status, r.json.error.code], [504, 'WAZUH_TIMEOUT']); MA.state.delayMs = 0;
    const down = await fake.start({ tag: 'D' }); const dres = await runCli(['register', '--tenant', C], reg(down)); assert.strictEqual(dres.code, 0); await down.stop();
    r = await call(C, 'GET', '/v1/endpoints/manager'); assert.deepStrictEqual([r.json.manager.status.reachable, r.json.manager.status.code], [false, 'UNREACHABLE']);
    r = await call(C, 'GET', '/v1/endpoints/agents'); assert.deepStrictEqual([r.status, r.json.error.code], [502, 'WAZUH_UNREACHABLE']);

    // the sealed password cannot be opened with another key (a changed NOTIFY_ENCRYPTION_KEY): a clear message, and with no key at all
    const keep = process.env.NOTIFY_ENCRYPTION_KEY;
    process.env.NOTIFY_ENCRYPTION_KEY = require('crypto').randomBytes(32).toString('base64');
    r = await call(A, 'GET', '/v1/endpoints/agents'); assert.deepStrictEqual([r.status, r.json.error.code], [500, 'WAZUH_SECRET']);
    r = await call(A, 'GET', '/v1/endpoints/manager'); assert.deepStrictEqual([r.status, r.json.manager.status.code], [200, 'SECRET']);
    delete process.env.NOTIFY_ENCRYPTION_KEY;
    r = await call(A, 'GET', '/v1/endpoints/agents'); assert.deepStrictEqual([r.status, r.json.error.code], [503, 'WAZUH_NO_KEY']);
    process.env.NOTIFY_ENCRYPTION_KEY = keep;

    // row security, as a role that is not a superuser: without the tenant setting nothing is visible, with it only its own row
    await db.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wz_plain') THEN CREATE ROLE wz_plain NOLOGIN; END IF; END $$");
    await db.query('GRANT SELECT, INSERT, UPDATE, DELETE ON wazuh_managers TO wz_plain');
    const cl = await db.query('SELECT 1').then(() => require('pg')); const pool = new cl.Pool({ host: process.env.DB_HOST, database: process.env.DB_NAME || 'asix_platform', user: process.env.DB_USER || 'asix_admin', password: process.env.DB_PASSWORD }); const client = await pool.connect();
    try {
      await client.query('BEGIN'); await client.query('SET LOCAL ROLE wz_plain'); await client.query("SELECT set_config('app.current_tenant_id', $1, true)", [A]);
      assert.deepStrictEqual((await client.query('SELECT tenant_id FROM wazuh_managers')).rows.map((x) => x.tenant_id), [A], 'tenant A sees only its own row');
      await client.query('SAVEPOINT s1');
      await assert.rejects(client.query('INSERT INTO wazuh_managers (tenant_id, api_url, api_user, api_secret_enc, ca_pem, cert_sha256) VALUES ($1, $2, $3, $4, $5, $6)', [B, 'https://10.0.0.1:55000', 'x-user', 'v1.a.b.c', 'pem', 'a'.repeat(64)]), /row-level security/, 'cannot write another tenant\'s row');
      await client.query('ROLLBACK TO s1');
      assert.strictEqual((await client.query('UPDATE wazuh_managers SET api_url = $1 WHERE tenant_id = $2', ['https://10.9.9.9:55000', B])).rowCount, 0, 'cannot change it either');
      await client.query('ROLLBACK');
    } finally { client.release(); await pool.end(); }
    assert.strictEqual((await rowOf(B)).api_url, MB.url);
    // the table refuses an address that is not https://host:port, whatever wrote it
    await assert.rejects(db.query("INSERT INTO wazuh_managers (tenant_id, api_url, api_user, api_secret_enc, ca_pem, cert_sha256) VALUES ($1,'http://10.0.0.1:55000','u','v1.a.b.c','p',$2)", [A, 'a'.repeat(64)]), /check constraint|duplicate key/);

    // the CLI: refuses a bad manager and saves nothing; show, check, remove, and a second register replaces
    let x = await runCli(['register', '--tenant', A], reg(MB, { password: 'wrong-password' })); assert.deepStrictEqual([x.code, /AUTH_FAILED/.test(x.err), /Not saved/.test(x.err)], [1, true, true]); assert.strictEqual((await rowOf(A)).api_url, MA.url, 'unchanged');
    x = await runCli(['register', '--tenant', A], reg(MB, { ca_pem: MA.cert })); assert.deepStrictEqual([x.code, /TLS/.test(x.err)], [1, true], 'a certificate that is not the manager\'s');
    x = await runCli(['register', '--tenant', A], 'not json'); assert.strictEqual(x.code, 2);
    x = await runCli(['register', '--tenant', A], reg(MB, { url: 'http://127.0.0.1:1' })); assert.strictEqual(x.code, 2); assert.match(x.err, /https/);
    x = await runCli(['show', '--tenant', A]); assert.strictEqual(x.code, 0); assert.match(x.out, new RegExp(MA.url.replace(/[.]/g, '\\.'))); assert.ok(!x.out.includes('A-Passw0rd'));
    x = await runCli(['check', '--tenant', A]); assert.deepStrictEqual([x.code, /Working: Wazuh v4\.14\.9/.test(x.out)], [0, true]);
    x = await runCli(['register', '--tenant', A], reg(MB, { label: 'moved to B' })); assert.strictEqual(x.code, 0); assert.strictEqual((await rowOf(A)).api_url, MB.url, 'registering again replaces');
    r = await call(A, 'GET', '/v1/endpoints/agents/summary'); assert.strictEqual(r.json.summary.total, 2, 'and the proxy now follows the new row (no stale token)');
    x = await runCli(['register', '--tenant', A, '--no-check'], reg(MA)); assert.strictEqual(x.code, 0);
    x = await runCli(['remove', '--tenant', 'wz-a-' + stamp]); assert.deepStrictEqual([x.code, /Removed/.test(x.out)], [0, true]); assert.strictEqual(await rowOf(A), undefined);
    x = await runCli(['remove', '--tenant', A]); assert.match(x.out, /had no central manager/);
    x = await runCli(['show', '--tenant', 'no-such-tenant-' + stamp]); assert.strictEqual(x.code, 1);
    x = await runCli(['frobnicate', '--tenant', A]); assert.strictEqual(x.code, 2); x = await runCli(['show']); assert.strictEqual(x.code, 2); x = await runCli(['show', '--tenant', A, '--no-check']); assert.strictEqual(x.code, 2);
    const keep2 = process.env.NOTIFY_ENCRYPTION_KEY; delete process.env.NOTIFY_ENCRYPTION_KEY;
    x = await runCli(['register', '--tenant', A], reg(MA)); assert.strictEqual(x.code, 1); assert.match(x.err, /NOTIFY_ENCRYPTION_KEY/); process.env.NOTIFY_ENCRYPTION_KEY = keep2;
    console.log('wazuh-manager-db: ok');
  } finally {
    srv.close(); await MA.stop(); await MB.stop();
    for (const t of [A, B, C]) await db.query('DELETE FROM wazuh_managers WHERE tenant_id = $1', [t]);
    await db.close();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
