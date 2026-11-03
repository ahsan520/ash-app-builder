'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/wazuh-indexer-db.test.js
// Skips itself otherwise. The central indexer entry of a tenant (docs/endpoints.md task E6e): the REAL routes, the REAL wazuh_indexers table with its row security (checked as a role
// that is not a superuser, because a superuser bypasses it), the REAL operator CLI, and one stand-in indexer over HTTPS holding TWO tenants' indexes
// (tests/fixtures/fake-wazuh-indexer.js, a documented shape, not a real indexer). The point: a tenant reads ITS index and no other, and no route can change where that is.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
process.env.ASIX_WAZUH_INDEXER_TIMEOUT_MS = '1500';
process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true';
process.env.NOTIFY_ENCRYPTION_KEY = require('crypto').randomBytes(32).toString('base64');

const assert = require('assert');
const express = require('express');
const { Readable } = require('stream');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const fake = require('./fixtures/fake-wazuh-indexer');

let TENANT, PERMS = [];
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: (p) => [(req, res, next) => { PERMS.push(p); req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };
const cli = require('../src/endpoints/wazuh-indexer-cli');

const IA = 'wazuh-states-vulnerabilities-mgr-a', IB = 'wazuh-states-vulnerabilities-mgr-b';
const reg = (m, extra = {}) => JSON.stringify({ url: m.url, user: m.user, password: m.password, ca_pem: m.cert, index: IA, label: 'indexer ' + m.tag, ...extra });
async function runCli(args, stdin = '') { const out = [], err = []; const code = await cli.run(args, { stdin: Readable.from([stdin]), out: (l) => out.push(l), err: (l) => err.push(l) }); return { code, out: out.join('\n'), err: err.join('\n') }; }

async function main() {
  const stamp = Date.now();
  const A = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['ix-a-' + stamp])).rows[0].id;
  const B = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['ix-b-' + stamp])).rows[0].id;
  const C = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['ix-c-' + stamp])).rows[0].id;
  const X = await fake.start({ tag: 'X', indexes: { [IA]: fake.DOCS_A, [IB]: fake.DOCS_B } });   // one indexer, both tenants' indexes; this user may read both: the ASIX side must keep them apart
  const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/wazuh-indexer'));
  const srv = app.listen(0), base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (as, method, p, body) => { TENANT = as; const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json().catch(() => null) }; };
  const rowOf = async (t) => (await db.query('SELECT * FROM wazuh_indexers WHERE tenant_id = $1', [t])).rows[0];
  try {
    // nothing registered
    let r = await call(A, 'GET', '/v1/endpoints/vulnerabilities/status'); assert.deepStrictEqual([r.status, r.json.source], [200, { available: true, registered: false }]);
    for (const p of ['/v1/endpoints/vulnerabilities', '/v1/endpoints/vulnerabilities/summary']) { r = await call(A, 'GET', p); assert.deepStrictEqual([r.status, r.json.error.code], [404, 'VULN_NO_INDEXER'], p); }

    // the CLI registers (after reading the index); the row holds a sealed password
    let c = await runCli(['register', '--tenant', 'ix-a-' + stamp], reg(X)); assert.strictEqual(c.code, 0, c.err); assert.match(c.out, /The index answered: 6 findings/); assert.match(c.out, /Registered for tenant/);
    c = await runCli(['register', '--tenant', B], reg(X, { index: IB })); assert.strictEqual(c.code, 0, c.err); assert.match(c.out, /answered: 1 finding\b/);
    const row = await rowOf(A); assert.deepStrictEqual([row.index_url, row.index_user, row.index_name, row.updated_by], [X.url, X.user, IA, 'cli']); assert.ok(!JSON.stringify(row).includes('Idx-Passw0rd'), 'the password is not in the row'); assert.ok(row.secret_enc.length > 20); assert.strictEqual(row.cert_sha256.length, 64);

    // reading: each tenant reads its OWN index, though the indexer user could read both
    r = await call(A, 'GET', '/v1/endpoints/vulnerabilities/status'); assert.deepStrictEqual([r.status, r.json.source.registered, r.json.source.index, r.json.source.status.reachable, r.json.source.status.count], [200, true, IA, true, 6]);
    const shown = JSON.stringify(r.json); for (const s of ['Idx-Passw0rd', 'secret_enc', 'BEGIN CERTIFICATE']) assert.ok(!shown.includes(s), s + ' in the view');
    r = await call(A, 'GET', '/v1/endpoints/vulnerabilities'); assert.deepStrictEqual([r.status, r.json.total, r.json.findings.length], [200, 6, 6]); assert.ok(r.json.findings.every((f) => f.cve !== 'CVE-2026-9001'), 'A never sees B\'s finding');
    r = await call(B, 'GET', '/v1/endpoints/vulnerabilities'); assert.deepStrictEqual([r.status, r.json.total, r.json.findings.map((f) => f.cve)], [200, 1, ['CVE-2026-9001']]);
    r = await call(A, 'GET', '/v1/endpoints/vulnerabilities/summary?severity=critical'); assert.deepStrictEqual([r.status, r.json.summary.total, r.json.summary.machines], [200, 2, 2]);
    const seen = X.state.requests.filter((q) => q.path.startsWith('/' + IB + '/')).length;
    const sawA = X.state.requests.length;
    r = await call(C, 'GET', '/v1/endpoints/vulnerabilities'); assert.deepStrictEqual([r.status, r.json.error.code], [404, 'VULN_NO_INDEXER'], 'a tenant with no row reaches nothing'); assert.strictEqual(X.state.requests.length, sawA, 'and the indexer was not called for it');
    assert.ok(seen >= 1);
    assert.ok(X.state.requests.every((q) => q.method === 'GET' || (q.method === 'POST' && /\/_search\?/.test(q.path))), 'the indexer only ever saw a count or a search');

    // bad requests never reach the indexer
    const n = X.state.requests.length;
    for (const p of ['/v1/endpoints/vulnerabilities?index=wazuh-alerts-4.x', '/v1/endpoints/vulnerabilities?size=9999', '/v1/endpoints/vulnerabilities?limit=101', '/v1/endpoints/vulnerabilities?severity=urgent', '/v1/endpoints/vulnerabilities?agent=1', '/v1/endpoints/vulnerabilities?sort=password', '/v1/endpoints/vulnerabilities/summary?limit=5']) { r = await call(A, 'GET', p); assert.deepStrictEqual([r.status, r.json.error.code], [400, 'INVALID_VULN_QUERY'], p); }
    assert.strictEqual(X.state.requests.length, n, 'nothing was sent for a bad request');

    // NO route changes where the indexer or the index is: every other method answers 404 (no handler) and the row is untouched
    for (const [m, p, body] of [['PUT', '/v1/endpoints/vulnerabilities/status', { url: X.url }], ['POST', '/v1/endpoints/vulnerabilities/status', { index: IB }], ['DELETE', '/v1/endpoints/vulnerabilities/status'], ['POST', '/v1/endpoints/vulnerabilities', {}], ['DELETE', '/v1/endpoints/vulnerabilities']]) { r = await call(A, m, p, body); assert.strictEqual(r.status, 404, m + ' ' + p); }
    assert.deepStrictEqual([(await rowOf(A)).index_url, (await rowOf(A)).index_name], [X.url, IA]);
    assert.ok(PERMS.length > 0 && PERMS.every((p) => p === 'capacity:read'), 'every route asks for capacity:read only');

    // states are shown, not thrown
    X.state.mode = null; X.state.allowed = [IB]; r = await call(A, 'GET', '/v1/endpoints/vulnerabilities/status'); assert.deepStrictEqual([r.status, r.json.source.status.reachable, r.json.source.status.code], [200, false, 'AUTH_FAILED']);
    r = await call(A, 'GET', '/v1/endpoints/vulnerabilities'); assert.deepStrictEqual([r.status, r.json.error.code], [502, 'VULN_AUTH_FAILED']); X.state.allowed = null;
    X.state.delayMs = 2500; r = await call(A, 'GET', '/v1/endpoints/vulnerabilities/summary'); assert.deepStrictEqual([r.status, r.json.error.code], [504, 'VULN_TIMEOUT']); X.state.delayMs = 0;
    delete X.state.indexes[IB];
    r = await call(B, 'GET', '/v1/endpoints/vulnerabilities'); assert.deepStrictEqual([r.status, r.json.error.code], [404, 'VULN_NO_INDEX']); X.state.indexes[IB] = fake.DOCS_B;

    // the sealed password cannot be opened with another key: a clear message, and with no key at all
    const keep = process.env.NOTIFY_ENCRYPTION_KEY;
    process.env.NOTIFY_ENCRYPTION_KEY = require('crypto').randomBytes(32).toString('base64');
    r = await call(A, 'GET', '/v1/endpoints/vulnerabilities'); assert.deepStrictEqual([r.status, r.json.error.code], [500, 'VULN_SECRET']);
    r = await call(A, 'GET', '/v1/endpoints/vulnerabilities/status'); assert.deepStrictEqual([r.status, r.json.source.status.code], [200, 'SECRET']);
    delete process.env.NOTIFY_ENCRYPTION_KEY;
    r = await call(A, 'GET', '/v1/endpoints/vulnerabilities'); assert.deepStrictEqual([r.status, r.json.error.code], [503, 'VULN_NO_KEY']);
    process.env.NOTIFY_ENCRYPTION_KEY = keep;

    // row security, as a role that is not a superuser: without the tenant setting nothing is visible, with it only its own row
    await db.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wz_plain_ix') THEN CREATE ROLE wz_plain_ix NOLOGIN; END IF; END $$");
    await db.query('GRANT SELECT, INSERT, UPDATE, DELETE ON wazuh_indexers TO wz_plain_ix');
    const pg = await db.query('SELECT 1').then(() => require('pg')); const pool = new pg.Pool({ host: process.env.DB_HOST, database: process.env.DB_NAME || 'asix_platform', user: process.env.DB_USER || 'asix_admin', password: process.env.DB_PASSWORD }); const client = await pool.connect();
    try {
      await client.query('BEGIN'); await client.query('SET LOCAL ROLE wz_plain_ix'); await client.query("SELECT set_config('app.current_tenant_id', $1, true)", [A]);
      assert.deepStrictEqual((await client.query('SELECT tenant_id FROM wazuh_indexers')).rows.map((x) => x.tenant_id), [A], 'tenant A sees only its own row');
      await client.query('SAVEPOINT s1');
      await assert.rejects(client.query('INSERT INTO wazuh_indexers (tenant_id, index_url, index_user, secret_enc, ca_pem, cert_sha256, index_name) VALUES ($1, $2, $3, $4, $5, $6, $7)', [B, 'https://10.0.0.1:9200', 'x-user', 'v1.a.b.c', 'pem', 'a'.repeat(64), IB]), /row-level security/, 'cannot write another tenant\'s row');
      await client.query('ROLLBACK TO s1');
      assert.strictEqual((await client.query('UPDATE wazuh_indexers SET index_name = $1 WHERE tenant_id = $2', [IA, B])).rowCount, 0, 'cannot change it either');
      await client.query('ROLLBACK');
    } finally { client.release(); await pool.end(); }
    assert.strictEqual((await rowOf(B)).index_name, IB);
    // the table refuses an address that is not https://host:port and an index that is not one exact vulnerability index, whatever wrote it
    await assert.rejects(db.query("INSERT INTO wazuh_indexers (tenant_id, index_url, index_user, secret_enc, ca_pem, cert_sha256, index_name) VALUES ($1,'http://10.0.0.1:9200','u','v1.a.b.c','p',$2,$3)", [C, 'a'.repeat(64), IA]), /check constraint/);
    for (const bad of ['wazuh-states-vulnerabilities-*', '_all', 'wazuh-alerts-4.x-2026']) await assert.rejects(db.query("INSERT INTO wazuh_indexers (tenant_id, index_url, index_user, secret_enc, ca_pem, cert_sha256, index_name) VALUES ($1,'https://10.0.0.1:9200','u','v1.a.b.c','p',$2,$3)", [C, 'a'.repeat(64), bad]), /check constraint/, bad);

    // the CLI: refuses a bad registration and saves nothing; show, check, remove, and a second register replaces
    let x = await runCli(['register', '--tenant', A], reg(X, { password: 'wrong-password' })); assert.deepStrictEqual([x.code, /AUTH_FAILED/.test(x.err), /Not saved/.test(x.err)], [1, true, true]); assert.strictEqual((await rowOf(A)).index_name, IA, 'unchanged');
    x = await runCli(['register', '--tenant', A], reg(X, { index: 'wazuh-states-vulnerabilities-nothing-yet' })); assert.deepStrictEqual([x.code, /NO_INDEX/.test(x.err)], [1, true]);
    x = await runCli(['register', '--tenant', A, '--no-check'], reg(X, { index: 'wazuh-states-vulnerabilities-nothing-yet' })); assert.strictEqual(x.code, 0, 'an index that does not exist yet can be registered with --no-check'); assert.strictEqual((await rowOf(A)).index_name, 'wazuh-states-vulnerabilities-nothing-yet');
    r = await call(A, 'GET', '/v1/endpoints/vulnerabilities'); assert.deepStrictEqual([r.status, r.json.error.code], [404, 'VULN_NO_INDEX']);
    x = await runCli(['register', '--tenant', A], 'not json'); assert.strictEqual(x.code, 2);
    x = await runCli(['register', '--tenant', A], reg(X, { index: 'wazuh-states-vulnerabilities-*' })); assert.strictEqual(x.code, 2); assert.match(x.err, /index/);
    x = await runCli(['register', '--tenant', A], reg(X)); assert.strictEqual(x.code, 0, x.err);
    x = await runCli(['show', '--tenant', A]); assert.strictEqual(x.code, 0); assert.match(x.out, new RegExp(IA)); assert.ok(!x.out.includes('Idx-Passw0rd'));
    x = await runCli(['check', '--tenant', A]); assert.deepStrictEqual([x.code, /Working: 6 findings/.test(x.out)], [0, true]);
    x = await runCli(['remove', '--tenant', 'ix-a-' + stamp]); assert.deepStrictEqual([x.code, /Removed/.test(x.out)], [0, true]); assert.strictEqual(await rowOf(A), undefined);
    x = await runCli(['remove', '--tenant', A]); assert.match(x.out, /had no indexer registered/);
    x = await runCli(['show', '--tenant', 'no-such-tenant-' + stamp]); assert.strictEqual(x.code, 1);
    x = await runCli(['frobnicate', '--tenant', A]); assert.strictEqual(x.code, 2); x = await runCli(['show']); assert.strictEqual(x.code, 2); x = await runCli(['show', '--tenant', A, '--no-check']); assert.strictEqual(x.code, 2);
    // E6j: `indices` prints the registered index name of EVERY tenant (the keep list of scripts/deploy/wazuh-indexer-prune.sh): names only, sorted, once each, nothing secret, no --tenant
    x = await runCli(['register', '--tenant', A], reg(X)); assert.strictEqual(x.code, 0, x.err);
    x = await runCli(['register', '--tenant', B], reg(X, { index: IB })); assert.strictEqual(x.code, 0, x.err);
    x = await runCli(['indices']); assert.strictEqual(x.code, 0, x.err); const lines = x.out.split('\n').filter(Boolean);
    assert.ok(lines.includes(IA) && lines.includes(IB), 'both tenants\' indices are listed'); assert.deepStrictEqual(lines, [...new Set(lines)].sort(), 'sorted, once each');
    assert.ok(lines.every((l) => /^wazuh-states-vulnerabilities-[a-z0-9][a-z0-9._-]*$/.test(l)), 'nothing but index names on standard output'); assert.ok(!x.out.includes(X.url) && !x.out.includes('Idx-Passw0rd') && !x.out.includes('asix-vuln'), 'no address, password or user');
    x = await runCli(['indices', '--tenant', A]); assert.strictEqual(x.code, 2);
    await runCli(['remove', '--tenant', B]); x = await runCli(['indices']); assert.ok(!x.out.split('\n').includes(IB), 'a removed registration leaves the list'); assert.ok(x.out.split('\n').includes(IA));
    await runCli(['remove', '--tenant', A]);
    const keep2 = process.env.NOTIFY_ENCRYPTION_KEY; delete process.env.NOTIFY_ENCRYPTION_KEY;
    x = await runCli(['register', '--tenant', A], reg(X)); assert.strictEqual(x.code, 1); assert.match(x.err, /NOTIFY_ENCRYPTION_KEY/); process.env.NOTIFY_ENCRYPTION_KEY = keep2;
    console.log('wazuh-indexer-db: ok');
  } finally {
    srv.close(); await X.stop();
    for (const t of [A, B, C]) await db.query('DELETE FROM wazuh_indexers WHERE tenant_id = $1', [t]);
    await db.close();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
