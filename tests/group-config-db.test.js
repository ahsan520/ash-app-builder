'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/group-config-db.test.js
// Skips itself otherwise. E10, monitored folders per agent group (docs/endpoints.md): the REAL routes, the REAL tables wazuh_manager_writers and endpoint_group_config_history with their
// row security (checked as a role that is not a superuser), the REAL operator command (register-writer), and two stand-in manager APIs over HTTPS (tests/fixtures/fake-wazuh-api.js,
// a documented shape, NOT a real manager). Only the sign-in chain is replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
process.env.ASIX_WAZUH_API_TIMEOUT_MS = '1500';
process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true';
process.env.NOTIFY_ENCRYPTION_KEY = require('crypto').randomBytes(32).toString('base64');
delete process.env.ASIX_ENDPOINT_CONFIG_WRITE;

const assert = require('assert');
const express = require('express');
const { Readable } = require('stream');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const fake = require('./fixtures/fake-wazuh-api');

let TENANT, USER, PERMS = [];
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: (p) => [(req, res, next) => { PERMS.push(p); req.tenant_id = TENANT; req.user_id = USER; next(); }] };
const cli = require('../src/endpoints/wazuh-manager-cli');
const store = require('../src/endpoints/group-config-store');
const gc = require('../src/endpoints/group-config');

const WA = { user: 'asix-groupconfig', password: 'A-Wr1ter-pw!' }, WB = { user: 'asix-groupconfig-b', password: 'B-Wr1ter-pw!' };
const reg = (m) => JSON.stringify({ url: m.url, user: m.user, password: m.password, ca_pem: m.cert, label: 'manager ' + m.tag });
async function runCli(args, stdin = '') { const out = [], err = []; const code = await cli.run(args, { stdin: Readable.from([stdin]), out: (l) => out.push(l), err: (l) => err.push(l) }); return { code, out: out.join('\n'), err: err.join('\n') }; }
const L = (path, realtime = false) => ({ system: 'linux', path, realtime });

async function main() {
  const stamp = Date.now();
  const A = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['gc-a-' + stamp])).rows[0].id;
  const B = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['gc-b-' + stamp])).rows[0].id;
  const C = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['gc-c-' + stamp])).rows[0].id;
  const UA = (await db.query("INSERT INTO users (tenant_id, username, email) VALUES ($1, $2, 'a@example.test') RETURNING id", [A, 'alice-' + stamp])).rows[0].id;
  const MA = await fake.start({ tag: 'A', password: 'A-Passw0rd!x', writer: WA }), MB = await fake.start({ tag: 'B', cn: 'wazuh-b', password: 'B-Passw0rd!x', writer: WB });
  const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/group-config'));
  const srv = app.listen(0), base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (as, method, p, body, user = UA) => { TENANT = as; USER = user; PERMS = []; const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); let json = null; try { json = await r.json(); } catch { /* none */ } return { status: r.status, json, perms: PERMS.slice() }; };
  try {
    // ---- the operator registers the manager, then the writer
    let x = await runCli(['register-writer', '--tenant', A], JSON.stringify(WA)); assert.strictEqual(x.code, 1); assert.match(x.err, /no central manager registered/);
    for (const [t, m] of [[A, MA], [B, MB]]) { x = await runCli(['register', '--tenant', t], reg(m)); assert.strictEqual(x.code, 0, x.err); }
    x = await runCli(['register-writer', '--tenant', A], JSON.stringify({ user: MA.user, password: MA.password })); assert.strictEqual(x.code, 1, 'the read-only user is not accepted as the writer'); assert.match(x.err, /FORBIDDEN|did not accept/);
    x = await runCli(['register-writer', '--tenant', A], JSON.stringify({ user: WA.user, password: 'Wrong-pw-1!' })); assert.strictEqual(x.code, 1); assert.match(x.err, /AUTH_FAILED/);
    x = await runCli(['register-writer', '--tenant', A], JSON.stringify({ ...WA, url: 'https://10.0.0.1:55000' })); assert.strictEqual(x.code, 2, 'no address in a writer registration'); assert.match(x.err, /Unknown field/);
    x = await runCli(['register-writer', '--tenant', A], '{"user":"x","password":"short"}'); assert.strictEqual(x.code, 2); x = await runCli(['register-writer', '--tenant', A], 'not json'); assert.strictEqual(x.code, 2);
    assert.strictEqual((await db.query('SELECT 1 FROM wazuh_manager_writers WHERE tenant_id = $1', [A])).rowCount, 0, 'nothing saved by the refusals');
    x = await runCli(['register-writer', '--tenant', A], JSON.stringify(WA)); assert.strictEqual(x.code, 0, x.err); assert.match(x.out, /lists 2 group/); assert.match(x.out, /switched off until ASIX_ENDPOINT_CONFIG_WRITE/);
    x = await runCli(['show', '--tenant', A]); assert.match(x.out, /Group configuration user: asix-groupconfig/); x = await runCli(['show', '--tenant', B]); assert.match(x.out, /Group configuration user: none registered/);
    const row = (await db.query('SELECT * FROM wazuh_manager_writers WHERE tenant_id = $1', [A])).rows[0]; assert.ok(!JSON.stringify(row).includes(WA.password), 'the password is stored sealed'); assert.match(row.api_secret_enc, /^v1\./);

    // ---- reading works with writing switched off
    let r = await call(A, 'GET', '/v1/endpoints/group-config'); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.perms, ['capacity:read']); assert.strictEqual(r.json.write_enabled, false); assert.strictEqual(r.json.writer_registered, true); assert.deepStrictEqual(r.json.groups.map((g) => g.name).sort(), ['default', 'linux']); assert.strictEqual(r.json.writer.api_user, WA.user);
    assert.ok(!JSON.stringify(r.json).includes(WA.password) && !JSON.stringify(r.json).includes('v1.'));
    r = await call(A, 'GET', '/v1/endpoints/group-config/default'); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.state, 'none'); assert.deepStrictEqual(r.json.history, []); const base0 = r.json.sha256; assert.match(base0, /^[0-9a-f]{64}$/);
    r = await call(A, 'POST', '/v1/endpoints/group-config/default/preview', { entries: [L('/srv/data', true), { system: 'windows', path: 'C:\\Data' }] }); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.perms, ['capacity:read']); assert.strictEqual(r.json.changed, true); assert.deepStrictEqual(r.json.diff.added, ['Linux /srv/data (real time)', 'Windows C:\\Data']); assert.strictEqual(r.json.base_sha256, base0);
    assert.strictEqual(MA.state.groupWrites.length, 0);

    // ---- writing is refused while the server switch is off (a registered writer alone changes nothing)
    r = await call(A, 'PUT', '/v1/endpoints/group-config/default', { entries: [L('/srv/data')], base_sha256: base0 }); assert.strictEqual(r.status, 403); assert.strictEqual(r.json.error.code, 'GROUP_CONFIG_WRITE_OFF'); assert.strictEqual(MA.state.groupWrites.length, 0);
    r = await call(A, 'POST', '/v1/endpoints/group-config/default/undo', { history_id: '00000000-0000-4000-8000-000000000000', base_sha256: base0 }); assert.strictEqual(r.status, 403);
    process.env.ASIX_ENDPOINT_CONFIG_WRITE = 'true';

    // ---- bad requests send nothing to the manager
    const n0 = MA.state.requests.length;
    for (const [m, p, b, code, st] of [['PUT', '/v1/endpoints/group-config/a%20b', { entries: [], base_sha256: base0 }, 'GROUP_CONFIG_BAD_GROUP', 400], ['PUT', '/v1/endpoints/group-config/default', { entries: 'x', base_sha256: base0 }, 'GROUP_CONFIG_BAD_BODY', 400],
      ['PUT', '/v1/endpoints/group-config/default', { entries: [], base_sha256: base0, force: true }, 'GROUP_CONFIG_BAD_BODY', 400], ['PUT', '/v1/endpoints/group-config/default', [], 'GROUP_CONFIG_BAD_BODY', 400],
      ['PUT', '/v1/endpoints/group-config/default', { entries: [L('/')], base_sha256: base0 }, 'GROUP_CONFIG_INVALID', 400], ['PUT', '/v1/endpoints/group-config/default', { entries: [L('/a')] }, 'GROUP_CONFIG_BASE_REQUIRED', 400],
      ['POST', '/v1/endpoints/group-config/default/undo', { history_id: 'nope', base_sha256: base0 }, 'GROUP_CONFIG_BAD_BODY', 400], ['POST', '/v1/endpoints/group-config/default/preview', { entries: [L('/a')], extra: 1 }, 'GROUP_CONFIG_BAD_BODY', 400]]) {
      r = await call(A, m, p, b); assert.strictEqual(r.status, st, m + ' ' + p + ' ' + JSON.stringify(r.json)); assert.strictEqual(r.json.error.code, code);
    }
    assert.strictEqual(MA.state.groupWrites.length, 0);
    // (the three that reach the manager are the ones that need it to read the file first; none of them wrote)
    assert.ok(MA.state.requests.slice(n0).every((q) => q.method === 'GET' || q.path.startsWith('/security')));

    // ---- apply, history with the person's name, stale refusal
    r = await call(A, 'PUT', '/v1/endpoints/group-config/default', { entries: [L('/srv/data', true), { system: 'windows', path: 'C:\\Data' }], base_sha256: base0 }); assert.strictEqual(r.status, 200, JSON.stringify(r.json)); assert.deepStrictEqual(r.perms, ['endpoints:config:write']); assert.strictEqual(r.json.changed, true);
    assert.strictEqual(MA.state.groupWrites.length, 1); assert.deepStrictEqual(gc.find(MA.state.groups.get('default')).entries.map((e) => e.path), ['/srv/data', 'C:\\Data']); const hid = r.json.history_id;
    r = await call(A, 'GET', '/v1/endpoints/group-config/default'); assert.strictEqual(r.json.state, 'ok'); assert.strictEqual(r.json.history.length, 1); assert.strictEqual(r.json.history[0].by, 'alice-' + stamp); assert.strictEqual(r.json.history[0].result, 'applied'); assert.strictEqual(r.json.history[0].id, hid); const base1 = r.json.sha256;
    assert.ok(!JSON.stringify(r.json).includes('before_content'), 'the old file text is kept in the database, not sent to the page');
    r = await call(A, 'PUT', '/v1/endpoints/group-config/default', { entries: [L('/other')], base_sha256: base0 }); assert.strictEqual(r.status, 409); assert.strictEqual(r.json.error.code, 'GROUP_CONFIG_STALE'); assert.strictEqual(MA.state.groupWrites.length, 1);
    // the manager says no: 422, the file is as it was, the history says failed
    MA.state.rejectConf = () => 'Wazuh syntax error: nope'; r = await call(A, 'PUT', '/v1/endpoints/group-config/default', { entries: [L('/srv/data'), L('/more')], base_sha256: base1 }); MA.state.rejectConf = null;
    assert.strictEqual(r.status, 422); assert.strictEqual(r.json.error.code, 'GROUP_CONFIG_REJECTED'); assert.match(r.json.error.message, /nope/); assert.strictEqual(r.json.unchanged, true);
    r = await call(A, 'GET', '/v1/endpoints/group-config/default'); assert.strictEqual(r.json.sha256, base1); assert.deepStrictEqual(r.json.history.map((h) => h.result), ['failed', 'applied']);

    // ---- undo: the block goes back, edits elsewhere in the file stay
    MA.state.groups.set('default', MA.state.groups.get('default') + '<!-- hand edit -->\n'); r = await call(A, 'GET', '/v1/endpoints/group-config/default'); const base2 = r.json.sha256;
    r = await call(A, 'POST', '/v1/endpoints/group-config/default/undo', { history_id: r.json.history.find((h) => h.result === 'failed').id, base_sha256: base2 }); assert.strictEqual(r.status, 409); assert.strictEqual(r.json.error.code, 'GROUP_CONFIG_NOT_UNDOABLE');
    r = await call(A, 'POST', '/v1/endpoints/group-config/default/undo', { history_id: '00000000-0000-4000-8000-000000000000', base_sha256: base2 }); assert.strictEqual(r.status, 404);
    r = await call(A, 'POST', '/v1/endpoints/group-config/default/undo', { history_id: hid, base_sha256: base2 }); assert.strictEqual(r.status, 200, JSON.stringify(r.json)); assert.deepStrictEqual(r.perms, ['endpoints:config:write']);
    assert.strictEqual(gc.find(MA.state.groups.get('default')).state, 'none'); assert.ok(MA.state.groups.get('default').includes('<!-- hand edit -->')); assert.ok(MA.state.groups.get('default').startsWith('<agent_config>'));
    r = await call(A, 'GET', '/v1/endpoints/group-config/default'); assert.strictEqual(r.json.history[0].action, 'undo'); assert.strictEqual(r.json.history[0].result, 'applied');

    // ---- tenants: B has a manager but no writer; its calls never touch A's manager or A's history
    r = await call(B, 'GET', '/v1/endpoints/group-config/default'); assert.strictEqual(r.status, 404); assert.strictEqual(r.json.error.code, 'GROUP_CONFIG_NO_WRITER');
    r = await call(B, 'GET', '/v1/endpoints/group-config'); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.writer_registered, false); assert.deepStrictEqual(r.json.groups, []);
    r = await call(C, 'GET', '/v1/endpoints/group-config'); assert.strictEqual(r.status, 404); assert.strictEqual(r.json.error.code, 'GROUP_CONFIG_NO_MANAGER');
    x = await runCli(['register-writer', '--tenant', B], JSON.stringify(WB)); assert.strictEqual(x.code, 0, x.err);
    r = await call(B, 'GET', '/v1/endpoints/group-config/default'); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json.history, [], 'A\'s history is not B\'s'); assert.strictEqual(MB.state.groupWrites.length, 0);
    r = await call(B, 'POST', '/v1/endpoints/group-config/default/undo', { history_id: hid, base_sha256: r.json.sha256 }); assert.strictEqual(r.status, 404, 'a history id of another tenant is not found');
    x = await runCli(['register-writer', '--tenant', B], JSON.stringify(WA)); assert.strictEqual(x.code, 1, 'A\'s writer is not B\'s writer: the other manager does not know that user');

    // ---- row security on both new tables, as a role that is not a superuser
    await db.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gc_plain') THEN CREATE ROLE gc_plain NOLOGIN; END IF; END $$");
    await db.query('GRANT SELECT, INSERT, UPDATE, DELETE ON wazuh_manager_writers, endpoint_group_config_history TO gc_plain');
    const pg = require('pg'); const pool = new pg.Pool({ host: process.env.DB_HOST, database: process.env.DB_NAME || 'asix_platform', user: process.env.DB_USER || 'asix_admin', password: process.env.DB_PASSWORD }); const client = await pool.connect();
    try {
      await client.query('BEGIN'); await client.query('SET LOCAL ROLE gc_plain');
      for (const t of ['wazuh_manager_writers', 'endpoint_group_config_history']) { await client.query('SAVEPOINT s0'); await assert.rejects(client.query('SELECT 1 FROM ' + t), /app\.current_tenant_id/, 'no tenant setting: nothing is readable'); await client.query('ROLLBACK TO s0'); }
      await client.query("SELECT set_config('app.current_tenant_id', $1, true)", [A]);
      assert.deepStrictEqual((await client.query('SELECT tenant_id FROM wazuh_manager_writers')).rows.map((q) => q.tenant_id), [A]); assert.ok((await client.query('SELECT 1 FROM endpoint_group_config_history')).rowCount >= 3);
      await client.query('SAVEPOINT s1'); await assert.rejects(client.query("INSERT INTO endpoint_group_config_history (tenant_id, group_name, action, result, entries_before, entries_after, before_sha256, before_content) VALUES ($1, 'x', 'apply', 'applied', '[]', '[]', $2, '')", [B, 'a'.repeat(64)]), /row-level security/); await client.query('ROLLBACK TO s1');
      await client.query('SAVEPOINT s2'); await assert.rejects(client.query("INSERT INTO endpoint_group_config_history (tenant_id, group_name, action, result, entries_before, entries_after, before_sha256, before_content) VALUES ($1, 'x', 'delete', 'applied', '[]', '[]', $2, '')", [A, 'a'.repeat(64)]), /check constraint/); await client.query('ROLLBACK TO s2');
      await client.query('ROLLBACK');
    } finally { client.release(); await pool.end(); }

    // ---- the history keeps the newest 50 per group
    for (let i = 0; i < 55; i++) await db.withTenant(A, (c) => store.record(c, A, 'linux', { action: 'apply', result: 'applied', entries_before: [], entries_after: [L('/x' + i)], before_sha256: 'b'.repeat(64), after_sha256: 'c'.repeat(64), before_content: '', actor: String(UA) }));
    assert.strictEqual((await db.query("SELECT count(*)::int AS n FROM endpoint_group_config_history WHERE tenant_id = $1 AND group_name = 'linux'", [A])).rows[0].n, 50);
    assert.strictEqual((await db.query("SELECT count(*)::int AS n FROM endpoint_group_config_history WHERE tenant_id = $1 AND group_name = 'default'", [A])).rows[0].n, 3, 'another group\'s history is not pruned');
    assert.strictEqual((await db.withTenant(A, (c) => store.list(c, A, 'linux', 500))).length, 50);

    // ---- remove-writer
    x = await runCli(['remove-writer', '--tenant', A]); assert.strictEqual(x.code, 0); assert.match(x.out, /Removed/); r = await call(A, 'GET', '/v1/endpoints/group-config/default'); assert.strictEqual(r.json.error.code, 'GROUP_CONFIG_NO_WRITER');
    x = await runCli(['remove-writer', '--tenant', A]); assert.match(x.out, /had no group configuration user/);
    console.log('group-config-db: ok');
  } finally {
    srv.close(); await MA.stop(); await MB.stop();
    for (const t of [A, B, C]) { await db.query('DELETE FROM endpoint_group_config_history WHERE tenant_id = $1', [t]); await db.query('DELETE FROM wazuh_manager_writers WHERE tenant_id = $1', [t]); await db.query('DELETE FROM wazuh_managers WHERE tenant_id = $1', [t]); }
    await db.query('DELETE FROM users WHERE id = $1', [UA]);
    await db.close();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
