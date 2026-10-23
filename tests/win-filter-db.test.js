'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/win-filter-db.test.js
// Skips itself otherwise. The saved Windows filter policy (docs/endpoints.md task E2): the real routes and the real win_filter_policy table, including the row security
// policy (checked as a role that is not a superuser, because a superuser bypasses it) and two saves racing on the same revision. Only the sign-in chain is replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };

const POLICY = { rules: [{ id: 'a', action: 'drop', channel: 'Security', event_ids: [4656, '4700-4710'] }], strip_message: true };

async function main() {
  const stamp = Date.now();
  const A = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wf-a-' + stamp])).rows[0].id;
  const B = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wf-b-' + stamp])).rows[0].id;
  const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/win-filter'));
  const srv = app.listen(0), base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (as, method, p, body) => { TENANT = as; const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const row = async (t) => (await db.query('SELECT policy, revision, updated_by FROM win_filter_policy WHERE tenant_id = $1', [t])).rows[0];
  try {
    // nothing saved
    let r = await call(A, 'GET', '/v1/endpoints/win-filter'); assert.deepStrictEqual([r.status, r.json.settings.available, r.json.settings.configured, r.json.settings.revision], [200, true, false, 0]);

    // save, read back, save again: the revision counts up and the stored policy is the shown shape
    r = await call(A, 'PUT', '/v1/endpoints/win-filter', { policy: POLICY }); assert.deepStrictEqual([r.status, r.json.settings.revision], [200, 1]);
    assert.deepStrictEqual((await row(A)).policy.rules[0].event_ids, [4656, '4700-4710']); assert.strictEqual((await row(A)).updated_by, 'tester');
    r = await call(A, 'GET', '/v1/endpoints/win-filter'); assert.deepStrictEqual([r.json.settings.configured, r.json.settings.policy.strip_message, r.json.settings.policy.rules[0].id], [true, true, 'a']);
    r = await call(A, 'PUT', '/v1/endpoints/win-filter', { policy: { default: 'keep' }, if_revision: 1 }); assert.deepStrictEqual([r.status, r.json.settings.revision], [200, 2]);

    // the other tenant sees nothing and has its own
    r = await call(B, 'GET', '/v1/endpoints/win-filter'); assert.strictEqual(r.json.settings.configured, false);
    r = await call(B, 'PUT', '/v1/endpoints/win-filter', { policy: POLICY, if_revision: 0 }); assert.deepStrictEqual([r.status, r.json.settings.revision], [200, 1]);
    assert.strictEqual((await row(A)).revision, 2);

    // a stale revision is refused and the row is untouched
    r = await call(A, 'PUT', '/v1/endpoints/win-filter', { policy: POLICY, if_revision: 1 }); assert.deepStrictEqual([r.status, r.json.error.code], [409, 'WIN_FILTER_CHANGED']);
    assert.deepStrictEqual([(await row(A)).revision, (await row(A)).policy.rules.length], [2, 0]);

    // two saves based on the same revision, forced to overlap: another connection holds the row while both saves arrive, then lets go. With the row read under lock the
    // first save to get the row wins and the second then sees the new revision and is refused; without the lock both would read the old revision and both would be saved.
    const holder = await db.pool.connect();
    let race;
    try {
      await holder.query('BEGIN'); await holder.query('SELECT 1 FROM win_filter_policy WHERE tenant_id = $1 FOR UPDATE', [A]);
      const pending = [call(A, 'PUT', '/v1/endpoints/win-filter', { policy: POLICY, if_revision: 2 }), call(A, 'PUT', '/v1/endpoints/win-filter', { policy: { default: 'drop' }, if_revision: 2 })];
      await new Promise((ok) => setTimeout(ok, 400));
      await holder.query('COMMIT'); race = await Promise.all(pending);
    } finally { holder.release(); }
    assert.deepStrictEqual(race.map((x) => x.status).sort(), [200, 409]); assert.strictEqual((await row(A)).revision, 3);

    // an invalid policy writes nothing
    r = await call(A, 'PUT', '/v1/endpoints/win-filter', { policy: { rules: [{ id: 'x', action: 'drop', match: { regex: '(?=x)' } }] } }); assert.strictEqual(r.status, 400); assert.strictEqual((await row(A)).revision, 3);

    // row security: as a role that is not a superuser, a query with no tenant filter sees only the current tenant's row
    await db.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wf_rls_tester') THEN CREATE ROLE wf_rls_tester NOLOGIN; END IF; END $$");
    await db.query('GRANT SELECT, INSERT, UPDATE, DELETE ON win_filter_policy TO wf_rls_tester');
    const seen = async (t) => { const c = await db.pool.connect(); try { await c.query('BEGIN'); await c.query('SELECT set_config($1, $2, true)', ['app.current_tenant_id', t]); await c.query('SET LOCAL ROLE wf_rls_tester');
      const n = (await c.query('SELECT tenant_id FROM win_filter_policy WHERE tenant_id IN ($1, $2)', [A, B])).rows.map((x) => x.tenant_id);
      let blocked = false; try { await c.query('SAVEPOINT s'); await c.query('INSERT INTO win_filter_policy (tenant_id, policy) VALUES ($1, $2::jsonb)', [t === A ? B : A, '{}']); } catch (e) { blocked = true; }
      await c.query('ROLLBACK'); return { n, blocked }; } finally { c.release(); } };
    if (db.pool) { assert.deepStrictEqual(await seen(A), { n: [A], blocked: true }); assert.deepStrictEqual(await seen(B), { n: [B], blocked: true }); } else console.log('note: db.pool not exported, row security check skipped');

    // clear: the row is gone, the other tenant's stays
    r = await call(A, 'PUT', '/v1/endpoints/win-filter', { clear: true }); assert.deepStrictEqual([r.status, r.json.settings.configured, r.json.settings.revision], [200, false, 0]);
    assert.strictEqual(await row(A), undefined); assert.strictEqual((await row(B)).revision, 1);

    // the revision check in the table itself
    await assert.rejects(() => db.query('INSERT INTO win_filter_policy (tenant_id, policy, revision) VALUES ($1, $2::jsonb, 0)', [A, '{}']), /revision_check/);
    console.log('win-filter-db: ok');
  } finally {
    srv.close();
    await db.query('DELETE FROM win_filter_policy WHERE tenant_id = ANY($1)', [[A, B]]);
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[A, B]]);
    await db.close();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
