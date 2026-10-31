'use strict';
// E4o against a real PostgreSQL (platform schema applied): the real routes, the real detection_rules table, the real rule runner (ensureBuiltinRules and runTenant) and the real
// PostgreSQL event store. Only the sign-in chain is replaced.
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/score-alert-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };
const sa = require('../src/endpoints/score-alert');
const rules = require('../src/detection/rule-runner');
const { getEventStore } = require('../src/events');

const ago = (min) => new Date(Date.now() - min * 60000).toISOString();

async function main() {
  const stamp = Date.now();
  const mk = async (n) => (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['scorealert-' + n + '-' + stamp])).rows[0].id;
  const A = await mk('a'), B = await mk('b'), C = await mk('c-no-rule');
  for (const t of [A, B]) await db.withTenant(t, (c) => rules.ensureBuiltinRules(c, t));
  TENANT = A;
  const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/score-alert'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const U = '/v1/endpoints/score-alert';
  const ruleRow = async (t) => (await db.query(`SELECT id, enabled, severity, description, definition FROM detection_rules WHERE tenant_id = $1 AND builtin_key = $2`, [t, sa.RULE_KEY])).rows[0];
  const store = getEventStore();
  const summary = (t, machine, score) => store.insertBatch(t, [{ source_type: 'endpoint-alert', raw: `[Endpoint alert] rule 19004 level 7: SCA summary: Score less than 50% (${score})`, received_at: ago(3),
    parsed: { sca_score: score, sca_key: `CIS test policy on ${machine}`, alert_level: 7, data_sca_type: 'summary' } }]);
  const run = async (t) => { await db.query('UPDATE detection_rules SET last_run_at = NULL WHERE tenant_id = $1', [t]); const r = await rules.runTenant(t); assert.strictEqual(r.errors, 0, 'no rule failed'); return r; };
  const raised = async (t) => (await db.query('SELECT group_key FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY group_key', [t, 'Endpoint configuration check score low'])).rows.map((x) => x.group_key);

  try {
    // 1. the rule as ensureBuiltinRules makes it: on, shipped query, the E4o description
    let r = await ruleRow(A); assert.strictEqual(r.enabled, true); assert.strictEqual(r.definition.xql, 'sca_score != null and sca_score < 50'); assert.strictEqual(r.description, sa.DESCRIPTION);
    let g = await call('GET', U); assert.strictEqual(g.status, 200); assert.deepStrictEqual([g.json.settings.available, g.json.settings.enabled, g.json.settings.limit, g.json.settings.edited, g.json.settings.rule_id], [true, true, 50, false, r.id]);

    // 2. a limit changes only the query text and switches the rule on: severity, window, suppression and the rest of the definition stay as they were (Detections page edits survive)
    await db.query(`UPDATE detection_rules SET severity = 'high', enabled = false, definition = jsonb_set(jsonb_set(definition, '{suppression,minutes}', '720'), '{window_minutes}', '120') WHERE tenant_id = $1 AND builtin_key = $2`, [A, sa.RULE_KEY]);
    const before = (await ruleRow(A)).definition;
    let p = await call('PUT', U, { limit: 70 }); assert.strictEqual(p.status, 200); assert.deepStrictEqual([p.json.settings.limit, p.json.settings.enabled, p.json.settings.severity], [70, true, 'high']);
    r = await ruleRow(A); assert.strictEqual(r.definition.xql, 'sca_score != null and sca_score < 70'); assert.strictEqual(r.enabled, true); assert.strictEqual(r.severity, 'high');
    assert.deepStrictEqual({ ...r.definition, xql: null }, { ...before, xql: null }, 'only the query changed'); assert.strictEqual(r.definition.suppression.minutes, 720); assert.strictEqual(r.definition.window_minutes, 120);
    assert.strictEqual((await call('GET', U)).json.settings.limit, 70);

    // 3. another tenant's rule is not touched, and a tenant with no rule yet is "not ready", not an error
    assert.strictEqual((await ruleRow(B)).definition.xql, 'sca_score != null and sca_score < 50');
    TENANT = C; g = await call('GET', U); assert.deepStrictEqual([g.status, g.json.settings.available], [200, false]);
    for (const b of [{ limit: 30 }, { off: true }]) { p = await call('PUT', U, b); assert.deepStrictEqual([p.status, p.json.error.code], [503, 'SCORE_ALERT_NOT_READY']); }
    assert.strictEqual((await ruleRow(C)), undefined, 'a save never creates the rule'); TENANT = A;

    // 4. off keeps the query; a limit switches it on again
    p = await call('PUT', U, { off: true }); assert.deepStrictEqual([p.status, p.json.settings.enabled, p.json.settings.limit], [200, false, 70]); assert.strictEqual((await ruleRow(A)).definition.xql, 'sca_score != null and sca_score < 70');
    p = await call('PUT', U, { limit: 70 }); assert.deepStrictEqual([p.status, p.json.settings.enabled], [200, true]);

    // 5. a hand-edited query is not guessed at: 409, nothing changes; off still works; putting the shipped shape back (what Reset does) lets a limit through again
    const edited = 'sca_score != null and sca_score < 70 and sca_key ~= "web"';
    await db.query(`UPDATE detection_rules SET definition = jsonb_set(definition, '{xql}', to_jsonb($3::text)) WHERE tenant_id = $1 AND builtin_key = $2`, [A, sa.RULE_KEY, edited]);
    p = await call('PUT', U, { limit: 30 }); assert.deepStrictEqual([p.status, p.json.error.code], [409, 'SCORE_ALERT_EDITED']); assert.strictEqual((await ruleRow(A)).definition.xql, edited);
    g = await call('GET', U); assert.deepStrictEqual([g.json.settings.limit, g.json.settings.edited, g.json.settings.enabled], [null, true, true]);
    p = await call('PUT', U, { off: true }); assert.strictEqual(p.status, 200); assert.strictEqual((await ruleRow(A)).enabled, false); assert.strictEqual((await ruleRow(A)).definition.xql, edited);
    await db.query(`UPDATE detection_rules SET definition = jsonb_set(definition, '{xql}', to_jsonb($3::text)) WHERE tenant_id = $1 AND builtin_key = $2`, [A, sa.RULE_KEY, sa.queryFor(50)]);
    p = await call('PUT', U, { limit: 50 }); assert.deepStrictEqual([p.status, p.json.settings.enabled, p.json.settings.limit], [200, true, 50]);

    // 6. bad bodies change nothing
    for (const b of [{}, { limit: 0 }, { limit: 101 }, { limit: "1'; DROP TABLE alerts; --" }, { off: false }, { limit: 30, off: true }]) { p = await call('PUT', U, b); assert.deepStrictEqual([p.status, p.json.error.code], [400, 'INVALID_SCORE_ALERT'], JSON.stringify(b)); }
    assert.strictEqual((await ruleRow(A)).definition.xql, sa.queryFor(50));
    // the database refuses nothing it should accept: the lowest and highest limit
    for (const n of [1, 100]) { p = await call('PUT', U, { limit: n }); assert.deepStrictEqual([p.status, p.json.settings.limit], [200, n]); }
    p = await call('PUT', U, { limit: 50 });

    // 7. end to end with the REAL rule runner and event store: the limit decides which scan summaries raise an alert
    await summary(A, 'web1', 45); await summary(A, 'web2', 60); await summary(A, 'web3', 80);
    await summary(B, 'web2', 60);                                                       // tenant B stays at 50
    await run(A); await run(B);
    assert.deepStrictEqual(await raised(A), ['CIS test policy on web1'], 'limit 50: only the 45');
    p = await call('PUT', U, { limit: 70 }); await run(A); await run(B);
    assert.deepStrictEqual(await raised(A), ['CIS test policy on web1', 'CIS test policy on web2'], 'limit 70 adds the 60 and not the 80');
    assert.deepStrictEqual(await raised(B), [], 'another tenant\'s limit is its own: 60 is above 50');
    p = await call('PUT', U, { off: true }); await summary(A, 'web4', 10); await run(A);
    assert.deepStrictEqual(await raised(A), ['CIS test policy on web1', 'CIS test policy on web2'], 'off: the 10 raises nothing');
    p = await call('PUT', U, { limit: 70 }); await run(A);
    assert.deepStrictEqual(await raised(A), ['CIS test policy on web1', 'CIS test policy on web2', 'CIS test policy on web4'], 'on again: the 10 raises');

    // 8. ensureBuiltinRules: an untouched E4n description is replaced; an edited one is not; the query and the limit are never written by it
    await db.query(`UPDATE detection_rules SET description = $3 WHERE tenant_id = $1 AND builtin_key = $2`, [A, sa.RULE_KEY, sa.E4N_DESCRIPTION]);
    await db.query(`UPDATE detection_rules SET description = 'my own words' WHERE tenant_id = $1 AND builtin_key = $2`, [B, sa.RULE_KEY]);
    await db.query(`UPDATE detection_rules SET definition = jsonb_set(definition, '{xql}', to_jsonb($3::text)) WHERE tenant_id = $1 AND builtin_key = $2`, [A, sa.RULE_KEY, sa.queryFor(33)]);
    for (const t of [A, B]) await db.withTenant(t, (c) => rules.ensureBuiltinRules(c, t));
    r = await ruleRow(A); assert.strictEqual(r.description, sa.DESCRIPTION); assert.strictEqual(r.definition.xql, sa.queryFor(33), 'the saved limit survives the rule runner\'s own upgrade step');
    assert.strictEqual((await ruleRow(B)).description, 'my own words');
    for (const t of [A, B]) await db.withTenant(t, (c) => rules.ensureBuiltinRules(c, t));   // and again: nothing changes
    assert.strictEqual((await ruleRow(A)).definition.xql, sa.queryFor(33)); assert.strictEqual((await ruleRow(B)).description, 'my own words');
    console.log('score-alert-db: all checks passed');
  } finally {
    srv.close();
    for (const t of [A, B, C]) { await db.query('DELETE FROM alerts WHERE tenant_id = $1', [t]); await db.query('DELETE FROM detection_rules WHERE tenant_id = $1', [t]); await db.query('DELETE FROM events WHERE tenant_id = $1', [t]).catch(() => {}); await db.query('DELETE FROM tenants WHERE id = $1', [t]).catch(() => {}); }
    await db.pool.end().catch(() => {});
  }
}
main().then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });
