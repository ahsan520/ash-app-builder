'use strict';
// SR3 against a real PostgreSQL (platform schema applied): the real routes (people and engine callback), the real SQL, the real action registry and the real lists and cases tables.
// Only the sign-in chain is replaced (same way as tests/actions-db.test.js) and the outbound call to the engine, which is a stub that records what ASIX would have sent.
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_USER=asix_admin DB_NAME=asix_platform DB_PASSWORD=... node tests/engine-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
process.env.ASIX_PROFILE = process.env.ASIX_PROFILE || 'home';
process.env.ASIX_ENGINE_CALLBACK_BASE = 'https://asix.example.test:30443';
process.env.ASIX_ENGINE_RATE_PER_MIN = '30';
delete process.env.ASIX_ENGINE_ALLOW_PRIVATE;

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT; let USER; const asked = [];
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared,
  guarded: (permission) => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = USER; asked.push([req.method, req.route ? req.route.path : req.path, permission]); next(); }],
};
const start = require('../src/engine/start');
const model = require('../src/engine/model');

const HOOK = 'https://engine.example.test/api/webhooks/wf_abc/s3cr3t-hook-value';
let sent = []; let hookAnswer = { ok: true, status: 200, engineRef: 'exec-1', error: null };
start.postHook = async (url, body) => { sent.push({ url, body }); return hookAnswer; };   // the route calls start.postHook at request time

async function main() {
  const stamp = Date.now();
  const q = (t, p) => db.query(t, p);
  const mkTenant = async (n) => (await q('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['engine-' + n + '-' + stamp])).rows[0].id;
  const mkUser = async (t, n) => (await q('INSERT INTO users (tenant_id, username, email) VALUES ($1, $2, $3) RETURNING id', [t, `${n}-${stamp}`, `${n}-${stamp}@example.test`])).rows[0].id;
  const mkList = async (t, name) => (await q(`INSERT INTO lists (tenant_id, name, kind, item_type, created_by_name) VALUES ($1, $2, 'block', 'ip', 'test') RETURNING id`, [t, name])).rows[0].id;
  const A = await mkTenant('a'); const B = await mkTenant('b');
  const alice = await mkUser(A, 'alice'); const eve = await mkUser(B, 'eve');
  const listA = await mkList(A, 'engine-block-' + stamp);

  const app = express(); app.use(express.json());
  app.use(require('../src/gateway/routes/actions')); app.use(require('../src/gateway/routes/lists')); app.use(require('../src/gateway/routes/cases'));
  app.use(require('../src/gateway/routes/engine')); app.use(require('../src/engine/callback').router);
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body, headers) => {
    const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...(headers || {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
    let json = null; let text = ''; try { text = await r.text(); json = JSON.parse(text); } catch { /* no body */ }
    return { status: r.status, json, text };
  };
  const code = (r) => r.json && r.json.error && r.json.error.code;
  const as = (t, u) => { TENANT = t; USER = u; };
  const rows = async (sql, p) => (await q(sql, p)).rows;
  const auditCount = async (t, action) => (await rows('SELECT COUNT(*)::int AS n FROM audit_events WHERE tenant_id = $1 AND action = $2', [t, action]))[0].n;
  const bearer = (t) => ({ authorization: 'Bearer ' + t });
  const cb = (token, method, p, body) => call(method, '/v1/engine/callback' + p, body, bearer(token));
  const startRun = async (extra) => {
    sent = [];
    const r = await call('POST', '/v1/engine/runs', { playbook: 'block-ip', webhook_url: HOOK, allowed_actions: ['list.add_entry', 'case.create', 'case.add_note'], input: { list_id: listA, value: '203.0.113.50' }, ...(extra || {}) });
    return { r, token: sent[0] && sent[0].body.token, hook: sent[0] };
  };

  try {
    as(A, alice);
    await call('PUT', '/v1/actions/list.add_entry/setting', { enabled: true, autonomy: 2 });
    await call('PUT', '/v1/actions/case.create/setting', { enabled: true, autonomy: 4 });

    // 1. starting a run: 201, the token goes to the engine only, and nothing secret is stored or shown
    let { r, token, hook } = await startRun();
    assert.strictEqual(r.status, 201, r.text);
    assert.ok(model.tokenShape(token), 'the engine received a run token');
    assert.strictEqual(hook.url, HOOK); assert.strictEqual(hook.body.callback_base, 'https://asix.example.test:30443/v1/engine/callback');
    assert.strictEqual(hook.body.tenant_id, A); assert.strictEqual(hook.body.run_id, r.json.run.id); assert.deepStrictEqual(hook.body.input, { list_id: listA, value: '203.0.113.50' });
    assert.ok(!('webhook_url' in hook.body), 'the webhook address is not handed on');
    assert.ok(!r.text.includes(token) && !r.text.includes('s3cr3t-hook-value') && !r.text.includes('token_hash'), 'neither the token nor the webhook address is in the answer');
    const run1 = r.json.run;
    assert.deepStrictEqual([run1.status, run1.playbook, run1.engine_host, run1.engine_ref, run1.call_count, run1.started_by_name], ['running', 'block-ip', 'engine.example.test', 'exec-1', 0, 'alice-' + stamp]);
    const stored = (await rows('SELECT * FROM engine_runs WHERE id = $1', [run1.id]))[0];
    assert.strictEqual(stored.token_hash, model.hashToken(token));
    assert.ok(!JSON.stringify(stored).includes(token) && !JSON.stringify(stored).includes('s3cr3t-hook-value'), 'the row holds a hash, no token and no webhook address');
    assert.strictEqual(await auditCount(A, 'soar:engine:start'), 1);
    assert.deepStrictEqual(asked.filter((a) => a[1] === '/v1/engine/runs' && a[0] === 'POST').map((a) => a[2]), ['soar:actions:write']);

    // 2. the workflow asks for a medium-risk action: the registry decides (waits for approval), records it as automation, and the engine is told in one word
    let c = await cb(token, 'POST', '/actions/list.add_entry', { parameters: { list_id: listA, value: '203.0.113.50', note: 'engine test' } });
    assert.deepStrictEqual([c.status, c.json.outcome, c.json.action_run.status, c.json.action_run.action], [200, 'awaiting_approval', 'awaiting_approval', 'list.add_entry']);
    assert.ok(!('params' in c.json.action_run) && !('undo' in c.json.action_run), 'the engine does not get the stored parameters or the undo');
    const ar = (await rows('SELECT * FROM action_runs WHERE id = $1', [c.json.action_run.id]))[0];
    assert.deepStrictEqual([ar.origin, ar.status, ar.requested_by_name, ar.tenant_id], ['automation', 'awaiting_approval', 'service account', A]);
    assert.strictEqual((await rows('SELECT COUNT(*)::int AS n FROM list_entries WHERE list_id = $1', [listA]))[0].n, 0, 'nothing was blocked before a person approved');
    const after = (await call('GET', '/v1/engine/runs/' + run1.id)).json.run;
    assert.strictEqual(after.call_count, 1); assert.strictEqual(after.calls[0].action_run_id, ar.id); assert.strictEqual(after.calls[0].action, 'list.add_entry');
    assert.strictEqual(await auditCount(A, 'soar:engine:callback'), 1);

    // 3. a person approves in ASIX; ASIX does the act itself; the engine can read how its own request ended
    let ap = await call('POST', `/v1/actions/runs/${ar.id}/approve`); assert.strictEqual(ap.status, 200, ap.text);
    assert.strictEqual((await rows('SELECT value FROM list_entries WHERE list_id = $1', [listA])).map((e) => e.value).join(), '203.0.113.50');
    c = await cb(token, 'GET', '/action-runs/' + ar.id); assert.deepStrictEqual([c.status, c.json.outcome, c.json.action_run.result.value], [200, 'executed', '203.0.113.50']);

    // 4. an action the registry runs by itself: executed at once; one the tenant never enabled: refused as an answer (HTTP 200), recorded
    c = await cb(token, 'POST', '/actions/case.create', { parameters: { title: 'From the engine' } });
    assert.deepStrictEqual([c.status, c.json.outcome], [200, 'executed']);
    assert.strictEqual((await rows(`SELECT COUNT(*)::int AS n FROM cases WHERE tenant_id = $1 AND title = 'From the engine'`, [A]))[0].n, 1);
    c = await cb(token, 'POST', '/actions/case.add_note', { parameters: { case_id: '00000000-0000-4000-8000-000000000000', body: 'x' } });
    assert.deepStrictEqual([c.status, c.json.outcome, c.json.action_run.error_code], [200, 'refused', 'ACTION_DISABLED']);
    assert.strictEqual((await rows(`SELECT status FROM action_runs WHERE id = $1`, [c.json.action_run.id]))[0].status, 'refused');

    // 5. what the run may not do: an action outside its list (403, nothing recorded), bad parameters (400, not counted), a body that names a tenant or an origin (400), another run's request (404)
    const before = (await rows('SELECT COUNT(*)::int AS n FROM action_runs WHERE tenant_id = $1', [A]))[0].n;
    c = await cb(token, 'POST', '/actions/list.remove_entry', { parameters: { list_id: listA, value: '203.0.113.50' } }); assert.deepStrictEqual([c.status, c.json.error.code], [403, 'ACTION_NOT_ALLOWED']);
    c = await cb(token, 'POST', '/actions/list.add_entry', { parameters: { list_id: 'nope', value: 'x' } }); assert.strictEqual(c.status, 400);
    c = await cb(token, 'POST', '/actions/list.add_entry', { parameters: {}, tenant_id: B }); assert.deepStrictEqual([c.status, c.json.error.code], [400, 'INVALID_BODY']);
    c = await cb(token, 'POST', '/actions/list.add_entry', { parameters: {}, origin: 'user' }); assert.deepStrictEqual([c.status, c.json.error.code], [400, 'INVALID_BODY']);
    c = await cb(token, 'POST', '/actions/Not-An-Id', {}); assert.strictEqual(c.status, 400);
    assert.strictEqual((await rows('SELECT COUNT(*)::int AS n FROM action_runs WHERE tenant_id = $1', [A]))[0].n, before, 'none of those was recorded as a run');
    assert.strictEqual((await call('GET', '/v1/engine/runs/' + run1.id)).json.run.call_count, 3, 'only the three recorded requests were counted');

    // 6. a token that is wrong, missing, of the wrong shape or another run's gets the same 401; a token of tenant B reaches nothing of tenant A
    const unknown = 'aet_' + 'A'.repeat(43);
    const same = [];
    for (const h of [bearer(unknown), bearer('garbage'), {}, { authorization: 'Basic abc' }]) { const x = await call('POST', '/v1/engine/callback/actions/case.create', { parameters: { title: 't' } }, h); same.push([x.status, x.text]); }
    assert.ok(same.every((s) => s[0] === 401 && s[1] === same[0][1]), 'every wrong credential gets the identical 401');
    as(B, eve);
    await call('PUT', '/v1/actions/list.add_entry/setting', { enabled: true, autonomy: 2 });
    const bRun = await startRun({ input: {} }); assert.strictEqual(bRun.r.status, 201); assert.strictEqual(bRun.hook.body.tenant_id, B);
    assert.strictEqual((await cb(bRun.token, 'GET', '/action-runs/' + ar.id)).status, 404, 'tenant B cannot read tenant A\'s action run');
    as(B, eve); assert.ok(!(await call('GET', '/v1/engine/runs')).json.runs.some((x) => x.id === run1.id), 'B does not see A\'s engine runs');
    assert.strictEqual((await call('GET', '/v1/engine/runs/' + run1.id)).status, 404);
    as(A, alice);

    // 7. the call limit
    const lim = await startRun({ max_calls: 2 }); assert.strictEqual(lim.r.status, 201);
    for (let i = 0; i < 2; i++) assert.strictEqual((await cb(lim.token, 'POST', '/actions/case.create', { parameters: { title: 'n' + i } })).status, 200);
    c = await cb(lim.token, 'POST', '/actions/case.create', { parameters: { title: 'n2' } }); assert.deepStrictEqual([c.status, c.json.error.code], [409, 'CALL_LIMIT']);

    // 8. finish: the status and summary are kept, the token is dead afterwards (also for a second finish), the audit row exists
    c = await cb(token, 'POST', '/finish', { status: 'maybe' }); assert.deepStrictEqual([c.status, c.json.error.code], [400, 'INVALID_STATUS']);
    c = await cb(token, 'POST', '/finish', { status: 'succeeded', summary: 'asked for a block, waiting for a person' }); assert.deepStrictEqual([c.status, c.json.status], [200, 'succeeded']);
    const done = (await call('GET', '/v1/engine/runs/' + run1.id)).json.run;
    assert.deepStrictEqual([done.status, done.summary, !!done.finished_at], ['succeeded', 'asked for a block, waiting for a person', true]);
    assert.strictEqual((await rows('SELECT token_hash FROM engine_runs WHERE id = $1', [run1.id]))[0].token_hash, null, 'the token was cleared');
    assert.strictEqual((await cb(token, 'POST', '/finish', { status: 'succeeded' })).status, 401);
    assert.strictEqual((await cb(token, 'POST', '/actions/case.create', { parameters: { title: 'late' } })).status, 401);
    assert.strictEqual(await auditCount(A, 'soar:engine:finish'), 1);

    // 9. time: a token past its time is refused and the run reads as expired
    const old = await startRun(); await q(`UPDATE engine_runs SET expires_at = localtimestamp - interval '1 second' WHERE id = $1`, [old.r.json.run.id]);
    assert.strictEqual((await cb(old.token, 'POST', '/actions/case.create', { parameters: { title: 'late' } })).status, 401);
    assert.strictEqual((await call('GET', '/v1/engine/runs/' + old.r.json.run.id)).json.run.status, 'expired');

    // 10. the engine did not take the call: 502, the run failed, its token is dead, and the answer does not repeat the webhook address
    hookAnswer = { ok: false, status: 500, engineRef: null, error: 'The engine answered HTTP 500' };
    const failed = await startRun(); hookAnswer = { ok: true, status: 200, engineRef: 'exec-1', error: null };
    assert.deepStrictEqual([failed.r.status, code(failed.r)], [502, 'ENGINE_START_FAILED']); assert.ok(!failed.r.text.includes('s3cr3t-hook-value'));
    const frow = (await rows('SELECT status, token_hash, error_message FROM engine_runs WHERE id = $1', [failed.r.json.error.run_id]))[0];
    assert.deepStrictEqual([frow.status, frow.token_hash, frow.error_message], ['failed', null, 'The engine answered HTTP 500']);
    assert.strictEqual((await cb(failed.token, 'POST', '/actions/case.create', { parameters: { title: 'x' } })).status, 401);

    // 11. a request that cannot start a run: nothing is sent and no run is made
    const runs0 = (await rows('SELECT COUNT(*)::int AS n FROM engine_runs WHERE tenant_id = $1', [A]))[0].n;
    const bad = async (body, st, cd) => { sent = []; const x = await call('POST', '/v1/engine/runs', { playbook: 'p', webhook_url: HOOK, allowed_actions: ['case.create'], ...body }); assert.deepStrictEqual([x.status, code(x)], [st, cd], JSON.stringify(body)); assert.strictEqual(sent.length, 0); };
    await bad({ tenant_id: B }, 400, 'INVALID_BODY');
    await bad({ allowed_actions: ['no.such_action'] }, 400, 'INVALID_ALLOWED_ACTIONS');
    await bad({ allowed_actions: [] }, 400, 'INVALID_ALLOWED_ACTIONS');
    await bad({ playbook: 'Bad Name' }, 400, 'INVALID_PLAYBOOK');
    await bad({ webhook_url: 'http://engine.example.test/hook' }, 400, 'INVALID_WEBHOOK_URL');
    await bad({ webhook_url: 'https://169.254.169.254/latest' }, 400, 'ENGINE_URL_BLOCKED');
    await bad({ webhook_url: 'https://127.0.0.1/hook' }, 400, 'ENGINE_URL_BLOCKED');
    await bad({ webhook_url: 'https://10.1.2.3/hook' }, 400, 'ENGINE_URL_BLOCKED');
    await bad({ ttl_seconds: 5 }, 400, 'INVALID_TTL_SECONDS');
    await bad({ input: [1] }, 400, 'INVALID_INPUT');
    assert.strictEqual((await rows('SELECT COUNT(*)::int AS n FROM engine_runs WHERE tenant_id = $1', [A]))[0].n, runs0);
    const saved = process.env.ASIX_ENGINE_CALLBACK_BASE; delete process.env.ASIX_ENGINE_CALLBACK_BASE; delete process.env.ASIX_PUBLIC_URL;
    await bad({}, 503, 'ENGINE_NOT_CONFIGURED'); process.env.ASIX_ENGINE_CALLBACK_BASE = saved;

    // 12. reading: newest first, paged, read permission
    r = await call('GET', '/v1/engine/runs?limit=2'); assert.deepStrictEqual([r.status, r.json.runs.length, r.json.total > 2], [200, 2, true]);
    assert.strictEqual((await call('GET', '/v1/engine/runs?limit=0')).status, 400);
    assert.ok(asked.some((a) => a[0] === 'GET' && a[1] === '/v1/engine/runs' && a[2] === 'soar:actions:read'));
    assert.ok(!(await call('GET', '/v1/engine/runs')).text.includes('token_hash'));

    // 13. a token is limited a minute (30 here): the 31st call with the same token is 429, and it never reached the database
    const hammer = 'aet_' + 'B'.repeat(43); let last = 0;
    for (let i = 0; i < 31; i++) last = (await call('POST', '/v1/engine/callback/finish', { status: 'failed' }, bearer(hammer))).status;
    assert.strictEqual(last, 429);
    console.log('engine-db: all checks passed');
  } finally {
    srv.close();
    await db.close();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
