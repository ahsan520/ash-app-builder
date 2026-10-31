'use strict';
// E4o: the limit of the "Endpoint configuration check score low" rule chosen from the Endpoints page (src/endpoints/score-alert.js, src/gateway/routes/score-alert.js).
// The rules, the agreement with the shipped rule, and the two routes with the sign-in chain and the database replaced by a recorder. No real database (see score-alert-db.test.js).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const express = require('express');
const sa = require('../src/endpoints/score-alert');
const { BUILTIN_RULES } = require('../src/detection/rule-runner');

describe('checkLimit', () => {
  it('accepts 1 to 100, as a number or digits', () => {
    for (const v of [1, '1', 50, ' 50 ', 99, 100, '100']) assert.strictEqual(sa.checkLimit(v).value, Number(v), String(v));
  });
  it('refuses 0 (that is off), 101, negatives, fractions, text and everything that is not a whole number', () => {
    for (const v of [0, '0', 101, '101', -1, 50.5, '50.5', '', ' ', null, undefined, 'abc', '050', '1e2', [50], {}, true, '٥٠', '5 0', 'NaN', Infinity]) assert.ok(sa.checkLimit(v).error, JSON.stringify(v));
    assert.match(sa.checkLimit('x').error, /^Limit must be a whole number from 1 to 100/);
  });
});

describe('parseBody', () => {
  it('knows exactly two shapes', () => {
    assert.deepStrictEqual(sa.parseBody({ limit: 30 }), { limit: 30 });
    assert.deepStrictEqual(sa.parseBody({ limit: '75' }), { limit: 75 });
    assert.deepStrictEqual(sa.parseBody({ off: true }), { off: true });
  });
  it('refuses mixes, extra keys, wrong types and everything else', () => {
    for (const b of [null, undefined, [], 'x', 5, {}, { off: false }, { off: 'true' }, { off: 1 }, { limit: 30, off: true }, { limit: 30, extra: 1 }, { off: true, extra: 1 }, { limit: 0 }, { limit: 101 }, { limit: '' }, { limit: null },
      { limit: "30'; DROP TABLE detection_rules; --" }, { minutes: 30 }, { limit: [30] }]) assert.ok(sa.parseBody(b).error, JSON.stringify(b));
  });
});

describe('the limit is the number in the rule\'s own query', () => {
  it('queryFor and limitFromQuery are each other\'s inverse over every allowed limit', () => {
    for (let n = 1; n <= 100; n++) assert.strictEqual(sa.limitFromQuery(sa.queryFor(n)), n);
  });
  it('anything but the exact shape reads as null (edited by hand), never a guess', () => {
    for (const x of ['sca_score != null and sca_score < 50 and agent_name = "web1"', 'sca_score < 50', 'sca_score != null and sca_score <= 50', 'sca_score != null and sca_score < 050', 'sca_score != null and sca_score < 1000',
      'sca_score != null and sca_score < 5.5', ' sca_score != null and sca_score < 50', 'sca_score != null and sca_score < 50 ', 'SCA_SCORE != null and sca_score < 50', 'alert_level >= 12', '', null, undefined, 50, {}]) assert.strictEqual(sa.limitFromQuery(x), null, JSON.stringify(x));
    assert.strictEqual(sa.limitFromQuery('sca_score != null and sca_score < 0'), 0, 'zero reads as 0 (a hand-made limit), which is never written from here');
  });
  it('the SQL pattern the write is guarded with accepts exactly what the JavaScript pattern accepts (for the numbers this page writes)', () => {
    const re = new RegExp(sa.XQL_SQL_RE);
    for (let n = 1; n <= 100; n++) assert.ok(re.test(sa.queryFor(n)), String(n));
    for (const x of ['sca_score != null and sca_score < 50 and x = 1', 'sca_score != null and sca_score < ', 'sca_score != null and sca_score < 1234', 'sca_score != null and sca_score < 5\n']) assert.ok(!re.test(x), JSON.stringify(x));
  });
});

describe('the shipped rule agrees with this module', () => {
  const rule = BUILTIN_RULES.find((r) => r.key === sa.RULE_KEY);
  it('is the same rule key, shipped at 50 with the E4o description', () => {
    assert.ok(rule); assert.strictEqual(rule.definition.xql, 'sca_score != null and sca_score < 50'); assert.strictEqual(sa.limitFromQuery(rule.definition.xql), sa.DEFAULT_LIMIT);
    assert.strictEqual(rule.description, sa.DESCRIPTION);
  });
  it('the description does not name a number that the limit can make false, and the E4n text it replaces did', () => {
    assert.ok(!/\b(1|50|100)%/.test(sa.DESCRIPTION.replace('50% as shipped', '')), 'only the "50% as shipped" remark names a number');
    assert.match(sa.E4N_DESCRIPTION, /under 50%/); assert.notStrictEqual(sa.E4N_DESCRIPTION, sa.DESCRIPTION);
  });
});

describe('view', () => {
  const row = { id: 'r1', enabled: true, severity: 'medium', xql: sa.queryFor(50), updated_at: new Date('2026-10-31T10:00:00Z') };
  it('no rule yet: not available', () => {
    const v = sa.view(null); assert.deepStrictEqual([v.available, v.enabled, v.limit, v.edited, v.rule_id], [false, false, null, false, null]); assert.deepStrictEqual(v.limits, [1, 100]); assert.strictEqual(v.default_limit, 50);
  });
  it('a rule at the shipped query: on, limit 50, not edited', () => {
    const v = sa.view(row); assert.deepStrictEqual([v.available, v.enabled, v.limit, v.edited, v.severity, v.rule_id, v.updated_at], [true, true, 50, false, 'medium', 'r1', '2026-10-31T10:00:00.000Z']);
  });
  it('switched off keeps its limit; an edited query has no limit and says so', () => {
    const o = sa.view({ ...row, enabled: false, xql: sa.queryFor(30) }); assert.deepStrictEqual([o.enabled, o.limit, o.edited], [false, 30, false]);
    const e = sa.view({ ...row, xql: 'sca_score != null and sca_score < 50 and agent_name = "x"' }); assert.deepStrictEqual([e.enabled, e.limit, e.edited], [true, null, true]);
  });
});

describe('routes', () => {
  const TENANT = '11111111-1111-4111-8111-111111111111';
  let rule; let writes; let mode;   // rule: the tenant's rule row or null; mode: 'ok' | 'broken'
  const fakeDb = { withTenant: async (t, fn) => fn({ query: async (sql, args) => {
    if (mode === 'broken') throw new Error('connection reset');
    if (/^\s*SELECT .* FROM detection_rules/.test(sql)) { assert.deepStrictEqual(args, [TENANT, 'endpoint-config-score-low']); return { rows: rule ? [{ id: rule.id, enabled: rule.enabled, severity: rule.severity, xql: rule.xql, updated_at: rule.updated_at }] : [] }; }
    if (/^\s*UPDATE detection_rules\s+SET definition/.test(sql)) {   // writeLimit: only while the stored query has the shape
      writes.push({ op: 'limit', args });
      if (rule && new RegExp(args[3]).test(rule.xql)) { rule.xql = args[2]; rule.enabled = true; rule.updated_at = new Date('2026-10-31T11:00:00Z'); return { rowCount: 1, rows: [] }; }
      return { rowCount: 0, rows: [] };
    }
    if (/^\s*UPDATE detection_rules SET enabled = false/.test(sql)) { writes.push({ op: 'off', args }); if (rule) { rule.enabled = false; return { rowCount: 1, rows: [] }; } return { rowCount: 0, rows: [] }; }
    throw new Error('unexpected SQL ' + sql);
  } }) };
  const shared = require('../src/gateway/shared');
  const savedShared = require.cache[require.resolve('../src/gateway/shared')].exports;
  const perms = [];
  let srv; let base;
  before(() => {
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: fakeDb, guarded: (p) => { perms.push(p); return [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'u1'; next(); }]; } };
    delete require.cache[require.resolve('../src/gateway/routes/score-alert')];
    const app = express(); app.use(express.json());
    app.use(require('../src/gateway/routes/score-alert'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = savedShared; });
  const call = async (method, p, body, raw) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: raw !== undefined ? raw : body === undefined ? undefined : JSON.stringify(body) }); const t = await r.text(); let json = null; try { json = JSON.parse(t); } catch (e) { /* Express's own page for malformed JSON */ } return { status: r.status, json }; };
  const reset = (xql = sa.queryFor(50), enabled = true, m = 'ok') => { rule = { id: 'rule-1', enabled, severity: 'medium', xql, updated_at: new Date('2026-10-31T10:00:00Z') }; writes = []; mode = m; };
  const U = '/v1/endpoints/score-alert';

  it('uses the Detections permissions: detections:rules:read to read, detections:rules:write to change (no role change)', () => {
    assert.deepStrictEqual([...new Set(perms)].sort(), ['detections:rules:read', 'detections:rules:write']);
    const r = fs.readFileSync(path.join(__dirname, '..', 'src', 'gateway', 'routes', 'score-alert.js'), 'utf8');
    assert.match(r, /router\.get\('\/v1\/endpoints\/score-alert', \.\.\.guarded\('detections:rules:read'\)/); assert.match(r, /router\.put\('\/v1\/endpoints\/score-alert', \.\.\.guarded\('detections:rules:write'\)/);
  });
  it('is mounted in the gateway before the readiness check', () => {
    const g = fs.readFileSync(path.join(__dirname, '..', 'src', 'gateway', 'index.js'), 'utf8');
    assert.ok(g.includes("app.use(require('./routes/score-alert'));")); assert.ok(g.indexOf("routes/score-alert'") < g.indexOf("app.get('/v1/health/ready'"));
  });
  it('GET: the rule as shipped is on at 50', async () => {
    reset(); const r = await call('GET', U); assert.strictEqual(r.status, 200);
    assert.deepStrictEqual([r.json.settings.available, r.json.settings.enabled, r.json.settings.limit, r.json.settings.edited], [true, true, 50, false]);
  });
  it('GET: no rule yet is available:false (200), not an error', async () => {
    reset(); rule = null; const r = await call('GET', U); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.settings.available, false);
  });
  it('PUT { limit } writes the new query, switches the rule on and answers with the new settings', async () => {
    reset(sa.queryFor(50), false); const r = await call('PUT', U, { limit: 30 });
    assert.strictEqual(r.status, 200); assert.deepStrictEqual([r.json.settings.limit, r.json.settings.enabled], [30, true]);
    assert.strictEqual(rule.xql, 'sca_score != null and sca_score < 30'); assert.strictEqual(writes.length, 1); assert.deepStrictEqual(writes[0].args.slice(0, 3), [TENANT, 'endpoint-config-score-low', 'sca_score != null and sca_score < 30']);
  });
  it('PUT { limit } as digits and with spaces is accepted; the stored query holds the whole number only', async () => {
    reset(); const r = await call('PUT', U, { limit: ' 75 ' }); assert.strictEqual(r.status, 200); assert.strictEqual(rule.xql, 'sca_score != null and sca_score < 75');
  });
  it('PUT { off: true } switches the rule off and keeps its limit; a later { limit } switches it on again', async () => {
    reset(sa.queryFor(40)); let r = await call('PUT', U, { off: true });
    assert.deepStrictEqual([r.status, r.json.settings.enabled, r.json.settings.limit], [200, false, 40]); assert.strictEqual(rule.xql, 'sca_score != null and sca_score < 40');
    r = await call('PUT', U, { limit: 40 }); assert.deepStrictEqual([r.status, r.json.settings.enabled], [200, true]);
  });
  it('a hand-edited query: a new limit is refused with 409 and nothing is changed; turning it off still works', async () => {
    const edited = 'sca_score != null and sca_score < 50 and agent_name = "web1"';
    reset(edited); let r = await call('PUT', U, { limit: 30 });
    assert.strictEqual(r.status, 409); assert.strictEqual(r.json.error.code, 'SCORE_ALERT_EDITED'); assert.strictEqual(rule.xql, edited); assert.strictEqual(rule.enabled, true);
    assert.match(r.json.error.message, /Reset/);
    r = await call('PUT', U, { off: true }); assert.strictEqual(r.status, 200); assert.strictEqual(rule.enabled, false); assert.strictEqual(rule.xql, edited); assert.strictEqual(r.json.settings.edited, true);
    const g = await call('GET', U); assert.deepStrictEqual([g.json.settings.limit, g.json.settings.edited], [null, true]);
  });
  it('no rule yet: PUT is 503 SCORE_ALERT_NOT_READY for both shapes', async () => {
    for (const b of [{ limit: 30 }, { off: true }]) { reset(); rule = null; const r = await call('PUT', U, b); assert.strictEqual(r.status, 503); assert.strictEqual(r.json.error.code, 'SCORE_ALERT_NOT_READY'); }
  });
  it('every bad body is a 400 INVALID_SCORE_ALERT and nothing is written (not even a read)', async () => {
    reset();
    for (const b of [{}, { limit: 0 }, { limit: 101 }, { limit: 'x' }, { off: false }, { limit: 30, off: true }, { limit: 30, x: 1 }, [], { limit: "1'; DROP TABLE alerts; --" }]) {
      const r = await call('PUT', U, b); assert.strictEqual(r.status, 400, JSON.stringify(b)); assert.strictEqual(r.json.error.code, 'INVALID_SCORE_ALERT');
    }
    assert.strictEqual((await call('PUT', U, undefined, '{not json')).status, 400); assert.strictEqual(writes.length, 0); assert.strictEqual(rule.xql, sa.queryFor(50));
  });
  it('a database failure is a 500 with no detail leaked', async () => {
    reset(sa.queryFor(50), true, 'broken');
    for (const [m, b] of [['GET'], ['PUT', { limit: 30 }], ['PUT', { off: true }]]) { const r = await call(m, U, b); assert.strictEqual(r.status, 500); assert.strictEqual(r.json.error.code, 'SCORE_ALERT_ERROR'); assert.ok(!/connection reset/.test(JSON.stringify(r.json))); }
  });
});

describe('wiring', () => {
  it('the rule runner builds the shipped rule from this module (one place for the number), and the CI list runs the database test', () => {
    const rr = fs.readFileSync(path.join(__dirname, '..', 'src', 'detection', 'rule-runner.js'), 'utf8');
    assert.ok(rr.includes('scoreAlert.queryFor(scoreAlert.DEFAULT_LIMIT)') && rr.includes('scoreAlert.DESCRIPTION'));
    const ci = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'ci.yml'), 'utf8');
    assert.match(ci, /\bscore-alert-db\b/);
  });
});
