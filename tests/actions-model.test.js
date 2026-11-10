'use strict';
// SR2: the rules in src/actions/model.js and the invariants of the built-in catalog, which need no database. (The SQL, the routes, approval, undo and
// the audit rows are tested against a real PostgreSQL in tests/actions-db.test.js.)
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const m = require('../src/actions/model');
const catalog = require('../src/actions/catalog');
const registry = require('../src/modules/registry');

const U1 = '11111111-1111-4111-8111-111111111111';
const U2 = '22222222-2222-4222-8222-222222222222';
const ok = (r) => { assert.ok(!r.error, r.error && r.error.message); return r.value; };
const err = (r, re, code) => { assert.ok(r.error, 'expected an error'); if (code) assert.strictEqual(r.error.code, code); assert.match(r.error.message, re); };
const noop = async () => ({ ok: true, result: {}, undo: null });
const def = (over = {}) => ({
  id: 'test.thing', name: 'Thing', description: 'd', publisher: 'ASIX', kind: 'builtin', source: 's', risk: 'low', reversible: true, max_autonomy: 4, default_autonomy: 2,
  parameters: [{ name: 'case_id', type: 'uuid', required: true, description: 'x' }], execute: noop, ...over,
});

describe('the allowed values match the database', () => {
  const yaml = fs.readFileSync(path.join(__dirname, '../k8s/12-schema-init.yaml'), 'utf8');
  const list = (name) => [...yaml.match(new RegExp(`CONSTRAINT ${name} CHECK \\(\\w+ IN \\(([^)]*)\\)\\)`))[1].matchAll(/'([a-z_]+)'/g)].map((x) => x[1]);
  it('run statuses', () => assert.deepStrictEqual([...m.STATUSES].sort(), list('action_runs_status_chk').sort()));
  it('run origins', () => assert.deepStrictEqual([...m.ORIGINS].sort(), list('action_runs_origin_chk').sort()));
  it('risk classes', () => assert.deepStrictEqual([...m.RISKS].sort(), list('action_runs_risk_chk').sort()));
  it('autonomy levels are 0 to 4 in both tables', () => {
    assert.deepStrictEqual(m.LEVELS, [0, 1, 2, 3, 4]);
    assert.match(yaml, /action_settings_level_chk CHECK \(autonomy_level BETWEEN 0 AND 4\)/);
    assert.match(yaml, /action_runs_level_chk CHECK \(autonomy_level BETWEEN 0 AND 4\)/);
  });
  it('every status has an audit word, and every level a label', () => {
    for (const s of m.STATUSES) assert.ok(m.AUDIT_RESULT[s], s);
    for (const l of m.LEVELS) assert.ok(m.LEVEL_LABEL[l], String(l));
  });
  it('both tables are tenant-isolated with row-level security', () => {
    for (const t of ['action_settings', 'action_runs']) {
      assert.match(yaml, new RegExp(`ALTER TABLE ${t} ENABLE ROW LEVEL SECURITY`));
      assert.match(yaml, new RegExp(`CREATE POLICY ${t}_tenant_isolation ON ${t}`));
    }
  });
  it('an action with no setting row is disabled: the setting column defaults to false', () => assert.match(yaml, /enabled BOOLEAN NOT NULL DEFAULT FALSE/));
});

describe('checkDefinition', () => {
  const problems = (over) => m.checkDefinition(def(over)).join(' | ');
  it('a good definition has no problems', () => assert.deepStrictEqual(m.checkDefinition(def()), []));
  it('not an object', () => assert.match(m.checkDefinition(null)[0], /must be an object/));
  it('ids are lowercase words joined by dots', () => { for (const id of ['Case.add', 'case', 'case-add', 'case..add', '1case.add', undefined]) assert.match(problems({ id }), /id must be/, String(id)); });
  it('every text field is required', () => { for (const f of ['name', 'description', 'publisher', 'source']) assert.match(problems({ [f]: ' ' }), new RegExp(f + ' is required')); });
  it('kind, risk and levels are checked', () => {
    assert.match(problems({ kind: 'magic' }), /kind must be/);
    assert.match(problems({ risk: 'huge' }), /risk must be/);
    assert.match(problems({ max_autonomy: 5 }), /max_autonomy must be 0 to 4/);
    assert.match(problems({ default_autonomy: -1 }), /default_autonomy must be 0 to 4/);
    assert.match(problems({ reversible: 'yes' }), /reversible must be true or false/);
    assert.match(problems({ execute: null }), /execute must be a function/);
  });
  it('a high-risk action never reaches level 3 and a medium one never level 4', () => {
    assert.match(problems({ risk: 'high', max_autonomy: 3 }), /high-risk action cannot have max_autonomy above 2/);
    assert.match(problems({ risk: 'medium', max_autonomy: 4 }), /medium-risk action cannot have max_autonomy above 3/);
    assert.deepStrictEqual(m.checkDefinition(def({ risk: 'high', max_autonomy: 2 })), []);
  });
  it('what cannot be undone and is not append-only cannot run by itself', () => {
    assert.match(problems({ reversible: false, risk: 'medium', max_autonomy: 3 }), /neither reversible nor append-only/);
    assert.match(problems({ reversible: false, risk: 'low' }), /low-risk action must be reversible or append-only/);
    assert.deepStrictEqual(m.checkDefinition(def({ reversible: false, append_only: true })), []);
    assert.deepStrictEqual(m.checkDefinition(def({ reversible: false, risk: 'medium', max_autonomy: 2 })), []);
  });
  it('the default level cannot pass the highest level', () => assert.match(problems({ max_autonomy: 2, default_autonomy: 3 }), /default_autonomy cannot be above max_autonomy/));
  it('undo is not a field of a definition', () => assert.match(problems({ undo: noop }), /execute returns the undo/));
  it('parameters are checked', () => {
    assert.match(problems({ parameters: 'x' }), /parameters must be a list/);
    assert.match(problems({ parameters: [{ name: 'Bad', type: 'uuid', description: 'x' }] }), /needs a name/);
    assert.match(problems({ parameters: [{ name: 'a', type: 'uuid', description: 'x' }, { name: 'a', type: 'uuid', description: 'x' }] }), /listed twice/);
    assert.match(problems({ parameters: [{ name: 'a', type: 'blob', description: 'x' }] }), /type must be/);
    assert.match(problems({ parameters: [{ name: 'a', type: 'enum', description: 'x' }] }), /enum needs values/);
    assert.match(problems({ parameters: [{ name: 'a', type: 'uuid' }] }), /description is required/);
  });
});

describe('validateParams', () => {
  const d = def({ parameters: [
    { name: 'case_id', type: 'uuid', required: true, description: 'x' },
    { name: 'note', type: 'string', max: 10, description: 'x' },
    { name: 'sev', type: 'enum', values: ['low', 'high'], description: 'x' },
    { name: 'ids', type: 'uuid_list', max: 3, description: 'x' },
    { name: 'owner', type: 'uuid', nullable: true, description: 'x' },
  ] });
  it('accepts a good set and keeps only the listed names, trimmed and lower-cased', () => {
    const v = ok(m.validateParams(d, { case_id: U1.toUpperCase(), note: '  hi  ', sev: 'low', ids: [U1, U2.toUpperCase(), U1], owner: null }));
    assert.deepStrictEqual(v, { case_id: U1, note: 'hi', sev: 'low', ids: [U1, U2], owner: null });
  });
  it('a missing required parameter', () => err(m.validateParams(d, {}), /case_id is required/, 'INVALID_PARAMETERS'));
  it('a parameter that was not listed is refused, not ignored', () => err(m.validateParams(d, { case_id: U1, origin: 'automation' }), /unknown parameter: origin/, 'INVALID_PARAMETERS'));
  it('parameters that are not an object', () => { for (const bad of ['x', [], 5, null]) err(m.validateParams(d, bad), /JSON object/, 'INVALID_PARAMETERS'); });
  it('no parameters at all is an empty object', () => err(m.validateParams(d, undefined), /case_id is required/));
  it('each type refuses what does not fit', () => {
    for (const [name, value, re] of [['case_id', 'nope', /must be an id/], ['case_id', null, /cannot be null/], ['case_id', 5, /must be an id/], ['note', '', /1 to 10/], ['note', 'x'.repeat(11), /1 to 10/], ['note', 5, /1 to 10/],
      ['sev', 'medium', /one of low, high/], ['ids', [], /1 to 3 ids/], ['ids', [U1, U2, '33333333-3333-4333-8333-333333333333', '44444444-4444-4444-8444-444444444444'], /1 to 3 ids/], ['ids', ['nope'], /1 to 3 ids/], ['ids', U1, /1 to 3 ids/]]) {
      err(m.validateParams(d, { case_id: U1, [name]: value, ...(name === 'case_id' ? { case_id: value } : {}) }), re, 'INVALID_PARAMETER');
    }
  });
  it('a string is never longer than the global limit, whatever the definition says', () => {
    const big = def({ parameters: [{ name: 's', type: 'string', max: 999999, description: 'x' }] });
    err(m.validateParams(big, { s: 'x'.repeat(m.LIMITS.stringMax + 1) }), /1 to 5000/);
  });
});

describe('parseSetting', () => {
  const d = def({ max_autonomy: 3, default_autonomy: 2 });
  it('enabling uses the default level for an action never set', () => assert.deepStrictEqual(ok(m.parseSetting(d, { enabled: true }, null)), { enabled: true, autonomy: 2 }));
  it('a level alone keeps the enabled state; none stored means off', () => {
    assert.deepStrictEqual(ok(m.parseSetting(d, { autonomy: 3 }, null)), { enabled: false, autonomy: 3 });
    assert.deepStrictEqual(ok(m.parseSetting(d, { autonomy: 1 }, { enabled: true, autonomy_level: 3 })), { enabled: true, autonomy: 1 });
  });
  it('disabling keeps the level', () => assert.deepStrictEqual(ok(m.parseSetting(d, { enabled: false }, { enabled: true, autonomy_level: 3 })), { enabled: false, autonomy: 3 }));
  it('the level may not pass the ceiling of the action', () => err(m.parseSetting(d, { autonomy: 4 }, null), /cannot be given a level above 3/, 'AUTONOMY_TOO_HIGH'));
  it('the message says why a high-risk or irreversible action is capped', () => {
    err(m.parseSetting(def({ risk: 'high', max_autonomy: 2 }), { autonomy: 3 }, null), /high-risk/, 'AUTONOMY_TOO_HIGH');
    err(m.parseSetting(def({ reversible: false, risk: 'medium', max_autonomy: 2 }), { autonomy: 3 }, null), /cannot be undone/, 'AUTONOMY_TOO_HIGH');
  });
  it('refuses bad bodies', () => {
    err(m.parseSetting(d, 'x', null), /JSON object/);
    err(m.parseSetting(d, {}, null), /send enabled, autonomy or both/);
    err(m.parseSetting(d, { enabled: 'yes' }, null), /true or false/);
    for (const a of [1.5, -1, 5, '2', null]) err(m.parseSetting(d, { autonomy: a }, null), /whole number from 0 to 4/);
    err(m.parseSetting(d, { enabled: true, role: 'admin' }, null), /unknown field: role/);
  });
  it('a stored level above a ceiling lowered later is brought down', () => assert.strictEqual(ok(m.parseSetting(def({ max_autonomy: 2 }), { enabled: true }, { enabled: false, autonomy_level: 4 })).autonomy, 2));
});

describe('decide: the whole table', () => {
  const on = (level) => ({ enabled: true, autonomy_level: level });
  const low = def({ risk: 'low' }); const med = def({ risk: 'medium', max_autonomy: 3 }); const high = def({ risk: 'high', max_autonomy: 2 });
  const out = (d, s, o) => m.decide(d, s, o).outcome;

  it('never enabled, or switched off: refused for everybody, at every level', () => {
    for (const origin of ['user', 'automation']) {
      assert.deepStrictEqual([out(low, null, origin), m.decide(low, null, origin).code], ['refuse', 'ACTION_DISABLED']);
      for (let l = 0; l <= 4; l++) assert.strictEqual(m.decide(low, { enabled: false, autonomy_level: l }, origin).code, 'ACTION_DISABLED');
    }
  });
  it('level 0 refuses and level 1 only recommends, whoever asks', () => {
    for (const origin of ['user', 'automation']) {
      assert.deepStrictEqual([out(low, on(0), origin), m.decide(low, on(0), origin).code], ['refuse', 'OBSERVE_ONLY']);
      assert.strictEqual(out(low, on(1), origin), 'recommend');
    }
  });
  it('a person pressing Run is the approval: it runs from level 2 up', () => { for (const l of [2, 3, 4]) for (const d of [low, med, high]) assert.strictEqual(out(d, on(Math.min(l, d.max_autonomy)), 'user'), 'execute'); });
  it('automation at level 2 waits for a person, whatever the risk', () => { for (const d of [low, med, high]) assert.strictEqual(out(d, on(2), 'automation'), 'approval'); });
  it('automation at level 3 runs only low-risk actions by itself', () => {
    assert.strictEqual(out(low, on(3), 'automation'), 'execute');
    assert.strictEqual(out(med, on(3), 'automation'), 'approval');
    assert.match(m.decide(med, on(3), 'automation').reason, /medium-risk/);
  });
  it('automation at level 4 runs the approved class by itself', () => assert.strictEqual(out(low, on(4), 'automation'), 'execute'));
  it('a high-risk action never runs by itself, even if a level above its ceiling was stored', () => {
    assert.strictEqual(out(high, on(4), 'automation'), 'approval');
    assert.strictEqual(m.decide(high, on(4), 'automation').level, 2);
  });
  it('a ceiling lowered after the setting was saved still wins', () => assert.strictEqual(out(def({ max_autonomy: 1 }), on(4), 'automation'), 'recommend'));
});

describe('approvalRefusal', () => {
  it('a high-risk run is not approved by the person who asked', () => {
    assert.strictEqual(m.approvalRefusal(def({ risk: 'high', max_autonomy: 2 }), { requested_by_id: U1 }, U1).code, 'SELF_APPROVAL');
    assert.strictEqual(m.approvalRefusal(def({ risk: 'high', max_autonomy: 2 }), { requested_by_id: U1 }, U2), null);
  });
  it('lower risks may be approved by the requester, and automation (no requester) by anybody', () => {
    assert.strictEqual(m.approvalRefusal(def({ risk: 'medium', max_autonomy: 3 }), { requested_by_id: U1 }, U1), null);
    assert.strictEqual(m.approvalRefusal(def({ risk: 'high', max_autonomy: 2 }), { requested_by_id: null }, U1), null);
  });
});

describe('parseRunsQuery and parseRunBody', () => {
  it('defaults, then each filter', () => {
    assert.deepStrictEqual(ok(m.parseRunsQuery({})), { status: null, action: null, limit: 50, offset: 0 });
    assert.deepStrictEqual(ok(m.parseRunsQuery({ status: 'failed', action: 'case.add_note', limit: '10', offset: '5' })), { status: 'failed', action: 'case.add_note', limit: 10, offset: 5 });
  });
  it('bad queries', () => {
    err(m.parseRunsQuery({ status: 'weird' }), /status must be one of/, 'INVALID_STATUS');
    err(m.parseRunsQuery({ action: "x'; DROP" }), /action id/, 'INVALID_ACTION');
    err(m.parseRunsQuery({ limit: '0' }), /1 to 200/, 'INVALID_PAGE');
    err(m.parseRunsQuery({ limit: '201' }), /1 to 200/, 'INVALID_PAGE');
    err(m.parseRunsQuery({ offset: '-1' }), /offset/, 'INVALID_PAGE');
  });
  it('a run body takes parameters and nothing else: the origin is never a caller\'s to choose', () => {
    assert.deepStrictEqual(ok(m.parseRunBody(undefined)), { parameters: {} });
    assert.deepStrictEqual(ok(m.parseRunBody({ parameters: { a: 1 } })), { parameters: { a: 1 } });
    err(m.parseRunBody({ parameters: {}, origin: 'automation' }), /unknown field: origin/);
    err(m.parseRunBody({ approved: true }), /unknown field: approved/);
    err(m.parseRunBody([]), /JSON object/);
  });
});

describe('the built-in catalog', () => {
  const all = catalog.list();
  it('every built-in passes the definition check, and ids are unique', () => {
    for (const d of all) assert.deepStrictEqual(m.checkDefinition(d), [], d.id);
    assert.strictEqual(new Set(all.map((d) => d.id)).size, all.length);
  });
  it('lists the case actions', () => assert.deepStrictEqual(all.map((d) => d.id), ['case.add_alerts', 'case.add_note', 'case.create', 'case.remove_alerts', 'case.set_owner', 'case.set_severity', 'case.set_status']));
  it('nothing is enabled by the catalog itself: a definition has no "enabled" field', () => { for (const d of all) assert.ok(!('enabled' in d), d.id); });
  it('closing cases is medium-risk and cannot run by itself at level 4', () => { const d = catalog.get('case.set_status'); assert.deepStrictEqual([d.risk, d.max_autonomy], ['medium', 3]); });
  it('the public view has no functions', () => { for (const d of all) assert.ok(Object.values(catalog.publicView(d)).every((v) => typeof v !== 'function'), d.id); });
  it('register refuses a bad or repeated definition, and a registered one is frozen', () => {
    assert.throws(() => catalog.register(def({ id: 'Bad' })), /action Bad: id must be/);
    assert.throws(() => catalog.register(def({ id: 'case.add_note' })), /already registered/);
    const id = catalog.register(def({ id: 'unit.frozen' }));
    assert.ok(Object.isFrozen(catalog.get(id)));
    assert.throws(() => { 'use strict'; catalog.get(id).risk = 'high'; }, TypeError);
  });
});

describe('the module', () => {
  const list = registry.loadDir();
  const mod = list.find((x) => x.id === 'actions');
  it('is loaded, available, needs cases and brings its page', () => {
    assert.ok(mod);
    assert.deepStrictEqual([mod.status, mod.tier, mod.requires], ['available', 'home', ['cases']]);
    assert.strictEqual(mod.ui.entries[0].page, 'actions.js');
    assert.ok(fs.existsSync(path.join(__dirname, '../src/portal/modules/actions/actions.js')));
  });
  it('its menu entry needs one of its own permissions', () => assert.ok(mod.permissions.includes(mod.ui.entries[0].permission)));
  it('the two permissions are given to the portal-admin role in both places the bootstrap writes it', () => {
    const sh = fs.readFileSync(path.join(__dirname, '../scripts/deploy/bootstrap-portal.sh'), 'utf8');
    for (const p of mod.permissions) assert.strictEqual(sh.split(`'${p}'`).length - 1, 2, p);
  });
  it('every route asks for one of the two permissions', () => {
    const src = fs.readFileSync(path.join(__dirname, '../src/gateway/routes/actions.js'), 'utf8');
    const asked = [...src.matchAll(/guarded\('([^']+)'\)/g)].map((x) => x[1]);
    assert.ok(asked.length >= 9);
    for (const p of asked) assert.ok(mod.permissions.includes(p), p);
  });
});
