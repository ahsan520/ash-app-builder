'use strict';
// BIOC conditions: validation, SQL building (parameters only) and the default XDM rules.
const assert = require('assert');
const { normalizeDefinition, buildMatch } = require('../src/detection/rule-query');
const { compileCondition } = require('../src/search/xql');
const { BUILTIN_RULES } = require('../src/detection/rule-runner');

// valid condition: constants resolve, everything user-typed is a bound parameter
const ok = normalizeDefinition({ xql: 'xdm.event.outcome = XDM_CONST.OUTCOME_FAILED and xdm.source.port > 1024', group_by: 'field:xdm.source.ipv4' });
assert.ok(ok.def && ok.def.xql);
const q = buildMatch('tenant-1', ok.def);
assert.ok(!/FAILED|1024|tenant-1/.test(q.text), 'values must not be inlined into SQL');
assert.ok(q.values.includes('FAILED') && q.values.includes(1024));

// "dataset = x | filter ..." form and bare form both work; other stages and bad input are rejected
assert.ok(normalizeDefinition({ xql: 'dataset = syslog | filter xdm.event.type = "authentication"' }).def);
for (const bad of ['xdm.x = ', 'comp count()', 'filter xdm.x = XDM_CONST.NOPE', 'dataset = a | fields b', 'x = "1"; DROP TABLE events']) {
  assert.ok(normalizeDefinition({ xql: bad }).error, 'should reject: ' + bad);
}
assert.throws(() => compileCondition('', []), /Enter a condition/);

// a rule needs some condition; builder rows are kept only when well formed
assert.ok(normalizeDefinition({}).error);
const b = normalizeDefinition({ xql: 'xdm.a = "1"', builder: { match: 'any', rows: [{ field: 'xdm.a', op: '=', value: '1' }, { field: 'bad field', op: '=', value: 'x' }, { field: 'xdm.b', op: 'DROP', value: '' }] } });
assert.deepStrictEqual(b.def.builder, { match: 'any', rows: [{ field: 'xdm.a', op: '=', value: '1' }] });

// every shipped rule is valid, keys are unique, and the XDM ones use xql
assert.strictEqual(new Set(BUILTIN_RULES.map((r) => r.key)).size, BUILTIN_RULES.length);
for (const r of BUILTIN_RULES) assert.ok(!normalizeDefinition(r.definition).error, r.key);
assert.ok(BUILTIN_RULES.filter((r) => r.definition.xql).length >= 6);
console.log('bioc-rules: all tests passed');
