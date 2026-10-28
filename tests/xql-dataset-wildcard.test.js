'use strict';
// Wildcard dataset names in XQL: dataset = *, dataset = endpoint*, dataset in (syslog, win*) (the Investigation & Response page used to answer
// 400 XQL_SYNTAX `Unexpected character "*"`). The parser, the PostgreSQL and ClickHouse SQL, and the in-memory reference engine; the real
// PostgreSQL run is tests/xql-dataset-wildcard-db.test.js.
const { describe, it } = require('node:test');
const assert = require('assert');
const xql = require('../src/search/xql');
const { validatePlan, hasWildcard, globToLike, datasetMatches } = require('../src/search/xql-plan');
const { toSql } = require('../src/search/xql-postgres');
const { toClickHouse } = require('../src/search/xql-clickhouse');
const { MemoryEventStore } = require('../src/events/memory-store');

const T = '11111111-1111-4111-8111-111111111111';
const TYPES = ['syslog', 'endpoint-alert', 'endpoint_other', 'endpointx', 'windows-event', 'wineventlog', 'cloud', 'My_Type%', 'a.b'];
const now = Date.now();

describe('parsing', () => {
  it('accepts a bare *, a prefix, a suffix, a middle star, a dashed name, and a mixed list', () => {
    for (const [q, names, list] of [['dataset = *', ['*'], false], ['dataset=endpoint*', ['endpoint*'], false], ['dataset = *event*', ['*event*'], false], ['dataset = win*-event', ['win*-event'], false],
      ['dataset in (syslog, win*)', ['syslog', 'win*'], true], ['dataset in (*)', ['*'], true], ['dataset = "endpoint*"', ['endpoint*'], false]]) {
      const plan = xql.parse(q); const d = plan.stages[0];
      assert.deepStrictEqual([d.op, d.names, d.list], ['dataset', names, list], q); validatePlan(plan);
    }
  });
  it('still reads the stages after a wildcard dataset', () => {
    const plan = xql.parse('dataset = endpoint* | filter host = "web1" | limit 5');
    assert.deepStrictEqual(plan.stages.map((s) => s.op), ['dataset', 'filter', 'limit'].filter((o) => plan.stages.some((s) => s.op === o)));
    assert.strictEqual(plan.limit, 5);
  });
  it('a wildcard anywhere but a dataset name is still a clear error, not a crash', () => {
    for (const q of ['dataset = syslog | filter host = web*', 'dataset = syslog | filter web* = 1', 'dataset = syslog | fields host* ', 'dataset = a%']) assert.throws(() => xql.parse(q), (e) => e.constructor.name === 'XqlError', q);
  });
});

describe('what a name matches', () => {
  it('helpers: exact without a star, * is any run including none, regex and LIKE characters are literal', () => {
    assert.ok(!hasWildcard('syslog') && hasWildcard('a*'));
    assert.strictEqual(globToLike('My_Type%*'), 'My\\_Type\\%%'); assert.strictEqual(globToLike('a\\b*'), 'a\\\\b%');
    assert.ok(datasetMatches(['*'], 'anything') && datasetMatches(['endpoint*'], 'endpoint') && datasetMatches(['endpoint*'], 'endpoint-alert'));
    assert.ok(!datasetMatches(['endpoint*'], 'xendpoint') && !datasetMatches(['endpoint'], 'endpoint-alert'));
    assert.ok(datasetMatches(['a.b'], 'a.b') && !datasetMatches(['a.b'], 'axb') && !datasetMatches(['a.*'], 'axb') && datasetMatches(['a.*'], 'a.b'));
    assert.ok(datasetMatches(['My_Type%'], 'My_Type%') && !datasetMatches(['My_Type%'], 'MyxType%'));
    assert.ok(!datasetMatches(['Endpoint*'], 'endpoint-alert'), 'case-sensitive, like an exact name');
  });
});

describe('the in-memory reference engine', () => {
  const run = async (q) => {
    const store = new MemoryEventStore();
    await store.insertBatch(T, TYPES.map((t, i) => ({ source_type: t, collector_id: 'c', raw: t, parsed: { host: 'h' }, received_at: new Date(now - i * 1000).toISOString() })));
    const out = await store.search(T, xql.parse(q, { from: new Date(now - 3600000).toISOString(), to: new Date(now + 60000).toISOString() }));
    return out.rows.map((r) => r.source_type).sort();
  };
  it('dataset = * returns every event', async () => assert.deepStrictEqual(await run('dataset = *'), [...TYPES].sort()));
  it('dataset = endpoint* returns the prefix matches only', async () => assert.deepStrictEqual(await run('dataset = endpoint*'), ['endpoint-alert', 'endpoint_other', 'endpointx']));
  it('a suffix, a middle star and a list mixing exact and wildcard names', async () => {
    assert.deepStrictEqual(await run('dataset = *event*'), ['windows-event', 'wineventlog']);
    assert.deepStrictEqual(await run('dataset = win*-event'), ['windows-event']);
    assert.deepStrictEqual(await run('dataset in (cloud, endpoint-*)'), ['cloud', 'endpoint-alert']);
  });
  it('LIKE and regex characters in a name are literal', async () => {
    assert.deepStrictEqual(await run('dataset = "My_Type%"'), ['My_Type%']); assert.deepStrictEqual(await run('dataset = "a.*"'), ['a.b']); assert.deepStrictEqual(await run('dataset = "My_*"'), ['My_Type%']);
  });
  it('an exact name and a name with no match are as before', async () => {
    assert.deepStrictEqual(await run('dataset = syslog'), ['syslog']); assert.deepStrictEqual(await run('dataset = nothing*'), []);
  });
});

describe('the SQL', () => {
  it('PostgreSQL: a bound LIKE pattern, never the typed text in the SQL; * is no condition; exact names stay = / IN', () => {
    let r = toSql(xql.parse('dataset = endpoint*'), T);
    assert.ok(/source_type LIKE \$2/.test(r.sql)); assert.deepStrictEqual(r.values.slice(1, 2), ['endpoint%']); assert.ok(!/endpoint/.test(r.sql));
    r = toSql(xql.parse('dataset = *'), T); assert.ok(!/source_type/.test(r.sql.split('ORDER')[0].split('WHERE')[1]), 'no source type condition for *');
    r = toSql(xql.parse('dataset in (syslog, win*, cloud)'), T);
    assert.ok(/\(source_type IN \(\$2, \$3\) OR source_type LIKE \$4\)/.test(r.sql)); assert.deepStrictEqual(r.values.slice(1, 4), ['syslog', 'cloud', 'win%']);
    r = toSql(xql.parse('dataset = syslog'), T); assert.ok(/source_type = \$2/.test(r.sql));
    r = toSql(xql.parse('dataset = "My_Type%*"'), T); assert.deepStrictEqual(r.values.slice(1, 2), ['My\\_Type\\%%']);
  });
  it('ClickHouse: a bound like(), * is no condition, exact names stay IN', () => {
    let r = toClickHouse(xql.parse('dataset = endpoint*'), T);
    assert.ok(/like\(toString\(source_type\), \{p\d+:String\}\)/.test(r.sql) || /like\(toString\(source_type\)/.test(r.sql), r.sql);
    assert.ok(!/endpoint/.test(r.sql)); assert.ok(Object.values(r.params || r.values || {}).some((v) => v === 'endpoint%'));
    r = toClickHouse(xql.parse('dataset = *'), T); assert.ok(!/source_type/.test(r.sql.split('WHERE')[1].split('ORDER')[0]));
    r = toClickHouse(xql.parse('dataset in (syslog, win*)'), T); assert.ok(/source_type IN/.test(r.sql) && /like\(/.test(r.sql) && /\bOR\b/.test(r.sql));
    r = toClickHouse(xql.parse('dataset = syslog'), T); assert.ok(/source_type IN/.test(r.sql) && !/like\(/.test(r.sql));
  });
});
