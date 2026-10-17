'use strict';
// The XQL parser produces a query plan and xql-postgres.js turns it into SQL. This checks the SQL, the
// bound values and every error message against what the old one-pass compiler produced (tests/fixtures/
// xql-golden.json, generated from that compiler before the change), so search and BIOC rules behave as before.
// The old `xql.compile()` / `compileCondition()` wrappers are gone; the two helpers below are what they were.
const test = require('node:test');
const assert = require('assert');
const { parse, parseCondition, XqlError } = require('../src/search/xql');
const { toSql, conditionToSql } = require('../src/search/xql-postgres');
const G = require('./fixtures/xql-golden.json');

const compile = (query, { tenantId, from, to, limit }) => toSql(parse(query, { from, to, limit }), tenantId);
const compileCondition = (query, values) => conditionToSql(parseCondition(query), values);

test('compile() matches the old compiler on every query (SQL, values, mode, columns, limit, errors)', () => {
  assert.ok(G.compile.length > 100);
  for (const c of G.compile) {
    let got;
    try { got = { ok: compile(c.query, c.opts) }; } catch (e) { got = { error: e.message, xqlError: e instanceof XqlError }; }
    assert.deepStrictEqual(got, c.ok !== undefined ? { ok: c.ok } : { error: c.error, xqlError: c.xqlError }, `query: ${JSON.stringify(c.query)} opts: ${JSON.stringify(c.opts)}`);
  }
});

test('compileCondition() matches the old compiler (fragments and bound values)', () => {
  for (const c of G.condition) {
    const values = c.pre.slice();
    let got;
    try { got = { ok: { frags: compileCondition(c.query, values), values } }; } catch (e) { got = { error: e.message, xqlError: e instanceof XqlError }; }
    assert.deepStrictEqual(got, c.ok !== undefined ? { ok: c.ok } : { error: c.error, xqlError: c.xqlError }, `condition: ${JSON.stringify(c.query)}`);
  }
});
