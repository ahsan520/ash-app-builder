'use strict';
// The XQL parser now produces a query plan and xql-postgres.js turns it into SQL. This checks the SQL, the
// bound values and every error message against what the old one-pass compiler produced (tests/fixtures/
// xql-golden.json, generated from that compiler before the change), so search and BIOC rules behave as before.
const test = require('node:test');
const assert = require('assert');
const { compile, compileCondition, XqlError } = require('../src/search/xql');
const G = require('./fixtures/xql-golden.json');

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
