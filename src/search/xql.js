'use strict';
// A small, safe XQL-style query language over events.
//
// This file only PARSES: XQL text -> a query plan (src/search/xql-plan.js), with no SQL in it. Each
// storage engine turns the plan into its own query: xql-postgres.js (toSql), xql-clickhouse.js,
// or xql-eval.js (in memory). The event store runs plans: store.search(tenantId, plan).
//
//   dataset = syslog
//   | filter host = "web01" and _raw contains "Failed password"
//   | fields _time, host, app_name as app
//   | sort desc _time
//   | limit 100
//
//   dataset in (syslog, mac)
//   | filter _raw ~= "sudo|su\[" | comp count() as hits, count_distinct(host) as hosts by app_name
//
// Stages: dataset, filter, fields, sort, limit, comp. Field names are checked against a strict identifier
// pattern and values stay values in the plan, so no engine ever builds a query by joining user text.

const XDM_CONSTANTS = require('../ingestion/xdm-schema').CONSTANTS;
const { assertSafeRegex, RegexSafetyError } = require('../security/regex-safety');

class XqlError extends Error {}

const KEYWORDS = new Set(['and', 'or', 'not', 'contains', 'in', 'by', 'as', 'asc', 'desc', 'null']);
const { IDENT_RE } = require('./xql-plan');
const { AGGS, MAX_LIMIT, DEFAULT_LIMIT } = require('./xql-plan');

function tokenize(src) {
  const out = []; let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    const pos = i;
    if (c === '"' || c === "'") {
      let j = i + 1, v = '';
      while (j < src.length && src[j] !== c) { if (src[j] === '\\' && j + 1 < src.length) j++; v += src[j]; j++; }
      if (j >= src.length) throw new XqlError(`Unterminated string starting at character ${pos + 1}`);
      out.push({ t: 'str', v, pos }); i = j + 1; continue;
    }
    if (/[0-9]/.test(c) || (c === '-' && /[0-9]/.test(src[i + 1] || ''))) {
      const m = /^-?[0-9]+(\.[0-9]+)?/.exec(src.slice(i));
      out.push({ t: 'num', v: Number(m[0]), pos }); i += m[0].length; continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      const m = /^[A-Za-z_][A-Za-z0-9_.]*/.exec(src.slice(i));
      out.push({ t: 'id', v: m[0], l: m[0].toLowerCase(), pos }); i += m[0].length; continue;
    }
    const two = src.slice(i, i + 2);
    if (['!=', '>=', '<=', '~='].includes(two)) { out.push({ t: 'op', v: two, pos }); i += 2; continue; }
    if ('=<>(),|'.includes(c)) { out.push({ t: 'op', v: c, pos }); i++; continue; }
    throw new XqlError(`Unexpected character "${c}" at character ${pos + 1}`);
  }
  return out;
}

function splitStages(tokens) {
  const stages = [[]];
  for (const t of tokens) { if (t.t === 'op' && t.v === '|') stages.push([]); else stages[stages.length - 1].push(t); }
  return stages.filter((s) => s.length);
}

class Cursor {
  constructor(tokens, stage) { this.t = tokens; this.i = 0; this.stage = stage; }
  get cur() { return this.t[this.i]; }
  done() { return this.i >= this.t.length; }
  isOp(v) { const c = this.cur; return c && c.t === 'op' && c.v === v; }
  isKw(l) { const c = this.cur; return c && c.t === 'id' && c.l === l; }
  next() { return this.t[this.i++]; }
  fail(msg) { const c = this.cur; throw new XqlError(`${this.stage}: ${msg}` + (c ? ` (near character ${c.pos + 1})` : ' (at end of stage)')); }
  expectOp(v) { if (!this.isOp(v)) this.fail(`expected "${v}"`); return this.next(); }
  ident(what = 'a field name') {
    const c = this.cur;
    if (!c || c.t !== 'id' || KEYWORDS.has(c.l)) this.fail(`expected ${what}`);
    if (!IDENT_RE.test(c.v)) this.fail('invalid field name');
    return this.next().v;
  }
}

// ---------- parse ------------------------------------------------------------------------
class Parser {
  value(c) {
    let v = c.cur;
    if (v && v.t === 'id' && v.v.startsWith('XDM_CONST.')) {   // XDM_CONST.OUTCOME_FAILED -> "FAILED"
      const k = v.v.slice(10);
      if (!(k in XDM_CONSTANTS)) c.fail('unknown constant ' + v.v);
      v = { t: 'str', v: XDM_CONSTANTS[k], pos: v.pos };
    }
    if (!v || (v.t !== 'str' && v.t !== 'num' && !(v.t === 'id' && v.l === 'null'))) c.fail('expected a quoted "text" or a number');
    c.next(); return v;
  }
  cmp(c) {
    const f = c.ident(); let neg = false;
    if (c.isKw('not')) { c.next(); neg = true; if (!c.isKw('contains') && !c.isKw('in')) c.fail('expected contains or in after not'); }
    if (c.isKw('contains')) {
      c.next(); const v = this.value(c); if (v.t === 'id') c.fail('contains needs a value');
      return { t: 'contains', field: f, value: String(v.v), neg };
    }
    if (c.isKw('in')) {
      c.next(); c.expectOp('('); const values = [];
      do { const v = this.value(c); if (v.t === 'id') c.fail('null is not allowed in a list'); values.push(String(v.v)); } while (c.isOp(',') && c.next());
      c.expectOp(')');
      return { t: 'in', field: f, values, neg };
    }
    const op = c.cur;
    if (!op || op.t !== 'op' || !['=', '!=', '>', '<', '>=', '<=', '~='].includes(op.v)) c.fail('expected an operator (=, !=, >, <, >=, <=, ~=, contains, in)');
    c.next(); const v = this.value(c);
    if (v.t === 'id') { if (op.v === '=') return { t: 'isnull', field: f, neg: false }; if (op.v === '!=') return { t: 'isnull', field: f, neg: true }; c.fail('null only works with = and !='); }
    if (op.v === '=') return { t: 'eq', field: f, value: String(v.v) };
    if (op.v === '!=') return { t: 'ne', field: f, value: String(v.v) };
    if (op.v === '~=') {
      const s = String(v.v);
      try { assertSafeRegex(s, { mode: 'pg' }); } catch (e) { if (e instanceof RegexSafetyError) c.fail(e.message); throw e; }
      try { new RegExp(s); } catch { c.fail('invalid regular expression'); }
      return { t: 'regex', field: f, pattern: s };
    }
    if (f === '_time' || f === '_insert_time') c.fail('use the time range picker to limit time');
    if (v.t !== 'num') c.fail(`${op.v} needs a number`);
    return { t: 'num', field: f, op: op.v, value: v.v };
  }
  unary(c) {
    if (c.isKw('not')) { c.next(); return { t: 'not', e: this.unary(c) }; }
    if (c.isOp('(')) { c.next(); const e = this.or(c); c.expectOp(')'); return { t: 'paren', e }; }
    return this.cmp(c);
  }
  and(c) { const args = [this.unary(c)]; while (c.isKw('and')) { c.next(); args.push(this.unary(c)); } return args.length === 1 ? args[0] : { t: 'and', args }; }
  or(c) { const args = [this.and(c)]; while (c.isKw('or')) { c.next(); args.push(this.and(c)); } return args.length === 1 ? args[0] : { t: 'or', args }; }
}

function aliasOf(c) { if (!c.isKw('as')) return null; c.next(); const a = c.ident('an alias'); return a; }

// XQL text -> plan. `from` / `to` are ISO times (or null); `limit` is the default row limit.
function parse(query, { from = null, to = null, limit } = {}) {
  if (typeof query !== 'string' || !query.trim()) throw new XqlError('Enter a query, for example: dataset = syslog | limit 100');
  if (query.length > 8000) throw new XqlError('Query is too long (max 8000 characters)');
  const stages = splitStages(tokenize(query));
  if (stages.length > 12) throw new XqlError('At most 12 stages');
  const P = new Parser(), out = [];
  const aliases = new Set();
  let mode = 'raw', select = null, order = null, lim = Math.min(Number(limit) || DEFAULT_LIMIT, MAX_LIMIT);

  stages.forEach((toks, idx) => {
    const c = new Cursor(toks, toks[0].t === 'id' ? toks[0].l : 'query');
    const kw = toks[0].t === 'id' ? toks[0].l : '';
    if (kw === 'dataset') {
      if (idx !== 0) c.fail('dataset must be the first stage');
      c.next();
      if (c.isOp('=')) { c.next(); const n = c.cur; if (!n || (n.t !== 'id' && n.t !== 'str')) c.fail('expected a dataset name'); c.next(); out.push({ op: 'dataset', names: [String(n.v)], list: false }); }
      else if (c.isKw('in')) {
        c.next(); c.expectOp('('); const names = [];
        do { const n = c.cur; if (!n || (n.t !== 'id' && n.t !== 'str')) c.fail('expected a dataset name'); c.next(); names.push(String(n.v)); } while (c.isOp(',') && c.next());
        c.expectOp(')'); out.push({ op: 'dataset', names, list: true });
      } else c.fail('expected = or in');
    } else if (kw === 'filter') {
      if (mode !== 'raw' || select) c.fail('filter must come before fields / comp');
      c.next(); out.push({ op: 'filter', expr: P.or(c) });
    } else if (kw === 'fields') {
      if (mode === 'comp') c.fail('fields cannot follow comp');
      c.next(); select = []; mode = 'fields';
      const items = [];
      do { const f = c.ident(); const a = aliasOf(c) || f; items.push({ field: f, alias: a }); select.push(a); aliases.add(a); } while (c.isOp(',') && c.next());
      out.push({ op: 'fields', items });
    } else if (kw === 'comp') {
      if (mode === 'comp') c.fail('only one comp stage is allowed');
      c.next(); mode = 'comp'; select = [];
      const aggs = [], by = [];
      do {
        const fn = c.cur; if (!fn || fn.t !== 'id' || !AGGS.includes(fn.l)) c.fail('expected an aggregate: ' + AGGS.map((x) => x + '()').join(', '));
        c.next(); c.expectOp('(');
        let arg = null; if (!c.isOp(')')) arg = c.ident(); c.expectOp(')');
        if (fn.l !== 'count' && !arg) c.fail(fn.l + '() needs a field');
        const alias = aliasOf(c) || (arg ? `${fn.l}_${arg.replace(/\./g, '_')}` : fn.l);
        aggs.push({ fn: fn.l, field: arg, alias });
      } while (c.isOp(',') && c.next());
      if (c.isKw('by')) { c.next(); do { const f = c.ident(); by.push(f); aliases.add(f); } while (c.isOp(',') && c.next()); }
      by.forEach((f) => select.push(f));
      aggs.forEach((a) => { select.push(a.alias); aliases.add(a.alias); });
      out.push({ op: 'comp', aggs, by });
    } else if (kw === 'sort') {
      c.next(); order = true;
      const keys = [];
      let dir = c.isKw('asc') || c.isKw('desc') ? c.next().l : null;
      do {
        const f = c.ident(); let d = dir || 'desc';
        if (c.isKw('asc') || c.isKw('desc')) d = c.next().l;
        const isAlias = aliases.has(f);
        if (!isAlias && mode === 'comp') c.fail(`"${f}" is not an output column of comp`);
        keys.push({ name: f, alias: isAlias, dir: d });
      } while (c.isOp(',') && c.next());
      out.push({ op: 'sort', keys });
    } else if (kw === 'limit') {
      c.next(); const n = c.cur; if (!n || n.t !== 'num' || n.v < 1) c.fail('expected a positive number'); c.next();
      lim = Math.min(Math.floor(n.v), MAX_LIMIT); out.push({ op: 'limit', n: lim });
    } else {
      c.fail(`unknown stage "${toks[0].v}" (use dataset, filter, fields, sort, limit, comp)`);
    }
    if (!c.done()) c.fail('unexpected "' + c.cur.v + '"');
  });
  void order;
  return { v: 1, from: from || null, to: to || null, stages: out, mode, limit: lim, columns: mode === 'raw' ? null : select };
}

// Turns "dataset = x | filter <condition>" (or a bare condition) into the dataset / filter stages of a plan.
// Only dataset and filter are allowed; used for BIOC rule conditions.
function parseCondition(query) {
  if (typeof query !== 'string' || !query.trim()) throw new XqlError('Enter a condition, for example: xdm.event.outcome = XDM_CONST.OUTCOME_FAILED');
  if (query.length > 4000) throw new XqlError('Condition is too long (max 4000 characters)');
  let q = query.trim();
  if (!/^(dataset|filter)\b/i.test(q)) q = 'filter ' + q;
  const P = new Parser(), out = [];
  for (const toks of splitStages(tokenize(q))) {
    const kw = toks[0].t === 'id' ? toks[0].l : '', c = new Cursor(toks, kw || 'query');
    if (kw === 'dataset') {
      c.next();
      if (!c.isOp('=')) c.fail('expected =');
      c.next(); const n = c.cur; if (!n || (n.t !== 'id' && n.t !== 'str')) c.fail('expected a dataset name');
      c.next(); out.push({ op: 'dataset', names: [String(n.v)], list: false });
    } else if (kw === 'filter') { c.next(); out.push({ op: 'filter', expr: P.or(c) }); }
    else c.fail('a BIOC condition can only use dataset and filter');
    if (!c.done()) c.fail('unexpected "' + c.cur.v + '"');
  }
  return out;
}

module.exports = { parse, parseCondition, XqlError, MAX_LIMIT };
