'use strict';
// A small, safe XQL-style query language over the events table.
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
// Stages: dataset, filter, fields, sort, limit, comp. Everything user-typed is bound as a SQL
// parameter or checked against a strict identifier pattern - nothing is concatenated into SQL.

const XDM_CONSTANTS = require('../ingestion/xdm-schema').CONSTANTS;

class XqlError extends Error {}

const KEYWORDS = new Set(['and', 'or', 'not', 'contains', 'in', 'by', 'as', 'asc', 'desc', 'null']);
const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_.]{0,63}$/;
const AGGS = ['count', 'count_distinct', 'sum', 'min', 'max', 'avg'];
const MAX_LIMIT = 5000;
const DEFAULT_LIMIT = 1000;

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

// ---------- compile ----------------------------------------------------------------------
const TS = 'COALESCE(event_time, received_at)';
const COLUMNS = { _raw: 'raw', raw: 'raw', source_type: 'source_type', dataset: 'source_type', collector_id: 'collector_id', _id: 'id::text', _insert_time: 'received_at', _time: TS };

class Compiler {
  // With `shared` (an existing parameter array) the compiler only produces conditions and binds into
  // that array; the caller owns tenant / time filtering. Used by BIOC rules.
  constructor(tenantId, from, to, shared) {
    this.values = shared || [tenantId]; this.where = shared ? [] : ['tenant_id = $1'];
    if (from) this.where.push(`${TS} >= ${this.bind(from)}`);
    if (to) this.where.push(`${TS} <= ${this.bind(to)}`);
    this.aliases = new Map();   // output alias -> sql expression (fields / comp)
  }
  bind(v) { this.values.push(v); return '$' + this.values.length; }
  field(name) {
    if (COLUMNS[name]) return COLUMNS[name];
    return `(parsed #>> ${this.bind(name.split('.'))}::text[])`;
  }
  textField(name) { const e = this.field(name); return name === '_time' || name === '_insert_time' ? `(${e})::text` : e; }
  num(name) { const e = this.field(name); return `(CASE WHEN (${e})::text ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN (${e})::text::numeric END)`; }
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
    const mark = this.values.length;   // lets the numeric branch drop the unused field-path parameter
    const fe = this.textField(f);
    if (c.isKw('not')) { c.next(); neg = true; if (!c.isKw('contains') && !c.isKw('in')) c.fail('expected contains or in after not'); }
    if (c.isKw('contains')) {
      c.next(); const v = this.value(c); if (v.t === 'id') c.fail('contains needs a value');
      const p = this.bind('%' + String(v.v).replace(/[\\%_]/g, '\\$&') + '%');
      return neg ? `NOT COALESCE(${fe} ILIKE ${p}, false)` : `COALESCE(${fe} ILIKE ${p}, false)`;
    }
    if (c.isKw('in')) {
      c.next(); c.expectOp('('); const ps = [];
      do { const v = this.value(c); if (v.t === 'id') c.fail('null is not allowed in a list'); ps.push(this.bind(String(v.v))); } while (c.isOp(',') && c.next());
      c.expectOp(')');
      return `${neg ? 'NOT ' : ''}COALESCE(${fe} IN (${ps.join(', ')}), false)`;
    }
    const op = c.cur;
    if (!op || op.t !== 'op' || !['=', '!=', '>', '<', '>=', '<=', '~='].includes(op.v)) c.fail('expected an operator (=, !=, >, <, >=, <=, ~=, contains, in)');
    c.next(); const v = this.value(c);
    if (v.t === 'id') { if (op.v === '=') return `${fe} IS NULL`; if (op.v === '!=') return `${fe} IS NOT NULL`; c.fail('null only works with = and !='); }
    if (op.v === '=') return `${fe} = ${this.bind(String(v.v))}`;
    if (op.v === '!=') return `${fe} IS DISTINCT FROM ${this.bind(String(v.v))}`;
    if (op.v === '~=') {
      const s = String(v.v); if (s.length > 500) c.fail('regex too long');
      try { new RegExp(s); } catch { c.fail('invalid regular expression'); }
      return `COALESCE(${fe} ~* ${this.bind(s)}, false)`;
    }
    if (f === '_time' || f === '_insert_time') c.fail('use the time range picker to limit time');
    if (v.t !== 'num') c.fail(`${op.v} needs a number`);
    this.values.length = mark;         // textField() bound a path that this branch does not use
    return `COALESCE(${this.num(f)} ${op.v} ${this.bind(v.v)}, false)`;
  }
  unary(c) {
    if (c.isKw('not')) { c.next(); return `NOT (${this.unary(c)})`; }
    if (c.isOp('(')) { c.next(); const e = this.or(c); c.expectOp(')'); return `(${e})`; }
    return this.cmp(c);
  }
  and(c) { let e = this.unary(c); while (c.isKw('and')) { c.next(); e += ' AND ' + this.unary(c); } return e; }
  or(c) { let e = this.and(c); while (c.isKw('or')) { c.next(); e = `(${e}) OR (${this.and(c)})`; } return e; }
}

function aliasOf(c) { if (!c.isKw('as')) return null; c.next(); const a = c.ident('an alias'); return a; }

function compile(query, { tenantId, from, to, limit }) {
  if (typeof query !== 'string' || !query.trim()) throw new XqlError('Enter a query, for example: dataset = syslog | limit 100');
  if (query.length > 8000) throw new XqlError('Query is too long (max 8000 characters)');
  const stages = splitStages(tokenize(query));
  if (stages.length > 12) throw new XqlError('At most 12 stages');
  const C = new Compiler(tenantId, from, to);
  let mode = 'raw', select = null, group = null, order = null, lim = Math.min(Number(limit) || DEFAULT_LIMIT, MAX_LIMIT);
  let sawLimit = false;

  stages.forEach((toks, idx) => {
    const c = new Cursor(toks, toks[0].t === 'id' ? toks[0].l : 'query');
    const kw = toks[0].t === 'id' ? toks[0].l : '';
    if (kw === 'dataset') {
      if (idx !== 0) c.fail('dataset must be the first stage');
      c.next();
      if (c.isOp('=')) { c.next(); const n = c.cur; if (!n || (n.t !== 'id' && n.t !== 'str')) c.fail('expected a dataset name'); c.next(); C.where.push(`source_type = ${C.bind(String(n.v))}`); }
      else if (c.isKw('in')) {
        c.next(); c.expectOp('('); const ps = [];
        do { const n = c.cur; if (!n || (n.t !== 'id' && n.t !== 'str')) c.fail('expected a dataset name'); c.next(); ps.push(C.bind(String(n.v))); } while (c.isOp(',') && c.next());
        c.expectOp(')'); C.where.push(`source_type IN (${ps.join(', ')})`);
      } else c.fail('expected = or in');
    } else if (kw === 'filter') {
      if (mode !== 'raw' || select) c.fail('filter must come before fields / comp');
      c.next(); C.where.push(`(${C.or(c)})`);
    } else if (kw === 'fields') {
      if (mode === 'comp') c.fail('fields cannot follow comp');
      c.next(); select = []; mode = 'fields';
      do { const f = c.ident(); const a = aliasOf(c) || f; select.push({ alias: a, expr: C.textField(f) }); C.aliases.set(a, `"${a}"`); } while (c.isOp(',') && c.next());
    } else if (kw === 'comp') {
      if (mode === 'comp') c.fail('only one comp stage is allowed');
      c.next(); mode = 'comp'; select = []; group = [];
      const aggs = [];
      do {
        const fn = c.cur; if (!fn || fn.t !== 'id' || !AGGS.includes(fn.l)) c.fail('expected an aggregate: ' + AGGS.map((x) => x + '()').join(', '));
        c.next(); c.expectOp('(');
        let arg = null; if (!c.isOp(')')) arg = c.ident(); c.expectOp(')');
        if (fn.l !== 'count' && !arg) c.fail(fn.l + '() needs a field');
        const alias = aliasOf(c) || (arg ? `${fn.l}_${arg.replace(/\./g, '_')}` : fn.l);
        let e;
        if (fn.l === 'count') e = arg ? `COUNT(${C.field(arg)})` : 'COUNT(*)';
        else if (fn.l === 'count_distinct') e = `COUNT(DISTINCT ${C.textField(arg)})`;
        else e = `${fn.l.toUpperCase()}(${C.num(arg)})`;
        aggs.push({ alias, expr: e });
      } while (c.isOp(',') && c.next());
      if (c.isKw('by')) { c.next(); do { const f = c.ident(); group.push({ alias: f, expr: C.textField(f) }); C.aliases.set(f, `"${f}"`); } while (c.isOp(',') && c.next()); }
      group.forEach((g) => select.push(g));
      aggs.forEach((a) => { select.push(a); C.aliases.set(a.alias, `"${a.alias}"`); });
      C._aggs = aggs;
    } else if (kw === 'sort') {
      c.next(); order = [];
      let dir = c.isKw('asc') || c.isKw('desc') ? c.next().l : null;
      do {
        const f = c.ident(); let d = dir || 'desc';
        if (c.isKw('asc') || c.isKw('desc')) d = c.next().l;
        const ref = C.aliases.get(f) || (mode === 'comp' ? null : f === '_time' ? TS : C.field(f));
        if (!ref) c.fail(`"${f}" is not an output column of comp`);
        order.push(`${ref} ${d.toUpperCase()} NULLS LAST`);
      } while (c.isOp(',') && c.next());
    } else if (kw === 'limit') {
      c.next(); const n = c.cur; if (!n || n.t !== 'num' || n.v < 1) c.fail('expected a positive number'); c.next();
      lim = Math.min(Math.floor(n.v), MAX_LIMIT); sawLimit = true;
    } else {
      c.fail(`unknown stage "${toks[0].v}" (use dataset, filter, fields, sort, limit, comp)`);
    }
    if (!c.done()) c.fail('unexpected "' + c.cur.v + '"');
  });

  let selectSql, columns;
  if (mode === 'raw') {
    selectSql = `id::text AS "_id", ${TS} AS "_time", source_type, collector_id, raw AS "_raw", parsed`;
    columns = null;
  } else {
    selectSql = select.map((s) => `${s.expr} AS "${s.alias}"`).join(', ');
    columns = select.map((s) => s.alias);
  }
  if (!order) order = mode === 'comp' ? [`${C._aggs[C._aggs.length - 1].expr} DESC`] : [`${TS} DESC`];
  const sql = `SELECT ${selectSql} FROM events WHERE ${C.where.join(' AND ')}`
    + (mode === 'comp' && group.length ? ` GROUP BY ${group.map((_, i) => i + 1).join(', ')}` : '')
    + ` ORDER BY ${order.join(', ')} LIMIT ${lim + 1}`;
  return { sql, values: C.values, mode, columns, limit: lim };
}

// Turns "dataset = x | filter <condition>" (or a bare condition) into WHERE fragments that bind into
// `values`. Only dataset and filter stages are allowed; used for BIOC rule conditions.
function compileCondition(query, values) {
  if (typeof query !== 'string' || !query.trim()) throw new XqlError('Enter a condition, for example: xdm.event.outcome = XDM_CONST.OUTCOME_FAILED');
  if (query.length > 4000) throw new XqlError('Condition is too long (max 4000 characters)');
  let q = query.trim();
  if (!/^(dataset|filter)\b/i.test(q)) q = 'filter ' + q;
  const C = new Compiler(null, null, null, values), out = [];
  for (const toks of splitStages(tokenize(q))) {
    const kw = toks[0].t === 'id' ? toks[0].l : '', c = new Cursor(toks, kw || 'query');
    if (kw === 'dataset') {
      c.next();
      if (!c.isOp('=')) c.fail('expected =');
      c.next(); const n = c.cur; if (!n || (n.t !== 'id' && n.t !== 'str')) c.fail('expected a dataset name');
      c.next(); out.push(`source_type = ${C.bind(String(n.v))}`);
    } else if (kw === 'filter') { c.next(); out.push(`(${C.or(c)})`); }
    else c.fail('a BIOC condition can only use dataset and filter');
    if (!c.done()) c.fail('unexpected "' + c.cur.v + '"');
  }
  return out;
}

module.exports = { compile, compileCondition, XqlError, MAX_LIMIT };
