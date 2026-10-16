'use strict';
// The XQL query plan: what a parsed XQL query means, with no SQL in it. src/search/xql.js parses XQL
// text into a plan; each storage engine turns the plan into its own query (xql-postgres.js,
// xql-clickhouse.js) or runs it directly (xql-eval.js, the in-memory adapter). One parser, one meaning.
//
// plan = {
//   v: 1,
//   from, to,          // ISO-8601 UTC or null; bounds on the event time (event_time, else received_at)
//   stages: [...],     // the pipeline, in the order the user wrote it
//   mode,              // 'raw' | 'fields' | 'comp'   (what the result rows look like)
//   limit,             // 1..MAX_LIMIT
//   columns,           // output column names for 'fields' / 'comp'; null for 'raw'
// }
//
// stages (op):
//   { op:'dataset', names:[string], list:boolean }           list = written as  dataset in (...)
//   { op:'filter',  expr }
//   { op:'fields',  items:[{ field, alias }] }
//   { op:'comp',    aggs:[{ fn, field|null, alias }], by:[field] }
//   { op:'sort',    keys:[{ name, alias:boolean, dir:'asc'|'desc' }] }   alias = names an output column
//   { op:'limit',   n }
//
// expr (t):
//   { t:'and', args:[expr] }  { t:'or', args:[expr] }  { t:'not', e }  { t:'paren', e }
//   { t:'eq'|'ne', field, value:string }  { t:'isnull', field, neg:boolean }
//   { t:'contains', field, value, neg }   { t:'in', field, values:[string], neg }
//   { t:'regex', field, pattern }         { t:'num', field, op:'>'|'<'|'>='|'<=', value:number }
//
// Meaning that every engine must share (tests/xql-engines.test.js checks it):
//   * a field is a column (_raw, raw, source_type, dataset, collector_id, _id, _insert_time, _time) or a
//     path into parsed, split on dots (xdm.source.ipv4); a value is text, or missing (null)
//   * "@path" (for example @xdm.source.ipv4 or @user-agent) is always a path into parsed, never a column, and
//     may contain hyphens and start with a digit. XQL text cannot produce it; detection rules use it so a
//     rule field called "dataset" or "_time" stays the parsed field the rule author meant
//   * text comparison is exact; contains and ~= ignore case; ~= is an unanchored search
//   * eq is null when the field is missing (so `not host = "a"` also drops events without host);
//     ne, contains, in, regex and num never yield null (missing counts as no match)
//   * num compares only values that look like numbers (-?digits[.digits]); the rest do not match
//   * count(f) counts events where f exists; count_distinct counts distinct text values; sum/min/max/avg use
//     the numeric values only; grouping treats a missing value as its own group
//   * sort puts missing values last; ties are in no defined order

const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_.]{0,63}$/;
const PARSED_PATH_RE = /^@[A-Za-z0-9_.-]{1,64}$/;
const AGGS = ['count', 'count_distinct', 'sum', 'min', 'max', 'avg'];
const MAX_LIMIT = 5000;
const DEFAULT_LIMIT = 1000;
const MAX_STAGES = 12;
const MAX_NODES = 2000;
const MAX_DEPTH = 60;
const MAX_TEXT = 8000;
const NUM_ARGS = ['>', '<', '>=', '<='];
// columns an XQL field name can point at (the rest is parsed.<path>)
const COLUMN_NAMES = ['_raw', 'raw', 'source_type', 'dataset', 'collector_id', '_id', '_insert_time', '_time'];

class PlanError extends Error {}

const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

function validatePlan(plan) {
  const bad = (m) => { throw new PlanError(m); };
  if (!plan || typeof plan !== 'object' || plan.v !== 1) bad('plan must be an object with v: 1');
  for (const k of ['from', 'to']) if (plan[k] !== null && plan[k] !== undefined && !(typeof plan[k] === 'string' && TIME_RE.test(plan[k]))) bad(`plan.${k} must be an ISO-8601 UTC time or null`);
  if (!['raw', 'fields', 'comp'].includes(plan.mode)) bad('plan.mode must be raw, fields or comp');
  if (!Number.isInteger(plan.limit) || plan.limit < 1 || plan.limit > MAX_LIMIT) bad(`plan.limit must be a whole number from 1 to ${MAX_LIMIT}`);
  if (!Array.isArray(plan.stages) || plan.stages.length > MAX_STAGES) bad(`plan.stages must be an array of at most ${MAX_STAGES}`);
  const ident = (v, what) => { if (typeof v !== 'string' || !IDENT_RE.test(v)) bad(`${what} is not a valid name`); };
  const fieldId = (v) => { if (!(typeof v === 'string' && PARSED_PATH_RE.test(v))) ident(v, 'field'); };
  const text = (v, what) => { if (typeof v !== 'string' || v.length > MAX_TEXT || v.includes('\0')) bad(`${what} must be text of at most ${MAX_TEXT} characters`); };
  let nodes = 0;
  const expr = (e, depth) => {
    if (!e || typeof e !== 'object') bad('expression node expected');
    if (++nodes > MAX_NODES || depth > MAX_DEPTH) bad('query is too complex');
    switch (e.t) {
      case 'and': case 'or':
        if (!Array.isArray(e.args) || !e.args.length) bad(`${e.t} needs arguments`);
        e.args.forEach((a) => expr(a, depth + 1)); break;
      case 'not': case 'paren': expr(e.e, depth + 1); break;
      case 'eq': case 'ne': fieldId(e.field); text(e.value, 'value'); break;
      case 'isnull': fieldId(e.field); break;
      case 'contains': fieldId(e.field); text(e.value, 'value'); break;
      case 'in':
        fieldId(e.field);
        if (!Array.isArray(e.values) || !e.values.length || e.values.length > 500) bad('in needs 1 to 500 values');
        e.values.forEach((v) => text(v, 'value')); break;
      case 'regex': {
        fieldId(e.field); text(e.pattern, 'pattern');
        const { assertSafeRegex } = require('../security/regex-safety');
        try { assertSafeRegex(e.pattern, { mode: 'pg' }); } catch (err) { bad(err.message); }
        break;
      }
      case 'num':
        fieldId(e.field);
        if (!NUM_ARGS.includes(e.op)) bad('invalid number comparison');
        if (typeof e.value !== 'number' || !Number.isFinite(e.value)) bad('number expected');
        break;
      default: bad(`unknown expression "${e.t}"`);
    }
  };
  for (const s of plan.stages) {
    if (!s || typeof s !== 'object') bad('stage expected');
    switch (s.op) {
      case 'dataset':
        if (!Array.isArray(s.names) || !s.names.length || s.names.length > 100) bad('dataset needs 1 to 100 names');
        s.names.forEach((n) => text(n, 'dataset name')); break;
      case 'filter': expr(s.expr, 0); break;
      case 'fields':
        if (!Array.isArray(s.items) || !s.items.length || s.items.length > 100) bad('fields needs 1 to 100 items');
        s.items.forEach((i) => { ident(i.field, 'field'); ident(i.alias, 'alias'); }); break;
      case 'comp':
        if (!Array.isArray(s.aggs) || !s.aggs.length || s.aggs.length > 50) bad('comp needs 1 to 50 aggregates');
        s.aggs.forEach((a) => {
          if (!AGGS.includes(a.fn)) bad('unknown aggregate');
          if (a.field !== null && a.field !== undefined) ident(a.field, 'field'); else if (a.fn !== 'count') bad(a.fn + '() needs a field');
          ident(a.alias, 'alias');
        });
        if (!Array.isArray(s.by) || s.by.length > 50) bad('by must be an array');
        s.by.forEach((f) => ident(f, 'field')); break;
      case 'sort':
        if (!Array.isArray(s.keys) || !s.keys.length || s.keys.length > 20) bad('sort needs 1 to 20 keys');
        s.keys.forEach((k) => { ident(k.name, 'sort field'); if (k.dir !== 'asc' && k.dir !== 'desc') bad('sort direction'); }); break;
      case 'limit': if (!Number.isInteger(s.n) || s.n < 1) bad('limit'); break;
      default: bad(`unknown stage "${s.op}"`);
    }
  }
  if (plan.mode === 'comp') {
    for (const s of plan.stages) {
      if (s.op === 'sort') for (const k of s.keys) if (!k.alias) bad(`"${k.name}" is not an output column of comp`);
    }
  }
  if (plan.columns !== null && plan.columns !== undefined) {
    if (!Array.isArray(plan.columns)) bad('plan.columns must be an array or null');
    plan.columns.forEach((c) => ident(c, 'column'));
  }
  return plan;
}

// Flattens the stages the way the pipeline means it: filters add up, the last fields / comp and the last
// sort win. Engines that do not replay the stages (memory, ClickHouse) read this.
function summarize(plan) {
  const out = { datasets: [], filters: [], fields: null, comp: null, sort: null, aliases: new Set() };
  for (const s of plan.stages) {
    if (s.op === 'dataset') out.datasets.push(s);
    else if (s.op === 'filter') out.filters.push(s.expr);
    else if (s.op === 'fields') { out.fields = s.items; out.comp = null; s.items.forEach((i) => out.aliases.add(i.alias)); }
    else if (s.op === 'comp') {
      out.comp = s; out.fields = null;
      s.by.forEach((f) => out.aliases.add(f)); s.aggs.forEach((a) => out.aliases.add(a.alias));
    } else if (s.op === 'sort') out.sort = s.keys;
  }
  return out;
}

module.exports = { PARSED_PATH_RE, IDENT_RE,
  IDENT_RE, AGGS, MAX_LIMIT, DEFAULT_LIMIT, COLUMN_NAMES, PlanError, validatePlan, summarize,
};
