'use strict';
// Runs a query plan (src/search/xql-plan.js) directly over event envelopes in memory. It is the reference
// for what a plan means, and it is what the in-memory event store uses. Where PostgreSQL has a rule, this
// follows it: missing values are null, eq is null when the field is missing (so `not host = "a"` drops
// events without a host), nulls sort last, and the text of _time looks like 2026-10-13 10:00:01.123.

const { summarize, COLUMN_NAMES, datasetMatches } = require('./xql-plan');
const { clampSubject } = require('../security/regex-safety');

const NUM_RE = /^-?[0-9]+(\.[0-9]+)?$/;
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// "2026-10-13T10:00:01.120Z" -> "2026-10-13 10:00:01.12" (PostgreSQL's timestamp::text, trailing zeros trimmed)
function pgTimeText(iso) {
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z?$/.exec(String(iso));
  if (!m) return String(iso);
  const frac = (m[3] || '').replace(/0+$/, '');
  return `${m[1]} ${m[2]}${frac ? '.' + frac : ''}`;
}

// jsonb::text: keys ordered by length then bytes, ": " and ", " separators.
function jsonbText(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jsonbText).join(', ') + ']';
  const keys = Object.keys(v).sort((a, b) => Buffer.byteLength(a) - Buffer.byteLength(b) || (a < b ? -1 : a > b ? 1 : 0));
  return '{' + keys.map((k) => JSON.stringify(k) + ': ' + jsonbText(v[k])).join(', ') + '}';
}

// parsed #>> '{a,b}': the text at a path, or null
function pathText(parsed, path) {
  let cur = parsed;
  for (const seg of path) {
    if (Array.isArray(cur)) {
      if (!/^-?\d+$/.test(seg)) return null;
      const i = Number(seg); cur = cur[i < 0 ? cur.length + i : i];
    } else if (cur && typeof cur === 'object' && own(cur, seg)) cur = cur[seg];
    else return null;
  }
  if (cur === undefined || cur === null) return null;
  if (typeof cur === 'string') return cur;
  if (typeof cur === 'number' || typeof cur === 'boolean') return String(cur);
  return jsonbText(cur);
}

const eventTime = (e) => e.event_time || e.received_at;

function textOf(e, name) {
  switch (name) {
    case '_raw': case 'raw': return e.raw;
    case 'source_type': case 'dataset': return e.source_type;
    case 'collector_id': return e.collector_id === undefined ? null : e.collector_id;
    case '_id': return e.id;
    case '_insert_time': return pgTimeText(e.received_at);
    case '_time': return pgTimeText(eventTime(e));
    default: return pathText(e.parsed, (name[0] === '@' ? name.slice(1) : name).split('.'));   // @path: explicit parsed path
  }
}

// three-valued logic: true / false / null
function evalExpr(n, e, cache) {
  switch (n.t) {
    case 'paren': return evalExpr(n.e, e, cache);
    case 'not': { const v = evalExpr(n.e, e, cache); return v === null ? null : !v; }
    case 'and': { let r = true; for (const a of n.args) { const v = evalExpr(a, e, cache); if (v === false) return false; if (v === null) r = null; } return r; }
    case 'or': { let r = false; for (const a of n.args) { const v = evalExpr(a, e, cache); if (v === true) return true; if (v === null) r = null; } return r; }
    case 'eq': { const t = textOf(e, n.field); return t === null ? null : t === n.value; }
    case 'ne': return textOf(e, n.field) !== n.value;
    case 'isnull': return (textOf(e, n.field) === null) !== n.neg;
    case 'contains': { const t = textOf(e, n.field); const has = t !== null && t.toLowerCase().includes(n.value.toLowerCase()); return n.neg ? !has : has; }
    case 'in': { const t = textOf(e, n.field); const has = t !== null && n.values.includes(t); return n.neg ? !has : has; }
    case 'regex': {
      const t = textOf(e, n.field); if (t === null) return false;
      let re = cache.get(n); if (!re) { re = new RegExp(n.pattern, 'is'); cache.set(n, re); }
      return re.test(clampSubject(t));   // this engine runs the pattern in Node: bound the work (it is for tests and local use)
    }
    case 'num': {
      const t = textOf(e, n.field); if (t === null || !NUM_RE.test(t)) return false;
      const x = Number(t);
      return n.op === '>' ? x > n.value : n.op === '<' ? x < n.value : n.op === '>=' ? x >= n.value : x <= n.value;
    }
    default: throw new Error('unknown expression ' + n.t);
  }
}

// nulls last in either direction; numbers by value, text by code unit
function cmpValues(a, b, dir) {
  if (a === null || a === undefined) return (b === null || b === undefined) ? 0 : 1;
  if (b === null || b === undefined) return -1;
  const c = typeof a === 'number' && typeof b === 'number' ? a - b : a < b ? -1 : a > b ? 1 : 0;
  return dir === 'desc' ? -c : c;
}

function aggregate(a, evs) {
  if (a.fn === 'count') return a.field ? evs.filter((e) => textOf(e, a.field) !== null).length : evs.length;
  if (a.fn === 'count_distinct') return new Set(evs.map((e) => textOf(e, a.field)).filter((t) => t !== null)).size;
  const nums = evs.map((e) => textOf(e, a.field)).filter((t) => t !== null && NUM_RE.test(t)).map(Number);
  if (!nums.length) return null;
  if (a.fn === 'sum') return nums.reduce((x, y) => x + y, 0);
  if (a.fn === 'min') return Math.min(...nums);
  if (a.fn === 'max') return Math.max(...nums);
  return nums.reduce((x, y) => x + y, 0) / nums.length;
}

// events: envelopes of ONE tenant. Returns at most plan.limit + 1 rows (the caller trims and reports truncation).
function runPlan(plan, events) {
  const S = summarize(plan), cache = new Map();
  const from = plan.from ? Date.parse(plan.from) : null, to = plan.to ? Date.parse(plan.to) : null;
  let evs = events.filter((e) => {
    const t = Date.parse(eventTime(e));
    if ((from !== null && t < from) || (to !== null && t > to)) return false;
    for (const d of S.datasets) if (!datasetMatches(d.names, e.source_type)) return false;
    for (const f of S.filters) if (evalExpr(f, e, cache) !== true) return false;
    return true;
  });
  const lim = plan.limit + 1;

  let recs;
  if (plan.mode === 'comp') {
    const groups = new Map();
    for (const e of evs) {
      const vals = S.comp.by.map((f) => textOf(e, f));
      const key = JSON.stringify(vals);
      if (!groups.has(key)) groups.set(key, { vals, evs: [] });
      groups.get(key).evs.push(e);
    }
    recs = [...groups.values()].map((g) => {
      // fromEntries, not out[name] = ...: a field called __proto__ must be a column, not the object's prototype
      return { out: Object.fromEntries([...S.comp.by.map((f, i) => [f, g.vals[i]]), ...S.comp.aggs.map((a) => [a.alias, aggregate(a, g.evs)])]) };
    });
  } else if (plan.mode === 'fields') {
    recs = evs.map((e) => ({ out: Object.fromEntries(S.fields.map((i) => [i.alias, textOf(e, i.field)])), e }));
  } else {
    recs = evs.map((e) => ({ out: { _id: e.id, _time: new Date(eventTime(e)), source_type: e.source_type, collector_id: e.collector_id === undefined ? null : e.collector_id, _raw: e.raw, parsed: e.parsed || {} }, e }));
  }

  if (S.sort) {
    recs.sort((x, y) => {
      for (const k of S.sort) {
        const f = (r) => (k.alias ? r.out[k.name] : textOf(r.e, k.name));
        const c = cmpValues(f(x), f(y), k.dir);
        if (c) return c;
      }
      return 0;
    });
  } else if (plan.mode === 'comp') {
    const last = S.comp.aggs[S.comp.aggs.length - 1].alias;
    // ORDER BY <aggregate> DESC with no NULLS clause: PostgreSQL puts nulls first
    recs.sort((x, y) => { const a = x.out[last], b = y.out[last]; if (a === null || b === null) return a === b ? 0 : a === null ? -1 : 1; return b - a; });
  } else {
    recs.sort((x, y) => Date.parse(eventTime(y.e)) - Date.parse(eventTime(x.e)));
  }
  return recs.slice(0, lim).map((r) => r.out);
}

// Rule match spec (src/search/match-spec.js) over the envelopes of ONE tenant.
function runMatch(spec, events) {
  const cache = new Map(), after = Date.parse(spec.after);
  const capture = spec.group.by === 'capture' ? new RegExp(spec.group.pattern, 's') : null;
  const groups = new Map();
  for (const e of events) {
    if (!(Date.parse(eventTime(e)) > after)) continue;
    if (spec.filter && evalExpr(spec.filter, e, cache) !== true) continue;
    let key = 'all';
    if (spec.group.by === 'field') key = textOf(e, spec.group.field);
    else if (capture) { const m = capture.exec(clampSubject(e.raw)); key = m ? (m[1] !== undefined ? m[1] : m[0]) : null; if (key === '') key = null; }
    if (key === null) key = 'unknown';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(e);
  }
  const newestFirst = (x, y) => Date.parse(eventTime(y)) - Date.parse(eventTime(x)) || (x.id < y.id ? 1 : x.id > y.id ? -1 : 0);
  return [...groups].filter(([, evs]) => evs.length >= spec.threshold).map(([key, evs]) => {
    const sorted = [...evs].sort(newestFirst), times = evs.map((e) => Date.parse(eventTime(e)));
    return { key, n: evs.length, first_at: new Date(Math.min(...times)).toISOString(), last_at: new Date(Math.max(...times)).toISOString(), sample_ids: sorted.slice(0, 5).map((e) => e.id), sample_raw: sorted[0].raw };
  }).sort((a, b) => b.n - a.n || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0)).slice(0, spec.limit);
}

module.exports = { runPlan, runMatch, textOf, pgTimeText, pathText, COLUMN_NAMES };
