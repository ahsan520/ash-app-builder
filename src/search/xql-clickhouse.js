'use strict';
// Query plan -> ClickHouse SQL (the plan is defined in src/search/xql-plan.js). It must mean what the
// PostgreSQL translation means; tests/event-search-conformance.js holds both to the same results.
//
// Safety: every value (text, pattern, number, time, tenant) is a ClickHouse query parameter ({pN:Type}); field
// names reach the SQL only as parameters or as validated integers, and the table name is checked by the adapter.
// Output columns are named c0, c1, ... and mapped back to the user's names by the caller, so an alias such as
// `parsed` or `raw` cannot shadow a real column in the WHERE clause (ClickHouse aliases are visible everywhere).
//
// How events are stored (src/events/clickhouse-store.js): `parsed` is JSON text in a String column, times are
// DateTime64(3, 'UTC'), collector_id and event_time are Nullable.
//
// Known differences from PostgreSQL (documented in docs/event-store.md):
//   * the regex dialect is RE2 (no lookahead, no back-references); a pattern PostgreSQL accepts but RE2 rejects fails
//     with BACKEND_ERROR
//   * the text of a whole object or array value keeps the stored (compact) JSON formatting
//   * numbers are compared and aggregated as Float64 (PostgreSQL uses exact numeric)
//   * text sorts by bytes (PostgreSQL by the database collation)

const { EventStoreError } = require('../events/event-store');
const { hasWildcard, globToLike } = require('./xql-plan');

const MAX_NUMERIC_SEGMENTS = 3;
const NUM_SEG = /^-?\d+$/;
// timestamp text the way PostgreSQL prints it: 2026-10-01 00:07:00 or 2026-10-01 00:07:00.12 (no trailing zeros)
const PG_TIME_TRIM = '(\\.\\d*?[1-9])0+$|\\.0+$';
const TS = 'coalesce(event_time, received_at)';
const NUM_RE = '^-?[0-9]+(\\.[0-9]+)?$';

class Emitter {
  constructor(tenant) { this.params = {}; this.n = 0; this.cache = new Map(); this.tenant = tenant; }
  bind(type, value) {
    const key = type + '\0' + value;
    if (this.cache.has(key)) return this.cache.get(key);
    const name = 'p' + this.n++;
    this.params[name] = value;
    const ref = `{${name}:${type}}`;
    this.cache.set(key, ref);
    return ref;
  }
  str(v) { return this.bind('String', String(v)); }

  fmtTime(expr) { return `replaceRegexpOne(toString(${expr}), ${this.str(PG_TIME_TRIM)}, ${this.str('\\1')})`; }

  // text of parsed.<path> as Nullable(String); a numeric segment is an array index when the container is an array,
  // and a plain key otherwise (parsed #>> '{a,0}' does the same)
  pathText(name) {
    const segs = name.split('.');
    if (segs.filter((s) => NUM_SEG.test(s)).length > MAX_NUMERIC_SEGMENTS) {
      throw new EventStoreError('NOT_IMPLEMENTED', `a path with more than ${MAX_NUMERIC_SEGMENTS} numeric parts is not supported on ClickHouse`);
    }
    const leaf = (keys) => {
      const k = keys.join(', ');
      const t = `JSONType(parsed, ${k})`;
      return `multiIf(${t} = 'String', toNullable(JSONExtractString(parsed, ${k})), ${t} IN ('Int64', 'UInt64', 'Double', 'Bool', 'Array', 'Object'), toNullable(JSONExtractRaw(parsed, ${k})), NULL)`;
    };
    const walk = (i, acc) => {
      if (i === segs.length) return leaf(acc);
      const seg = segs[i];
      const asKey = this.str(seg);
      if (!NUM_SEG.test(seg)) return walk(i + 1, acc.concat(asKey));
      const idx = Number(seg);
      const asIdx = String(idx >= 0 ? idx + 1 : idx);
      const container = acc.length ? `JSONType(parsed, ${acc.join(', ')})` : 'JSONType(parsed)';
      return `if(${container} = 'Array', ${walk(i + 1, acc.concat(asIdx))}, ${walk(i + 1, acc.concat(asKey))})`;
    };
    return walk(0, []);
  }

  field(name) {          // non-text form where it matters (the time columns)
    if (name[0] === '@') return this.pathText(name.slice(1));   // explicit parsed path
    switch (name) {
      case '_raw': case 'raw': return 'raw';
      case 'source_type': case 'dataset': return 'toString(source_type)';
      case 'collector_id': return 'collector_id';
      case '_id': return 'toString(id)';
      case '_insert_time': return 'received_at';
      case '_time': return TS;
      default: return this.pathText(name);
    }
  }
  textField(name) {
    if (name === '_insert_time') return this.fmtTime('received_at');
    if (name === '_time') return this.fmtTime(TS);
    return this.field(name);
  }
  num(name) { const e = this.field(name); return `if(match(${e}, ${this.str(NUM_RE)}), toFloat64OrNull(${e}), NULL)`; }

  expr(n) {
    switch (n.t) {
      case 'paren': return `(${this.expr(n.e)})`;
      case 'not': return `NOT (${this.expr(n.e)})`;
      case 'and': return n.args.map((a) => `(${this.expr(a)})`).join(' AND ');
      case 'or': return n.args.map((a) => `(${this.expr(a)})`).join(' OR ');
      case 'contains': {
        const p = this.str('%' + String(n.value).replace(/[\\%_]/g, '\\$&') + '%');
        const has = `ifNull(ilike(${this.textField(n.field)}, ${p}), 0)`;
        return n.neg ? `NOT ${has}` : has;
      }
      case 'in': {
        const has = `ifNull(${this.textField(n.field)} IN (${n.values.map((v) => this.str(v)).join(', ')}), 0)`;
        return n.neg ? `NOT ${has}` : has;
      }
      case 'isnull': return `${this.textField(n.field)} IS ${n.neg ? 'NOT ' : ''}NULL`;
      case 'eq': return `${this.textField(n.field)} = ${this.str(n.value)}`;
      case 'ne': return `ifNull(${this.textField(n.field)} != ${this.str(n.value)}, 1)`;
      case 'regex': return `ifNull(match(${this.textField(n.field)}, concat('(?is)', ${this.str(n.pattern)})), 0)`;
      case 'num': return `ifNull(${this.num(n.field)} ${n.op} ${this.bind('Float64', String(n.value))}, 0)`;
      default: throw new Error('unknown expression ' + n.t);
    }
  }
}

// plan -> { sql, params, columns:[{ c, name }], mode, limit }. Rows come back keyed c0, c1, ...; `columns` maps them.
function toClickHouse(plan, tenant, table) {
  const E = new Emitter(tenant);
  const where = [`tenant_id = ${E.bind('UUID', tenant)}`];
  if (plan.from) where.push(`${TS} >= ${E.bind("DateTime64(3, 'UTC')", plan.from.replace('T', ' ').replace(/Z$/, ''))}`);
  if (plan.to) where.push(`${TS} <= ${E.bind("DateTime64(3, 'UTC')", plan.to.replace('T', ' ').replace(/Z$/, ''))}`);
  let select = null, group = null, aggs = null, order = null;

  for (const s of plan.stages) {
    if (s.op === 'dataset') {
      const exact = s.names.filter((n) => !hasWildcard(n)), globs = s.names.filter(hasWildcard), parts = [];
      if (!globs.some((n) => /^\*+$/.test(n))) {
        if (exact.length) parts.push(`source_type IN (${exact.map((n) => E.str(n)).join(', ')})`);
        for (const g of globs) parts.push(`like(toString(source_type), ${E.str(globToLike(g))})`);
        where.push(parts.length === 1 ? parts[0] : `(${parts.join(' OR ')})`);
      }
    }
    else if (s.op === 'filter') where.push(`(${E.expr(s.expr)})`);
    else if (s.op === 'fields') select = s.items.map((i) => ({ name: i.alias, expr: E.textField(i.field) }));
    else if (s.op === 'comp') {
      aggs = s.aggs.map((a) => {
        let e;
        if (a.fn === 'count') e = a.field ? `count(${E.field(a.field)})` : 'count()';
        else if (a.fn === 'count_distinct') e = `uniqExact(${E.textField(a.field)})`;
        else e = `${a.fn}(${E.num(a.field)})`;
        return { name: a.alias, expr: e };
      });
      group = s.by.map((f) => ({ name: f, expr: E.textField(f) }));
      select = group.concat(aggs);
    } else if (s.op === 'sort') {
      order = s.keys.map((k) => ({ name: k.name, alias: k.alias, dir: k.dir.toUpperCase(), expr: k.alias ? null : (k.name === '_time' ? TS : E.field(k.name)) }));
    }
  }

  let cols;
  if (plan.mode === 'raw') {
    cols = [
      { name: '_id', expr: 'toString(id)' }, { name: '_time', expr: `toString(${TS})` }, { name: 'source_type', expr: 'toString(source_type)' },
      { name: 'collector_id', expr: 'collector_id' }, { name: '_raw', expr: 'raw' }, { name: 'parsed', expr: 'parsed' },
    ];
  } else cols = select;
  const columns = cols.map((c, i) => ({ c: 'c' + i, name: c.name }));
  const cOf = (name) => columns.find((c) => c.name === name).c;

  let orderSql;
  if (order) orderSql = order.map((k) => `${k.alias ? cOf(k.name) : k.expr} ${k.dir} NULLS LAST`).join(', ');
  else if (plan.mode === 'comp') orderSql = `${aggs[aggs.length - 1].expr} DESC NULLS FIRST`;   // like PostgreSQL: DESC with no NULLS clause puts nulls first
  else orderSql = `${TS} DESC`;

  const sql = `SELECT ${cols.map((c, i) => `${c.expr} AS c${i}`).join(', ')} FROM ${table} FINAL WHERE ${where.join(' AND ')}`
    + (plan.mode === 'comp' && group.length ? ` GROUP BY ${group.map((_, i) => i + 1).join(', ')}` : '')
    + ` ORDER BY ${orderSql} LIMIT ${plan.limit + 1}`;
  return { sql, params: E.params, columns, mode: plan.mode, limit: plan.limit };
}

// Rule match spec (src/search/match-spec.js) -> ClickHouse SQL. Output columns are c0..c5 (see toClickHouse for why).
// The five newest ids come from sorting (time, id) pairs of the group; that holds one small tuple per matching
// event, which is fine for rule time frames but is the thing to revisit if a single group can reach many millions.
function matchToClickHouse(spec, tenant, table) {
  const E = new Emitter(tenant);
  const dt = (iso) => E.bind("DateTime64(3, 'UTC')", iso.replace('T', ' ').replace(/Z$/, ''));
  const where = [`tenant_id = ${E.bind('UUID', tenant)}`, `${TS} > ${dt(spec.after)}`];
  if (spec.filter) where.push(`(${E.expr(spec.filter)})`);
  let g;
  if (spec.group.by === 'none') g = "'all'";
  else if (spec.group.by === 'field') g = `ifNull(${E.textField(spec.group.field)}, 'unknown')`;
  else g = `ifNull(nullIf(extract(raw, ${E.str(spec.group.pattern)}), ''), 'unknown')`;
  const thr = E.bind('UInt32', String(spec.threshold));
  const key = `(${TS}, toString(id))`;
  const sql = `SELECT ${g} AS c0, count() AS c1, toString(min(${TS})) AS c2, toString(max(${TS})) AS c3,
           arrayMap(x -> x.2, arraySlice(arrayReverseSort(groupArray(${key})), 1, 5)) AS c4, argMax(raw, ${key}) AS c5
    FROM ${table} FINAL WHERE ${where.join(' AND ')}
    GROUP BY 1 HAVING count() >= ${thr} ORDER BY c1 DESC, c0 ASC LIMIT ${spec.limit | 0}`;
  return { sql, params: E.params };
}

module.exports = { toClickHouse, matchToClickHouse };
