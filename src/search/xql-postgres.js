'use strict';
// Query plan -> PostgreSQL SQL (the plan is defined in src/search/xql-plan.js). Everything the user typed is
// bound as a parameter ($n) or was checked against a strict identifier pattern when the plan was parsed or
// validated; nothing is concatenated into the SQL. The SQL is the same text the old one-pass compiler made.

const { MAX_LIMIT, hasWildcard, globToLike } = require('./xql-plan');

const TS = 'COALESCE(event_time, received_at)';
const COLUMNS = { _raw: 'raw', raw: 'raw', source_type: 'source_type', dataset: 'source_type', collector_id: 'collector_id', _id: 'id::text', _insert_time: 'received_at', _time: TS };

class Emitter {
  // With `shared` (an existing parameter array) it only produces conditions and binds into that array; the
  // caller owns tenant and time filtering. Used by BIOC rules.
  constructor(values) { this.values = values; }
  bind(v) { this.values.push(v); return '$' + this.values.length; }
  field(name) {
    if (name[0] === '@') return `(parsed #>> ${this.bind(name.slice(1).split('.'))}::text[])`;   // explicit parsed path
    if (Object.prototype.hasOwnProperty.call(COLUMNS, name)) return COLUMNS[name];
    return `(parsed #>> ${this.bind(name.split('.'))}::text[])`;
  }
  textField(name) { const e = this.field(name); return name === '_time' || name === '_insert_time' ? `(${e})::text` : e; }
  num(name) { const e = this.field(name); return `(CASE WHEN (${e})::text ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN (${e})::text::numeric END)`; }
  expr(n) {
    switch (n.t) {
      case 'paren': return `(${this.expr(n.e)})`;
      case 'not': return `NOT (${this.expr(n.e)})`;
      case 'and': return n.args.map((a) => this.expr(a)).join(' AND ');
      case 'or': return n.args.map((a) => this.expr(a)).reduce((e, x) => `(${e}) OR (${x})`);
      case 'contains': {
        const fe = this.textField(n.field);
        const p = this.bind('%' + String(n.value).replace(/[\\%_]/g, '\\$&') + '%');
        return n.neg ? `NOT COALESCE(${fe} ILIKE ${p}, false)` : `COALESCE(${fe} ILIKE ${p}, false)`;
      }
      case 'in': {
        const fe = this.textField(n.field);
        const ps = n.values.map((v) => this.bind(String(v)));
        return `${n.neg ? 'NOT ' : ''}COALESCE(${fe} IN (${ps.join(', ')}), false)`;
      }
      case 'isnull': return `${this.textField(n.field)} ${n.neg ? 'IS NOT NULL' : 'IS NULL'}`;
      case 'eq': { const fe = this.textField(n.field); return `${fe} = ${this.bind(String(n.value))}`; }
      case 'ne': { const fe = this.textField(n.field); return `${fe} IS DISTINCT FROM ${this.bind(String(n.value))}`; }
      case 'regex': { const fe = this.textField(n.field); return `COALESCE(${fe} ~* ${this.bind(n.pattern)}, false)`; }
      case 'num': return `COALESCE(${this.num(n.field)} ${n.op} ${this.bind(n.value)}, false)`;
      default: throw new Error('unknown expression ' + n.t);
    }
  }
}

function datasetSql(E, s) {
  const exact = s.names.filter((n) => !hasWildcard(n)), globs = s.names.filter(hasWildcard);
  if (globs.some((n) => /^\*+$/.test(n))) return 'TRUE';   // dataset = *  : every source type
  const parts = [];
  if (exact.length === 1 && !s.list) parts.push(`source_type = ${E.bind(String(exact[0]))}`);
  else if (exact.length) parts.push(`source_type IN (${exact.map((n) => E.bind(String(n))).join(', ')})`);
  for (const g of globs) parts.push(`source_type LIKE ${E.bind(globToLike(g))}`);
  return parts.length === 1 ? parts[0] : `(${parts.join(' OR ')})`;
}

// plan -> { sql, values, mode, columns, limit }. The first parameter is the tenant.
function toSql(plan, tenantId) {
  const E = new Emitter([tenantId]);
  const where = ['tenant_id = $1'];
  if (plan.from) where.push(`${TS} >= ${E.bind(plan.from)}`);
  if (plan.to) where.push(`${TS} <= ${E.bind(plan.to)}`);
  let select = null, group = null, aggs = null, order = null;
  const aliases = new Set();

  for (const s of plan.stages) {
    if (s.op === 'dataset') where.push(datasetSql(E, s));
    else if (s.op === 'filter') where.push(`(${E.expr(s.expr)})`);
    else if (s.op === 'fields') {
      select = s.items.map((i) => ({ alias: i.alias, expr: E.textField(i.field) }));
      s.items.forEach((i) => aliases.add(i.alias));
    } else if (s.op === 'comp') {
      aggs = s.aggs.map((a) => {
        let e;
        if (a.fn === 'count') e = a.field ? `COUNT(${E.field(a.field)})` : 'COUNT(*)';
        else if (a.fn === 'count_distinct') e = `COUNT(DISTINCT ${E.textField(a.field)})`;
        else e = `${a.fn.toUpperCase()}(${E.num(a.field)})`;
        return { alias: a.alias, expr: e };
      });
      group = s.by.map((f) => ({ alias: f, expr: E.textField(f) }));
      select = group.concat(aggs);
      s.by.forEach((f) => aliases.add(f)); s.aggs.forEach((a) => aliases.add(a.alias));
    } else if (s.op === 'sort') {
      order = s.keys.map((k) => {
        const ref = k.alias ? `"${k.name}"` : k.name === '_time' ? TS : E.field(k.name);
        return `${ref} ${k.dir.toUpperCase()} NULLS LAST`;
      });
    }
  }

  let selectSql;
  if (plan.mode === 'raw') selectSql = `id::text AS "_id", ${TS} AS "_time", source_type, collector_id, raw AS "_raw", parsed`;
  else selectSql = select.map((x) => `${x.expr} AS "${x.alias}"`).join(', ');
  if (!order) order = plan.mode === 'comp' ? [`${aggs[aggs.length - 1].expr} DESC`] : [`${TS} DESC`];
  const lim = Math.min(plan.limit, MAX_LIMIT);
  const sql = `SELECT ${selectSql} FROM events WHERE ${where.join(' AND ')}`
    + (plan.mode === 'comp' && group.length ? ` GROUP BY ${group.map((_, i) => i + 1).join(', ')}` : '')
    + ` ORDER BY ${order.join(', ')} LIMIT ${lim + 1}`;
  return { sql, values: E.values, mode: plan.mode, columns: plan.columns, limit: lim };
}

// dataset / filter stages -> WHERE fragments that bind into `values`. No production code calls this any more (BIOC rules go
// through matchToSql); tests/xql-golden.test.js keeps it as the oracle that pins how conditions were compiled before the plan.
function conditionToSql(stages, values) {
  const E = new Emitter(values), out = [];
  for (const s of stages) out.push(s.op === 'dataset' ? `source_type = ${E.bind(String(s.names[0]))}` : `(${E.expr(s.expr)})`);
  return out;
}

// Rule match spec (src/search/match-spec.js) -> SQL. $1 is the tenant, $2 the lower bound, then the filter's values.
// Groups on the event time, like the search does; first/last come back as text so no precision is lost.
function matchToSql(spec, tenantId) {
  const E = new Emitter([tenantId]);
  const where = ['tenant_id = $1', `${TS} > ${E.bind(spec.after)}`];
  if (spec.filter) where.push(`(${E.expr(spec.filter)})`);
  let g;
  if (spec.group.by === 'none') g = "'all'";
  else if (spec.group.by === 'field') g = `COALESCE(${E.textField(spec.group.field)}, 'unknown')`;
  else g = `COALESCE(substring(raw from ${E.bind(spec.group.pattern)}::text), 'unknown')`;
  const thr = E.bind(spec.threshold);
  const sql = `SELECT ${g} AS gkey, COUNT(*)::int AS n, MIN(ts)::text AS first_at, MAX(ts)::text AS last_at,
           (array_agg(id::text ORDER BY ts DESC, id DESC))[1:5] AS sample_ids,
           (array_agg(raw ORDER BY ts DESC, id DESC))[1] AS sample_raw
    FROM (SELECT *, ${TS} AS ts FROM events WHERE ${where.join(' AND ')}) e
    GROUP BY 1 HAVING COUNT(*) >= ${thr}::int ORDER BY n DESC, gkey ASC LIMIT ${spec.limit | 0}`;
  return { sql, values: E.values };
}

module.exports = { toSql, conditionToSql, matchToSql, TS, COLUMNS };
