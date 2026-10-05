'use strict';
// Shared by the rule runner and the "Test" endpoint: validates a rule definition and turns it
// into one parameterised SQL query. Nothing user-supplied is ever concatenated into SQL:
// field names and values are bound parameters; group-by columns come from a fixed whitelist.

const SOURCE_IP_SQL =
  "substring(raw from '(?:from|rhost=|src=)\\s*([0-9]{1,3}(?:\\.[0-9]{1,3}){3})')";
const GROUP_EXPR = {
  none: "'all'",
  host: "COALESCE(parsed->>'host', 'unknown')",
  source_ip: `COALESCE(${SOURCE_IP_SQL}, 'unknown')`,
};
const COLUMN_FIELDS = new Set(['raw', 'source_type', 'collector_id']);
const FIELD_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const OPS = ['contains', 'equals', 'not_equals', 'regex'];
const { compileCondition, XqlError } = require('../search/xql');
const ID_RE = /^[a-z_]{1,30}$/;
const BUILDER_OPS = ['=', '!=', 'contains', 'not contains', '~=', 'in', 'not in', '>', '<', 'is set', 'is empty'];
const EVENT_TYPES = ['process', 'file', 'network', 'image_load', 'registry', 'event_log', 'network_connections'];
const RUN_EVERY = [1, 5, 15, 30, 60];

const int = (v, d, lo, hi) => {
  const n = Number(v === undefined || v === '' || v === null ? d : v);
  return Number.isInteger(n) && n >= lo && n <= hi ? n : null;
};
function regexOk(s) {
  if (s.length > 500) return false;
  try { new RegExp(s); return true; } catch { return false; }
}

// Returns { def } (cleaned definition) or { error } (message for the user).
function normalizeDefinition(input) {
  const d = input && typeof input === 'object' ? input : {};
  const out = {};
  out.regex = typeof d.regex === 'string' ? d.regex.trim() : '';
  if (out.regex && !regexOk(out.regex)) return { error: 'Match text is not a valid regular expression (max 500 chars)' };
  out.source_type = typeof d.source_type === 'string' ? d.source_type.trim().slice(0, 100) : '';
  out.filters = [];
  for (const f of Array.isArray(d.filters) ? d.filters : []) {
    if (!f || !f.field) continue;
    const field = String(f.field).trim();
    if (!FIELD_RE.test(field)) return { error: 'Invalid field name: ' + field.slice(0, 40) };
    if (!OPS.includes(f.op)) return { error: 'Invalid filter operator' };
    const value = String(f.value ?? '').slice(0, 500);
    if (f.op === 'regex' && !regexOk(value)) return { error: 'Filter on ' + field + ' is not a valid regular expression' };
    out.filters.push({ field, op: f.op, value });
  }
  if (out.filters.length > 10) return { error: 'At most 10 filters' };
  out.xql = typeof d.xql === 'string' ? d.xql.trim() : '';
  if (out.xql) {
    try { compileCondition(out.xql, [null]); } catch (e) { if (e instanceof XqlError) return { error: 'XQL condition: ' + e.message }; throw e; }
  }
  if (d.event_type && EVENT_TYPES.includes(d.event_type)) out.event_type = d.event_type;
  // The portal's BIOC builders keep their inputs so a rule can be reopened in the same builder:
  //   builder.rows      - the condition-list builder (match any/all)
  //   builder.entities  - the page builder (Process / File / ... blocks with a field grid)
  if (d.builder && typeof d.builder === 'object') {
    const cleanRows = (rows) => (Array.isArray(rows) ? rows : []).slice(0, 30)
      .filter((r) => r && FIELD_RE.test(String(r.field || '')) && BUILDER_OPS.includes(r.op))
      .map((r) => ({ field: String(r.field), op: r.op, value: String(r.value ?? '').slice(0, 500) }));
    const b = {};
    const rows = Array.isArray(d.builder.rows) && d.builder.rows.length <= 20 ? cleanRows(d.builder.rows) : [];
    if (rows.length) { b.match = d.builder.match === 'any' ? 'any' : 'all'; b.rows = rows; }
    if (Array.isArray(d.builder.entities) && d.builder.entities.length && d.builder.entities.length <= 8) {
      const ents = d.builder.entities.filter((e) => e && ID_RE.test(String(e.id || ''))).map((e) => ({ id: String(e.id), label: String(e.label || '').slice(0, 40), rows: cleanRows(e.rows) }));
      if (ents.length) {
        b.entities = ents;
        b.main = ID_RE.test(String(d.builder.main || '')) ? String(d.builder.main) : ents[0].id;
        b.subs = (Array.isArray(d.builder.subs) ? d.builder.subs : []).filter((x) => ID_RE.test(String(x))).slice(0, 12).map(String);
      }
    }
    if (b.rows || b.entities) out.builder = b;
  }
  if (!out.regex && !out.source_type && !out.filters.length && !out.xql) return { error: 'Add a condition, match text, a source type or at least one filter' };

  const gb = typeof d.group_by === 'string' ? d.group_by : 'none';
  if (GROUP_EXPR[gb] || (gb.startsWith('field:') && FIELD_RE.test(gb.slice(6)))) out.group_by = gb;
  else return { error: 'Invalid group by' };

  out.threshold = int(d.threshold, 1, 1, 100000);
  out.window_minutes = int(d.window_minutes, 5, 1, 10080);
  out.run_every_minutes = int(d.run_every_minutes, 1, 1, 1440);
  if (out.threshold === null) return { error: 'Threshold must be 1-100000' };
  if (out.window_minutes === null) return { error: 'Time frame must be 1 minute to 7 days' };
  if (out.run_every_minutes === null) return { error: 'Run interval must be 1-1440 minutes' };
  out.mode = d.mode === 'scheduled' ? 'scheduled' : 'realtime';
  if (out.mode === 'realtime') out.run_every_minutes = 1;

  const s = d.suppression || {};
  const sm = int(s.minutes, 60, 1, 10080);
  if (sm === null) return { error: 'Suppression duration must be 1 minute to 7 days' };
  out.suppression = { enabled: !!s.enabled, minutes: sm };
  return { def: out };
}

// One grouped query over the events inside the rule's time frame.
function buildMatch(tenantId, d, opts = {}) {
  const values = [tenantId, d.window_minutes];
  const bind = (v) => { values.push(v); return '$' + values.length; };
  const where = [
    'tenant_id = $1',
    'COALESCE(event_time, received_at) > localtimestamp - make_interval(mins => $2::int)',
  ];
  const fieldExpr = (f) => (COLUMN_FIELDS.has(f) ? f : `(parsed #>> ${bind(f.split('.'))}::text[])`);
  if (d.regex) where.push(`raw ~* ${bind(d.regex)}`);
  if (d.source_type) where.push(`source_type = ${bind(d.source_type)}`);
  if (d.xql) where.push(...compileCondition(d.xql, values));   // BIOC condition on parsed / xdm.* fields
  for (const f of d.filters || []) {
    const e = fieldExpr(f.field);
    if (f.op === 'equals') where.push(`${e} = ${bind(f.value)}`);
    else if (f.op === 'not_equals') where.push(`${e} IS DISTINCT FROM ${bind(f.value)}`);
    else if (f.op === 'regex') where.push(`${e} ~* ${bind(f.value)}`);
    else where.push(`${e} ILIKE ${bind('%' + f.value.replace(/[\\%_]/g, '\\$&') + '%')}`);
  }
  const gb = d.group_by || 'none';
  const groupExpr = GROUP_EXPR[gb] || `COALESCE(parsed #>> ${bind(gb.slice(6).split('.'))}::text[], 'unknown')`;
  const thr = bind(d.threshold);
  const limit = opts.limit ? `ORDER BY n DESC LIMIT ${Number(opts.limit) | 0}` : '';
  const text = `
    SELECT ${groupExpr} AS gkey, COUNT(*)::int AS n, MIN(ts) AS first_at, MAX(ts) AS last_at,
           (array_agg(id ORDER BY ts DESC))[1:5] AS sample_ids,
           (array_agg(raw ORDER BY ts DESC))[1] AS sample_raw
    FROM (
      SELECT id, raw, parsed, source_type, collector_id, COALESCE(event_time, received_at) AS ts
      FROM events WHERE ${where.join(' AND ')}
    ) e
    GROUP BY 1 HAVING COUNT(*) >= ${thr}::int ${limit}`;
  return { text, values };
}

module.exports = { normalizeDefinition, buildMatch, GROUP_EXPR, RUN_EVERY, OPS };
