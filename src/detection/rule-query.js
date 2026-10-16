'use strict';
// Shared by the rule runner and the "Test" endpoint: validates a rule definition and turns it into a rule
// match spec (src/search/match-spec.js) that any event store runs: getEventStore().matchGroups(tenantId, spec).
// No SQL is built here. The filter is the query plan's expression tree, so field names and values are data,
// and the group-by is one of a few fixed forms.

const SOURCE_IP_PATTERN = '(?:from|rhost=|src=)\\s*([0-9]{1,3}(?:\\.[0-9]{1,3}){3})';
// group_by choices that are not "field:<path>"
const GROUPS = {
  none: { by: 'none' },
  host: { by: 'field', field: '@host' },
  source_ip: { by: 'capture', pattern: SOURCE_IP_PATTERN },
};
const isNamedGroup = (g) => Object.prototype.hasOwnProperty.call(GROUPS, g);
const COLUMN_FIELDS = new Set(['raw', 'source_type', 'collector_id']);
const FIELD_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const OPS = ['contains', 'equals', 'not_equals', 'regex'];
const { parseCondition, XqlError } = require('../search/xql');
const { validateMatchSpec } = require('../search/match-spec');
const { PlanError } = require('../search/xql-plan');
const { assertSafeRegex } = require('../security/regex-safety');
const ID_RE = /^[a-z_]{1,30}$/;
const BUILDER_OPS = ['=', '!=', 'contains', 'not contains', '~=', 'in', 'not in', '>', '<', 'is set', 'is empty'];
const EVENT_TYPES = ['process', 'file', 'network', 'image_load', 'registry', 'event_log', 'network_connections'];
const RUN_EVERY = [1, 5, 15, 30, 60];

const int = (v, d, lo, hi) => {
  const n = Number(v === undefined || v === '' || v === null ? d : v);
  return Number.isInteger(n) && n >= lo && n <= hi ? n : null;
};
function regexOk(s) {
  try { assertSafeRegex(s, { mode: 'pg' }); new RegExp(s); return true; } catch { return false; }
}

// Returns { def } (cleaned definition) or { error } (message for the user).
function normalizeDefinition(input) {
  const d = input && typeof input === 'object' ? input : {};
  const out = {};
  out.regex = typeof d.regex === 'string' ? d.regex.trim() : '';
  if (out.regex && !regexOk(out.regex)) return { error: 'Match text is not a valid, safe regular expression (max 500 chars, no back-references)' };
  out.source_type = typeof d.source_type === 'string' ? d.source_type.trim().slice(0, 100) : '';
  out.filters = [];
  for (const f of Array.isArray(d.filters) ? d.filters : []) {
    if (!f || !f.field) continue;
    const field = String(f.field).trim();
    if (!FIELD_RE.test(field)) return { error: 'Invalid field name: ' + field.slice(0, 40) };
    if (!OPS.includes(f.op)) return { error: 'Invalid filter operator' };
    const value = String(f.value ?? '').slice(0, 500);
    if (f.op === 'regex' && !regexOk(value)) return { error: 'Filter on ' + field + ' is not a valid, safe regular expression (max 500 chars, no back-references)' };
    out.filters.push({ field, op: f.op, value });
  }
  if (out.filters.length > 10) return { error: 'At most 10 filters' };
  out.xql = typeof d.xql === 'string' ? d.xql.trim() : '';
  if (out.xql) {
    try { parseCondition(out.xql); } catch (e) { if (e instanceof XqlError) return { error: 'XQL condition: ' + e.message }; throw e; }
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
  if (isNamedGroup(gb) || (gb.startsWith('field:') && FIELD_RE.test(gb.slice(6)))) out.group_by = gb;
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
  // the whole rule must be something the event store can run (limits on conditions, patterns and names)
  try { buildRuleMatch(out); } catch (e) { if (e instanceof PlanError) return { error: 'Rule is not valid: ' + e.message }; throw e; }
  return { def: out };
}

// A rule's conditions as one plan expression (all of them must hold), or null when it has none.
// Rule fields use "@path" for anything that is not raw / source_type / collector_id, so a rule field named
// "dataset" or "_time" is still the parsed field the author meant.
function ruleFilter(d) {
  const parts = [];
  if (d.regex) parts.push({ t: 'regex', field: 'raw', pattern: d.regex });
  if (d.source_type) parts.push({ t: 'eq', field: 'source_type', value: d.source_type });
  if (d.xql) {   // BIOC condition on parsed / xdm.* fields (XQL names keep their XQL meaning)
    for (const s of parseCondition(d.xql)) parts.push(s.op === 'dataset' ? { t: 'eq', field: 'source_type', value: String(s.names[0]) } : s.expr);
  }
  for (const f of d.filters || []) {
    const field = COLUMN_FIELDS.has(f.field) ? f.field : '@' + f.field;
    if (f.op === 'equals') parts.push({ t: 'eq', field, value: f.value });
    else if (f.op === 'not_equals') parts.push({ t: 'ne', field, value: f.value });
    else if (f.op === 'regex') parts.push({ t: 'regex', field, pattern: f.value });
    else parts.push({ t: 'contains', field, value: f.value, neg: false });
  }
  // each part is wrapped in a paren node: an XQL condition may be an `or`, and the emitters only add
  // parentheses where the XQL parser put them
  return parts.length === 0 ? null : parts.length === 1 ? parts[0] : { t: 'and', args: parts.map((e) => ({ t: 'paren', e })) };
}

// The match spec for one rule: events inside its time frame that meet its conditions, grouped, with a
// threshold. `now` (a Date, default: now) and `limit` are for the caller. Throws PlanError if the rule
// cannot be expressed (too many or too long conditions).
function buildRuleMatch(d, { now = new Date(), limit } = {}) {
  const gb = d.group_by || 'none';
  const group = isNamedGroup(gb) ? GROUPS[gb] : { by: 'field', field: '@' + gb.slice(6) };
  const spec = {
    after: new Date(now.getTime() - d.window_minutes * 60000).toISOString(),
    filter: ruleFilter(d), group, threshold: d.threshold,
  };
  if (limit) spec.limit = limit;
  return validateMatchSpec(spec);
}

module.exports = { normalizeDefinition, buildRuleMatch, ruleFilter, GROUPS, SOURCE_IP_PATTERN, RUN_EVERY, OPS };
