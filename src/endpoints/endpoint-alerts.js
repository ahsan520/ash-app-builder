'use strict';
// Endpoint alerts as the Endpoints section shows them (docs/endpoints.md, task E6b). The alerts themselves are ordinary events of source type
// `endpoint-alert` (E4d: a broker reads the manager's alert file; the `wazuh_alert` parsing rule adds alert_level, alert_severity, user, src_ip, file_path ...).
// This module is the read side only and holds no I/O: it turns a request's query string into an XQL query plan (src/search/xql-plan.js, no SQL, run by whichever
// event store the install uses), and turns the stored events back into the small shapes the portal draws, with the MITRE ATT&CK details split out per alert.
// Nothing here writes, and no value from a request reaches a query except as a bound text value of a validated plan.

const SOURCE_TYPE = 'endpoint-alert';
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
// The manager's rule level bands (the same bands as the parsing rule's alert_severity and the built-in rules).
const BANDS = { critical: [12, 15], high: [8, 11], medium: [5, 7], low: [0, 4] };
const WINDOWS = { '1h': 3600000, '24h': 86400000, '7d': 7 * 86400000, '30d': 30 * 86400000 };
const DEFAULT_WINDOW = '24h';
const MAX_LIMIT = 100, DEFAULT_LIMIT = 50, MAX_OFFSET = 900;   // offset + limit never goes past 1,000 events read from the store
const SAMPLE = 1000;                                            // the newest alerts the summary reads for its top lists
const MAX_TEXT = 200;
const RULE_ID_RE = /^[0-9]{1,10}$/;
const MITRE_RE = /^T[0-9]{4}(\.[0-9]{3})?$/;
const MAX_EXCLUDE = 20;
const QUERY_KEYS = ['window', 'severity', 'agent', 'rule', 'exclude_rule', 'mitre', 'q', 'limit', 'offset'];

const one = (v) => (Array.isArray(v) ? (v.length === 1 ? v[0] : undefined) : v);
function intIn(v, lo, hi, what) {
  const x = one(v);
  if (typeof x !== 'string' || !/^[0-9]{1,6}$/.test(x) || Number(x) < lo || Number(x) > hi) return { error: `${what} must be a whole number from ${lo} to ${hi}` };
  return { value: Number(x) };
}
const plainText = (s) => typeof s === 'string' && s.length >= 1 && s.length <= MAX_TEXT && !/[\u0000-\u001f\u007f]/.test(s);

// Query string -> { error } or the validated filter. Unknown parameters are refused so a typo is not silently ignored.
function parseQuery(query, { now = Date.now() } = {}) {
  const q = query || {};
  for (const k of Object.keys(q)) if (!QUERY_KEYS.includes(k)) return { error: `unknown parameter "${k}"` };
  const out = { window: DEFAULT_WINDOW, severity: null, agent: null, rule: null, exclude: [], mitre: null, q: null, limit: DEFAULT_LIMIT, offset: 0 };
  const w = one(q.window);
  if (q.window !== undefined) { if (typeof w !== 'string' || !Object.prototype.hasOwnProperty.call(WINDOWS, w)) return { error: `window must be one of ${Object.keys(WINDOWS).join(', ')}` }; out.window = w; }
  if (q.severity !== undefined && q.severity !== '') { const s = one(q.severity); if (!SEVERITIES.includes(s)) return { error: `severity must be one of ${SEVERITIES.join(', ')}` }; out.severity = s; }
  if (q.agent !== undefined && q.agent !== '') { const a = one(q.agent); if (!plainText(a)) return { error: `agent must be text of 1 to ${MAX_TEXT} characters on one line` }; out.agent = a; }
  if (q.rule !== undefined && q.rule !== '') { const r = one(q.rule); if (typeof r !== 'string' || !RULE_ID_RE.test(r)) return { error: 'rule must be a rule id (digits)' }; out.rule = r; }
  if (q.exclude_rule !== undefined && q.exclude_rule !== '') {
    const x = one(q.exclude_rule); const ids = typeof x === 'string' ? [...new Set(x.split(','))] : null;
    if (!ids || ids.length > MAX_EXCLUDE || !ids.every((r) => RULE_ID_RE.test(r))) return { error: `exclude_rule must be up to ${MAX_EXCLUDE} rule ids (digits) separated by commas` };
    out.exclude = ids;
  }
  if (q.mitre !== undefined && q.mitre !== '') { const m = one(q.mitre); if (typeof m !== 'string' || !MITRE_RE.test(m)) return { error: 'mitre must be a technique id such as T1110 or T1110.003' }; out.mitre = m; }
  if (q.q !== undefined && q.q !== '') { const t = one(q.q); if (!plainText(t)) return { error: `q must be text of 1 to ${MAX_TEXT} characters on one line` }; out.q = t; }
  if (q.limit !== undefined) { const r = intIn(q.limit, 1, MAX_LIMIT, 'limit'); if (r.error) return r; out.limit = r.value; }
  if (q.offset !== undefined) { const r = intIn(q.offset, 0, MAX_OFFSET, 'offset'); if (r.error) return r; out.offset = r.value; }
  out.from = new Date(now - WINDOWS[out.window]).toISOString();
  return out;
}

// The filter conditions shared by the list and the summary (the summary ignores severity so its severity counts stay a breakdown of the rest).
function conditions(f, { withSeverity }) {
  const c = [];
  if (withSeverity && f.severity) c.push({ t: 'and', args: [{ t: 'num', field: '@alert_level', op: '>=', value: BANDS[f.severity][0] }, { t: 'num', field: '@alert_level', op: '<=', value: BANDS[f.severity][1] }] });
  if (f.agent) c.push({ t: 'eq', field: '@agent_name', value: f.agent });
  if (f.rule) c.push({ t: 'eq', field: '@rule_id', value: f.rule });
  if (f.exclude && f.exclude.length) c.push({ t: 'in', field: '@rule_id', values: f.exclude, neg: true });   // hide these rules
  if (f.mitre) c.push({ t: 'contains', field: '@mitre_ids', value: f.mitre, neg: false });   // T1110 also finds T1110.003: the id is a fixed width, so no other id contains it
  if (f.q) c.push({ t: 'or', args: ['@rule_description', '@agent_name', '@user', '@file_path', '@src_ip'].map((field) => ({ t: 'contains', field, value: f.q, neg: false })) });
  return c;
}
function stages(f, opts) {
  const s = [{ op: 'dataset', names: [SOURCE_TYPE], list: false }], c = conditions(f, opts);
  if (c.length) s.push({ op: 'filter', expr: c.length === 1 ? c[0] : { t: 'and', args: c } });
  return s;
}

// A raw-mode plan: the newest events first (the store's own order), offset + limit of them; `truncated` from the store says there are more.
function listPlan(f) { return { v: 1, from: f.from, to: null, stages: stages(f, { withSeverity: true }), mode: 'raw', limit: f.offset + f.limit, columns: null }; }
// The summary: exact counts per severity (a comp over the parsed severity), and the newest SAMPLE alerts for the top lists.
function severityPlan(f) {
  return { v: 1, from: f.from, to: null, stages: [...stages(f, { withSeverity: false }), { op: 'comp', aggs: [{ fn: 'count', field: null, alias: 'n' }], by: ['alert_severity'] }], mode: 'comp', limit: 20, columns: ['alert_severity', 'n'] };
}
function samplePlan(f) { return { v: 1, from: f.from, to: null, stages: stages(f, { withSeverity: false }), mode: 'raw', limit: SAMPLE, columns: null }; }

// ---- shaping -------------------------------------------------------------------------------------------------------------------------------------

const text = (v, max) => (v === undefined || v === null ? null : String(v).slice(0, max || 500));
const list = (v) => (typeof v === 'string' && v ? v.split(',').map((x) => x.trim()).filter(Boolean) : []);
const num = (v) => { const n = typeof v === 'number' ? v : typeof v === 'string' && /^-?[0-9]+$/.test(v) ? Number(v) : NaN; return Number.isFinite(n) ? n : null; };
const oneLine = (v) => (v === null ? null : v.replace(/\s+/g, ' ').trim());
const severityOf = (level) => (level === null ? null : level >= 12 ? 'critical' : level >= 8 ? 'high' : level >= 5 ? 'medium' : 'low');

// ATT&CK technique page of a valid id (T1110 -> .../techniques/T1110/, T1110.003 -> .../techniques/T1110/003/). Only a well-formed id gets a link.
const mitreUrl = (id) => (MITRE_RE.test(id) ? 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/' : null);

// The alert's MITRE ATT&CK details. The manager writes three lists: technique ids, the technique names (same order as the ids) and the tactics those techniques
// belong to (a different list: one tactic can cover several techniques, so they are NOT paired with the ids). A name list of another length than the id list
// (a name that itself holds a comma, say) is not paired at all rather than paired wrongly.
function mitreOf(parsed) {
  const p = parsed || {}, ids = list(p.mitre_ids), names = list(p.mitre_techniques), tactics = list(p.mitre_tactics);
  const paired = names.length === ids.length;
  return {
    techniques: ids.map((id, i) => ({ id, name: paired ? names[i] : null, url: mitreUrl(id) })),
    unpaired_names: paired ? [] : names,
    tactics,
  };
}

// An envelope -> what the list shows. `detail` adds the long text and every extra field the broker sent.
function shape(e, { detail = false } = {}) {
  const p = e.parsed || {}, level = num(p.alert_level !== undefined ? p.alert_level : p.rule_level);
  const out = {
    id: e.id, time: e.event_time || e.received_at, received_at: e.received_at,
    rule_id: text(p.rule_id, 20), level, severity: SEVERITIES.includes(p.alert_severity) ? p.alert_severity : severityOf(level),
    description: oneLine(text(p.alert_name !== undefined ? p.alert_name : p.rule_description, 500)),
    agent: { id: text(p.agent_id, 20), name: text(p.agent_name, 200), ip: text(p.agent_ip, 64) },
    groups: list(p.rule_groups).slice(0, 30), mitre: mitreOf(p),
    file_path: text(p.file_path, 500), file_event: text(p.file_event, 50), user: text(p.user, 200), src_ip: text(p.src_ip, 64),
  };
  if (detail) {
    out.manager = text(p.manager_name, 200); out.decoder = text(p.decoder_name, 200); out.location = text(p.location, 500); out.alert_ref = text(p.alert_id, 100);
    out.full_log = text(p.full_log, 2000);
    // Everything the broker flattened from the alert's data and file integrity objects (data_<path>, syscheck_<path>). The wazuh marker field and the grouping keys are not shown.
    out.data = {}; out.file_integrity = {};
    for (const [k, v] of Object.entries(p)) {
      if (v === null || v === undefined || typeof v === 'object') continue;
      if (k.startsWith('data_')) out.data[k.slice(5)] = text(v, 500);
      else if (k.startsWith('syscheck_')) out.file_integrity[k.slice(9)] = text(v, 500);
    }
  }
  return out;
}

// Top lists from a sample of events (already shaped or raw envelopes). Counts are of the sample, which the caller says out loud.
function topLists(events, n = 10) {
  const rules = new Map(), agents = new Map(), tech = new Map(), tactics = new Map();
  const bump = (m, key, init) => { const r = m.get(key); if (r) r.count += 1; else m.set(key, { ...init, count: 1 }); };
  for (const e of events) {
    const a = shape(e);
    if (a.rule_id) bump(rules, a.rule_id, { rule_id: a.rule_id, description: a.description, level: a.level });
    if (a.agent.name) bump(agents, a.agent.name, { name: a.agent.name });
    for (const t of a.mitre.techniques) bump(tech, t.id, { id: t.id, name: t.name, url: t.url });
    for (const t of a.mitre.tactics) bump(tactics, t, { name: t });
  }
  const top = (m) => [...m.values()].sort((x, y) => y.count - x.count || ((x.id || x.rule_id || x.name) < (y.id || y.rule_id || y.name) ? -1 : 1)).slice(0, n);
  return { rules: top(rules), agents: top(agents), techniques: top(tech), tactics: top(tactics) };
}

// comp rows -> { critical, high, medium, low, unknown, total }. A row with no severity (an alert the parsing rule did not reach) counts as unknown.
function severityCounts(rows) {
  const out = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 };
  for (const r of rows || []) {
    const n = Number(r.n); if (!Number.isFinite(n)) continue;
    const k = SEVERITIES.includes(r.alert_severity) ? r.alert_severity : 'unknown';
    out[k] += n; out.total += n;
  }
  return out;
}

// ---- MITRE on the ASIX alerts raised from endpoint alerts (E4f) ---------------------------------------------------------------------------------------
// The rule runner raises an ASIX alert per group of endpoint-alert events (the E4e rules). The built-in rules carry no ATT&CK list of their own (which technique applies
// depends on the manager rule that fired), so each alert takes it from its sample events: the union of the techniques and tactics of the events the alert was raised from.
const MAX_ALERT_TECHNIQUES = 20, MAX_ALERT_TACTICS = 14;

// Union of the MITRE details of several events (envelopes or { parsed } objects), in the order first seen, without duplicates.
function mitreOfEvents(events) {
  const tech = new Map(), tactics = new Set();
  for (const e of events || []) {
    const m = mitreOf(e && e.parsed);
    for (const t of m.techniques) { const old = tech.get(t.id); if (!old) tech.set(t.id, { id: t.id, name: t.name }); else if (!old.name && t.name) old.name = t.name; }
    for (const t of m.tactics) tactics.add(t);
  }
  return { techniques: [...tech.values()].slice(0, MAX_ALERT_TECHNIQUES), tactics: [...tactics].slice(0, MAX_ALERT_TACTICS) };
}

// What is stored in an alert's details.mitre -> what the alert view shows (a link only for a well-formed id). Anything of the wrong shape is ignored, not trusted.
function mitreView(stored) {
  const s = stored && typeof stored === 'object' ? stored : {};
  const str = (v, n) => (typeof v === 'string' ? v.replace(/\s+/g, ' ').trim().slice(0, n) : '');
  const techniques = (Array.isArray(s.techniques) ? s.techniques : []).slice(0, MAX_ALERT_TECHNIQUES)
    .map((t) => ({ id: str(t && t.id, 20), name: str(t && t.name, 200) || null })).filter((t) => t.id).map((t) => ({ ...t, url: mitreUrl(t.id) }));
  const tactics = (Array.isArray(s.tactics) ? s.tactics : []).slice(0, MAX_ALERT_TACTICS).map((t) => str(t, 100)).filter(Boolean);
  return { techniques, tactics };
}

// For the rule runner: the MITRE details of each group the rule matched, read from the groups' sample events through the event store (one batched read per cycle).
// Returns Map(group key -> { techniques, tactics }) with only the groups that have something. The caller treats a failure as "no MITRE", never as a failure to alert.
async function mitreForGroups(store, tenantId, rows) {
  const ids = [...new Set((rows || []).flatMap((r) => (Array.isArray(r.sample_ids) ? r.sample_ids : [])))];
  const byId = new Map();
  for (let i = 0; i < ids.length; i += 500) for (const e of await store.getByIds(tenantId, ids.slice(i, i + 500))) byId.set(e.id, e);
  const out = new Map();
  for (const r of rows || []) {
    const m = mitreOfEvents((r.sample_ids || []).map((id) => byId.get(id)).filter(Boolean));
    if (m.techniques.length || m.tactics.length) out.set(r.gkey !== undefined ? r.gkey : r.key, m);
  }
  return out;
}

module.exports = {
  mitreOfEvents, mitreView, mitreForGroups, MAX_ALERT_TECHNIQUES, MAX_ALERT_TACTICS, SOURCE_TYPE, SEVERITIES, BANDS, WINDOWS, DEFAULT_WINDOW, MAX_LIMIT, DEFAULT_LIMIT, MAX_OFFSET, MAX_EXCLUDE, SAMPLE, QUERY_KEYS, MITRE_RE,
  parseQuery, listPlan, severityPlan, samplePlan, shape, mitreOf, mitreUrl, topLists, severityCounts };
