'use strict';
// Cases (task CS1, docs/cases.md): the rules that need no database. Input checks, the worst severity of a set of alerts, what counts as a
// change, and how a timeline entry reads. src/cases/service.js does the SQL; src/gateway/routes/cases.js does the HTTP.
// Every parse function returns { value } or { error: { code, message } } and never throws.
// (src/cases/cases-engine.js is an older placeholder from the first design; nothing uses it, and this module does not touch it.)

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const STATUSES = ['open', 'investigating', 'closed'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];   // worst first
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const STATUS_LABEL = { open: 'Open', investigating: 'Investigating', closed: 'Closed' };
const LIMITS = { title: 200, description: 5000, note: 2000, alertsPerRequest: 50, pageMax: 200, pageDefault: 50, offsetMax: 100000 };
const KINDS = ['created', 'status', 'owner', 'severity', 'title', 'description', 'alert_added', 'alert_removed', 'note'];

const bad = (message, code = 'INVALID_BODY') => ({ error: { code, message } });
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// The worst severity in a list of severities; 'medium' when there are none (a case with no alerts yet).
function topSeverity(list) {
  const known = (list || []).filter((s) => SEV_RANK[s]);
  return known.length ? known.reduce((a, b) => (SEV_RANK[b] > SEV_RANK[a] ? b : a)) : 'medium';
}

function title(v) {
  if (typeof v !== 'string' || !v.trim() || v.trim().length > LIMITS.title) return bad(`title must be 1-${LIMITS.title} characters`);
  return { value: v.trim() };
}
function description(v) {
  if (v === null || v === undefined) return { value: null };
  if (typeof v !== 'string' || v.length > LIMITS.description) return bad(`description must be text of at most ${LIMITS.description} characters, or null`);
  return { value: v.trim() || null };
}
function severity(v) {
  if (!SEVERITIES.includes(v)) return bad(`severity must be one of ${SEVERITIES.join(', ')}`);
  return { value: v };
}
function status(v) {
  if (!STATUSES.includes(v)) return bad(`status must be one of ${STATUSES.join(', ')}`);
  return { value: v };
}
function ownerId(v) {
  if (v === null) return { value: null };
  if (typeof v !== 'string' || !UUID_RE.test(v)) return bad('owner_id must be a user id, or null for no owner');
  return { value: v.toLowerCase() };
}
// 1..50 distinct alert ids (lower-cased), or none at all when `optional`.
function alertIds(v, optional) {
  if (v === undefined && optional) return { value: [] };
  if (!Array.isArray(v) || (!optional && v.length === 0) || v.length > LIMITS.alertsPerRequest || v.some((x) => typeof x !== 'string' || !UUID_RE.test(x))) {
    return bad(`alert_ids must be a list of ${optional ? 'up to' : '1 to'} ${LIMITS.alertsPerRequest} alert ids`);
  }
  const ids = [...new Set(v.map((x) => x.toLowerCase()))];
  return { value: ids };
}

// body of POST /v1/cases
function parseCreate(body) {
  if (!isObj(body)) return bad('send a JSON object');
  const extra = Object.keys(body).filter((k) => !['title', 'description', 'severity', 'owner_id', 'alert_ids'].includes(k));
  if (extra.length) return bad(`unknown field: ${extra.join(', ')}`);
  const t = title(body.title); if (t.error) return t;
  const d = description(body.description); if (d.error) return d;
  const out = { title: t.value, description: d.value, severity: null, owner_id: null, alert_ids: [] };
  if (body.severity !== undefined) { const s = severity(body.severity); if (s.error) return s; out.severity = s.value; }
  if (body.owner_id !== undefined) { const o = ownerId(body.owner_id); if (o.error) return o; out.owner_id = o.value; }
  const a = alertIds(body.alert_ids, true); if (a.error) return a;
  out.alert_ids = a.value;
  return { value: out };
}

// body of PATCH /v1/cases/:id: only the fields that are present, and at least one
function parsePatch(body) {
  if (!isObj(body)) return bad('send a JSON object');
  const allowed = { title, description, severity, status, owner_id: ownerId };
  const extra = Object.keys(body).filter((k) => !has(allowed, k));
  if (extra.length) return bad(`unknown field: ${extra.join(', ')}`);
  const out = {};
  for (const k of Object.keys(allowed)) {
    if (!has(body, k)) continue;
    const r = allowed[k](body[k]); if (r.error) return r;
    out[k] = r.value;
  }
  if (!Object.keys(out).length) return bad('send at least one of: title, description, severity, status, owner_id');
  return { value: out };
}

// body of POST /v1/cases/:id/notes
function parseNote(body) {
  const t = isObj(body) && typeof body.body === 'string' ? body.body.trim() : '';
  if (!t || t.length > LIMITS.note) return bad(`body must be 1-${LIMITS.note} characters`);
  return { value: t };
}

// body of POST /v1/cases/:id/alerts
function parseAlertIds(body) {
  if (!isObj(body)) return bad('send a JSON object');
  return alertIds(body.alert_ids, false);
}

// query of GET /v1/cases. owner: 'me' needs a signed-in user.
function parseListQuery(q, userId) {
  const out = { status: 'active', owner: null, limit: LIMITS.pageDefault, offset: 0 };
  const st = q.status === undefined ? 'active' : String(q.status);
  if (!['active', 'all', ...STATUSES].includes(st)) return bad('status must be active, all, open, investigating or closed', 'INVALID_STATUS');
  out.status = st;
  if (q.owner !== undefined) {
    const o = String(q.owner);
    if (o === 'me') { if (!userId) return bad('owner=me needs a signed-in user', 'INVALID_OWNER'); out.owner = { me: userId }; }
    else if (o === 'unassigned') out.owner = { none: true };
    else if (UUID_RE.test(o)) out.owner = { id: o.toLowerCase() };
    else return bad('owner must be me, unassigned or a user id', 'INVALID_OWNER');
  }
  const num = (v, name, min, max) => { const n = Number(v); return Number.isInteger(n) && n >= min && n <= max ? n : null; };
  if (q.limit !== undefined) { out.limit = num(q.limit, 'limit', 1, LIMITS.pageMax); if (out.limit === null) return bad(`limit must be a whole number from 1 to ${LIMITS.pageMax}`, 'INVALID_PAGE'); }
  if (q.offset !== undefined) { out.offset = num(q.offset, 'offset', 0, LIMITS.offsetMax); if (out.offset === null) return bad(`offset must be a whole number from 0 to ${LIMITS.offsetMax}`, 'INVALID_PAGE'); }
  return { value: out };
}

// A closed case is read-only except to reopen it: a patch that leaves it closed may not change anything else.
// (Notes and reopening are always allowed; the service decides about alerts.)
function closedBlocks(beforeStatus, patch) {
  if (beforeStatus !== 'closed') return false;
  const stillClosed = patch.status === undefined || patch.status === 'closed';
  return stillClosed && Object.keys(patch).some((k) => k !== 'status');
}

// The timeline entries a patch makes, only for fields that really change, in a fixed order.
// before = { title, description, severity, status, owner_id, owner_name }; ownerNameAfter = the new owner's name (or null).
function changeEvents(before, patch, ownerNameAfter) {
  const out = [];
  if (patch.status !== undefined && patch.status !== before.status) out.push({ kind: 'status', data: { from: before.status, to: patch.status } });
  if (patch.owner_id !== undefined && patch.owner_id !== (before.owner_id || null)) out.push({ kind: 'owner', data: { from: before.owner_name || null, to: ownerNameAfter || null } });
  if (patch.severity !== undefined && patch.severity !== before.severity) out.push({ kind: 'severity', data: { from: before.severity, to: patch.severity } });
  if (patch.title !== undefined && patch.title !== before.title) out.push({ kind: 'title', data: { from: before.title, to: patch.title } });
  if (patch.description !== undefined && (patch.description || null) !== (before.description || null)) out.push({ kind: 'description', data: {} });
  return out;
}

// The words a person reads for one timeline entry. The server sends this text, so every client shows the same words.
function describeEvent(e) {
  const d = e.data || {};
  switch (e.kind) {
    case 'created': return d.alerts ? `Case created with ${d.alerts} alert${d.alerts === 1 ? '' : 's'}` : 'Case created';
    case 'status': return `Status: ${STATUS_LABEL[d.from] || d.from} → ${STATUS_LABEL[d.to] || d.to}`;
    case 'owner': return `Owner: ${d.from || 'nobody'} → ${d.to || 'nobody'}`;
    case 'severity': return `Severity: ${d.from} → ${d.to}`;
    case 'title': return `Title changed from "${d.from}" to "${d.to}"`;
    case 'description': return 'Description edited';
    case 'alert_added': return `Alert added: ${d.title || d.alert_id}`;
    case 'alert_removed': return `Alert removed: ${d.title || d.alert_id}`;
    case 'note': return e.body || '';
    default: return String(e.kind);
  }
}

module.exports = {
  UUID_RE, STATUSES, SEVERITIES, LIMITS, KINDS, STATUS_LABEL,
  topSeverity, parseCreate, parsePatch, parseNote, parseAlertIds, parseListQuery, closedBlocks, changeEvents, describeEvent,
};
