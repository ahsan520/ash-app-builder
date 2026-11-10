'use strict';
// Database side of cases (task CS1, docs/cases.md). Every function takes an open tenant-scoped client (from db.withTenant) and filters on
// tenant_id explicitly, because the API connects as the table owner, which bypasses row-level security (same rule as src/packs/service.js).
// Functions that can be refused return { code } instead of throwing: NOT_FOUND, CASE_CLOSED, OWNER_NOT_FOUND, ALERTS_NOT_FOUND, ALERTS_TAKEN, NOT_ATTACHED.
const model = require('./model');

const SEV_ORDER = "CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END";
const LOCK_NAMESPACE = 7001;   // pg_advisory_xact_lock(namespace, hash of tenant id): one case number is handed out at a time per tenant

// Who did this: { id, name }. A user id that is not a user of this tenant (a service account) is recorded by name only, never as a foreign key.
async function resolveActor(client, tenantId, userId) {
  if (userId) {
    const u = await client.query('SELECT id, username FROM users WHERE id = $1 AND tenant_id = $2', [userId, tenantId]);
    if (u.rows.length) return { id: u.rows[0].id, name: u.rows[0].username };
  }
  return { id: null, name: 'service account' };
}

const addEvent = (client, tenantId, caseId, actor, kind, data, body) => client.query(
  `INSERT INTO case_events (tenant_id, case_id, kind, actor_id, actor_name, body, data) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
  [tenantId, caseId, kind, actor.id, actor.name, body || null, JSON.stringify(data || {})]);

const touch = (client, tenantId, caseId) => client.query('UPDATE cases SET updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2', [caseId, tenantId]);

// ---- reading -----------------------------------------------------------------------------------------------------------------------

async function list(client, tenantId, q) {
  const params = [tenantId]; const where = ['c.tenant_id = $1'];
  if (q.status === 'active') where.push("c.status IN ('open', 'investigating')");
  else if (q.status !== 'all') { params.push(q.status); where.push(`c.status = $${params.length}`); }
  if (q.owner) {
    if (q.owner.none) where.push('c.owner_id IS NULL');
    else { params.push(q.owner.me || q.owner.id); where.push(`c.owner_id = $${params.length}`); }
  }
  const total = await client.query(`SELECT COUNT(*)::int AS n FROM cases c WHERE ${where.join(' AND ')}`, params);
  params.push(q.limit, q.offset);
  const r = await client.query(
    `SELECT c.id, c.case_number, c.title, c.severity, c.status, c.owner_id, u.username AS owner_name, c.created_at, c.updated_at, c.closed_at,
            (SELECT COUNT(*)::int FROM case_alerts ca WHERE ca.case_id = c.id AND ca.tenant_id = c.tenant_id) AS alert_count
     FROM cases c LEFT JOIN users u ON u.id = c.owner_id AND u.tenant_id = c.tenant_id
     WHERE ${where.join(' AND ')}
     ORDER BY c.updated_at DESC, c.case_number DESC LIMIT $${params.length - 1} OFFSET $${params.length}`, params);
  return { cases: r.rows, total: total.rows[0].n };
}

// One case with its alerts and its timeline (oldest first, at most 1000 entries), or null.
async function get(client, tenantId, id) {
  const c = await client.query(
    `SELECT c.id, c.case_number, c.title, c.description, c.severity, c.status, c.owner_id, u.username AS owner_name,
            c.created_by_name, c.created_at, c.updated_at, c.closed_at
     FROM cases c LEFT JOIN users u ON u.id = c.owner_id AND u.tenant_id = c.tenant_id
     WHERE c.id = $1 AND c.tenant_id = $2`, [id, tenantId]);
  if (!c.rows.length) return null;
  const alerts = await client.query(
    `SELECT a.id, a.title, a.severity, a.status, a.rule_name, a.last_event_at, ca.added_at
     FROM case_alerts ca JOIN alerts a ON a.id = ca.alert_id AND a.tenant_id = ca.tenant_id
     WHERE ca.case_id = $1 AND ca.tenant_id = $2 ORDER BY ${SEV_ORDER}, a.last_event_at DESC NULLS LAST, a.id`, [id, tenantId]);
  const events = await client.query(
    `SELECT id, kind, actor_name, body, data, created_at FROM case_events
     WHERE case_id = $1 AND tenant_id = $2 ORDER BY created_at, id LIMIT 1000`, [id, tenantId]);
  return {
    case: c.rows[0],
    alerts: alerts.rows,
    timeline: events.rows.map((e) => ({ id: e.id, kind: e.kind, actor_name: e.actor_name, text: model.describeEvent(e), body: e.body, created_at: e.created_at })),
  };
}

// Active alerts that are not in any case yet, worst first: what the "add alerts" list offers.
async function candidates(client, tenantId, limit = 50) {
  const r = await client.query(
    `SELECT a.id, a.title, a.severity, a.status, a.rule_name, a.last_event_at FROM alerts a
     WHERE a.tenant_id = $1 AND a.status IN ('open', 'acknowledged') AND a.merged_into_id IS NULL
       AND NOT EXISTS (SELECT 1 FROM case_alerts ca WHERE ca.alert_id = a.id)
     ORDER BY ${SEV_ORDER}, a.last_event_at DESC NULLS LAST, a.id LIMIT $2`, [tenantId, limit]);
  return r.rows;
}

// The case an alert is in, or null.
async function ofAlert(client, tenantId, alertId) {
  const r = await client.query(
    `SELECT c.id, c.case_number, c.title, c.status, c.severity FROM case_alerts ca JOIN cases c ON c.id = ca.case_id AND c.tenant_id = ca.tenant_id
     WHERE ca.alert_id = $1 AND ca.tenant_id = $2`, [alertId, tenantId]);
  return r.rows[0] || null;
}

// ---- alerts: checks shared by create and attach --------------------------------------------------------------------------------------

// Reads the alerts and who has them. { missing: [ids not in this tenant], taken: [{ alert_id, case_number, case_id }], free: [rows], mine: [rows already in caseId] }
async function inspectAlerts(client, tenantId, ids, caseId) {
  const r = ids.length ? await client.query(
    `SELECT a.id, a.title, a.severity, ca.case_id, c.case_number FROM alerts a
     LEFT JOIN case_alerts ca ON ca.alert_id = a.id AND ca.tenant_id = a.tenant_id
     LEFT JOIN cases c ON c.id = ca.case_id AND c.tenant_id = a.tenant_id
     WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])`, [tenantId, ids]) : { rows: [] };
  const found = new Map(r.rows.map((x) => [x.id, x]));
  const out = { missing: ids.filter((id) => !found.has(id)), taken: [], free: [], mine: [] };
  for (const row of r.rows) {
    if (!row.case_id) out.free.push(row);
    else if (row.case_id === caseId) out.mine.push(row);
    else out.taken.push({ alert_id: row.id, case_id: row.case_id, case_number: row.case_number });
  }
  const place = (row) => ids.indexOf(row.id);   // the timeline follows the order the caller sent, not the order the database happens to return
  out.free.sort((a, b) => place(a) - place(b)); out.mine.sort((a, b) => place(a) - place(b));
  return out;
}
const refusal = (insp) => (insp.missing.length ? { code: 'ALERTS_NOT_FOUND', ids: insp.missing } : insp.taken.length ? { code: 'ALERTS_TAKEN', taken: insp.taken } : null);

const linkAlerts = async (client, tenantId, caseId, actor, rows) => {
  for (const a of rows) {
    await client.query('INSERT INTO case_alerts (tenant_id, case_id, alert_id, added_by_name) VALUES ($1, $2, $3, $4)', [tenantId, caseId, a.id, actor.name]);
    await addEvent(client, tenantId, caseId, actor, 'alert_added', { alert_id: a.id, title: a.title });
  }
};

// ---- writing -------------------------------------------------------------------------------------------------------------------------

// input from model.parseCreate. Returns { id, case_number } or a refusal.
async function create(client, tenantId, userId, input) {
  const actor = await resolveActor(client, tenantId, userId);
  // one create at a time per tenant: the case number is handed out, and the alerts are checked, under this lock (released when the transaction ends)
  await client.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [LOCK_NAMESPACE, String(tenantId)]);
  let ownerName = null;
  if (input.owner_id) {
    const o = await client.query('SELECT username FROM users WHERE id = $1 AND tenant_id = $2', [input.owner_id, tenantId]);
    if (!o.rows.length) return { code: 'OWNER_NOT_FOUND' };
    ownerName = o.rows[0].username;
  }
  const insp = await inspectAlerts(client, tenantId, input.alert_ids, null);
  const refused = refusal(insp); if (refused) return refused;
  const n = await client.query('SELECT COALESCE(MAX(case_number), 0) + 1 AS n FROM cases WHERE tenant_id = $1', [tenantId]);
  const sev = input.severity || model.topSeverity(insp.free.map((a) => a.severity));
  const ins = await client.query(
    `INSERT INTO cases (tenant_id, case_number, title, description, severity, owner_id, created_by_id, created_by_name)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, case_number`,
    [tenantId, n.rows[0].n, input.title, input.description, sev, input.owner_id, actor.id, actor.name]);
  const id = ins.rows[0].id;
  await addEvent(client, tenantId, id, actor, 'created', { alerts: insp.free.length, owner: ownerName, severity: sev });
  await linkAlerts(client, tenantId, id, actor, insp.free);
  return ins.rows[0];
}

// patch from model.parsePatch. Returns { id } (also when nothing changed) or a refusal.
async function update(client, tenantId, userId, id, patch) {
  const c = await client.query(
    `SELECT c.id, c.title, c.description, c.severity, c.status, c.owner_id, u.username AS owner_name
     FROM cases c LEFT JOIN users u ON u.id = c.owner_id AND u.tenant_id = c.tenant_id
     WHERE c.id = $1 AND c.tenant_id = $2 FOR UPDATE OF c`, [id, tenantId]);
  if (!c.rows.length) return { code: 'NOT_FOUND' };
  const before = c.rows[0];
  if (model.closedBlocks(before.status, patch)) return { code: 'CASE_CLOSED' };
  let ownerNameAfter = null;
  if (patch.owner_id) {
    const o = await client.query('SELECT username FROM users WHERE id = $1 AND tenant_id = $2', [patch.owner_id, tenantId]);
    if (!o.rows.length) return { code: 'OWNER_NOT_FOUND' };
    ownerNameAfter = o.rows[0].username;
  }
  const events = model.changeEvents(before, patch, ownerNameAfter);
  if (!events.length) return { id, unchanged: true };
  const actor = await resolveActor(client, tenantId, userId);
  const sets = []; const params = [id, tenantId];
  for (const col of ['title', 'description', 'severity', 'status', 'owner_id']) {   // a fixed list: a key from the request is never a column name
    if (patch[col] === undefined) continue;
    params.push(patch[col]); sets.push(`${col} = $${params.length}`);
  }
  if (patch.status !== undefined && patch.status !== before.status) sets.push(patch.status === 'closed' ? 'closed_at = localtimestamp' : 'closed_at = NULL');
  await client.query(`UPDATE cases SET ${sets.join(', ')}, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2`, params);
  for (const e of events) await addEvent(client, tenantId, id, actor, e.kind, e.data);
  return { id };
}

// Adds alerts to a case. Alerts already in this case are skipped; alerts in another case refuse the whole request.
async function attachAlerts(client, tenantId, userId, id, alertIds) {
  const c = await client.query('SELECT status FROM cases WHERE id = $1 AND tenant_id = $2 FOR UPDATE', [id, tenantId]);
  if (!c.rows.length) return { code: 'NOT_FOUND' };
  if (c.rows[0].status === 'closed') return { code: 'CASE_CLOSED' };
  const insp = await inspectAlerts(client, tenantId, alertIds, id);
  const refused = refusal(insp); if (refused) return refused;
  const actor = await resolveActor(client, tenantId, userId);
  await linkAlerts(client, tenantId, id, actor, insp.free);
  if (insp.free.length) await touch(client, tenantId, id);
  return { id, added: insp.free.length, already: insp.mine.length };
}

async function detachAlert(client, tenantId, userId, id, alertId) {
  const c = await client.query('SELECT status FROM cases WHERE id = $1 AND tenant_id = $2 FOR UPDATE', [id, tenantId]);
  if (!c.rows.length) return { code: 'NOT_FOUND' };
  if (c.rows[0].status === 'closed') return { code: 'CASE_CLOSED' };
  const a = await client.query('SELECT title FROM alerts WHERE id = $1 AND tenant_id = $2', [alertId, tenantId]);
  const del = await client.query('DELETE FROM case_alerts WHERE case_id = $1 AND alert_id = $2 AND tenant_id = $3 RETURNING alert_id', [id, alertId, tenantId]);
  if (!del.rows.length) return { code: 'NOT_ATTACHED' };
  const actor = await resolveActor(client, tenantId, userId);
  await addEvent(client, tenantId, id, actor, 'alert_removed', { alert_id: alertId, title: a.rows[0] ? a.rows[0].title : null });
  await touch(client, tenantId, id);
  return { id };
}

// A note is allowed on a closed case too.
async function addNote(client, tenantId, userId, id, text) {
  const c = await client.query('SELECT 1 FROM cases WHERE id = $1 AND tenant_id = $2 FOR UPDATE', [id, tenantId]);
  if (!c.rows.length) return { code: 'NOT_FOUND' };
  const actor = await resolveActor(client, tenantId, userId);
  await addEvent(client, tenantId, id, actor, 'note', {}, text);
  await touch(client, tenantId, id);
  return { id };
}

module.exports = { list, get, candidates, ofAlert, create, update, attachAlerts, detachAlert, addNote, resolveActor };
