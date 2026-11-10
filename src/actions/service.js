'use strict';
// Database side of the action registry (task SR2, docs/actions.md). Every function takes an open tenant-scoped client (from db.withTenant) and
// filters on tenant_id explicitly, because the API connects as the table owner, which bypasses row-level security (same rule as src/cases/service.js).
//
// What is written, always in the same transaction as the work itself, so a run and its audit row exist together or not at all:
//   action_runs     one row per request: what was asked, by whom, the decision, the outcome, and (for a change that can be undone) how to undo it
//   audit_events    one row per request, approval, rejection, undo and setting change (action `soar:action:*`)
// Refusals a caller can fix (unknown action, wrong state) come back as { code }; a refused request for a known action is recorded as a run with
// status `refused`, so a blocked attempt is visible too.
const model = require('./model');
const catalog = require('./catalog');
const casesService = require('../cases/service');

const RUN_COLS = `id, action_id, origin, status, risk_class, autonomy_level, params, result, error_code, error_message, undo, undone_by_run_id, undo_of_run_id,
  requested_by_id, requested_by_name, decided_by_id, decided_by_name, decided_at, decision_note, created_at, finished_at`;

// What goes to audit_events.resource: the action, the run and (for a setting) the new state. Never a parameter value (it can be long, and the run row holds it).
const audit = (client, tenantId, userId, action, resource, result) => client.query(
  'INSERT INTO audit_events (tenant_id, user_id, action, resource, result) VALUES ($1, $2, $3, $4, $5)',
  [tenantId, userId || null, action, String(resource).slice(0, 255), result]);

const settingOf = async (client, tenantId, actionId) => {
  const r = await client.query('SELECT enabled, autonomy_level, updated_by_name, updated_at FROM action_settings WHERE tenant_id = $1 AND action_id = $2', [tenantId, actionId]);
  return r.rows[0] || null;
};

// ---- the registry and its settings ---------------------------------------------------------------------------------------------------

// Every known action with this tenant's setting. An action that was never enabled shows enabled: false (installed actions start disabled).
async function listActions(client, tenantId) {
  const s = await client.query('SELECT action_id, enabled, autonomy_level, updated_by_name, updated_at FROM action_settings WHERE tenant_id = $1', [tenantId]);
  const bySetting = new Map(s.rows.map((r) => [r.action_id, r]));
  const last = await client.query('SELECT action_id, MAX(created_at) AS last_run_at, COUNT(*)::int AS runs FROM action_runs WHERE tenant_id = $1 GROUP BY action_id', [tenantId]);
  const byRuns = new Map(last.rows.map((r) => [r.action_id, r]));
  return catalog.list().map((def) => {
    const st = bySetting.get(def.id); const rn = byRuns.get(def.id);
    return {
      ...catalog.publicView(def),
      enabled: !!(st && st.enabled),
      autonomy: st ? Math.min(st.autonomy_level, def.max_autonomy) : def.default_autonomy,
      autonomy_label: model.LEVEL_LABEL[st ? Math.min(st.autonomy_level, def.max_autonomy) : def.default_autonomy],
      configured: !!st, updated_by_name: st ? st.updated_by_name : null, updated_at: st ? st.updated_at : null,
      runs: rn ? rn.runs : 0, last_run_at: rn ? rn.last_run_at : null,
    };
  });
}

async function getAction(client, tenantId, id) {
  const def = catalog.get(id);
  if (!def) return null;
  return (await listActions(client, tenantId)).find((a) => a.id === id);
}

// body: already through model.parseSetting. Returns { action } or { code: 'NOT_FOUND' }.
async function setSetting(client, tenantId, userId, id, body) {
  const def = catalog.get(id);
  if (!def) return { code: 'NOT_FOUND' };
  const current = await settingOf(client, tenantId, id);
  const parsed = model.parseSetting(def, body, current);
  if (parsed.error) return { code: parsed.error.code, message: parsed.error.message };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const v = parsed.value;
  const prevEnabled = !!(current && current.enabled);
  const prevLevel = current ? current.autonomy_level : def.default_autonomy;
  if (current && prevEnabled === v.enabled && prevLevel === v.autonomy) return { action: await getAction(client, tenantId, id) };   // nothing changes: no new row, no audit entry
  await client.query(
    `INSERT INTO action_settings (tenant_id, action_id, enabled, autonomy_level, updated_by_name, updated_at) VALUES ($1, $2, $3, $4, $5, localtimestamp)
     ON CONFLICT (tenant_id, action_id) DO UPDATE SET enabled = EXCLUDED.enabled, autonomy_level = EXCLUDED.autonomy_level, updated_by_name = EXCLUDED.updated_by_name, updated_at = localtimestamp`,
    [tenantId, id, v.enabled, v.autonomy, actor.name]);
  if (v.enabled !== prevEnabled) await audit(client, tenantId, actor.id, v.enabled ? 'soar:action:enable' : 'soar:action:disable', `${id} level=${v.autonomy}`, 'success');
  else if (v.autonomy !== prevLevel) await audit(client, tenantId, actor.id, 'soar:action:autonomy', `${id} level=${v.autonomy}`, 'success');
  return { action: await getAction(client, tenantId, id) };
}

// ---- runs ----------------------------------------------------------------------------------------------------------------------------

async function insertRun(client, tenantId, def, o) {
  const r = await client.query(
    `INSERT INTO action_runs (tenant_id, action_id, origin, status, risk_class, autonomy_level, params, error_code, error_message, undo_of_run_id, requested_by_id, requested_by_name, decision_note)
     VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12, $13) RETURNING id`,
    [tenantId, def.id, o.origin, o.status, def.risk, o.level, JSON.stringify(o.params), o.code || null, o.message || null, o.undoOf || null, o.actor.id, o.actor.name, o.note || null]);
  return r.rows[0].id;
}

const getRunRow = async (client, tenantId, runId, lock) => {
  const r = await client.query(`SELECT ${RUN_COLS}, tenant_id FROM action_runs WHERE id = $1 AND tenant_id = $2${lock ? ' FOR UPDATE' : ''}`, [runId, tenantId]);
  return r.rows[0] || null;
};

// Runs the executor inside a savepoint: a refusal or an error rolls back whatever the action changed, and the run is then recorded as failed.
// Writes the outcome onto the run and its audit row.
async function execute(client, tenantId, def, runId, params, actor, decided) {
  let out;
  await client.query('SAVEPOINT action_run');
  try {
    out = await def.execute({ client, tenantId, userId: actor.id }, params);
    if (!out || out.ok !== true) { await client.query('ROLLBACK TO SAVEPOINT action_run'); out = { ok: false, code: (out && out.code) || 'ACTION_FAILED', message: (out && out.message) || 'The action failed' }; }
    else await client.query('RELEASE SAVEPOINT action_run');
  } catch (e) {
    await client.query('ROLLBACK TO SAVEPOINT action_run');
    console.error(`Action ${def.id} failed:`, e.message);
    out = { ok: false, code: 'ACTION_ERROR', message: 'The action failed with an internal error' };   // the database's own words are not shown to a caller
  }
  const status = out.ok ? 'succeeded' : 'failed';
  await client.query(
    `UPDATE action_runs SET status = $3, result = $4::jsonb, error_code = $5, error_message = $6, undo = $7::jsonb, finished_at = localtimestamp,
       decided_by_id = COALESCE($8::uuid, decided_by_id), decided_by_name = COALESCE($9::text, decided_by_name),
       decided_at = CASE WHEN $9::text IS NULL THEN decided_at ELSE COALESCE(decided_at, localtimestamp) END
     WHERE id = $1 AND tenant_id = $2`,
    [runId, tenantId, status, JSON.stringify(out.ok ? out.result : {}), out.ok ? null : out.code, out.ok ? null : out.message,
      out.ok && out.undo ? JSON.stringify(out.undo) : null, decided ? decided.id : null, decided ? decided.name : null]);
  await audit(client, tenantId, actor.id, 'soar:action:run', `${def.id} run=${runId}`, model.AUDIT_RESULT[status]);
  return status;
}

// A request to run an action.
//   origin 'user' | 'automation' (never 'undo': that is undoRun). `rawParams` are the caller's, checked here against the definition.
// Returns { run } for every request that is recorded (including a refused one, which also carries `refused: code`), or
// { code: 'NOT_FOUND' } for an unknown action and { code, message } (INVALID_PARAMETER, INVALID_PARAMETERS) for parameters that do not fit (not recorded: nothing was asked).
async function request(client, tenantId, userId, actionId, rawParams, origin) {
  if (origin !== 'user' && origin !== 'automation') throw new Error('origin must be user or automation');
  const def = catalog.get(actionId);
  if (!def) return { code: 'NOT_FOUND' };
  const v = model.validateParams(def, rawParams);
  if (v.error) return { code: v.error.code, message: v.error.message };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const setting = await settingOf(client, tenantId, actionId);
  const d = model.decide(def, setting, origin);

  if (d.outcome === 'refuse') {
    const id = await insertRun(client, tenantId, def, { origin, status: 'refused', level: d.level, params: v.value, actor, code: d.code, message: d.reason });
    await audit(client, tenantId, actor.id, 'soar:action:run', `${def.id} run=${id}`, model.AUDIT_RESULT.refused);
    return { run: await getRunRow(client, tenantId, id), refused: d.code };
  }
  if (d.outcome === 'recommend' || d.outcome === 'approval') {
    const status = d.outcome === 'recommend' ? 'recommended' : 'awaiting_approval';
    const id = await insertRun(client, tenantId, def, { origin, status, level: d.level, params: v.value, actor, note: d.reason });
    await audit(client, tenantId, actor.id, 'soar:action:run', `${def.id} run=${id}`, model.AUDIT_RESULT[status]);
    return { run: await getRunRow(client, tenantId, id) };
  }
  // execute now. A person pressing Run is the decision (recorded as the decider); automation allowed by its level has no decider.
  const id = await insertRun(client, tenantId, def, { origin, status: 'failed', level: d.level, params: v.value, actor, note: d.reason });   // placeholder status, replaced below in the same transaction
  await execute(client, tenantId, def, id, v.value, actor, origin === 'user' ? actor : null);
  return { run: await getRunRow(client, tenantId, id) };
}

// Approves a run that is waiting and runs it. The stored parameters are used, so what was approved is what runs. The action must still be
// enabled and above Observe only: switching an action off also stops what was already waiting (that run is then recorded as refused).
// Returns { run } or { code: 'NOT_FOUND' | 'NOT_WAITING' | 'SELF_APPROVAL', message? }.
async function approve(client, tenantId, userId, runId) {
  const row = await getRunRow(client, tenantId, runId, true);
  if (!row) return { code: 'NOT_FOUND' };
  if (row.status !== 'awaiting_approval') return { code: 'NOT_WAITING' };
  const def = catalog.get(row.action_id);
  const actor = await casesService.resolveActor(client, tenantId, userId);
  if (!def) return finishRefused(client, tenantId, runId, actor, 'ACTION_GONE', 'This action is no longer known to ASIX.');
  const sr = model.approvalRefusal(def, row, actor.id);
  if (sr) return { code: sr.code, message: sr.message };
  const setting = await settingOf(client, tenantId, row.action_id);
  if (!setting || !setting.enabled || Math.min(setting.autonomy_level, def.max_autonomy) === 0) {
    return finishRefused(client, tenantId, runId, actor, !setting || !setting.enabled ? 'ACTION_DISABLED' : 'OBSERVE_ONLY', 'The action was switched off before it was approved.');
  }
  await client.query('UPDATE action_runs SET decided_by_id = $3, decided_by_name = $4, decided_at = localtimestamp WHERE id = $1 AND tenant_id = $2', [runId, tenantId, actor.id, actor.name]);
  await audit(client, tenantId, actor.id, 'soar:action:approve', `${row.action_id} run=${runId}`, 'success');
  await execute(client, tenantId, def, runId, row.params || {}, { id: row.requested_by_id, name: row.requested_by_name }, actor);
  return { run: await getRunRow(client, tenantId, runId) };
}

async function reject(client, tenantId, userId, runId, note) {
  const row = await getRunRow(client, tenantId, runId, true);
  if (!row) return { code: 'NOT_FOUND' };
  if (row.status !== 'awaiting_approval') return { code: 'NOT_WAITING' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  await client.query(
    `UPDATE action_runs SET status = 'rejected', decided_by_id = $3, decided_by_name = $4, decided_at = localtimestamp, decision_note = COALESCE($5, decision_note), finished_at = localtimestamp
     WHERE id = $1 AND tenant_id = $2`, [runId, tenantId, actor.id, actor.name, note || null]);
  await audit(client, tenantId, actor.id, 'soar:action:reject', `${row.action_id} run=${runId}`, model.AUDIT_RESULT.rejected);
  return { run: await getRunRow(client, tenantId, runId) };
}

async function finishRefused(client, tenantId, runId, actor, code, message) {
  const row = await getRunRow(client, tenantId, runId);
  await client.query(
    `UPDATE action_runs SET status = 'refused', error_code = $3, error_message = $4, finished_at = localtimestamp WHERE id = $1 AND tenant_id = $2`,
    [runId, tenantId, code, message]);
  await audit(client, tenantId, actor.id, 'soar:action:approve', `${row.action_id} run=${runId}`, model.AUDIT_RESULT.refused);
  return { run: await getRunRow(client, tenantId, runId), refused: code };
}

// Puts a run's change back: runs the undo the action gave (a second run, origin 'undo', linked both ways). Undo is allowed whatever the setting of the
// action is now, because it only reverses something that was allowed when it ran; it is still checked, recorded and audited like any run.
// Returns { run (the undo run), undone (the original) } or { code: 'NOT_FOUND' | 'NOT_UNDOABLE' | 'ALREADY_UNDONE' }.
async function undoRun(client, tenantId, userId, runId) {
  const row = await getRunRow(client, tenantId, runId, true);
  if (!row) return { code: 'NOT_FOUND' };
  if (row.status !== 'succeeded' || !row.undo || row.origin === 'undo') return { code: 'NOT_UNDOABLE' };
  if (row.undone_by_run_id) return { code: 'ALREADY_UNDONE' };
  const def = catalog.get(row.undo.action);
  if (!def) return { code: 'NOT_UNDOABLE' };
  const v = model.validateParams(def, row.undo.params);
  if (v.error) return { code: 'NOT_UNDOABLE', message: v.error.message };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const id = await insertRun(client, tenantId, def, { origin: 'undo', status: 'failed', level: row.autonomy_level, params: v.value, actor, undoOf: runId, note: `Undo of run ${runId}` });
  const status = await execute(client, tenantId, def, id, v.value, actor, actor);
  if (status === 'succeeded') await client.query('UPDATE action_runs SET undone_by_run_id = $3 WHERE id = $1 AND tenant_id = $2', [runId, tenantId, id]);
  return { run: await getRunRow(client, tenantId, id), undone: await getRunRow(client, tenantId, runId) };
}

// ---- reading runs --------------------------------------------------------------------------------------------------------------------

async function listRuns(client, tenantId, q) {
  const params = [tenantId]; const where = ['tenant_id = $1'];
  if (q.status) { params.push(q.status); where.push(`status = $${params.length}`); }
  if (q.action) { params.push(q.action); where.push(`action_id = $${params.length}`); }
  const total = await client.query(`SELECT COUNT(*)::int AS n FROM action_runs WHERE ${where.join(' AND ')}`, params);
  params.push(q.limit, q.offset);
  const r = await client.query(
    `SELECT ${RUN_COLS} FROM action_runs WHERE ${where.join(' AND ')} ORDER BY created_at DESC, id DESC LIMIT $${params.length - 1} OFFSET $${params.length}`, params);
  return { runs: r.rows, total: total.rows[0].n };
}

async function getRun(client, tenantId, runId) { return getRunRow(client, tenantId, runId); }

module.exports = { listActions, getAction, setSetting, request, approve, reject, undoRun, listRuns, getRun };
