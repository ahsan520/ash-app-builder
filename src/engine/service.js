'use strict';
// Database side of the engine runs (task SR3, docs/engine-callback.md). Every function takes an open tenant-scoped client (db.withTenant) and filters on tenant_id
// explicitly, because the API connects as the table owner, which bypasses row-level security (same rule as src/actions/service.js).
// A callback from the engine is an ordinary request to the action registry with origin `automation`: the registry decides, records the run and audits it. This file only
// adds what is specific to the engine: the run, its token, its allowed actions, its call limit and its end.
const model = require('./model');
const actionsModel = require('../actions/model');
const actionsService = require('../actions/service');
const casesService = require('../cases/service');

// `status` is what a reader sees: a run that is still open after its time is `expired`.
const COLS = `id, playbook, CASE WHEN status IN ('starting', 'running') AND expires_at <= localtimestamp THEN 'expired' ELSE status END AS status,
  allowed_actions, input, max_calls, call_count, calls, engine_host, engine_ref, summary, error_message, started_by_name, expires_at, created_at, finished_at`;
const OPEN = `status IN ('starting', 'running') AND expires_at > localtimestamp`;   // a run whose token still works

const audit = (client, tenantId, userId, action, resource, result) => client.query(
  'INSERT INTO audit_events (tenant_id, user_id, action, resource, result) VALUES ($1, $2, $3, $4, $5)', [tenantId, userId || null, action, String(resource).slice(0, 255), result]);

// p: parseStart's value plus tokenHash and engineHost. Written (and committed) BEFORE the engine is called, so a callback that arrives at once finds its run.
async function createRun(client, tenantId, userId, p) {
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const r = await client.query(
    `INSERT INTO engine_runs (tenant_id, playbook, token_hash, allowed_actions, input, max_calls, engine_host, started_by_id, started_by_name, expires_at)
     VALUES ($1, $2, $3, $4::text[], $5::jsonb, $6, $7, $8, $9, localtimestamp + make_interval(secs => $10::double precision)) RETURNING id`,
    [tenantId, p.playbook, p.tokenHash, p.allowed_actions, JSON.stringify(p.input), p.max_calls, p.engineHost || null, actor.id, actor.name, p.ttl_seconds]);
  const id = r.rows[0].id;
  await audit(client, tenantId, actor.id, 'soar:engine:start', `${p.playbook} engine_run=${id}`, 'success');
  return id;
}

// The engine accepted the call: remember its reference. A run that already finished (a fast workflow) keeps its status.
const markStarted = (client, tenantId, runId, engineRef) => client.query(
  `UPDATE engine_runs SET engine_ref = $3, status = CASE WHEN status = 'starting' THEN 'running' ELSE status END WHERE id = $1 AND tenant_id = $2`, [runId, tenantId, engineRef || null]);

// The engine did not take the call: the run is over and its token is dead.
async function markStartFailed(client, tenantId, runId, message) {
  await client.query(`UPDATE engine_runs SET status = 'failed', token_hash = NULL, error_message = $3, finished_at = localtimestamp WHERE id = $1 AND tenant_id = $2 AND status IN ('starting', 'running')`,
    [runId, tenantId, String(message || 'The engine did not accept the request').slice(0, 300)]);
  await audit(client, tenantId, null, 'soar:engine:start', `engine_run=${runId}`, 'failure');
}

// Which run a token belongs to. Run on the pool, not a tenant client: the tenant is what is being found. Wrong, expired, ended: the same empty answer.
async function findOpenByHash(db, hash) {
  const r = await db.query(`SELECT id, tenant_id FROM engine_runs WHERE token_hash = $1 AND ${OPEN}`, [hash]);
  return r.rows[0] ? { runId: r.rows[0].id, tenantId: r.rows[0].tenant_id } : null;
}

const lockOpen = async (client, tenantId, runId) => (await client.query(
  `SELECT id, allowed_actions, max_calls, call_count FROM engine_runs WHERE id = $1 AND tenant_id = $2 AND ${OPEN} FOR UPDATE`, [runId, tenantId])).rows[0] || null;

// The engine asks for an action. Returns { run (the action run), outcome } for every request the registry recorded (including a refused one), or { code }:
//   NOT_OPEN (the run ended or expired while the call was on its way), ACTION_NOT_ALLOWED, CALL_LIMIT, or the registry's own INVALID_PARAMETER(S) / NOT_FOUND.
async function callAction(client, tenantId, runId, actionId, rawParams) {
  const row = await lockOpen(client, tenantId, runId);
  if (!row) return { code: 'NOT_OPEN' };
  if (!row.allowed_actions.includes(actionId)) return { code: 'ACTION_NOT_ALLOWED' };
  if (row.call_count >= row.max_calls) return { code: 'CALL_LIMIT' };
  const out = await actionsService.request(client, tenantId, null, actionId, rawParams, 'automation');
  if (out.code) return { code: out.code, message: out.message };
  const run = out.run;
  const call = { n: row.call_count + 1, action: actionId, action_run_id: run.id, at: new Date().toISOString() };
  await client.query('UPDATE engine_runs SET call_count = call_count + 1, calls = calls || $3::jsonb WHERE id = $1 AND tenant_id = $2', [runId, tenantId, JSON.stringify([call])]);
  await audit(client, tenantId, null, 'soar:engine:callback', `${actionId} engine_run=${runId} run=${run.id}`, actionsModel.AUDIT_RESULT[run.status] || 'success');
  return { run, outcome: model.outcomeOf(run) };
}

// The engine reads back one of ITS OWN requests (to see whether a person approved it). Another run's action run is simply not found.
async function readCall(client, tenantId, runId, actionRunId) {
  const own = await client.query('SELECT 1 FROM engine_runs WHERE id = $1 AND tenant_id = $2 AND calls @> $3::jsonb', [runId, tenantId, JSON.stringify([{ action_run_id: actionRunId }])]);
  if (!own.rows.length) return null;
  return actionsService.getRun(client, tenantId, actionRunId);
}

// The workflow ends: the status it reports and a short summary. The token dies with it.
async function finish(client, tenantId, runId, v) {
  const row = await lockOpen(client, tenantId, runId);
  if (!row) return { code: 'NOT_OPEN' };
  await client.query(`UPDATE engine_runs SET status = $3, summary = $4, token_hash = NULL, finished_at = localtimestamp WHERE id = $1 AND tenant_id = $2`, [runId, tenantId, v.status, v.summary]);
  await audit(client, tenantId, null, 'soar:engine:finish', `engine_run=${runId}`, v.status === 'succeeded' ? 'success' : 'failure');
  return { ok: true };
}

async function listRuns(client, tenantId, { limit, offset }) {
  const total = await client.query('SELECT COUNT(*)::int AS n FROM engine_runs WHERE tenant_id = $1', [tenantId]);
  const r = await client.query(`SELECT ${COLS} FROM engine_runs WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`, [tenantId, limit, offset]);
  return { runs: r.rows, total: total.rows[0].n };
}
const getRun = async (client, tenantId, id) => (await client.query(`SELECT ${COLS} FROM engine_runs WHERE id = $1 AND tenant_id = $2`, [id, tenantId])).rows[0] || null;

module.exports = { createRun, markStarted, markStartFailed, findOpenByHash, callAction, readCall, finish, listRuns, getRun };
