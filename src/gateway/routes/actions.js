const express = require('express');
const router = express.Router();
const { db, guarded, UUID_RE, apiError } = require('../shared');

// ---- Action registry (task SR2, docs/actions.md): which actions exist, which a tenant has switched on, and every run ------------------------
// Two new permissions: `soar:actions:read` (see the registry and the runs) and `soar:actions:write` (switch an action on or off, set its level, run it,
// approve, reject or undo a run). scripts/deploy/bootstrap-portal.sh gives both to the portal-admin role. Rules: src/actions/model.js; definitions:
// src/actions/catalog.js; SQL: src/actions/service.js.
// A person calling the API is always origin `user`: the body can never say otherwise. Origin `automation` is for the playbook runner (SR3), which calls the service itself.
const model = require('../../actions/model');
const service = require('../../actions/service');
const modules = require('../../modules');

async function requireModule(req, res, next) {
  try {
    if (await modules.isEnabled('actions')) return next();
    return apiError(res, 403, 'MODULE_DISABLED', 'The Action registry module is not enabled on this deployment');
  } catch (e) {
    console.error('Module check failed:', e.message);
    return apiError(res, 500, 'MODULES_ERROR', 'Failed to resolve modules');
  }
}

const fail = (res, e, what, code) => { console.error(`${what} failed:`, e.message); apiError(res, 500, code, `Failed to ${what}`); };
const runIdOk = (req, res) => (UUID_RE.test(req.params.id) ? true : (apiError(res, 400, 'INVALID_ID', 'Invalid run id'), false));

// What a refused service call becomes.
function refused(res, out) {
  switch (out.code) {
    case 'NOT_FOUND': return apiError(res, 404, 'NOT_FOUND', 'Not found');
    case 'NOT_WAITING': return apiError(res, 409, 'NOT_WAITING', 'This run is not waiting for approval');
    case 'SELF_APPROVAL': return apiError(res, 409, 'SELF_APPROVAL', out.message);
    case 'NOT_UNDOABLE': return apiError(res, 409, 'NOT_UNDOABLE', out.message || 'This run cannot be undone');
    case 'ALREADY_UNDONE': return apiError(res, 409, 'ALREADY_UNDONE', 'This run was already undone');
    case 'AUTONOMY_TOO_HIGH': return apiError(res, 400, 'AUTONOMY_TOO_HIGH', out.message);
    case 'INVALID_PARAMETER': case 'INVALID_PARAMETERS': return apiError(res, 400, out.code, out.message);
    default: return apiError(res, 400, out.code || 'INVALID_BODY', out.message || 'Invalid request');
  }
}
// A request that was refused by the registry (not enabled, observe only) is recorded as a run; the caller gets the run id with the 409.
const refusedRun = (res, out) => res.status(409).json({ success: false, error: { code: out.refused, message: out.run.error_message, run_id: out.run.id }, run: out.run });

router.get('/v1/actions', ...guarded('soar:actions:read'), requireModule, async (req, res) => {
  try {
    const actions = await db.withTenant(req.tenant_id, (client) => service.listActions(client, req.tenant_id));
    res.status(200).json({ success: true, actions, levels: model.LEVEL_LABEL });
  } catch (e) { fail(res, e, 'list actions', 'ACTIONS_LIST_ERROR'); }
});

// Before /v1/actions/:id, which would otherwise take "runs" for an action id.
router.get('/v1/actions/runs', ...guarded('soar:actions:read'), requireModule, async (req, res) => {
  const q = model.parseRunsQuery(req.query);
  if (q.error) return apiError(res, 400, q.error.code, q.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.listRuns(client, req.tenant_id, q.value));
    res.status(200).json({ success: true, ...out, limit: q.value.limit, offset: q.value.offset });
  } catch (e) { fail(res, e, 'list runs', 'ACTION_RUNS_LIST_ERROR'); }
});

router.get('/v1/actions/runs/:id', ...guarded('soar:actions:read'), requireModule, async (req, res) => {
  if (!runIdOk(req, res)) return;
  try {
    const run = await db.withTenant(req.tenant_id, (client) => service.getRun(client, req.tenant_id, req.params.id));
    if (!run) return refused(res, { code: 'NOT_FOUND' });
    res.status(200).json({ success: true, run });
  } catch (e) { fail(res, e, 'read the run', 'ACTION_RUN_READ_ERROR'); }
});

// A run waiting for approval is approved (and runs now), rejected, or a finished run is undone.
router.post('/v1/actions/runs/:id/approve', ...guarded('soar:actions:write'), requireModule, async (req, res) => {
  if (!runIdOk(req, res)) return;
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.approve(client, req.tenant_id, req.user_id, req.params.id));
    if (out.refused) return refusedRun(res, out);
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, run: out.run });
  } catch (e) { fail(res, e, 'approve the run', 'ACTION_APPROVE_ERROR'); }
});

router.post('/v1/actions/runs/:id/reject', ...guarded('soar:actions:write'), requireModule, async (req, res) => {
  if (!runIdOk(req, res)) return;
  const note = req.body && typeof req.body.note === 'string' ? req.body.note.trim().slice(0, 500) : null;
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.reject(client, req.tenant_id, req.user_id, req.params.id, note));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, run: out.run });
  } catch (e) { fail(res, e, 'reject the run', 'ACTION_REJECT_ERROR'); }
});

router.post('/v1/actions/runs/:id/undo', ...guarded('soar:actions:write'), requireModule, async (req, res) => {
  if (!runIdOk(req, res)) return;
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.undoRun(client, req.tenant_id, req.user_id, req.params.id));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, run: out.run, undone: out.undone });
  } catch (e) { fail(res, e, 'undo the run', 'ACTION_UNDO_ERROR'); }
});

router.get('/v1/actions/:id', ...guarded('soar:actions:read'), requireModule, async (req, res) => {
  try {
    const action = await db.withTenant(req.tenant_id, (client) => service.getAction(client, req.tenant_id, req.params.id));
    if (!action) return refused(res, { code: 'NOT_FOUND' });
    res.status(200).json({ success: true, action });
  } catch (e) { fail(res, e, 'read the action', 'ACTION_READ_ERROR'); }
});

// body: { enabled?: boolean, autonomy?: 0..4 }. An action is disabled until this is called; the level may not pass the action's ceiling.
router.put('/v1/actions/:id/setting', ...guarded('soar:actions:write'), requireModule, async (req, res) => {
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.setSetting(client, req.tenant_id, req.user_id, req.params.id, req.body));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, action: out.action });
  } catch (e) { fail(res, e, 'change the action setting', 'ACTION_SETTING_ERROR'); }
});

// body: { parameters?: {...} }. Always origin `user`. 201 with the recorded run (succeeded, failed, recommended, or awaiting approval); 409 with the run when the registry refuses.
router.post('/v1/actions/:id/run', ...guarded('soar:actions:write'), requireModule, async (req, res) => {
  const body = model.parseRunBody(req.body);
  if (body.error) return apiError(res, 400, body.error.code, body.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.request(client, req.tenant_id, req.user_id, req.params.id, body.value.parameters, 'user'));
    if (out.refused) return refusedRun(res, out);
    if (out.code) return refused(res, out);
    res.status(201).json({ success: true, run: out.run });
  } catch (e) { fail(res, e, 'run the action', 'ACTION_RUN_ERROR'); }
});

module.exports = router;
