const express = require('express');
const router = express.Router();
const { db, guarded, UUID_RE, apiError } = require('../shared');

// ---- Automation engine runs (task SR3, docs/engine-callback.md): a person (or a service account) starts a workflow on the engine, and reads what it did -----------------------------
// Uses the permissions the Action registry already has: `soar:actions:write` to start a run, `soar:actions:read` to read runs. Starting a run does not run any action: the workflow
// can only ASK ASIX for the actions listed here, through src/engine/callback.js (run token), and the registry decides each request exactly as it does for a person.
// The webhook address is given in the request, used once and never stored (a lab shortcut: an encrypted address per tenant and playbook is the next step, see the doc).
const model = require('../../engine/model');
const service = require('../../engine/service');
const start = require('../../engine/start');
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

router.get('/v1/engine/runs', ...guarded('soar:actions:read'), requireModule, async (req, res) => {
  const limit = req.query.limit === undefined ? 50 : Number(req.query.limit);
  const offset = req.query.offset === undefined ? 0 : Number(req.query.offset);
  if (!Number.isInteger(limit) || limit < 1 || limit > 200) return apiError(res, 400, 'INVALID_LIMIT', 'limit must be 1 to 200');
  if (!Number.isInteger(offset) || offset < 0) return apiError(res, 400, 'INVALID_OFFSET', 'offset must be 0 or more');
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.listRuns(client, req.tenant_id, { limit, offset }));
    res.status(200).json({ success: true, ...out, limit, offset });
  } catch (e) { fail(res, e, 'list engine runs', 'ENGINE_RUNS_LIST_ERROR'); }
});

router.get('/v1/engine/runs/:id', ...guarded('soar:actions:read'), requireModule, async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid run id');
  try {
    const run = await db.withTenant(req.tenant_id, (client) => service.getRun(client, req.tenant_id, req.params.id));
    if (!run) return apiError(res, 404, 'NOT_FOUND', 'Not found');
    res.status(200).json({ success: true, run });
  } catch (e) { fail(res, e, 'read the engine run', 'ENGINE_RUN_READ_ERROR'); }
});

// body: { playbook, webhook_url, allowed_actions: [...], input?: {...}, ttl_seconds?, max_calls? }. 201 with the run; the token is given to the engine only and is never in any answer.
router.post('/v1/engine/runs', ...guarded('soar:actions:write'), requireModule, async (req, res) => {
  const base = model.callbackBase(process.env);
  if (base.error) return apiError(res, 503, base.error.code, base.error.message);
  const parsed = model.parseStart(req.body);
  if (parsed.error) return apiError(res, 400, parsed.error.code, parsed.error.message);
  const p = parsed.value;
  let target;
  try { target = start.checkTarget(p.webhook_url); } catch (e) { return apiError(res, 400, e.code === 'EBLOCKED' ? 'ENGINE_URL_BLOCKED' : 'INVALID_WEBHOOK_URL', e.message); }
  const tenantId = req.tenant_id;
  try {
    const token = model.newToken();
    const runId = await db.withTenant(tenantId, (client) => service.createRun(client, tenantId, req.user_id,
      { playbook: p.playbook, allowed_actions: p.allowed_actions, input: p.input, max_calls: p.max_calls, ttl_seconds: p.ttl_seconds, tokenHash: model.hashToken(token), engineHost: target.hostname.slice(0, 255) }));
    const sent = await start.postHook(p.webhook_url, model.hookBody({ runId, tenantId, token, callbackUrl: base.value, playbook: p.playbook, input: p.input }));
    if (!sent.ok) {
      await db.withTenant(tenantId, (client) => service.markStartFailed(client, tenantId, runId, sent.error));
      return res.status(502).json({ success: false, error: { code: 'ENGINE_START_FAILED', message: sent.error, run_id: runId } });
    }
    await db.withTenant(tenantId, (client) => service.markStarted(client, tenantId, runId, sent.engineRef));
    const run = await db.withTenant(tenantId, (client) => service.getRun(client, tenantId, runId));
    res.status(201).json({ success: true, run });
  } catch (e) { fail(res, e, 'start the engine run', 'ENGINE_RUN_START_ERROR'); }
});

module.exports = router;
