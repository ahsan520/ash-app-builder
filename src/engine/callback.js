'use strict';
// What the automation engine may call (task SR3, docs/engine-callback.md): POST /v1/engine/callback/actions/<id>, GET /v1/engine/callback/action-runs/<id>, POST /v1/engine/callback/finish.
// Not behind the sign-in chain: the engine cannot sign in as a person, and the credential is the RUN TOKEN that ASIX handed it when it started the run. The token is one run's:
//   - the tenant comes from the run, never from the request (a body that names one is refused),
//   - only the actions listed for the run can be asked for, at most `max_calls` times, until the run's time is up or the workflow reports its end (then the token is cleared),
//   - the token is stored only as a SHA-256 hash; a token that is wrong, expired or finished gets the same 401 (nothing says which); a token is limited to ASIX_ENGINE_RATE_PER_MIN a minute.
// The answer to a request is the registry's decision in one word (`outcome`): executed, awaiting_approval, recommended, refused, failed. A refusal is HTTP 200, because the workflow must be able to
// see it and finish; HTTP errors are for a bad token, a bad request, an action the run may not ask for and the call limit.
const express = require('express');
const db = require('../db');
const modules = require('../modules');
const model = require('./model');
const service = require('./service');

const RATE_PER_MIN = Math.max(1, Number(process.env.ASIX_ENGINE_RATE_PER_MIN || 60));
const router = express.Router();

const hits = new Map();
function limited(key) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < 60000);
  const over = arr.length >= RATE_PER_MIN;
  if (!over) arr.push(now);
  hits.set(key, arr);
  return over;
}
setInterval(() => { const now = Date.now(); for (const [k, a] of hits) { const f = a.filter((t) => now - t < 60000); f.length ? hits.set(k, f) : hits.delete(k); } }, 60000).unref();

const apiError = (res, status, code, message) => res.set('Cache-Control', 'no-store').status(status).json({ success: false, error: { code, message } });
const deny = (res) => apiError(res, 401, 'ENGINE_AUTH_INVALID', 'The run token is invalid, expired or the run has finished');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function runAuth(req, res, next) {
  try {
    const h = req.headers.authorization;
    const token = h && h.startsWith('Bearer ') ? h.slice(7).trim() : null;
    if (!model.tokenShape(token)) return deny(res);   // the wrong shape never reaches the database
    const hash = model.hashToken(token);
    if (limited(hash)) return apiError(res, 429, 'ENGINE_RATE_LIMITED', 'Too many requests with this run token');
    const found = await service.findOpenByHash(db, hash);
    if (!found) return deny(res);
    if (!(await modules.isEnabled('actions'))) return apiError(res, 403, 'MODULE_DISABLED', 'The Action registry module is not enabled on this deployment');
    req.engine = found;
    return next();
  } catch (e) { console.error('Engine callback auth failed:', e.message); return apiError(res, 500, 'ENGINE_CALLBACK_ERROR', 'Failed to check the run token'); }   // never the token
}

const answer = (res, run, outcome) => res.set('Cache-Control', 'no-store').status(200).json({ success: true, outcome, action_run: model.callView(run) });

router.post('/v1/engine/callback/actions/:actionId', runAuth, async (req, res) => {
  const actionId = req.params.actionId;
  if (!model.ACTION_ID_RE.test(actionId)) return apiError(res, 400, 'INVALID_ACTION', 'Not an action id');
  const body = model.parseCall(req.body);
  if (body.error) return apiError(res, 400, body.error.code, body.error.message);
  try {
    const { runId, tenantId } = req.engine;
    const out = await db.withTenant(tenantId, (client) => service.callAction(client, tenantId, runId, actionId, body.value.parameters));
    switch (out.code) {
      case undefined: return answer(res, out.run, out.outcome);
      case 'NOT_OPEN': return deny(res);
      case 'ACTION_NOT_ALLOWED': return apiError(res, 403, 'ACTION_NOT_ALLOWED', 'This run may not ask for that action');
      case 'CALL_LIMIT': return apiError(res, 409, 'CALL_LIMIT', 'This run has used all its action requests');
      case 'NOT_FOUND': return apiError(res, 404, 'NOT_FOUND', 'Not found');
      default: return apiError(res, 400, out.code, out.message || 'Invalid request');
    }
  } catch (e) { console.error('Engine callback failed:', e.message); return apiError(res, 500, 'ENGINE_CALLBACK_ERROR', 'Failed to handle the request'); }
});

// One of this run's own requests, to see how it stands now (for example after a person approved it). Another run's request is a plain 404.
router.get('/v1/engine/callback/action-runs/:id', runAuth, async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid id');
  try {
    const { runId, tenantId } = req.engine;
    const run = await db.withTenant(tenantId, (client) => service.readCall(client, tenantId, runId, req.params.id));
    if (!run) return apiError(res, 404, 'NOT_FOUND', 'Not found');
    return answer(res, run, model.outcomeOf(run));
  } catch (e) { console.error('Engine callback read failed:', e.message); return apiError(res, 500, 'ENGINE_CALLBACK_ERROR', 'Failed to read the request'); }
});

router.post('/v1/engine/callback/finish', runAuth, async (req, res) => {
  const body = model.parseFinish(req.body);
  if (body.error) return apiError(res, 400, body.error.code, body.error.message);
  try {
    const { runId, tenantId } = req.engine;
    const out = await db.withTenant(tenantId, (client) => service.finish(client, tenantId, runId, body.value));
    if (out.code) return deny(res);
    return res.set('Cache-Control', 'no-store').status(200).json({ success: true, status: body.value.status });
  } catch (e) { console.error('Engine finish failed:', e.message); return apiError(res, 500, 'ENGINE_CALLBACK_ERROR', 'Failed to finish the run'); }
});

module.exports = { router, RATE_PER_MIN };
