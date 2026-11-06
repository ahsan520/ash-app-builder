'use strict';
const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const managerStore = require('../../endpoints/wazuh-manager-store');
const writerStore = require('../../endpoints/group-config-store');
const histStore = require('../../endpoints/group-winlog-store');
const winStore = require('../../endpoints/win-filter-store');
const wf = require('../../endpoints/win-filter');
const api = require('../../endpoints/wazuh-api');
const gc = require('../../endpoints/group-config');
const wl = require('../../endpoints/group-winlog');
const service = require('../../endpoints/group-winlog-service');

// ---- Windows event channels of an agent group (docs/endpoints.md, task E11) ------------------------------------------------------------------------------------
// The second thing ASIX writes to the endpoint manager, with the same limits as the folders of E10 (src/gateway/routes/group-config.js): ONE marked block of one group's agent.conf,
// through the SEPARATE writer user an operator registered, only when ASIX_ENDPOINT_CONFIG_WRITE is "true", with `endpoints:config:write`, the hash of the file the person saw, a history
// row before the manager is called, a look afterwards and the old file put back if the manager holds something else. What goes into the block is chosen by two things: the channels in
// the request and the tenant's Windows filter policy as stored (never a policy or a query in the request). Reading and preview need `capacity:read`.
const writeOn = () => String(process.env.ASIX_ENDPOINT_CONFIG_WRITE || '').toLowerCase() === 'true';
const STATUS = { BAD_GROUP: 400, BASE_REQUIRED: 400, INVALID: 400, BAD_BODY: 400, STALE: 409, MARKERS_BROKEN: 409, BLOCK_EDITED: 409, TOO_LARGE: 409, BAD_FILE: 409, POLICY_INVALID: 409, REJECTED: 422, MANAGER: 502, VERIFY_FAILED: 502, NO_HISTORY: 404, NOT_UNDOABLE: 409 };
const API_STATUS = { AUTH_FAILED: 502, FORBIDDEN: 502, TLS: 502, UNREACHABLE: 502, TIMEOUT: 504, BAD_RESPONSE: 502, TOO_LARGE: 502, BUSY: 503, BLOCKED_ADDRESS: 502, BAD_ADDRESS: 502, BAD_GROUP: 400, BAD_BODY: 400, REJECTED: 422 };
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const gone = (e) => managerStore.isMissingTable(e) || writerStore.isMissingTable(e) || histStore.isMissingTable(e);

// { ctx, policy, revision } with the manager, the writer opened and the stored policy read, or { sent: true } after the answer was written.
async function load(req, res) {
  let mrow, wrow, prow;
  try { [mrow, wrow] = await db.withTenant(req.tenant_id, async (c) => [await managerStore.readRow(c, req.tenant_id), await writerStore.readWriter(c, req.tenant_id)]); }
  catch (e) {
    if (gone(e)) { apiError(res, 503, 'GROUP_WINLOG_NOT_READY', 'The database is missing a table for group configuration: run the schema job (a normal deploy does)'); return { sent: true }; }
    console.error('Group Windows events lookup failed:', e.message); apiError(res, 500, 'GROUP_WINLOG_ERROR', 'Failed to look up the endpoint manager'); return { sent: true };
  }
  if (!mrow) { apiError(res, 404, 'GROUP_WINLOG_NO_MANAGER', 'No central endpoint manager is registered for this tenant'); return { sent: true }; }
  if (!wrow) { apiError(res, 404, 'GROUP_WINLOG_NO_WRITER', 'No group configuration user is registered for this tenant\u2019s endpoint manager (an operator registers one with register-writer)'); return { sent: true }; }
  // The policy: no row = no policy = every channel is read whole. A stored policy that no longer validates is not guessed at.
  try { prow = await db.withTenant(req.tenant_id, (c) => winStore.readRow(c, req.tenant_id)); }
  catch (e) {
    if (winStore.isMissingTable(e)) prow = null;
    else { console.error('Windows filter policy not read:', e.message); apiError(res, 500, 'GROUP_WINLOG_ERROR', 'Failed to read the Windows event filter policy'); return { sent: true }; }
  }
  const v = wf.validate(prow ? prow.policy : {});
  if (!v.ok) { apiError(res, 409, 'GROUP_WINLOG_POLICY_INVALID', 'The saved Windows event filter policy is not valid: open Settings, Windows event filter and fix it first'); return { sent: true }; }
  try { return { ctx: { m: managerStore.credentials(mrow), w: writerStore.writerCredentials(wrow), api }, policy: v.policy, revision: prow ? prow.revision : 0 }; }
  catch (e) {
    if (e && e.code === 'NO_KEY') apiError(res, 503, 'GROUP_WINLOG_NO_KEY', 'NOTIFY_ENCRYPTION_KEY is not configured, so the stored manager passwords cannot be opened');
    else apiError(res, 500, 'GROUP_WINLOG_SECRET', 'A stored manager password cannot be opened (the encryption key may have changed): register it again');
    return { sent: true };
  }
}
const problem = (res, e) => (e instanceof api.WazuhApiError ? apiError(res, API_STATUS[e.code] || 502, 'GROUP_WINLOG_' + e.code, e.message) : (console.error('Group Windows events call failed:', e && e.message), apiError(res, 500, 'GROUP_WINLOG_ERROR', 'The call to the endpoint manager failed')));
const sendResult = (res, r) => {
  if (r.ok) return res.status(200).json({ success: true, ...r });
  const extra = {}; for (const k of ['unchanged', 'rolled_back', 'errors', 'current_sha256']) if (r[k] !== undefined) extra[k] = r[k];
  return res.status(STATUS[r.code] || 500).json({ success: false, error: { code: 'GROUP_WINLOG_' + r.code, message: r.message }, ...extra });
};
const groupOk = (req, res) => { if (!gc.validGroup(req.params.group)) { apiError(res, 400, 'GROUP_WINLOG_BAD_GROUP', 'A group name is 1 to 64 letters, digits, dots, dashes or underscores'); return false; } return true; };
const bodyOk = (req, res, allowed) => {
  const b = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : null;
  if (!b) { apiError(res, 400, 'GROUP_WINLOG_BAD_BODY', 'The body must be a JSON object'); return null; }
  const extra = Object.keys(b).filter((k) => !allowed.includes(k)); if (extra.length) { apiError(res, 400, 'GROUP_WINLOG_BAD_BODY', 'Unknown field "' + String(extra[0]).slice(0, 30) + '"'); return null; }
  return b;
};
const history = (req) => ({
  record: (row) => db.withTenant(req.tenant_id, (c) => histStore.record(c, req.tenant_id, req.params.group, { ...row, actor: req.user_id ? String(req.user_id) : null })),
  settle: (id, result, sha, note) => db.withTenant(req.tenant_id, (c) => histStore.settle(c, req.tenant_id, id, result, sha, note)),
});
const shapeHistory = (h) => ({ id: h.id, action: h.action, result: h.result, channels_before: h.channels_before, channels_after: h.channels_after, policy_revision: h.policy_revision, before_sha256: h.before_sha256, after_sha256: h.after_sha256, note: h.note, by: h.actor_name || null, at: h.created_at });
const writeGate = (req, res) => { if (!writeOn()) { apiError(res, 403, 'GROUP_WINLOG_WRITE_OFF', 'Changing group configuration is switched off on this server (ASIX_ENDPOINT_CONFIG_WRITE)'); return false; } return true; };

// One group: the hash to send back with a change, the state of the block, its channels, how each compares with the policy now, the channels worth offering and the recent history.
router.get('/v1/endpoints/group-winlog/:group', ...guarded('capacity:read'), async (req, res) => {
  if (!groupOk(req, res)) return; const l = await load(req, res); if (l.sent) return;
  try {
    const d = await service.describe(l.ctx, req.params.group, l.policy); if (!d.ok) return sendResult(res, d);
    let rows = []; try { rows = await db.withTenant(req.tenant_id, (c) => histStore.list(c, req.tenant_id, req.params.group, 20)); } catch (e) { if (!histStore.isMissingTable(e)) throw e; }
    const offered = winStore.channelsOf(l.policy);
    res.status(200).json({ success: true, ...d, write_enabled: writeOn(), policy_revision: l.revision, offered, pushes: wl.desired(l.policy, d.state === 'ok' ? d.channels : offered), history: rows.map(shapeHistory) });
  } catch (e) { problem(res, e); }
});

// What a change would do. Reads only; nothing is written anywhere.
router.post('/v1/endpoints/group-winlog/:group/preview', ...guarded('capacity:read'), async (req, res) => {
  if (!groupOk(req, res)) return; const b = bodyOk(req, res, ['channels']); if (!b) return;
  if (!Array.isArray(b.channels)) return apiError(res, 400, 'GROUP_WINLOG_BAD_BODY', 'channels must be a list');
  const l = await load(req, res); if (l.sent) return;
  try { sendResult(res, await service.preview(l.ctx, req.params.group, l.policy, b.channels)); } catch (e) { problem(res, e); }
});

// Change the block. An empty list removes it. Also the way to bring the block back in step with a policy that was saved after the block was written.
router.put('/v1/endpoints/group-winlog/:group', ...guarded('endpoints:config:write'), async (req, res) => {
  if (!groupOk(req, res) || !writeGate(req, res)) return; const b = bodyOk(req, res, ['channels', 'base_sha256']); if (!b) return;
  if (!Array.isArray(b.channels)) return apiError(res, 400, 'GROUP_WINLOG_BAD_BODY', 'channels must be a list');
  const l = await load(req, res); if (l.sent) return;
  try { sendResult(res, await service.apply({ ...l.ctx, hist: history(req) }, req.params.group, l.policy, b.channels, { baseSha: b.base_sha256, action: b.channels.length ? 'apply' : 'remove', policyRevision: l.revision })); } catch (e) { problem(res, e); }
});

// Undo one earlier change: the block goes back to the channels it had before that change, with the queries of the policy as it is NOW (the page says so).
router.post('/v1/endpoints/group-winlog/:group/undo', ...guarded('endpoints:config:write'), async (req, res) => {
  if (!groupOk(req, res) || !writeGate(req, res)) return; const b = bodyOk(req, res, ['history_id', 'base_sha256']); if (!b) return;
  if (typeof b.history_id !== 'string' || !UUID_RE.test(b.history_id)) return apiError(res, 400, 'GROUP_WINLOG_BAD_BODY', 'history_id must be the id of a history entry');
  const l = await load(req, res); if (l.sent) return;
  let row; try { row = await db.withTenant(req.tenant_id, (c) => histStore.get(c, req.tenant_id, req.params.group, b.history_id)); } catch (e) { return problem(res, e); }
  if (!row) return apiError(res, 404, 'GROUP_WINLOG_NO_HISTORY', 'No such change in this group\u2019s history');
  if (row.result !== 'applied') return apiError(res, 409, 'GROUP_WINLOG_NOT_UNDOABLE', 'Only a change that was applied can be undone');
  try { sendResult(res, await service.apply({ ...l.ctx, hist: history(req) }, req.params.group, l.policy, row.channels_before, { baseSha: b.base_sha256, action: 'undo', policyRevision: l.revision })); } catch (e) { problem(res, e); }
});

module.exports = router;
