'use strict';
const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const managerStore = require('../../endpoints/wazuh-manager-store');
const writerStore = require('../../endpoints/group-config-store');
const histStore = require('../../endpoints/group-linuxlog-store');
const api = require('../../endpoints/wazuh-api');
const gc = require('../../endpoints/group-config');
const service = require('../../endpoints/group-linuxlog-service');

// ---- Linux log files and the journal of an agent group (docs/endpoints.md, task E13) --------------------------------------------------------------------------------
// The third thing ASIX writes to the endpoint manager, with the same limits as E10 and E11 (group-config.js, group-winlog.js): ONE marked block of one group's agent.conf, through the
// SEPARATE writer user, only when ASIX_ENDPOINT_CONFIG_WRITE is "true", with `endpoints:config:write`, the hash of the file the person saw, a history row before the manager is called, a
// look afterwards and the old file put back if the manager holds something else. A request carries entries (a file path or the journal) and a hash, nothing else.
const writeOn = () => String(process.env.ASIX_ENDPOINT_CONFIG_WRITE || '').toLowerCase() === 'true';
const STATUS = { BAD_GROUP: 400, BASE_REQUIRED: 400, INVALID: 400, BAD_BODY: 400, STALE: 409, MARKERS_BROKEN: 409, BLOCK_EDITED: 409, TOO_LARGE: 409, BAD_FILE: 409, REJECTED: 422, MANAGER: 502, VERIFY_FAILED: 502, NO_HISTORY: 404, NOT_UNDOABLE: 409 };
const API_STATUS = { AUTH_FAILED: 502, FORBIDDEN: 502, TLS: 502, UNREACHABLE: 502, TIMEOUT: 504, BAD_RESPONSE: 502, TOO_LARGE: 502, BUSY: 503, BLOCKED_ADDRESS: 502, BAD_ADDRESS: 502, BAD_GROUP: 400, BAD_BODY: 400, REJECTED: 422 };
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const gone = (e) => managerStore.isMissingTable(e) || writerStore.isMissingTable(e) || histStore.isMissingTable(e);

async function load(req, res) {
  let mrow, wrow;
  try { [mrow, wrow] = await db.withTenant(req.tenant_id, async (c) => [await managerStore.readRow(c, req.tenant_id), await writerStore.readWriter(c, req.tenant_id)]); }
  catch (e) {
    if (gone(e)) { apiError(res, 503, 'GROUP_LINUXLOG_NOT_READY', 'The database is missing a table for group configuration: run the schema job (a normal deploy does)'); return { sent: true }; }
    console.error('Group Linux logs lookup failed:', e.message); apiError(res, 500, 'GROUP_LINUXLOG_ERROR', 'Failed to look up the endpoint manager'); return { sent: true };
  }
  if (!mrow) { apiError(res, 404, 'GROUP_LINUXLOG_NO_MANAGER', 'No central endpoint manager is registered for this tenant'); return { sent: true }; }
  if (!wrow) { apiError(res, 404, 'GROUP_LINUXLOG_NO_WRITER', 'No group configuration user is registered for this tenant\u2019s endpoint manager (an operator registers one with register-writer)'); return { sent: true }; }
  try { return { ctx: { m: managerStore.credentials(mrow), w: writerStore.writerCredentials(wrow), api } }; }
  catch (e) {
    if (e && e.code === 'NO_KEY') apiError(res, 503, 'GROUP_LINUXLOG_NO_KEY', 'NOTIFY_ENCRYPTION_KEY is not configured, so the stored manager passwords cannot be opened');
    else apiError(res, 500, 'GROUP_LINUXLOG_SECRET', 'A stored manager password cannot be opened (the encryption key may have changed): register it again');
    return { sent: true };
  }
}
const problem = (res, e) => (e instanceof api.WazuhApiError ? apiError(res, API_STATUS[e.code] || 502, 'GROUP_LINUXLOG_' + e.code, e.message) : (console.error('Group Linux logs call failed:', e && e.message), apiError(res, 500, 'GROUP_LINUXLOG_ERROR', 'The call to the endpoint manager failed')));
const sendResult = (res, r) => {
  if (r.ok) return res.status(200).json({ success: true, ...r });
  const extra = {}; for (const k of ['unchanged', 'rolled_back', 'errors', 'current_sha256']) if (r[k] !== undefined) extra[k] = r[k];
  return res.status(STATUS[r.code] || 500).json({ success: false, error: { code: 'GROUP_LINUXLOG_' + r.code, message: r.message }, ...extra });
};
const groupOk = (req, res) => { if (!gc.validGroup(req.params.group)) { apiError(res, 400, 'GROUP_LINUXLOG_BAD_GROUP', 'A group name is 1 to 64 letters, digits, dots, dashes or underscores'); return false; } return true; };
const bodyOk = (req, res, allowed) => {
  const b = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : null;
  if (!b) { apiError(res, 400, 'GROUP_LINUXLOG_BAD_BODY', 'The body must be a JSON object'); return null; }
  const extra = Object.keys(b).filter((k) => !allowed.includes(k)); if (extra.length) { apiError(res, 400, 'GROUP_LINUXLOG_BAD_BODY', 'Unknown field "' + String(extra[0]).slice(0, 30) + '"'); return null; }
  return b;
};
const history = (req) => ({
  record: (row) => db.withTenant(req.tenant_id, (c) => histStore.record(c, req.tenant_id, req.params.group, { ...row, actor: req.user_id ? String(req.user_id) : null })),
  settle: (id, result, sha, note) => db.withTenant(req.tenant_id, (c) => histStore.settle(c, req.tenant_id, id, result, sha, note)),
});
const shapeHistory = (h) => ({ id: h.id, action: h.action, result: h.result, entries_before: h.entries_before, entries_after: h.entries_after, before_sha256: h.before_sha256, after_sha256: h.after_sha256, note: h.note, by: h.actor_name || null, at: h.created_at });
const writeGate = (req, res) => { if (!writeOn()) { apiError(res, 403, 'GROUP_LINUXLOG_WRITE_OFF', 'Changing group configuration is switched off on this server (ASIX_ENDPOINT_CONFIG_WRITE)'); return false; } return true; };
const entriesOk = (b, res) => { if (!Array.isArray(b.entries)) { apiError(res, 400, 'GROUP_LINUXLOG_BAD_BODY', 'entries must be a list'); return false; } return true; };

router.get('/v1/endpoints/group-linuxlog/:group', ...guarded('capacity:read'), async (req, res) => {
  if (!groupOk(req, res)) return; const l = await load(req, res); if (l.sent) return;
  try {
    const d = await service.describe(l.ctx, req.params.group); if (!d.ok) return sendResult(res, d);
    let rows = []; try { rows = await db.withTenant(req.tenant_id, (c) => histStore.list(c, req.tenant_id, req.params.group, 20)); } catch (e) { if (!histStore.isMissingTable(e)) throw e; }
    res.status(200).json({ success: true, ...d, write_enabled: writeOn(), history: rows.map(shapeHistory) });
  } catch (e) { problem(res, e); }
});
router.post('/v1/endpoints/group-linuxlog/:group/preview', ...guarded('capacity:read'), async (req, res) => {
  if (!groupOk(req, res)) return; const b = bodyOk(req, res, ['entries']); if (!b || !entriesOk(b, res)) return;
  const l = await load(req, res); if (l.sent) return;
  try { sendResult(res, await service.preview(l.ctx, req.params.group, b.entries)); } catch (e) { problem(res, e); }
});
router.put('/v1/endpoints/group-linuxlog/:group', ...guarded('endpoints:config:write'), async (req, res) => {
  if (!groupOk(req, res) || !writeGate(req, res)) return; const b = bodyOk(req, res, ['entries', 'base_sha256']); if (!b || !entriesOk(b, res)) return;
  const l = await load(req, res); if (l.sent) return;
  try { sendResult(res, await service.apply({ ...l.ctx, hist: history(req) }, req.params.group, b.entries, { baseSha: b.base_sha256, action: b.entries.length ? 'apply' : 'remove' })); } catch (e) { problem(res, e); }
});
router.post('/v1/endpoints/group-linuxlog/:group/undo', ...guarded('endpoints:config:write'), async (req, res) => {
  if (!groupOk(req, res) || !writeGate(req, res)) return; const b = bodyOk(req, res, ['history_id', 'base_sha256']); if (!b) return;
  if (typeof b.history_id !== 'string' || !UUID_RE.test(b.history_id)) return apiError(res, 400, 'GROUP_LINUXLOG_BAD_BODY', 'history_id must be the id of a history entry');
  const l = await load(req, res); if (l.sent) return;
  let row; try { row = await db.withTenant(req.tenant_id, (c) => histStore.get(c, req.tenant_id, req.params.group, b.history_id)); } catch (e) { return problem(res, e); }
  if (!row) return apiError(res, 404, 'GROUP_LINUXLOG_NO_HISTORY', 'No such change in this group\u2019s history');
  if (row.result !== 'applied') return apiError(res, 409, 'GROUP_LINUXLOG_NOT_UNDOABLE', 'Only a change that was applied can be undone');
  try { sendResult(res, await service.apply({ ...l.ctx, hist: history(req) }, req.params.group, row.entries_before, { baseSha: b.base_sha256, action: 'undo' })); } catch (e) { problem(res, e); }
});

module.exports = router;
