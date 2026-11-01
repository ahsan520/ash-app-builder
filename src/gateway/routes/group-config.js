'use strict';
const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const managerStore = require('../../endpoints/wazuh-manager-store');
const store = require('../../endpoints/group-config-store');
const api = require('../../endpoints/wazuh-api');
const gc = require('../../endpoints/group-config');
const service = require('../../endpoints/group-config-service');

// ---- Monitored folders of an agent group (docs/endpoints.md, task E10) ---------------------------------------------------------------------------------
// The ONLY routes that change anything on the endpoint manager. What they can change is narrow on purpose:
//   - one block of one group's agent.conf, between ASIX's own markers; every other byte of the file is kept (src/endpoints/group-config.js);
//   - through a SEPARATE manager user whose role on the manager allows only reading groups and updating a group's configuration (an operator registers it, no route does);
//   - only when the server switch ASIX_ENDPOINT_CONFIG_WRITE is "true" (off in k8s/30-asix-api.yaml: a deploy never turns it on);
//   - with `endpoints:config:write`, the hash of the file the person saw (a changed file is refused), a history row written before the manager is called, a look at the manager
//     afterwards, and the old file put back if what it holds is not what was written.
// Reading (the list, one group, preview) needs `capacity:read` like the rest of the Endpoints page. Nothing in a request chooses an address, a path or a credential.
const writeOn = () => String(process.env.ASIX_ENDPOINT_CONFIG_WRITE || '').toLowerCase() === 'true';
const STATUS = { BAD_GROUP: 400, BASE_REQUIRED: 400, INVALID: 400, BAD_BODY: 400, STALE: 409, MARKERS_BROKEN: 409, BLOCK_EDITED: 409, TOO_LARGE: 409, BAD_FILE: 409, REJECTED: 422, MANAGER: 502, VERIFY_FAILED: 502, NO_HISTORY: 404, NOT_UNDOABLE: 409 };
const API_STATUS = { AUTH_FAILED: 502, FORBIDDEN: 502, TLS: 502, UNREACHABLE: 502, TIMEOUT: 504, BAD_RESPONSE: 502, TOO_LARGE: 502, BUSY: 503, BLOCKED_ADDRESS: 502, BAD_ADDRESS: 502, BAD_GROUP: 400, BAD_BODY: 400, REJECTED: 422 };
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// { ctx } with the manager and the writer opened, or { sent: true } after the answer was written. `needWriter: false` lets the status route answer without one.
async function load(req, res, needWriter = true) {
  let mrow, wrow;
  try { [mrow, wrow] = await db.withTenant(req.tenant_id, async (c) => [await managerStore.readRow(c, req.tenant_id), await store.readWriter(c, req.tenant_id)]); }
  catch (e) {
    if (managerStore.isMissingTable(e) || store.isMissingTable(e)) { apiError(res, 503, 'GROUP_CONFIG_NOT_READY', 'The database is missing a table for group configuration: run the schema job (a normal deploy does)'); return { sent: true }; }
    console.error('Group configuration lookup failed:', e.message); apiError(res, 500, 'GROUP_CONFIG_ERROR', 'Failed to look up the endpoint manager'); return { sent: true };
  }
  if (!mrow) { apiError(res, 404, 'GROUP_CONFIG_NO_MANAGER', 'No central endpoint manager is registered for this tenant'); return { sent: true }; }
  if (!wrow && needWriter) { apiError(res, 404, 'GROUP_CONFIG_NO_WRITER', 'No group configuration user is registered for this tenant\u2019s endpoint manager (an operator registers one with register-writer)'); return { sent: true }; }
  try { return { ctx: { m: managerStore.credentials(mrow), w: wrow ? store.writerCredentials(wrow) : null, api }, mrow, wrow }; }
  catch (e) {
    if (e && e.code === 'NO_KEY') apiError(res, 503, 'GROUP_CONFIG_NO_KEY', 'NOTIFY_ENCRYPTION_KEY is not configured, so the stored manager passwords cannot be opened');
    else apiError(res, 500, 'GROUP_CONFIG_SECRET', 'A stored manager password cannot be opened (the encryption key may have changed): register it again');
    return { sent: true };
  }
}
const problem = (res, e) => (e instanceof api.WazuhApiError ? apiError(res, API_STATUS[e.code] || 502, 'GROUP_CONFIG_' + e.code, e.message) : (console.error('Group configuration call failed:', e && e.message), apiError(res, 500, 'GROUP_CONFIG_ERROR', 'The call to the endpoint manager failed')));
// A failure keeps the usual { success: false, error: { code, message } } and adds what the page needs to explain it: whether the manager still has the old file (unchanged), whether the old
// file was put back (rolled_back), the list of problems with the entries (errors) and the hash of the file as it is now (current_sha256, for a refused stale change).
const sendResult = (res, r) => {
  if (r.ok) return res.status(200).json({ success: true, ...r });
  const extra = {}; for (const k of ['unchanged', 'rolled_back', 'errors', 'current_sha256']) if (r[k] !== undefined) extra[k] = r[k];
  return res.status(STATUS[r.code] || 500).json({ success: false, error: { code: 'GROUP_CONFIG_' + r.code, message: r.message }, ...extra });
};
const groupOk = (req, res) => { if (!gc.validGroup(req.params.group)) { apiError(res, 400, 'GROUP_CONFIG_BAD_GROUP', 'A group name is 1 to 64 letters, digits, dots, dashes or underscores'); return false; } return true; };
const bodyOk = (req, res, allowed) => {
  const b = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : null;
  if (!b) { apiError(res, 400, 'GROUP_CONFIG_BAD_BODY', 'The body must be a JSON object'); return null; }
  const extra = Object.keys(b).filter((k) => !allowed.includes(k)); if (extra.length) { apiError(res, 400, 'GROUP_CONFIG_BAD_BODY', 'Unknown field "' + String(extra[0]).slice(0, 30) + '"'); return null; }
  return b;
};
const history = (req) => ({
  record: (row) => db.withTenant(req.tenant_id, (c) => store.record(c, req.tenant_id, req.params.group, { ...row, actor: req.user_id ? String(req.user_id) : null })),
  settle: (id, result, sha, note) => db.withTenant(req.tenant_id, (c) => store.settle(c, req.tenant_id, id, result, sha, note)),
});

// What is possible here: is writing switched on, is there a manager and a writer, and the groups the manager has.
router.get('/v1/endpoints/group-config', ...guarded('capacity:read'), async (req, res) => {
  const l = await load(req, res, false); if (l.sent) return;
  const out = { success: true, write_enabled: writeOn(), manager_registered: true, writer_registered: !!l.wrow, writer: store.writerView(l.wrow), groups: [], limits: { max_entries: gc.MAX_ENTRIES, max_realtime: gc.MAX_REALTIME } };
  if (l.wrow) { try { out.groups = await api.groupList(l.ctx.m, l.ctx.w); } catch (e) { out.problem = { code: e.code || 'ERROR', message: e instanceof api.WazuhApiError ? e.message : 'The call to the endpoint manager failed' }; } }
  res.status(200).json(out);
});

// One group: the hash to send back with a change, the state of the ASIX block, its entries, and the recent history.
router.get('/v1/endpoints/group-config/:group', ...guarded('capacity:read'), async (req, res) => {
  if (!groupOk(req, res)) return; const l = await load(req, res); if (l.sent) return;
  try {
    const d = await service.describe(l.ctx, req.params.group); if (!d.ok) return sendResult(res, d);
    const rows = await db.withTenant(req.tenant_id, (c) => store.list(c, req.tenant_id, req.params.group, 20));
    res.status(200).json({ success: true, ...d, write_enabled: writeOn(), history: rows.map(shapeHistory) });
  } catch (e) { problem(res, e); }
});
const shapeHistory = (h) => ({ id: h.id, action: h.action, result: h.result, entries_before: h.entries_before, entries_after: h.entries_after, before_sha256: h.before_sha256, after_sha256: h.after_sha256, note: h.note, by: h.actor_name || null, at: h.created_at });

// What a change would do. Reads only; nothing is written anywhere.
router.post('/v1/endpoints/group-config/:group/preview', ...guarded('capacity:read'), async (req, res) => {
  if (!groupOk(req, res)) return; const b = bodyOk(req, res, ['entries']); if (!b) return;
  if (!Array.isArray(b.entries)) return apiError(res, 400, 'GROUP_CONFIG_BAD_BODY', 'entries must be a list');
  const l = await load(req, res); if (l.sent) return;
  try { sendResult(res, await service.preview(l.ctx, req.params.group, b.entries)); } catch (e) { problem(res, e); }
});

const writeGate = (req, res) => { if (!writeOn()) { apiError(res, 403, 'GROUP_CONFIG_WRITE_OFF', 'Changing group configuration is switched off on this server (ASIX_ENDPOINT_CONFIG_WRITE)'); return false; } return true; };

// Change the block. An empty list removes it.
router.put('/v1/endpoints/group-config/:group', ...guarded('endpoints:config:write'), async (req, res) => {
  if (!groupOk(req, res) || !writeGate(req, res)) return; const b = bodyOk(req, res, ['entries', 'base_sha256']); if (!b) return;
  if (!Array.isArray(b.entries)) return apiError(res, 400, 'GROUP_CONFIG_BAD_BODY', 'entries must be a list');
  const l = await load(req, res); if (l.sent) return;
  try { sendResult(res, await service.apply({ ...l.ctx, hist: history(req) }, req.params.group, b.entries, { baseSha: b.base_sha256, action: b.entries.length ? 'apply' : 'remove' })); } catch (e) { problem(res, e); }
});

// Undo one earlier change: the ASIX block goes back to the entries it had before that change. Only the block; nothing else in the file is touched.
router.post('/v1/endpoints/group-config/:group/undo', ...guarded('endpoints:config:write'), async (req, res) => {
  if (!groupOk(req, res) || !writeGate(req, res)) return; const b = bodyOk(req, res, ['history_id', 'base_sha256']); if (!b) return;
  if (typeof b.history_id !== 'string' || !UUID_RE.test(b.history_id)) return apiError(res, 400, 'GROUP_CONFIG_BAD_BODY', 'history_id must be the id of a history entry');
  const l = await load(req, res); if (l.sent) return;
  let row; try { row = await db.withTenant(req.tenant_id, (c) => store.get(c, req.tenant_id, req.params.group, b.history_id)); } catch (e) { return problem(res, e); }
  if (!row) return apiError(res, 404, 'GROUP_CONFIG_NO_HISTORY', 'No such change in this group\u2019s history');
  if (row.result !== 'applied') return apiError(res, 409, 'GROUP_CONFIG_NOT_UNDOABLE', 'Only a change that was applied can be undone');
  try { sendResult(res, await service.apply({ ...l.ctx, hist: history(req) }, req.params.group, row.entries_before, { baseSha: b.base_sha256, action: 'undo' })); } catch (e) { problem(res, e); }
});

module.exports = router;
