const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const store = require('../../endpoints/win-filter-store');
const wf = require('../../endpoints/win-filter');

// ---- Windows event filter policy (src/endpoints/win-filter-store.js, docs/endpoints.md task E2) ----------------------------------------
// Read and preview: capacity:read (same as the Parser pool page). Change: parsing:rules:write (the parsing settings permission). No role changes.
// Saving only stores the policy for this tenant; nothing is pushed to a broker or an agent (E3) and no event is touched.
router.get('/v1/endpoints/win-filter', ...guarded('capacity:read'), async (req, res) => {
  try {
    const row = await db.withTenant(req.tenant_id, (client) => store.readRow(client, req.tenant_id));
    res.status(200).json({ success: true, settings: store.view(row) });
  } catch (e) {
    // The schema job has not created the table yet: say so instead of failing, the page shows a notice.
    if (store.isMissingTable(e)) return res.status(200).json({ success: true, settings: store.view(null, true) });
    console.error('Windows filter read failed:', e.message);
    apiError(res, 500, 'WIN_FILTER_ERROR', 'Failed to read the Windows filter policy');
  }
});

// Body: { policy: {...}, if_revision?: N } or { clear: true }. if_revision is the revision the policy was edited from (0 = none saved yet); a different one means somebody
// saved in between and the save is refused with 409 and nothing is written.
router.put('/v1/endpoints/win-filter', ...guarded('parsing:rules:write'), async (req, res) => {
  const b = store.parseBody(req.body);
  if (b.error) return apiError(res, 400, 'INVALID_WIN_FILTER', b.error);
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const current = await store.readRow(client, req.tenant_id, true);
      if (!b.clear && b.if_revision !== null && b.if_revision !== (current ? current.revision : 0)) return { conflict: true };
      if (b.clear) await store.clearRow(client, req.tenant_id);
      else await store.writeRow(client, req.tenant_id, b.canonical, req.user_id);
      return { row: await store.readRow(client, req.tenant_id) };
    });
    if (out.conflict) return apiError(res, 409, 'WIN_FILTER_CHANGED', 'The policy was saved by someone else since you opened it: reload it and make your change again');
    res.status(200).json({ success: true, settings: store.view(out.row) });
  } catch (e) {
    if (store.isMissingTable(e)) return apiError(res, 503, 'WIN_FILTER_NOT_READY', 'The database has no win_filter_policy table yet: run the schema job (a normal deploy does)');
    console.error('Windows filter update failed:', e.message);
    apiError(res, 500, 'WIN_FILTER_ERROR', 'Failed to save the Windows filter policy');
  }
});

// Checks a policy without saving it. Body: { policy: {...}, events?: [{ channel, event_id, fields?, message? }] }. Returns the problems, or the Vector transform, the Wazuh
// agent group blocks and what each sample event would do. Touches no database.
router.post('/v1/endpoints/win-filter/preview', ...guarded('capacity:read'), (req, res) => {
  const b = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  const v = wf.validate(b.policy === undefined ? {} : b.policy);   // no policy given = the empty one
  if (!v.ok) return res.status(200).json({ success: true, preview: { ok: false, errors: v.errors } });
  const ev = store.parseEvents(b.events);
  if (ev.error) return apiError(res, 400, 'INVALID_WIN_FILTER', ev.error);
  res.status(200).json({ success: true, preview: store.preview(v.policy, ev.events) });
});

module.exports = router;
