const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const { getEventStore } = require('../../events');
const scoreAlert = require('../../endpoints/score-alert');

// ---- "Endpoint configuration check score low" alert: its limit from the Endpoints page (src/endpoints/score-alert.js, docs/endpoints.md task E4o) -----------------------
// It edits the tenant's built-in detection rule, so it uses the Detections permissions (read: detections:rules:read, change: detections:rules:write). No role changes, no new
// table. The rule runner reads the rule every cycle, so a change applies within about a minute. Nothing is sent to the manager or to an agent.
router.get('/v1/endpoints/score-alert', ...guarded('detections:rules:read'), async (req, res) => {
  try {
    const row = await db.withTenant(req.tenant_id, (client) => scoreAlert.readRow(client, req.tenant_id));
    res.status(200).json({ success: true, settings: scoreAlert.view(row) });
  } catch (e) {
    console.error('Score alert read failed:', e.message);
    apiError(res, 500, 'SCORE_ALERT_ERROR', 'Failed to read the configuration check score alert');
  }
});

// Body: { limit: 1..100 } | { off: true }
router.put('/v1/endpoints/score-alert', ...guarded('detections:rules:write'), async (req, res) => {
  const b = scoreAlert.parseBody(req.body);
  if (b.error) return apiError(res, 400, 'INVALID_SCORE_ALERT', b.error);
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const written = b.off ? await scoreAlert.writeOff(client, req.tenant_id) : await scoreAlert.writeLimit(client, req.tenant_id, b.limit);
      const row = await scoreAlert.readRow(client, req.tenant_id);
      return { written, row };
    });
    if (!out.row) return apiError(res, 503, 'SCORE_ALERT_NOT_READY', 'The rule does not exist yet: it is created within a minute of the API starting. Try again shortly');
    if (!out.written) return apiError(res, 409, 'SCORE_ALERT_EDITED', 'The rule\'s query was edited on the Detections page, so the limit is not changed from here. Change it there, or press Reset on the rule to get the shipped query back');
    res.status(200).json({ success: true, settings: scoreAlert.view(out.row) });
  } catch (e) {
    console.error('Score alert update failed:', e.message);
    apiError(res, 500, 'SCORE_ALERT_ERROR', 'Failed to save the configuration check score alert');
  }
});

// E4p: how many machines a limit would catch, from the newest stored scan summary per policy and machine (last 7 days). Reads event contents, so it uses search:events:read
// like the Endpoints alert tabs. Read only. ?limit=1..100
router.get('/v1/endpoints/score-alert/preview', ...guarded('search:events:read'), async (req, res) => {
  const l = scoreAlert.checkLimit(Array.isArray(req.query.limit) ? undefined : req.query.limit);
  if (l.error) return apiError(res, 400, 'INVALID_SCORE_ALERT', l.error);
  try {
    const r = await getEventStore().search(req.tenant_id, scoreAlert.previewPlan());
    res.status(200).json({ success: true, preview: scoreAlert.preview(r.rows, l.value, r.truncated) });
  } catch (e) {
    console.error('Score alert preview failed:', e.message);
    apiError(res, 500, 'SCORE_ALERT_ERROR', 'Failed to read the scan summaries');
  }
});

module.exports = router;
