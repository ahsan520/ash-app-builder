const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const mine = require('../../alerts/mine');
const { withMitre } = require('../../alerts/with-mitre');

// ---- My open alerts (Command Center tile) -----------------------------------------------------------
// Counts, by severity and status, of the active alerts (open or acknowledged) assigned to the signed-in user, plus the
// few that most need attention (each with its ATT&CK techniques and tactics). A service account has no user, so `applicable` is false and nothing is queried.
// Uses alerts:read, so no role changes are needed. The path avoids GET /v1/alerts/:id (owned by routes/alerts.js).
router.get('/v1/my-alerts', ...guarded('alerts:read'), async (req, res) => {
  if (!req.user_id) return res.status(200).json({ success: true, applicable: false });
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const g = await client.query(
        `SELECT severity, status, COUNT(*)::int AS n, MIN(created_at) AS oldest FROM alerts
         WHERE tenant_id = $1 AND assignee_id = $2 AND status IN ('open', 'acknowledged') GROUP BY severity, status`,
        [req.tenant_id, req.user_id]);
      const top = await client.query(
        `SELECT id, severity, status, title, event_count, last_event_at,
                details->'mitre' AS mitre_stored, details->'sample_event_ids' AS sample_ids FROM alerts
         WHERE tenant_id = $1 AND assignee_id = $2 AND status IN ('open', 'acknowledged')
         ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                  CASE status WHEN 'open' THEN 0 ELSE 1 END, last_event_at DESC
         LIMIT ${mine.TOP}`,
        [req.tenant_id, req.user_id]);
      return { summary: mine.summarise(g.rows), alerts: top.rows };
    });
    // ATT&CK of the few alerts shown (E4i): stored on the alert or taken from its sample events; best effort, a failed lookup gives none and never a failed tile.
    const alerts = await withMitre(req.tenant_id, out.alerts);
    res.status(200).json({ success: true, applicable: true, ...out.summary, alerts });
  } catch (error) {
    console.error('My alerts failed:', error.message);
    apiError(res, 500, 'MY_ALERTS_ERROR', 'Failed to read your alerts');
  }
});

module.exports = router;
