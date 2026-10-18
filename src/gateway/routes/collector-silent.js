const express = require('express');
const router = express.Router();
const { db, guarded, UUID_RE, apiError } = require('../shared');
const { checkMinutes, MIN_MINUTES, MAX_MINUTES } = require('../../collectors/silence');

// "Alert me when this collector is alive but sends no events" (src/collectors/silence.js does the alerting).
// Body: { minutes: 5..4320 } turns it on (alert after that many minutes without an event), { minutes: null } turns it off.
// Turning it off closes the collector's open alert on the next watchdog cycle.
router.put('/v1/collectors/:id/silent-watch', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid collector id');
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  if (!Object.prototype.hasOwnProperty.call(body, 'minutes')) return apiError(res, 400, 'INVALID_BODY', 'minutes is required (a whole number, or null to turn it off)');
  const m = checkMinutes(body.minutes);
  if (m.error) return apiError(res, 400, 'INVALID_SILENT_MINUTES', m.error);
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      'UPDATE collectors SET watch_silent_min = $2 WHERE id = $1 AND tenant_id = $3 RETURNING id, name, watch_silent_min',
      [req.params.id, m.value, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Collector not found');
    res.status(200).json({ success: true, collector: r.rows[0], limits: { min: MIN_MINUTES, max: MAX_MINUTES } });
  } catch (error) {
    console.error('Collector silent-watch update failed:', error.message);
    apiError(res, 500, 'COLLECTOR_UPDATE_ERROR', 'Failed to update collector');
  }
});

module.exports = router;
