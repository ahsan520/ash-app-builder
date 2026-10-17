const express = require('express');
const router = express.Router();
const { db, guarded, UUID_RE, apiError } = require('../shared');

// Turn "alert me when this collector goes Disconnected" on or off (src/collectors/watchdog.js does the alerting).
// Body: { watch: true | false }. Turning it off closes the collector's open alert on the next watchdog cycle.
router.put('/v1/collectors/:id/watch', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid collector id');
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  if (typeof body.watch !== 'boolean') return apiError(res, 400, 'INVALID_BODY', 'watch is required (true or false)');
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      'UPDATE collectors SET watch_disconnect = $2 WHERE id = $1 AND tenant_id = $3 RETURNING id, name, watch_disconnect',
      [req.params.id, body.watch, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Collector not found');
    res.status(200).json({ success: true, collector: r.rows[0] });
  } catch (error) {
    console.error('Collector watch update failed:', error.message);
    apiError(res, 500, 'COLLECTOR_UPDATE_ERROR', 'Failed to update collector');
  }
});

module.exports = router;
