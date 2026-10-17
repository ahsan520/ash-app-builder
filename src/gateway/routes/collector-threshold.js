const express = require('express');
const router = express.Router();
const { db, guarded, UUID_RE, apiError } = require('../shared');
const { checkMinutes, effectiveMinutes, isCustom, DEFAULT_MINUTES } = require('../../collectors/status');

// Per-collector "Connected if seen within N minutes". Body: { minutes: 1..10080 } or { minutes: null }
// to go back to the default. Only the threshold changes: status is still worked out when the list is read.
router.put('/v1/collectors/:id/threshold', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid collector id');
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  if (!Object.prototype.hasOwnProperty.call(body, 'minutes')) return apiError(res, 400, 'INVALID_BODY', 'minutes is required (a whole number, or null for the default)');
  const m = checkMinutes(body.minutes);
  if (m.error) return apiError(res, 400, 'INVALID_THRESHOLD', m.error);
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      'UPDATE collectors SET connected_within_min = $2 WHERE id = $1 AND tenant_id = $3 RETURNING id, name, connected_within_min',
      [req.params.id, m.value, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Collector not found');
    const c = r.rows[0];
    res.status(200).json({ success: true, collector: {
      id: c.id, name: c.name, connected_within_min: effectiveMinutes(c.connected_within_min),
      connected_custom: isCustom(c.connected_within_min), default_minutes: DEFAULT_MINUTES } });
  } catch (error) {
    console.error('Collector threshold update failed:', error.message);
    apiError(res, 500, 'COLLECTOR_UPDATE_ERROR', 'Failed to update collector');
  }
});

module.exports = router;
