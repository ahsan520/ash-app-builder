const express = require('express');
const router = express.Router();
const { db, guarded, UUID_RE, apiError } = require('../shared');

// Leave one collector out of the tenant-wide "watch everything" switch (src/collectors/watch-all.js), or put it back.
// Body: { exclude: true | false }. It only affects the switch: "Alert if down" and "Alert if silent" set by hand on this collector still apply.
// An alert that only the switch was holding open is closed by the next watchdog cycle ("no longer watched"). Uses collectors:write; no role change.
router.put('/v1/collectors/:id/watch-exclude', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid collector id');
  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  if (typeof body.exclude !== 'boolean') return apiError(res, 400, 'INVALID_BODY', 'exclude is required (true or false)');
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      'UPDATE collectors SET watch_exclude = $2 WHERE id = $1 AND tenant_id = $3 RETURNING id, name, watch_exclude',
      [req.params.id, body.exclude, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Collector not found');
    res.status(200).json({ success: true, collector: r.rows[0] });
  } catch (error) {
    console.error('Collector watch exclusion failed:', error.message);
    apiError(res, 500, 'COLLECTOR_UPDATE_ERROR', 'Failed to update collector');
  }
});

module.exports = router;
