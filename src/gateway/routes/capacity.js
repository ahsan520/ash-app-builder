const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');

// ---- Capacity & scaling (read-only recommendations) ---------------------------------------------
const capacity = require('../../capacity/capacity');
router.get('/v1/capacity', ...guarded('capacity:read'), async (req, res) => {
  const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 24, 1), 168);
  try { res.status(200).json({ success: true, ...(await capacity.report(req.tenant_id, hours)) }); }
  catch (e) { console.error('Capacity report failed:', e.message); apiError(res, 500, 'CAPACITY_ERROR', 'Failed to build the capacity report'); }
});

// Basic service endpoint.

module.exports = router;
