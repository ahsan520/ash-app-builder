const express = require('express');
const router = express.Router();
const { db, guarded, apiError, UUID_RE } = require('../shared');
const config = require('../../brokers/config');

// Leave ONE broker out of the tenant-wide syslog port (PUT /v1/broker-config), or put it back (collectors.syslog_port_exclude).
// A broker that is left out is told no port, so it keeps whatever it listens on now; a port set for it alone (PUT /v1/brokers/:id/syslog-port)
// still applies. Nothing is pushed and nothing on the broker changes: a broker that opted in (--accept-config) and has the current script
// asks with its own name. Body: { exclude: true | false }. Uses collectors:write; no role change.
router.put('/v1/brokers/:id/syslog-port-exclude', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid broker id');
  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  if (typeof body.exclude !== 'boolean') return apiError(res, 400, 'INVALID_BODY', 'exclude is required (true or false)');
  try {
    const broker = await db.withTenant(req.tenant_id, (client) => config.writeExclude(client, req.tenant_id, req.params.id, body.exclude));
    if (!broker) return apiError(res, 404, 'NOT_FOUND', 'Broker not found');
    res.status(200).json({ success: true, broker });
  } catch (e) {
    console.error('Broker port exclusion failed:', e.message);
    apiError(res, 500, 'BROKER_CONFIG_ERROR', 'Failed to save the broker setting');
  }
});

module.exports = router;
