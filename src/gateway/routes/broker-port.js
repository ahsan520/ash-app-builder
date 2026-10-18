const express = require('express');
const router = express.Router();
const { db, guarded, apiError, UUID_RE } = require('../shared');
const config = require('../../brokers/config');

// A syslog port for ONE broker (collectors.syslog_port_override). It wins over the tenant-wide port on the "Syslog port for brokers" card
// (PUT /v1/broker-config) for that broker only. Nothing is pushed: a broker that opted in (bootstrap-broker.sh --accept-config) asks for its
// port with its own name and applies it after its own checks. The Brokers page already returns it (GET /v1/brokers, config.source and
// config.override_port). Uses collectors:write; no role change.
// Body: { syslog_port: 1514 | null }. null (or an empty string) removes the override: the broker follows the tenant-wide port again.
router.put('/v1/brokers/:id/syslog-port', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid broker id');
  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  if (!Object.prototype.hasOwnProperty.call(body, 'syslog_port')) return apiError(res, 400, 'INVALID_BODY', 'Send syslog_port (for example 1514, or null to follow the tenant-wide port)');
  const p = config.checkSyslogPort(body.syslog_port);
  if (p.error) return apiError(res, 400, 'INVALID_SYSLOG_PORT', p.error);
  try {
    const broker = await db.withTenant(req.tenant_id, (client) => config.writeOverride(client, req.tenant_id, req.params.id, p.value));
    if (!broker) return apiError(res, 404, 'NOT_FOUND', 'Broker not found');
    res.status(200).json({ success: true, broker, syslog_port: p.value });
  } catch (e) {
    console.error('Broker port override failed:', e.message);
    apiError(res, 500, 'BROKER_CONFIG_ERROR', 'Failed to save the broker port');
  }
});

module.exports = router;
