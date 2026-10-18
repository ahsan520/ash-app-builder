const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const config = require('../../brokers/config');

// Broker config for the portal: the syslog port brokers that opted in (bootstrap-broker.sh --accept-config) should listen on.
// Nothing is pushed: brokers ask for it (src/ingest/broker-config.js). Uses collectors:read / collectors:write; no role change.
router.get('/v1/broker-config', ...guarded('collectors:read'), async (req, res) => {
  try {
    const port = await db.withTenant(req.tenant_id, (client) => config.readSyslogPort(client, req.tenant_id));
    res.status(200).json({ success: true, config: config.view(port) });
  } catch (e) {
    console.error('Broker config read failed:', e.message);
    apiError(res, 500, 'BROKER_CONFIG_ERROR', 'Failed to read the broker config');
  }
});

// Body: { syslog_port: 1514 | null }. null (or an empty string) clears it: brokers keep whatever they have.
router.put('/v1/broker-config', ...guarded('collectors:write'), async (req, res) => {
  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  if (!Object.prototype.hasOwnProperty.call(body, 'syslog_port')) return apiError(res, 400, 'INVALID_BODY', 'Send syslog_port (for example 1514, or null to clear it)');
  const p = config.checkSyslogPort(body.syslog_port);
  if (p.error) return apiError(res, 400, 'INVALID_SYSLOG_PORT', p.error);
  try {
    await db.withTenant(req.tenant_id, (client) => config.writeSyslogPort(client, req.tenant_id, p.value, req.user_id));
    res.status(200).json({ success: true, config: config.view(p.value) });
  } catch (e) {
    console.error('Broker config update failed:', e.message);
    apiError(res, 500, 'BROKER_CONFIG_ERROR', 'Failed to save the broker config');
  }
});

module.exports = router;
