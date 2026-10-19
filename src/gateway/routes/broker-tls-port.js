const express = require('express');
const router = express.Router();
const { db, guarded, apiError, UUID_RE } = require('../shared');
const config = require('../../brokers/config');

// A syslog-over-TLS port for ONE broker (collectors.tls_port_override). It wins over the tenant-wide TLS port on the "Syslog port for brokers" card
// (PUT /v1/broker-config) for that broker only, and it still applies when the broker is left out of the tenant-wide ports. Nothing is pushed: a broker
// that opted in (bootstrap-broker.sh --accept-config) asks with its own name and applies it after its own checks. It only moves the port of a TLS
// listener the broker already has; a broker without one ignores it (ASIX never turns TLS on). The Brokers page returns it (GET /v1/brokers,
// tls.source and tls.override_port). Uses collectors:write; no role change.
// Body: { tls_port: 6515 | null }. null (or an empty string) removes it: the broker follows the tenant-wide TLS port again.
// It must differ from the syslog port this broker is asked for (its own, else the tenant-wide one; a broker left out and with no own port is asked for none).
router.put('/v1/brokers/:id/tls-port', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid broker id');
  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  if (!Object.prototype.hasOwnProperty.call(body, 'tls_port')) return apiError(res, 400, 'INVALID_BODY', 'Send tls_port (for example 6515, or null to follow the tenant-wide TLS port)');
  const shape = config.checkTlsPort(body.tls_port);   // the format and reserved-port rules; the clash with the syslog port is checked below, against THIS broker's syslog port
  if (shape.error) return apiError(res, 400, 'INVALID_TLS_PORT', shape.error);
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const ports = await config.readBrokerPorts(client, req.tenant_id, req.params.id);
      if (!ports) return { status: 404 };
      if (shape.value !== null) {
        const tenantSyslog = ports.own === null && !ports.excluded ? await config.readSyslogPort(client, req.tenant_id) : null;
        const syslog = ports.own !== null ? ports.own : tenantSyslog;
        const clash = config.checkTlsPort(shape.value, syslog);
        if (clash.error) return { status: 400, message: clash.error };
      }
      const broker = await config.writeTlsOverride(client, req.tenant_id, req.params.id, shape.value);
      return broker ? { status: 200, broker } : { status: 404 };
    });
    if (out.status === 404) return apiError(res, 404, 'NOT_FOUND', 'Broker not found');
    if (out.status === 400) return apiError(res, 400, 'INVALID_TLS_PORT', out.message);
    res.status(200).json({ success: true, broker: out.broker, tls_port: shape.value });
  } catch (e) {
    console.error('Broker TLS port override failed:', e.message);
    apiError(res, 500, 'BROKER_CONFIG_ERROR', 'Failed to save the broker TLS port');
  }
});

module.exports = router;
