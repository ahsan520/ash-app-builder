const express = require('express');
const router = express.Router();
const { db, guarded, apiError, UUID_RE } = require('../shared');
const paused = require('../../brokers/paused');

// Pause or resume the optional inputs (log files, HTTP/JSON, the systemd journal) of ONE broker (collectors.inputs_paused). Nothing is pushed: a broker that
// opted in (bootstrap-broker.sh --accept-config) and has the current config script asks for the list with its own key and name, takes the paused inputs' config
// files out of Vector's list, validates, restarts and checks health, and puts everything back if any of that fails. Syslog and syslog over TLS cannot be paused.
// Body: { paused: ["journald", "file"] }, [] or null to resume everything. Uses collectors:write; no role change.
router.put('/v1/brokers/:id/inputs-paused', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid broker id');
  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  if (!('paused' in body)) return apiError(res, 400, 'INVALID_BODY', 'paused is required (a list of inputs, or [] to resume everything)');
  const c = paused.checkPaused(body.paused);
  if (c.error) return apiError(res, 400, 'INVALID_INPUT', c.error);
  try {
    const broker = await db.withTenant(req.tenant_id, (client) => paused.writePaused(client, req.tenant_id, req.params.id, c.value));
    if (!broker) return apiError(res, 404, 'NOT_FOUND', 'Broker not found');
    res.status(200).json({ success: true, broker: { id: broker.id, name: broker.name }, paused: broker.paused });
  } catch (e) {
    console.error('Broker paused inputs failed:', e.message);
    apiError(res, 500, 'BROKER_CONFIG_ERROR', 'Failed to save the broker setting');
  }
});

module.exports = router;
