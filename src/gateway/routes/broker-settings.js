const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const upgrade = require('../../brokers/upgrade');

// Broker settings: for now one setting, the Vector version the brokers should run (src/brokers/upgrade.js).
// It only makes the Brokers page say which brokers are behind and what to run; nothing is pushed to a broker.
// Uses collectors:read / collectors:write; no role change.
const view = (target) => ({ vector_target: target, upgrade_command: upgrade.upgradeCommand(target) });

router.get('/v1/broker-settings', ...guarded('collectors:read'), async (req, res) => {
  try {
    const target = await db.withTenant(req.tenant_id, (client) => upgrade.readTarget(client, req.tenant_id));
    res.status(200).json({ success: true, settings: view(target) });
  } catch (e) {
    console.error('Broker settings read failed:', e.message);
    apiError(res, 500, 'BROKER_SETTINGS_ERROR', 'Failed to read the broker settings');
  }
});

// Body: { vector_target: "0.59.0" | null }. null (or an empty string) clears the target.
router.put('/v1/broker-settings', ...guarded('collectors:write'), async (req, res) => {
  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  if (!Object.prototype.hasOwnProperty.call(body, 'vector_target')) return apiError(res, 400, 'INVALID_BODY', 'Send vector_target (for example "0.59.0", or null to clear it)');
  const t = upgrade.checkTarget(body.vector_target);
  if (t.error) return apiError(res, 400, 'INVALID_VECTOR_TARGET', t.error);
  try {
    await db.withTenant(req.tenant_id, (client) => upgrade.writeTarget(client, req.tenant_id, t.value, req.user_id));
    res.status(200).json({ success: true, settings: view(t.value) });
  } catch (e) {
    console.error('Broker settings update failed:', e.message);
    apiError(res, 500, 'BROKER_SETTINGS_ERROR', 'Failed to save the broker settings');
  }
});

module.exports = router;
