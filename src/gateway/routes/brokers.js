const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const { getEventStore } = require('../../events');
const view = require('../../brokers/broker-view');

// ---- Brokers (read-only) --------------------------------------------------------------------------
// The broker VMs that report to this install, recognised by their heartbeat (see src/brokers/broker-view.js), with their
// status, event counts, installer key state and what is wrong. Uses collectors:read; no schema or role change.
router.get('/v1/brokers', ...guarded('collectors:read'), async (req, res) => {
  try {
    const reg = await db.withTenant(req.tenant_id, (client) => client.query(
      `SELECT c.id, c.name, c.alias, c.os, c.version, c.last_ip, c.first_seen, c.last_seen, c.events_total::bigint AS events_total,
              c.connected_within_min, c.watch_disconnect, c.key_id, k.name AS installer_name, k.status AS key_status, k.key_prefix, k.last_used_at AS key_last_used_at
       FROM collectors c LEFT JOIN ingestion_keys k ON k.id = c.key_id
       WHERE c.tenant_id = $1 AND c.version ILIKE $2 ORDER BY c.name`, [req.tenant_id, view.BROKER_VERSION_SQL]));
    let day = []; let countsError = null;
    try { day = await getEventStore().groupCounts(req.tenant_id, { by: 'collector_id', since: new Date(Date.now() - 86400000).toISOString() }); }
    catch (e) { countsError = 'Event counts are unavailable right now.'; console.error('Broker counts failed:', e.message); }
    const d = new Map(day.map((g) => [g.key, g.events]));
    const now = Date.now();
    const brokers = reg.rows.filter(view.isBroker).map((r) => view.shape(r, { now, events24h: d.get(r.name) || 0 }));
    res.status(200).json({ success: true, generated_at: new Date(now).toISOString(), summary: view.summarize(brokers), brokers,
      install_command: view.installCommand(), counts_error: countsError });
  } catch (e) {
    console.error('Broker listing failed:', e.message);
    apiError(res, 500, 'BROKER_LIST_ERROR', 'Failed to list brokers');
  }
});

module.exports = router;
