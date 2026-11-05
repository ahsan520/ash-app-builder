const express = require('express');
const router = express.Router();
const { guarded, apiError } = require('../shared');
const { getEventStore } = require('../../events');
const alerts = require('../../endpoints/endpoint-alerts');

// ---- Alerts per machine (E6t, docs/endpoints.md): the number behind the \"Alerts (n)\" link on the Agents tab ----
// GET /v1/endpoints/alerts/by-machine?window=1h|24h|7d|30d  Only `window` is accepted. Exact counts per machine name over the tenant's `endpoint-alert` events (one comp query through the event
// store, any engine, scoped to the caller's tenant), most alerts first. Same permission as the other alert routes (`search:events:read`), no role change. In its own file so the three routes of
// endpoint-alerts.js stay three. `truncated` = the store held more machine names than were read.
router.get('/v1/endpoints/alerts/by-machine', ...guarded('search:events:read'), async (req, res) => {
  for (const k of Object.keys(req.query || {})) if (k !== 'window') return apiError(res, 400, 'INVALID_ALERT_QUERY', 'Unknown parameter \"' + String(k).slice(0, 40) + '\". Allowed: window');
  const f = alerts.parseQuery({ window: req.query.window });
  if (f.error) return apiError(res, 400, 'INVALID_ALERT_QUERY', f.error);
  try {
    const r = await getEventStore().search(req.tenant_id, alerts.machinePlan(f));
    res.status(200).json({ success: true, window: f.window, since: f.from, machines: alerts.machineCounts(r.rows), truncated: !!r.truncated || r.rows.length >= alerts.MACHINE_ROWS });
  } catch (e) {
    console.error('Alerts per machine failed:', e && e.message);
    apiError(res, 500, 'ENDPOINT_ALERTS_ERROR', 'Failed to count the alerts per machine');
  }
});

module.exports = router;
