const express = require('express');
const router = express.Router();
const { guarded, UUID_RE, apiError } = require('../shared');
const { getEventStore } = require('../../events');
const alerts = require('../../endpoints/endpoint-alerts');

// ---- Endpoint alerts, read only (src/endpoints/endpoint-alerts.js, docs/endpoints.md task E6b) -----------------------------------------------------
// Three GET routes over the events of source type `endpoint-alert` that a broker sends from the manager's alert file (E4d). They read through the event store, so they work
// on PostgreSQL and ClickHouse alike, and the store scopes every call to the caller's tenant. There is no write route.
// Permission: `search:events:read`, the one that reads event contents (the same as Log search), NOT `capacity:read` like the rest of the Endpoints section: an alert carries
// the log line and the details of the event it came from. No role change: the portal-admin role holds both.

const failed = (res, e, what) => {
  if (e && e.code === 'INVALID_QUERY') return apiError(res, 400, 'INVALID_ALERT_QUERY', String(e.message).slice(0, 200));
  console.error(`Endpoint alerts ${what} failed:`, e && e.message);
  return apiError(res, 500, 'ENDPOINT_ALERTS_ERROR', `Failed to read the endpoint alerts (${what})`);
};

const parse = (req, res, next) => {
  const f = alerts.parseQuery(req.query);
  if (f.error) return apiError(res, 400, 'INVALID_ALERT_QUERY', f.error);
  req.alertFilter = f; next();
};

// The newest alerts in the window, filtered. `offset` pages through at most the newest 1,000 matches; `more` says there are alerts beyond this page.
router.get('/v1/endpoints/alerts', ...guarded('search:events:read'), parse, async (req, res) => {
  const f = req.alertFilter;
  try {
    const r = await getEventStore().search(req.tenant_id, alerts.listPlan(f));
    const rows = r.rows.slice(f.offset, f.offset + f.limit).map((x) => alerts.shape({ id: x._id, received_at: x._time instanceof Date ? x._time.toISOString() : x._time, event_time: x._time instanceof Date ? x._time.toISOString() : x._time, parsed: x.parsed }));
    const more = !!r.truncated;   // the plan asked for offset + limit rows; the store says whether there were more than that
    res.status(200).json({ success: true, alerts: rows, count: rows.length, offset: f.offset, limit: f.limit, more, window: f.window, since: f.from });
  } catch (e) { failed(res, e, 'list'); }
});

// Counts for the cards: exact per severity (severity filter ignored so the cards stay a breakdown), and the top rules, machines and ATT&CK techniques and tactics
// among the newest 1,000 alerts that match the other filters (`sampled.truncated` says whether there were more).
router.get('/v1/endpoints/alerts/summary', ...guarded('search:events:read'), parse, async (req, res) => {
  const f = req.alertFilter, store = getEventStore();
  try {
    const [sev, sample] = await Promise.all([store.search(req.tenant_id, alerts.severityPlan(f)), store.search(req.tenant_id, alerts.samplePlan(f))]);
    const evs = sample.rows.map((x) => ({ id: x._id, received_at: x._time instanceof Date ? x._time.toISOString() : x._time, parsed: x.parsed }));
    res.status(200).json({ success: true, window: f.window, since: f.from, severity: alerts.severityCounts(sev.rows), top: alerts.topLists(evs), sampled: { events: evs.length, truncated: !!sample.truncated } });
  } catch (e) { failed(res, e, 'summary'); }
});

// One alert with its long text and every detail field. 404 for an id that is not an endpoint alert of this tenant (the store only looks in the caller's tenant).
router.get('/v1/endpoints/alerts/:id', ...guarded('search:events:read'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ALERT_ID', 'An alert id is a UUID');
  try {
    const [e] = await getEventStore().getByIds(req.tenant_id, [req.params.id.toLowerCase()]);
    if (!e || e.source_type !== alerts.SOURCE_TYPE) return apiError(res, 404, 'ALERT_NOT_FOUND', 'No endpoint alert with that id');
    res.status(200).json({ success: true, alert: alerts.shape(e, { detail: true }) });
  } catch (e) { failed(res, e, 'detail'); }
});

module.exports = router;
