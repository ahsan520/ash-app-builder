const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');

// ---- XQL-style search ---------------------------------------------------------------
const xql = require('../../search/xql');
const { getEventStore } = require('../../events');
router.post('/v1/search/xql', ...guarded('search:events:read'), async (req, res) => {
  const b = req.body || {};
  const mins = Number(b.minutes);
  const from = b.from ? new Date(b.from) : mins > 0 ? new Date(Date.now() - mins * 60000) : null;
  const to = b.to ? new Date(b.to) : null;
  if ((from && isNaN(from)) || (to && isNaN(to))) return apiError(res, 400, 'INVALID_TIME', 'Invalid time range');
  let plan;
  try {
    plan = xql.parse(b.query, { from: from && from.toISOString(), to: to && to.toISOString(), limit: b.limit });
  } catch (e) {
    if (e instanceof xql.XqlError) return apiError(res, 400, 'XQL_SYNTAX', e.message);
    throw e;
  }
  const t0 = Date.now();
  try {
    // The event store runs the plan on whatever engine this deployment uses (src/events); the route no longer sees SQL.
    const result = await getEventStore().search(req.tenant_id, plan);
    const rows = result.rows;
    const q = { mode: result.mode, columns: result.columns };
    const truncated = result.truncated;
    const str = (v) => (v === null || v === undefined ? null : v instanceof Date ? v.toISOString().replace('T', ' ').replace(/\..*$/, '') : typeof v === 'object' ? JSON.stringify(v) : String(v));
    let columns = q.columns, out;
    if (q.mode === 'raw') {
      const freq = new Map();
      out = rows.map((r) => {
        const row = { _time: str(r._time), source_type: r.source_type, collector_id: r.collector_id, _id: r._id };
        for (const [k, v] of Object.entries(r.parsed || {})) { if (k in row) continue; row[k] = str(v); freq.set(k, (freq.get(k) || 0) + 1); }
        row._raw = r._raw;
        return row;
      });
      columns = ['_time', 'source_type', 'collector_id', ...[...freq.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40).map((e) => e[0]), '_raw'];
    } else {
      out = rows.map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, str(v)])));
    }
    res.status(200).json({ success: true, mode: q.mode, columns, rows: out, count: out.length, truncated, took_ms: Date.now() - t0 });
  } catch (error) {
    console.error('XQL search failed:', error.message);
    apiError(res, 400, 'XQL_ERROR', 'Query failed: ' + String(error.message).slice(0, 200));
  }
});

// Fields and datasets seen recently (feeds the Fields panel and the Schema tab). Read through the event store.
router.get('/v1/search/fields', ...guarded('search:events:read'), async (req, res) => {
  try {
    const store = getEventStore();
    const [stats, datasets] = await Promise.all([
      store.fieldStats(req.tenant_id, { sample: 2000, xdmSample: 500 }),
      store.groupCounts(req.tenant_id, { by: 'source_type', since: new Date(Date.now() - 7 * 86400000).toISOString() })]);
    // Data model fields live nested under parsed.xdm; they are listed as xdm.a.b so the Search page can offer them.
    res.status(200).json({ success: true, fields: stats.fields.concat(stats.xdm),
      datasets: datasets.map((g) => ({ name: g.key, events: g.events, last_seen: g.last_seen })), sampled_events: 2000 });
  } catch (error) {
    console.error('Field listing failed:', error.message);
    apiError(res, 500, 'FIELDS_ERROR', 'Failed to list fields');
  }
});


module.exports = router;
