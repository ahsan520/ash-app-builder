const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');

// ---- XQL-style search ---------------------------------------------------------------
router.post('/v1/search/xql', ...guarded('search:events:read'), async (req, res) => {
  const b = req.body || {};
  const mins = Number(b.minutes);
  const from = b.from ? new Date(b.from) : mins > 0 ? new Date(Date.now() - mins * 60000) : null;
  const to = b.to ? new Date(b.to) : null;
  if ((from && isNaN(from)) || (to && isNaN(to))) return apiError(res, 400, 'INVALID_TIME', 'Invalid time range');
  let q;
  try {
    q = xql.compile(b.query, { tenantId: req.tenant_id, from: from && from.toISOString(), to: to && to.toISOString(), limit: b.limit });
  } catch (e) {
    if (e instanceof xql.XqlError) return apiError(res, 400, 'XQL_SYNTAX', e.message);
    throw e;
  }
  const t0 = Date.now();
  try {
    const rows = await db.withTenant(req.tenant_id, async (client) => {
      await client.query("SET LOCAL statement_timeout = '20s'");
      return (await client.query(q.sql, q.values)).rows;
    });
    const truncated = rows.length > q.limit;
    if (truncated) rows.length = q.limit;
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

// Fields and datasets seen recently (feeds the Fields panel and the Schema tab).
const flattenObj = (o, p = '') => Object.entries(o || {}).flatMap(([k, v]) => (v && typeof v === 'object' && !Array.isArray(v) ? flattenObj(v, p + k + '.') : [[p + k, v]]));
router.get('/v1/search/fields', ...guarded('search:events:read'), async (req, res) => {
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      await client.query("SET LOCAL statement_timeout = '10s'");
      const fields = await client.query(
        `SELECT k AS name, COUNT(*)::int AS events FROM (
           SELECT jsonb_object_keys(parsed) AS k FROM (
             SELECT parsed FROM events WHERE tenant_id = $1 ORDER BY received_at DESC LIMIT 2000) s
         ) t GROUP BY k ORDER BY events DESC, k LIMIT 200`, [req.tenant_id]);
      const datasets = await client.query(
        `SELECT source_type AS name, COUNT(*)::int AS events, MAX(received_at) AS last_seen FROM events
         WHERE tenant_id = $1 AND received_at > localtimestamp - interval '7 days' GROUP BY 1 ORDER BY 2 DESC`, [req.tenant_id]);
      // Data model fields live nested under parsed.xdm; list them as xdm.a.b so the Search page can offer them.
      const xs = await client.query(
        `SELECT parsed->'xdm' AS x FROM events WHERE tenant_id = $1 AND parsed ? 'xdm' ORDER BY received_at DESC LIMIT 500`, [req.tenant_id]);
      const xc = {};
      for (const row of xs.rows) for (const [k] of flattenObj(row.x, 'xdm.')) xc[k] = (xc[k] || 0) + 1;
      const xdmFields = Object.entries(xc).map(([name, events]) => ({ name, events })).sort((a, b) => b.events - a.events || a.name.localeCompare(b.name));
      return { fields: fields.rows.concat(xdmFields), datasets: datasets.rows };
    });
    res.status(200).json({ success: true, ...out, sampled_events: 2000 });
  } catch (error) {
    console.error('Field listing failed:', error.message);
    apiError(res, 500, 'FIELDS_ERROR', 'Failed to list fields');
  }
});


module.exports = router;
