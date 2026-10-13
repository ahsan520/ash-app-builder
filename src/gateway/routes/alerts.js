const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');

router.get('/v1/alerts/summary', ...guarded('alerts:read'), async (req, res) => {
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        `SELECT severity, COUNT(*)::int AS n FROM alerts
         WHERE tenant_id = $1 AND status IN ('open', 'acknowledged') GROUP BY severity`,
        [req.tenant_id]
      )
    );
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    r.rows.forEach((row) => { counts[row.severity] = row.n; });
    res.status(200).json({ success: true, active: counts, active_total: Object.values(counts).reduce((a, b) => a + b, 0) });
  } catch (error) {
    console.error('Alert summary failed:', error.message);
    apiError(res, 500, 'ALERT_SUMMARY_ERROR', 'Failed to summarise alerts');
  }
});

router.get('/v1/alerts', ...guarded('alerts:read'), async (req, res) => {
  const status = String(req.query.status || 'active');
  const where = ['tenant_id = $1'];
  const params = [req.tenant_id];
  if (status === 'active') where.push("status IN ('open', 'acknowledged')");
  else if (ALERT_STATUSES.includes(status)) { params.push(status); where.push(`status = $${params.length}`); }
  else if (status !== 'all') return apiError(res, 400, 'INVALID_STATUS', 'status must be active, all, open, acknowledged or closed');
  if (req.query.severity) {
    if (!SEVERITIES.includes(String(req.query.severity))) return apiError(res, 400, 'INVALID_SEVERITY', 'Invalid severity');
    params.push(String(req.query.severity));
    where.push(`severity = $${params.length}`);
  }
  const assignee = String(req.query.assignee || '');
  if (assignee === 'unassigned') where.push('assignee_id IS NULL');
  else if (assignee === 'me') {
    if (!req.user_id) return apiError(res, 400, 'INVALID_ASSIGNEE', 'assignee=me needs a signed-in user');
    params.push(req.user_id); where.push(`assignee_id = $${params.length}`);
  } else if (assignee) {
    if (!UUID_RE.test(assignee)) return apiError(res, 400, 'INVALID_ASSIGNEE', 'assignee must be me, unassigned or a user id');
    params.push(assignee); where.push(`assignee_id = $${params.length}`);
  }
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        `SELECT id, rule_id, rule_name, severity, status, title, summary, group_key,
                event_count, first_event_at, last_event_at, created_at, assignee_id,
                (SELECT u.username FROM users u WHERE u.id = alerts.assignee_id) AS assignee_name
         FROM alerts WHERE ${where.join(' AND ')}
         ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                  last_event_at DESC
         LIMIT ${limit} OFFSET ${offset}`,
        params
      )
    );
    res.status(200).json({ success: true, count: r.rows.length, alerts: r.rows });
  } catch (error) {
    console.error('Alert listing failed:', error.message);
    apiError(res, 500, 'ALERTS_LIST_ERROR', 'Failed to list alerts');
  }
});

router.get('/v1/alerts/:id', ...guarded('alerts:read'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid alert id');
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const a = await client.query('SELECT * FROM alerts WHERE id = $1 AND tenant_id = $2', [id, req.tenant_id]);
      if (!a.rows.length) return null;
      const ids = (a.rows[0].details && a.rows[0].details.sample_event_ids) || [];
      const ev = ids.length
        ? await client.query(
            `SELECT id, source_type, collector_id, received_at, event_time, raw
             FROM events WHERE tenant_id = $1 AND id = ANY($2::uuid[])
             ORDER BY COALESCE(event_time, received_at) DESC`,
            [req.tenant_id, ids]
          )
        : { rows: [] };
      return { alert: a.rows[0], events: ev.rows };
    });
    if (!out) return apiError(res, 404, 'NOT_FOUND', 'Alert not found');
    res.status(200).json({ success: true, ...out });
  } catch (error) {
    console.error('Alert detail failed:', error.message);
    apiError(res, 500, 'ALERT_DETAIL_ERROR', 'Failed to load alert');
  }
});

router.patch('/v1/alerts/:id', ...guarded('alerts:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid alert id');
  const status = (req.body || {}).status;
  if (!ALERT_STATUSES.includes(status)) return apiError(res, 400, 'INVALID_BODY', 'status must be open, acknowledged or closed');
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        'UPDATE alerts SET status = $2, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $3 RETURNING id, status',
        [id, status, req.tenant_id]
      )
    );
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Alert not found');
    res.status(200).json({ success: true, alert: r.rows[0] });
  } catch (error) {
    console.error('Alert update failed:', error.message);
    apiError(res, 500, 'ALERT_UPDATE_ERROR', 'Failed to update alert');
  }
});


module.exports = router;
