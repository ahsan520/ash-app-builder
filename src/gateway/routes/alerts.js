const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');
const { getEventStore } = require('../../events');
const { mitreOfEvents, mitreView } = require('../../endpoints/endpoint-alerts');
const { withMitre } = require('../../alerts/with-mitre');

const MITRE_PREFIX_RE = /^T[0-9]{1,4}(\.[0-9]{1,3})?$/;
const MITRE_SCAN = 1000;
// ATT&CK tactic filter (E4h): letters, spaces and hyphens only; compared case-insensitively, hyphens and runs of spaces counting as one space ("defense-evasion" = "Defense Evasion").
const TACTIC_RE = /^[A-Za-z][A-Za-z -]{0,39}$/;
const tacticKey = (v) => String(v).toLowerCase().replace(/[-\s]+/g, ' ').trim();
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
  // ATT&CK technique (E4g): a case-insensitive PREFIX of a technique id (t15, T15*, T1110, T1110.0). Decided after the alerts are read, because alerts raised before E4f
  // carry no stored ATT&CK and take theirs from their sample events (as the alert page does); so a filtered list reads the newest 1,000 matching alerts and slices them.
  let needle = '';
  if (req.query.mitre !== undefined) {
    needle = typeof req.query.mitre === 'string' ? req.query.mitre.trim().replace(/\*+$/, '').toUpperCase() : '';
    if (!MITRE_PREFIX_RE.test(needle)) return apiError(res, 400, 'INVALID_MITRE', 'mitre must start like an ATT&CK technique id, for example T15, T1110 or T1110.003 (a trailing * is allowed)');
  }
  // ATT&CK tactic (E4h): a case-insensitive prefix of a tactic name (credential, Credential Access, defense-evasion). Decided after the alerts are read, like the technique,
  // and combined with it (both must match). Nothing from the request goes into the SQL text.
  let tacticNeedle = '';
  if (req.query.tactic !== undefined) {
    const raw = typeof req.query.tactic === 'string' ? req.query.tactic.trim() : '';
    if (!TACTIC_RE.test(raw)) return apiError(res, 400, 'INVALID_TACTIC', 'tactic must be the start of an ATT&CK tactic name, for example Credential Access or impact (letters, spaces and hyphens only)');
    tacticNeedle = tacticKey(raw);
  }
  const filtered = Boolean(needle || tacticNeedle);
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const sqlLimit = filtered ? MITRE_SCAN : limit, sqlOffset = filtered ? 0 : offset;
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        `SELECT id, rule_id, rule_name, severity, status, title, summary, group_key,
                event_count, first_event_at, last_event_at, created_at, assignee_id, merged_into_id, merged_count,
                details->'mitre' AS mitre_stored, details->'sample_event_ids' AS sample_ids,
                (SELECT u.username FROM users u WHERE u.id = alerts.assignee_id) AS assignee_name
         FROM alerts WHERE ${where.join(' AND ')}
         ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                  last_event_at DESC
         LIMIT ${sqlLimit} OFFSET ${sqlOffset}`,
        params
      )
    );
    let alerts = await withMitre(req.tenant_id, r.rows);
    if (filtered) {
      alerts = alerts.filter((x) => (!needle || x.mitre.techniques.some((t) => t.id.toUpperCase().startsWith(needle)))
        && (!tacticNeedle || x.mitre.tactics.some((t) => tacticKey(t).startsWith(tacticNeedle)))).slice(offset, offset + limit);
    }
    res.status(200).json({ success: true, count: alerts.length, alerts });
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
      const ids = ((a.rows[0].details && a.rows[0].details.sample_event_ids) || []).filter((i) => typeof i === 'string' && UUID_RE.test(i));
      // sample events are read through the event store, newest first
      const ev = { rows: ids.length ? await getEventStore().getByIds(req.tenant_id, ids) : [] };
      // ATT&CK techniques and tactics: as stored on the alert when the rule runner raised it (E4f); an older alert, or one raised before the sample events were read, takes them
      // from its sample events as they are now. Empty lists for alerts that have none (most rules carry their own list on the rule, not here).
      const mitre = mitreView(a.rows[0].details && a.rows[0].details.mitre ? a.rows[0].details.mitre : mitreOfEvents(ev.rows));
      ev.rows = ev.rows
        .map(({ id, source_type, collector_id, received_at, event_time, raw }) => ({ id, source_type, collector_id, received_at, event_time, raw }))
        .sort((x, y) => Date.parse(y.event_time || y.received_at) - Date.parse(x.event_time || x.received_at));
      return { alert: a.rows[0], events: ev.rows, mitre };
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
