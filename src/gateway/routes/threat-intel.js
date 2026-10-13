const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');

// ---- Threat intelligence: indicators (IOCs) -------------------------------------------
const { TYPES: INDICATOR_TYPES, classify: classifyIndicator } = require('../../threat-intel/indicators');
const MAX_IMPORT = 5000;

router.get('/v1/threat-intel/indicators', ...guarded('threatintel:read'), async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const where = ['tenant_id = $1'];
  const args = [req.tenant_id];
  if (INDICATOR_TYPES.includes(req.query.type)) { args.push(req.query.type); where.push(`type = $${args.length}`); }
  if (req.query.source) { args.push(String(req.query.source)); where.push(`source = $${args.length}`); }
  if (req.query.q) { args.push('%' + String(req.query.q).toLowerCase().replace(/[%_\\]/g, '\\$&') + '%'); where.push(`value LIKE $${args.length}`); }
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const total = await client.query(`SELECT COUNT(*)::int AS n FROM threat_indicators WHERE ${where.join(' AND ')}`, args);
      const rows = await client.query(
        `SELECT id, type, value, source, severity, description, enabled, expires_at, created_at
         FROM threat_indicators WHERE ${where.join(' AND ')}
         ORDER BY created_at DESC, id LIMIT ${limit} OFFSET ${offset}`, args);
      return { total: total.rows[0].n, indicators: rows.rows };
    });
    res.status(200).json({ success: true, limit, offset, ...out });
  } catch (error) {
    console.error('Indicator listing failed:', error.message);
    apiError(res, 500, 'INDICATOR_LIST_ERROR', 'Failed to list indicators');
  }
});

// Body: { indicators: "one per line" | [..], source?, severity?, description?, expires_in_days? }
router.post('/v1/threat-intel/indicators', ...guarded('threatintel:write'), async (req, res) => {
  const b = req.body || {};
  // Text input: one or more indicators per line (separated by space, comma, semicolon or tab);
  // lines starting with # are comments.
  const lines = Array.isArray(b.indicators)
    ? b.indicators
    : String(b.indicators || '').split(/\r?\n/).filter((l) => !l.trim().startsWith('#')).flatMap((l) => l.split(/[\s,;]+/));
  const severity = b.severity || 'medium';
  if (!SEVERITIES.includes(severity)) return apiError(res, 400, 'INVALID_SEVERITY', 'severity must be one of ' + SEVERITIES.join(', '));
  const source = String(b.source || 'manual').trim().slice(0, 100) || 'manual';
  const days = Number(b.expires_in_days);
  const seen = new Set(); const types = []; const values = []; const invalid = [];
  for (const raw of lines) {
    const t = String(raw || '').trim();
    if (!t || t.startsWith('#')) continue;
    const c = classifyIndicator(t);
    if (!c) { invalid.push(t.slice(0, 80)); continue; }
    const k = c.type + ':' + c.value;
    if (!seen.has(k)) { seen.add(k); types.push(c.type); values.push(c.value); }
  }
  if (types.length > MAX_IMPORT) return apiError(res, 413, 'TOO_MANY', `At most ${MAX_IMPORT} indicators per request`);
  if (!types.length) return apiError(res, 400, 'NO_VALID_INDICATORS', 'No valid indicators found (invalid: ' + invalid.slice(0, 5).join(', ') + ')');
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      `INSERT INTO threat_indicators (tenant_id, type, value, source, severity, description, expires_at)
       SELECT $1, x.t, x.v, $4, $5, $6, CASE WHEN $7::int > 0 THEN localtimestamp + ($7::int * interval '1 day') END
       FROM unnest($2::text[], $3::text[]) AS x(t, v)
       ON CONFLICT (tenant_id, type, value) DO UPDATE
         SET source = EXCLUDED.source, severity = EXCLUDED.severity,
             description = COALESCE(EXCLUDED.description, threat_indicators.description),
             expires_at = EXCLUDED.expires_at, enabled = true, updated_at = localtimestamp
       RETURNING (xmax = 0) AS inserted`,
      [req.tenant_id, types, values, source, severity, b.description ? String(b.description).slice(0, 500) : null, days > 0 ? Math.floor(days) : 0]
    ));
    const added = r.rows.filter((x) => x.inserted).length;
    res.status(200).json({ success: true, added, updated: r.rows.length - added, invalid_count: invalid.length, invalid: invalid.slice(0, 10) });
  } catch (error) {
    console.error('Indicator import failed:', error.message);
    apiError(res, 500, 'INDICATOR_IMPORT_ERROR', 'Failed to import indicators');
  }
});

router.patch('/v1/threat-intel/indicators/:id', ...guarded('threatintel:write'), async (req, res) => {
  const { id } = req.params; const b = req.body || {};
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid indicator id');
  if (b.enabled !== undefined && typeof b.enabled !== 'boolean') return apiError(res, 400, 'INVALID_BODY', 'enabled must be true or false');
  if (b.severity !== undefined && !SEVERITIES.includes(b.severity)) return apiError(res, 400, 'INVALID_SEVERITY', 'severity must be one of ' + SEVERITIES.join(', '));
  if (b.enabled === undefined && b.severity === undefined) return apiError(res, 400, 'INVALID_BODY', 'Nothing to update');
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      `UPDATE threat_indicators SET enabled = COALESCE($2, enabled), severity = COALESCE($3, severity), updated_at = localtimestamp
       WHERE id = $1 AND tenant_id = $4 RETURNING id, enabled, severity`,
      [id, b.enabled ?? null, b.severity ?? null, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Indicator not found');
    res.status(200).json({ success: true, indicator: r.rows[0] });
  } catch (error) {
    console.error('Indicator update failed:', error.message);
    apiError(res, 500, 'INDICATOR_UPDATE_ERROR', 'Failed to update indicator');
  }
});

router.delete('/v1/threat-intel/indicators/:id', ...guarded('threatintel:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid indicator id');
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query('DELETE FROM threat_indicators WHERE id = $1 AND tenant_id = $2 RETURNING id', [id, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Indicator not found');
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Indicator delete failed:', error.message);
    apiError(res, 500, 'INDICATOR_DELETE_ERROR', 'Failed to delete indicator');
  }
});

// Library (per source) + type totals + IOC matcher status
router.get('/v1/threat-intel/summary', ...guarded('threatintel:read'), async (req, res) => {
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const types = await client.query(
        `SELECT type, COUNT(*)::int AS n FROM threat_indicators WHERE tenant_id = $1 GROUP BY type ORDER BY n DESC`, [req.tenant_id]);
      const sources = await client.query(
        `SELECT source, COUNT(*)::int AS indicators,
                COUNT(*) FILTER (WHERE enabled)::int AS enabled,
                array_agg(DISTINCT type) AS types, MAX(updated_at) AS last_updated
         FROM threat_indicators WHERE tenant_id = $1 GROUP BY source ORDER BY MAX(updated_at) DESC`, [req.tenant_id]);
      const active = await client.query(
        `SELECT COUNT(*)::int AS n FROM threat_indicators
         WHERE tenant_id = $1 AND enabled AND (expires_at IS NULL OR expires_at > localtimestamp)`, [req.tenant_id]);
      const matcher = await client.query(
        `SELECT last_run_at, last_error, matched_total::int AS matched_total FROM ioc_scan_state WHERE tenant_id = $1`, [req.tenant_id]);
      const alerts = await client.query(
        `SELECT COUNT(*) FILTER (WHERE status IN ('open','acknowledged'))::int AS open, COUNT(*)::int AS total
         FROM alerts WHERE tenant_id = $1 AND rule_name = 'IOC match'`, [req.tenant_id]);
      return { types: types.rows, sources: sources.rows, active_indicators: active.rows[0].n,
               matcher: matcher.rows[0] || null, ioc_alerts: alerts.rows[0] };
    });
    res.status(200).json({ success: true, ...out });
  } catch (error) {
    console.error('Threat intel summary failed:', error.message);
    apiError(res, 500, 'THREAT_INTEL_SUMMARY_ERROR', 'Failed to build threat intel summary');
  }
});


module.exports = router;
