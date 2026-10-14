const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');

// ---------------------------------------------------------------------------
// Detections and alerts
// ---------------------------------------------------------------------------
const { ensureBuiltinRules, BUILTIN_RULES } = require('../../detection/rule-runner');
const { normalizeDefinition, buildMatch } = require('../../detection/rule-query');
const xql = require('../../search/xql');

router.get('/v1/detections/rules', ...guarded('detections:rules:read'), async (req, res) => {
  try {
    const rules = await db.withTenant(req.tenant_id, async (client) => {
      await ensureBuiltinRules(client, req.tenant_id);
      const r = await client.query(
        `SELECT r.id, r.name, r.description, r.severity, r.enabled, r.builtin_key, r.mitre,
                r.definition, r.last_run_at, r.last_error, r.kind, r.category,
                (r.builtin_key IS NULL) AS custom,
                (SELECT COUNT(*)::int FROM alerts a
                  WHERE a.rule_id = r.id AND a.status <> 'closed') AS open_alerts
         FROM detection_rules r
         WHERE r.tenant_id = $1 AND ($2::text IS NULL OR r.kind = $2)
         ORDER BY CASE r.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, r.name`,
        [req.tenant_id, RULE_KINDS.includes(req.query.kind) ? req.query.kind : null]
      );
      return r.rows;
    });
    res.status(200).json({ success: true, rules });
  } catch (error) {
    console.error('Rule listing failed:', error.message);
    apiError(res, 500, 'RULES_LIST_ERROR', 'Failed to list detection rules');
  }
});

// ---- user-defined correlation / BIOC rules -------------------------------------------
const RULE_KINDS = ['correlation', 'bioc'];
const MITRE_RE = /^T\d{4}(\.\d{3})?$/;

// Validates the rule form; returns { rule } or { error }.
function parseRuleBody(b) {
  b = b || {};
  const name = typeof b.name === 'string' ? b.name.trim() : '';
  if (!name || name.length > 255) return { error: 'Rule name is required (max 255 characters)' };
  if (!RULE_KINDS.includes(b.kind)) return { error: 'kind must be correlation or bioc' };
  if (!SEVERITIES.includes(b.severity)) return { error: 'severity must be one of ' + SEVERITIES.join(', ') };
  const mitre = (Array.isArray(b.mitre) ? b.mitre : []).map((m) => String(m).trim().toUpperCase()).filter(Boolean);
  if (mitre.length > 20 || mitre.some((m) => !MITRE_RE.test(m))) return { error: 'MITRE techniques look like T1110 or T1059.004' };
  const norm = normalizeDefinition(b.definition);
  if (norm.error) return { error: norm.error };
  return {
    rule: {
      name, kind: b.kind, severity: b.severity, mitre, definition: norm.def,
      description: typeof b.description === 'string' ? b.description.trim().slice(0, 2000) : '',
      category: typeof b.category === 'string' && b.category.trim() ? b.category.trim().slice(0, 100) : null,
      enabled: b.enabled !== false,
    },
  };
}

router.post('/v1/detections/rules/test', ...guarded('detections:rules:write'), async (req, res) => {
  const norm = normalizeDefinition((req.body || {}).definition);
  if (norm.error) return apiError(res, 400, 'INVALID_DEFINITION', norm.error);
  try {
    const rows = await db.withTenant(req.tenant_id, async (client) => {
      await client.query("SET LOCAL statement_timeout = '10s'");
      const q = buildMatch(req.tenant_id, norm.def, { limit: 20 });
      return (await client.query(q.text, q.values)).rows;
    });
    res.status(200).json({
      success: true,
      window_minutes: norm.def.window_minutes,
      alerts_would_raise: rows.length,
      groups: rows.map((r) => ({ group: r.gkey, events: r.n, last_event_at: r.last_at, sample: r.sample_raw ? String(r.sample_raw).slice(0, 300) : null })),
    });
  } catch (error) {
    console.error('Rule test failed:', error.message);
    apiError(res, 400, 'RULE_TEST_ERROR', 'Query failed: ' + String(error.message).slice(0, 200));
  }
});

router.post('/v1/detections/rules', ...guarded('detections:rules:write'), async (req, res) => {
  const p = parseRuleBody(req.body);
  if (p.error) return apiError(res, 400, 'INVALID_RULE', p.error);
  const r = p.rule;
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const n = await client.query('SELECT COUNT(*)::int AS n FROM detection_rules WHERE tenant_id = $1 AND builtin_key IS NULL', [req.tenant_id]);
      if (n.rows[0].n >= 200) return { limit: true };
      const ins = await client.query(
        `INSERT INTO detection_rules (tenant_id, name, description, severity, enabled, mitre, definition, kind, category)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9) RETURNING id`,
        [req.tenant_id, r.name, r.description, r.severity, r.enabled, r.mitre, JSON.stringify(r.definition), r.kind, r.category]
      );
      return { id: ins.rows[0].id };
    });
    if (out.limit) return apiError(res, 409, 'RULE_LIMIT', 'Custom rule limit (200) reached');
    res.status(201).json({ success: true, id: out.id });
  } catch (error) {
    console.error('Rule create failed:', error.message);
    apiError(res, 500, 'RULE_CREATE_ERROR', 'Failed to create rule');
  }
});

router.put('/v1/detections/rules/:id', ...guarded('detections:rules:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid rule id');
  const p = parseRuleBody(req.body);
  if (p.error) return apiError(res, 400, 'INVALID_RULE', p.error);
  const r = p.rule;
  try {
    const u = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        `UPDATE detection_rules
         SET name = $3, description = $4, severity = $5, enabled = $6, mitre = $7, definition = $8::jsonb,
             kind = $9, category = $10, last_error = NULL, updated_at = localtimestamp
         WHERE id = $1 AND tenant_id = $2 RETURNING id`,
        [id, req.tenant_id, r.name, r.description, r.severity, r.enabled, r.mitre, JSON.stringify(r.definition), r.kind, r.category]
      )
    );
    if (!u.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Rule not found');
    res.status(200).json({ success: true, id });
  } catch (error) {
    console.error('Rule update failed:', error.message);
    apiError(res, 500, 'RULE_UPDATE_ERROR', 'Failed to update rule');
  }
});

// Put a built-in rule back to the definition shipped with the platform (keeps its enabled state).
router.post('/v1/detections/rules/:id/reset', ...guarded('detections:rules:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid rule id');
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const cur = await client.query('SELECT builtin_key FROM detection_rules WHERE id = $1 AND tenant_id = $2', [id, req.tenant_id]);
      if (!cur.rows.length) return { status: 404, code: 'NOT_FOUND', msg: 'Rule not found' };
      const def = BUILTIN_RULES.find((b) => b.key === cur.rows[0].builtin_key) || require('../../packs').findRuleByBuiltinKey(cur.rows[0].builtin_key);
      if (!def) return { status: 400, code: 'NOT_BUILTIN', msg: 'Only built-in rules can be reset' };
      await client.query(
        `UPDATE detection_rules SET name = $3, description = $4, severity = $5, mitre = $6, definition = $7::jsonb,
                kind = $8, category = $9, last_error = NULL, updated_at = localtimestamp
         WHERE id = $1 AND tenant_id = $2`,
        [id, req.tenant_id, def.name, def.description, def.severity, def.mitre, JSON.stringify(def.definition), def.kind, def.category]);
      return { ok: true };
    });
    if (!out.ok) return apiError(res, out.status, out.code, out.msg);
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Rule reset failed:', error.message);
    apiError(res, 500, 'RULE_RESET_ERROR', 'Failed to reset rule');
  }
});

router.delete('/v1/detections/rules/:id', ...guarded('detections:rules:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid rule id');
  try {
    const d = await db.withTenant(req.tenant_id, (client) =>
      client.query('DELETE FROM detection_rules WHERE id = $1 AND tenant_id = $2 AND builtin_key IS NULL RETURNING id', [id, req.tenant_id])
    );
    if (!d.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Custom rule not found (built-in rules cannot be deleted)');
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Rule delete failed:', error.message);
    apiError(res, 500, 'RULE_DELETE_ERROR', 'Failed to delete rule');
  }
});


router.patch('/v1/detections/rules/:id', ...guarded('detections:rules:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid rule id');
  if (typeof (req.body || {}).enabled !== 'boolean') {
    return apiError(res, 400, 'INVALID_BODY', 'Body must be {"enabled": true|false}');
  }
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        'UPDATE detection_rules SET enabled = $2, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $3 RETURNING id, enabled',
        [id, req.body.enabled, req.tenant_id]
      )
    );
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Rule not found');
    res.status(200).json({ success: true, rule: r.rows[0] });
  } catch (error) {
    console.error('Rule update failed:', error.message);
    apiError(res, 500, 'RULE_UPDATE_ERROR', 'Failed to update rule');
  }
});


module.exports = router;
