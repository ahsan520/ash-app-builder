const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');

// ---- Data model rules (XDM) ------------------------------------------------------------------
const xdmSchema = require('../../ingestion/xdm-schema');

router.get('/v1/data-model-rules', ...guarded('datamodel:rules:read'), async (req, res) => {
  try {
    const row = await rulesStore.loadUser(req.tenant_id, 'model');
    let info = [];
    if (row && row.content.trim()) { try { info = parsingRules.compile(row.content, 'model').info; } catch { /* shown by the editor on next save */ } }
    res.status(200).json({
      success: true,
      user_defined: { content: row ? row.content : '', version: row ? row.version : 0, updated_at: row ? row.updated_at : null, rules: info },
      default: { content: rulesStore.DEFAULT_MODEL_SRC, rules: rulesStore.DEFAULT_MODEL_INFO },
      schema: { fields: xdmSchema.FIELDS, constants: xdmSchema.CONSTANTS },
    });
  } catch (error) {
    console.error('Data model rules load failed:', error.message);
    apiError(res, 500, 'MODEL_RULES_ERROR', 'Failed to load data model rules');
  }
});

router.put('/v1/data-model-rules', ...guarded('datamodel:rules:write'), async (req, res) => {
  const content = req.body && req.body.content;
  if (typeof content !== 'string') return apiError(res, 400, 'INVALID_BODY', 'content (text) is required');
  let info = [];
  if (content.trim()) {
    try { info = parsingRules.compile(content, 'model').info; }
    catch (e) { if (e instanceof parsingRules.RuleError) return apiError(res, 400, 'MODEL_RULES_INVALID', e.message + ` (line ${e.line}, column ${e.column})`); throw e; }
  }
  try {
    const r = await rulesStore.saveUser(req.tenant_id, 'model', content, req.user_id);
    res.status(200).json({ success: true, version: r.version, updated_at: r.updated_at, rules: info });
  } catch (error) {
    console.error('Data model rules save failed:', error.message);
    apiError(res, 500, 'MODEL_RULES_ERROR', 'Failed to save data model rules');
  }
});

// Simulate the whole path: log line -> saved parsing rules -> model rules (unsaved editor text if given).
router.post('/v1/data-model-rules/simulate', ...guarded('datamodel:rules:read'), async (req, res) => {
  const b = req.body || {};
  const scope = ['user', 'default', 'both'].includes(b.scope) ? b.scope : 'both';
  const sourceType = /^[A-Za-z0-9._-]{1,50}$/.test(String(b.source_type || '')) ? String(b.source_type) : 'syslog';
  const lines = String(b.logs || '').split(/\r?\n/).filter((l) => l.trim());
  if (!lines.length) return apiError(res, 400, 'NO_LOGS', 'Paste at least one log line');
  if (lines.length > 50) return apiError(res, 400, 'TOO_MANY_LOGS', 'Simulate up to 50 lines at a time');
  try {
    const pSets = await rulesStore.getActiveSets(req.tenant_id);
    const mSets = [];
    if (scope !== 'user') mSets.push(rulesStore.DEFAULT_MODEL_RULES);
    if (scope !== 'default') {
      const src = typeof b.content === 'string' ? b.content : ((await rulesStore.loadUser(req.tenant_id, 'model')) || {}).content || '';
      if (src.trim()) { try { mSets.push(parsingRules.compile(src, 'model').rules); } catch (e) { if (e instanceof parsingRules.RuleError) return apiError(res, 400, 'MODEL_RULES_INVALID', e.message + ` (line ${e.line}, column ${e.column})`); throw e; } }
    }
    const results = lines.map((line) => {
      const it = parseIngestLine(line, 'simulate');
      it.parsed.collector_id = 'simulate';
      const o = parsingRules.apply(pSets, { source_type: WIN_LINE.test(it.raw) ? 'windows-event' : sourceType, raw: it.raw, time: it.time, parsed: it.parsed });
      const mo = parsingRules.applyModel(mSets, { source_type: o.source_type, raw: it.raw, time: o.time, parsed: o.parsed });
      return { raw: it.raw, dataset: o.source_type, parsing_rule: o.matched ? o.matched.content_id : null, dropped: o.dropped, xdm: mo.flat, pipelines_matched: mo.pipelines_matched, errors: o.errors.concat(mo.errors) };
    });
    res.status(200).json({ success: true, scope, results });
  } catch (error) {
    console.error('Data model simulate failed:', error.message);
    apiError(res, 500, 'MODEL_RULES_ERROR', 'Simulation failed');
  }
});


module.exports = router;
