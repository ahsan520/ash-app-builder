const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');

// ---- Parsing rules (XSIAM-style) ----------------------------------------------------------
const parsingRules = require('../../ingestion/parsing-rules');
const rulesStore = require('../../ingestion/rules-store');
const { parseLine: parseLineText, jsonEvent: parseJsonEvent } = require('../../ingest/http-ingest');
// A pasted line that starts with { is treated as a JSON event (message + fields), like the forwarders send.
const parseIngestLine = (line, collector) => {
  if (line.trim().startsWith('{')) { try { const it = parseJsonEvent(JSON.parse(line), collector); if (it) return it; } catch { /* not JSON: fall back to plain text */ } }
  return parseLineText(line, collector);
};
// Lines pasted from the Windows forwarder ("[Security] Provider id=4625 ...") are simulated as the windows-event dataset.
const WIN_LINE = /^\[(Security|System|Application)\] /;
const ruleErr = (res, e) => apiError(res, 400, 'PARSE_RULES_INVALID', e.message + (e.line ? ` (line ${e.line}, column ${e.column})` : '')) || res;

router.get('/v1/parsing-rules', ...guarded('parsing:rules:read'), async (req, res) => {
  try {
    const row = await rulesStore.loadUser(req.tenant_id);
    let info = [];
    if (row && row.content.trim()) { try { info = parsingRules.compile(row.content).info; } catch { /* shown by the editor on next save */ } }
    res.status(200).json({
      success: true,
      user_defined: { content: row ? row.content : '', version: row ? row.version : 0, updated_at: row ? row.updated_at : null, rules: info },
      default: { content: rulesStore.DEFAULT_SRC, rules: rulesStore.DEFAULT_INFO },
    });
  } catch (error) {
    console.error('Parsing rules load failed:', error.message);
    apiError(res, 500, 'PARSE_RULES_ERROR', 'Failed to load parsing rules');
  }
});

// Save = validate + store. Rejected with the line/column of the first error; ingestion keeps
// using the previously saved rules until a valid set is saved.
router.put('/v1/parsing-rules', ...guarded('parsing:rules:write'), async (req, res) => {
  const content = req.body && req.body.content;
  if (typeof content !== 'string') return apiError(res, 400, 'INVALID_BODY', 'content (text) is required');
  let info = [];
  if (content.trim()) { try { info = parsingRules.compile(content).info; } catch (e) { if (e instanceof parsingRules.RuleError) return ruleErr(res, e); throw e; } }
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      `INSERT INTO parsing_rules (tenant_id, content, version, updated_by) VALUES ($1, $2, 1, $3)
       ON CONFLICT (tenant_id) DO UPDATE SET content = EXCLUDED.content, version = parsing_rules.version + 1,
         updated_by = EXCLUDED.updated_by, updated_at = CURRENT_TIMESTAMP
       RETURNING version, updated_at`, [req.tenant_id, content, req.user_id || null]));
    rulesStore.invalidate(req.tenant_id);
    res.status(200).json({ success: true, version: r.rows[0].version, updated_at: r.rows[0].updated_at, rules: info });
  } catch (error) {
    console.error('Parsing rules save failed:', error.message);
    apiError(res, 500, 'PARSE_RULES_ERROR', 'Failed to save parsing rules');
  }
});

// Simulate: run sample log lines through user / default / both rules without storing anything.
// `content` (optional) is the unsaved editor text and is used as the user-defined set.
router.post('/v1/parsing-rules/simulate', ...guarded('parsing:rules:read'), async (req, res) => {
  const b = req.body || {};
  const scope = ['user', 'default', 'both'].includes(b.scope) ? b.scope : 'both';
  const sourceType = /^[A-Za-z0-9._-]{1,50}$/.test(String(b.source_type || '')) ? String(b.source_type) : 'syslog';
  const lines = String(b.logs || '').split(/\r?\n/).filter((l) => l.trim());
  if (!lines.length) return apiError(res, 400, 'NO_LOGS', 'Paste at least one log line');
  if (lines.length > 50) return apiError(res, 400, 'TOO_MANY_LOGS', 'Simulate up to 50 lines at a time');
  try {
    const sets = [];
    if (scope !== 'default') {
      const src = typeof b.content === 'string' ? b.content : ((await rulesStore.loadUser(req.tenant_id)) || {}).content || '';
      if (src.trim()) { try { sets.push(parsingRules.compile(src).rules); } catch (e) { if (e instanceof parsingRules.RuleError) return ruleErr(res, e); throw e; } }
    }
    if (scope !== 'user') sets.push(rulesStore.DEFAULT_RULES);
    const results = lines.map((line) => {
      const it = parseIngestLine(line, 'simulate');
      const before = { ...it.parsed };
      const o = parsingRules.apply(sets, { source_type: WIN_LINE.test(it.raw) ? 'windows-event' : sourceType, raw: it.raw, time: it.time, parsed: it.parsed });
      return { raw: it.raw, source_type: o.source_type, time: o.time, before, after: o.parsed, matched: o.matched, dropped: o.dropped, errors: o.errors };
    });
    res.status(200).json({ success: true, scope, results });
  } catch (error) {
    console.error('Parsing rules simulate failed:', error.message);
    apiError(res, 500, 'PARSE_RULES_ERROR', 'Simulation failed');
  }
});


module.exports = router;
