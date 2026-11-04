const express = require('express');
const router = express.Router();
const { guarded, apiError } = require('../shared');
const { getEventStore } = require('../../events');
const summary = require('../../endpoints/findings-summary');

// ---- The trend of the tenant's vulnerability findings, from the daily summaries (src/endpoints/findings-summary.js, docs/endpoints.md task E6k) ----
// GET /v1/endpoints/vulnerabilities/trend?days=N  (`capacity:read`, like the other Vulnerabilities routes; the summaries are counts only). Reads the `vuln-summary` events through the
// event store (any engine), keeps one per day (the newest), oldest first, and passes on only allow-listed numbers. The history is as long as the tenant's retention allows.
const NUM = ['findings_total', 'machines', 'distinct_cves', 'critical', 'high', 'medium', 'low', 'unknown', 'new_total', 'new_critical', 'new_high', 'new_medium', 'new_low'];
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const n = (v) => (Number.isInteger(v) && v >= 0 && v < 1e9 ? v : null);

function shape(events) {
  const byDay = new Map();
  for (const e of events) {                       // newest first: the first one seen for a day wins
    const p = e && e.parsed; if (!p || typeof p.summary_day !== 'string' || !DAY_RE.test(p.summary_day) || byDay.has(p.summary_day)) continue;
    const d = { day: p.summary_day };
    for (const k of NUM) d[k] = n(p[k]);
    d.total_change = Number.isInteger(p.total_change) ? p.total_change : null; d.critical_change = Number.isInteger(p.critical_change) ? p.critical_change : null;
    byDay.set(p.summary_day, d);
  }
  return [...byDay.values()].sort((a, b) => (a.day < b.day ? -1 : 1));
}

router.get('/v1/endpoints/vulnerabilities/trend', ...guarded('capacity:read'), async (req, res) => {
  for (const k of Object.keys(req.query || {})) if (k !== 'days') return apiError(res, 400, 'INVALID_VULN_TREND', 'Unknown parameter "' + String(k).slice(0, 40) + '". Allowed: days');
  const raw = req.query.days === undefined || req.query.days === '' ? '30' : req.query.days;
  if (Array.isArray(raw) || !/^[0-9]{1,3}$/.test(String(raw)) || Number(raw) < 1 || Number(raw) > 365) return apiError(res, 400, 'INVALID_VULN_TREND', 'days must be a whole number from 1 to 365');
  const days = Number(raw);
  try {
    const events = await getEventStore().listEvents(req.tenant_id, { source_type: summary.SOURCE_TYPE, from: new Date(Date.now() - (days + 1) * 86400000).toISOString(), limit: 500 });
    const list = shape(events).slice(-days);
    res.status(200).json({ success: true, days, points: list, latest: list.length ? list[list.length - 1] : null });
  } catch (e) {
    console.error('Vulnerability trend failed:', e.message);
    apiError(res, 500, 'VULN_TREND_ERROR', 'Failed to read the vulnerability summaries');
  }
});

module.exports = router;
