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

// E6l: which machines got worse between the two newest summaries that carry a machine list. A machine "got worse" when its critical or high count rose (a machine not in the earlier
// list counts as new, starting from 0, but only if the earlier list was complete, i.e. shorter than the cap; otherwise it may only have been below the cut). Parsed defensively:
// the field is text from the store.
function readMachines(p) {
  if (!p || typeof p.machines_json !== 'string' || p.machines_json.length > 20000) return null;
  let a; try { a = JSON.parse(p.machines_json); } catch (_) { return null; }
  if (!Array.isArray(a)) return null;
  const out = new Map();
  for (const r of a) { if (Array.isArray(r) && typeof r[0] === 'string' && r[0].length <= 20 && typeof r[1] === 'string') out.set(r[0], { agent_id: r[0], name: r[1].slice(0, 60), total: n(r[2]), critical: n(r[3]), high: n(r[4]) }); }
  return out;
}
function worse(events) {
  const seen = new Set(), withList = [];
  for (const e of events) {                       // newest first; one per day
    const p = e && e.parsed; if (!p || typeof p.summary_day !== 'string' || !DAY_RE.test(p.summary_day) || seen.has(p.summary_day)) continue;
    const m = readMachines(p); if (!m) continue; seen.add(p.summary_day); withList.push({ day: p.summary_day, m });
    if (withList.length === 2) break;
  }
  if (withList.length < 2) return null;
  const [now, before] = withList, complete = before.m.size < summary.TOP_MACHINES, list = [];
  for (const x of now.m.values()) {
    const o = before.m.get(x.agent_id);
    if (!o && !complete) continue;
    const dc = (x.critical || 0) - (o ? o.critical || 0 : 0), dh = (x.high || 0) - (o ? o.high || 0 : 0);
    if (dc > 0 || dh > 0) list.push({ agent_id: x.agent_id, name: x.name, total: x.total, critical: x.critical, high: x.high, critical_change: dc, high_change: dh, is_new: !o });
  }
  list.sort((a, b) => (b.critical_change - a.critical_change) || (b.high_change - a.high_change) || (a.agent_id < b.agent_id ? -1 : 1));
  return { day: now.day, since_day: before.day, complete, worse: list.slice(0, 20), worse_count: list.length };
}

router.get('/v1/endpoints/vulnerabilities/trend', ...guarded('capacity:read'), async (req, res) => {
  for (const k of Object.keys(req.query || {})) if (k !== 'days') return apiError(res, 400, 'INVALID_VULN_TREND', 'Unknown parameter "' + String(k).slice(0, 40) + '". Allowed: days');
  const raw = req.query.days === undefined || req.query.days === '' ? '30' : req.query.days;
  if (Array.isArray(raw) || !/^[0-9]{1,3}$/.test(String(raw)) || Number(raw) < 1 || Number(raw) > 365) return apiError(res, 400, 'INVALID_VULN_TREND', 'days must be a whole number from 1 to 365');
  const days = Number(raw);
  try {
    const events = await getEventStore().listEvents(req.tenant_id, { source_type: summary.SOURCE_TYPE, from: new Date(Date.now() - (Math.max(days, 3) + 1) * 86400000).toISOString(), limit: 500 });
    const list = shape(events).slice(-days);
    res.status(200).json({ success: true, days, points: list, latest: list.length ? list[list.length - 1] : null, machines: worse(events) });
  } catch (e) {
    console.error('Vulnerability trend failed:', e.message);
    apiError(res, 500, 'VULN_TREND_ERROR', 'Failed to read the vulnerability summaries');
  }
});

module.exports = router;
