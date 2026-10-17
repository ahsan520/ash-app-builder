'use strict';
// "My open alerts": the alerts assigned to one user that still need handling (open or acknowledged).
// Pure shaping of the database rows, so it can be tested without a database; the SQL lives in routes/my-alerts.js.
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const TOP = 5;

// rows: [{ severity, status, n, oldest }] from the grouped query (oldest = earliest created_at of that group).
function summarise(rows) {
  const active = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  const byStatus = { open: 0, acknowledged: 0 };
  let oldestOpen = null;
  for (const r of rows || []) {
    const n = Number(r.n) || 0;
    if (r.severity in active) active[r.severity] += n;
    if (r.status in byStatus) byStatus[r.status] += n;
    if (r.status === 'open' && r.oldest) {
      const t = new Date(r.oldest).toISOString();
      if (!oldestOpen || t < oldestOpen) oldestOpen = t;
    }
  }
  return { active, active_total: Object.values(active).reduce((a, b) => a + b, 0), open: byStatus.open, acknowledged: byStatus.acknowledged, oldest_open_at: oldestOpen };
}

module.exports = { summarise, SEVERITIES, TOP };
