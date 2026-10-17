const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');

// ---- Storage & retention ---------------------------------------------------------------------
const storage = require('../../storage/retention');
const { getEventStore } = require('../../events');
const limits = require('../../modules/limits');
const SRC_RE = /^[A-Za-z0-9._-]{1,100}$/;

router.get('/v1/storage/summary', ...guarded('storage:read'), async (req, res) => {
  try { res.status(200).json({ success: true, ...(await storage.summary(req.tenant_id)) }); }
  catch (e) { console.error('Storage summary failed:', e.message); apiError(res, 500, 'STORAGE_SUMMARY_ERROR', 'Failed to build storage summary'); }
});

router.get('/v1/storage/safety', ...guarded('storage:read'), async (req, res) => {
  try { res.status(200).json({ success: true, ...(await require('../../storage/safety').report()) }); }
  catch (e) { console.error('Data safety report failed:', e.message); apiError(res, 500, 'SAFETY_REPORT_ERROR', 'Failed to build the data safety report'); }
});

router.get('/v1/storage/retention', ...guarded('storage:read'), async (req, res) => {
  try {
    const pol = await storage.loadPolicy(db, req.tenant_id);
    const sources = await getEventStore().sourceTypes(req.tenant_id, { since: new Date(Date.now() - 30 * 86400000).toISOString() });
    const runs = (await db.query(
      `SELECT id, tenant_id, trigger, status, started_at, finished_at, partitions_dropped, rows_deleted::bigint AS rows_deleted, error
       FROM retention_runs WHERE tenant_id = $1 OR tenant_id IS NULL ORDER BY started_at DESC LIMIT 20`, [req.tenant_id])).rows
      .map((r) => ({ ...r, rows_deleted: Number(r.rows_deleted) }));
    const lim = await limits.currentLimits();
    res.status(200).json({ success: true, policy: pol, known_sources: sources, runs, system_default_days: storage.DEFAULT_DAYS,
      limit_days: lim.retention_days_max ?? null, over_limit: limits.retentionOverLimit(pol, lim) });
  } catch (e) { console.error('Retention read failed:', e.message); apiError(res, 500, 'RETENTION_READ_ERROR', 'Failed to read retention settings'); }
});

// Body: { auto_purge?: bool, default_days?: 1..3650, overrides?: [{ source_type, retention_days: 1..3650 | null }] }
// `overrides`, when present, REPLACES the tenant's list. null = keep that source forever.
router.put('/v1/storage/retention', ...guarded('storage:write'), async (req, res) => {
  const b = req.body || {};
  const days = (v) => Number.isInteger(v) && v >= 1 && v <= 3650;
  if (b.auto_purge !== undefined && typeof b.auto_purge !== 'boolean') return apiError(res, 400, 'INVALID_BODY', 'auto_purge must be true or false');
  if (b.default_days !== undefined && !days(b.default_days)) return apiError(res, 400, 'INVALID_BODY', 'default_days must be a whole number from 1 to 3650');
  let overrides = null;
  if (b.overrides !== undefined) {
    if (!Array.isArray(b.overrides) || b.overrides.length > 50) return apiError(res, 400, 'INVALID_BODY', 'overrides must be a list of at most 50 entries');
    const seen = new Set();
    for (const o of b.overrides) {
      if (!o || !SRC_RE.test(String(o.source_type || ''))) return apiError(res, 400, 'INVALID_BODY', 'Each override needs a valid source_type');
      if (o.retention_days !== null && !days(o.retention_days)) return apiError(res, 400, 'INVALID_BODY', `retention_days for "${o.source_type}" must be 1-3650 or null (keep forever)`);
      if (seen.has(o.source_type)) return apiError(res, 400, 'INVALID_BODY', `Duplicate source_type "${o.source_type}"`);
      seen.add(o.source_type);
    }
    overrides = b.overrides;
  }
  // the license (or Home default) cap on how long events may be kept; checked only on what this request changes
  const over = limits.checkRetentionChange(b, await limits.currentLimits());
  if (over) return apiError(res, 403, over.code, over.message);
  try {
    await db.withTenant(req.tenant_id, async (client) => {
      await client.query(
        `INSERT INTO retention_settings (tenant_id, auto_purge, default_days, updated_by) VALUES ($1, COALESCE($2::boolean, false), COALESCE($3::int, $5::int), $4::text)
         ON CONFLICT (tenant_id) DO UPDATE SET auto_purge = COALESCE($2::boolean, retention_settings.auto_purge),
           default_days = COALESCE($3::int, retention_settings.default_days), updated_at = localtimestamp, updated_by = $4::text`,
        [req.tenant_id, b.auto_purge ?? null, b.default_days ?? null, req.user_id || null, storage.DEFAULT_DAYS]);
      if (overrides) {
        await client.query('DELETE FROM retention_policies WHERE tenant_id = $1', [req.tenant_id]);
        for (const o of overrides) {
          await client.query('INSERT INTO retention_policies (tenant_id, source_type, retention_days) VALUES ($1, $2, $3)', [req.tenant_id, o.source_type, o.retention_days]);
        }
      }
    });
    res.status(200).json({ success: true, policy: await storage.loadPolicy(db, req.tenant_id) });
  } catch (e) { console.error('Retention update failed:', e.message); apiError(res, 500, 'RETENTION_UPDATE_ERROR', 'Failed to save retention settings'); }
});

// dry_run (default) only counts what a purge would delete. A real purge needs confirm: true.
router.post('/v1/storage/retention/run', ...guarded('storage:write'), async (req, res) => {
  const b = req.body || {};
  const dryRun = b.dry_run !== false;
  if (!dryRun && b.confirm !== true) return apiError(res, 400, 'CONFIRM_REQUIRED', 'A real purge permanently deletes events: send confirm: true');
  try {
    const r = await storage.runManual(req.tenant_id, { dryRun });
    if (r.busy) return apiError(res, 409, 'RETENTION_BUSY', 'A retention run is already in progress; try again in a minute');
    res.status(200).json({ success: true, ...r });
  } catch (e) { console.error('Retention run failed:', e.message); apiError(res, 500, 'RETENTION_RUN_ERROR', 'Retention run failed'); }
});


module.exports = router;
