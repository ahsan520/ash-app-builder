const express = require('express');
const router = express.Router();
const { db, guarded, UUID_RE, apiError } = require('../shared');
const dedupe = require('../../alerts/dedupe');

// ---- Alert dedupe: find and merge repeat alerts ---------------------------------------------------
// Uses the existing alerts:read / alerts:write permissions, so no role changes are needed.
// Paths avoid GET /v1/alerts/:id (owned by routes/alerts.js) and follow the alert-triage pattern.

const MERGE_ERRORS = {
  NOT_FOUND: [404, 'NOT_FOUND', 'One or more alerts were not found'],
  NOT_ACTIVE: [409, 'NOT_ACTIVE', 'Only active alerts that are not already merged can be merged'],
  NOT_DUPLICATES: [409, 'NOT_DUPLICATES', 'Alerts can only be merged when they come from the same rule and have the same group'],
  NOTHING_TO_MERGE: [400, 'INVALID_BODY', 'ids must contain at least one alert other than primary_id'],
  TOO_MANY: [400, 'TOO_MANY', `Up to ${dedupe.MAX_MERGE} alerts at a time`],
};

// Who is asking, for the audit note on the primary alert.
async function actorName(client, req) {
  if (!req.user_id) return 'a service account';
  const u = await client.query('SELECT username FROM users WHERE id = $1 AND tenant_id = $2', [req.user_id, req.tenant_id]);
  return u.rows.length ? u.rows[0].username : null;
}

// Groups of active alerts from the same rule and group. alerts[0] of each group is the one a merge keeps.
router.get('/v1/alert-duplicates', ...guarded('alerts:read'), async (req, res) => {
  try {
    const groups = await db.withTenant(req.tenant_id, (client) => dedupe.findGroups(client, req.tenant_id));
    res.status(200).json({
      success: true,
      group_count: groups.length,
      alert_count: groups.reduce((n, g) => n + g.count, 0),
      groups,
    });
  } catch (error) {
    console.error('Alert duplicates failed:', error.message);
    apiError(res, 500, 'ALERT_DUPLICATES_ERROR', 'Failed to look for repeat alerts');
  }
});

// Merge chosen alerts into primary_id. They must all be active and from the same rule + group.
router.post('/v1/alerts/merge', ...guarded('alerts:write'), async (req, res) => {
  const { primary_id: primaryId, ids } = req.body || {};
  if (typeof primaryId !== 'string' || !UUID_RE.test(primaryId)) return apiError(res, 400, 'INVALID_BODY', 'primary_id must be an alert id');
  if (!Array.isArray(ids) || !ids.length || !ids.every((i) => typeof i === 'string' && UUID_RE.test(i))) {
    return apiError(res, 400, 'INVALID_BODY', 'ids must be a non-empty array of alert ids');
  }
  if (new Set(ids).size > dedupe.MAX_MERGE) return apiError(res, 400, ...MERGE_ERRORS.TOO_MANY.slice(1));
  try {
    const out = await db.withTenant(req.tenant_id, async (client) =>
      dedupe.mergeInto(client, req.tenant_id, primaryId, ids, await actorName(client, req)));
    if (out.error) return apiError(res, ...MERGE_ERRORS[out.error]);
    res.status(200).json({ success: true, ...out });
  } catch (error) {
    console.error('Alert merge failed:', error.message);
    apiError(res, 500, 'ALERT_MERGE_ERROR', 'Failed to merge alerts');
  }
});

// Merge every group of repeats into its oldest alert.
router.post('/v1/alert-duplicates/merge', ...guarded('alerts:write'), async (req, res) => {
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      await client.query("SET LOCAL statement_timeout = '30s'");
      return dedupe.mergeAll(client, req.tenant_id, await actorName(client, req));
    });
    res.status(200).json({ success: true, ...out });
  } catch (error) {
    console.error('Alert merge-all failed:', error.message);
    apiError(res, 500, 'ALERT_MERGE_ERROR', 'Failed to merge repeat alerts');
  }
});

// The alerts that were merged into this one.
router.get('/v1/alerts/:id/merged', ...guarded('alerts:read'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid alert id');
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        `SELECT id, title, severity, event_count, first_event_at, last_event_at, created_at
         FROM alerts WHERE tenant_id = $1 AND merged_into_id = $2
         ORDER BY COALESCE(first_event_at, created_at), id LIMIT 200`,
        [req.tenant_id, id]));
    res.status(200).json({ success: true, merged: r.rows });
  } catch (error) {
    console.error('Merged alerts load failed:', error.message);
    apiError(res, 500, 'ALERT_MERGED_ERROR', 'Failed to load merged alerts');
  }
});

module.exports = router;
