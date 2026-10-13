const express = require('express');
const router = express.Router();
const { db, guarded, UUID_RE, ALERT_STATUSES, apiError } = require('../shared');

// ---- Alert triage: assignment, analyst notes, bulk status change ---------------------------------
// Uses the existing alerts:read / alerts:write permissions, so no role changes are needed.
// (Not under /v1/alerts/:x because routes/alerts.js owns GET /v1/alerts/:id.)
const MAX_BULK = 200;
const MAX_NOTE = 2000;

// People an alert can be assigned to (this tenant's users only).
router.get('/v1/alert-assignees', ...guarded('alerts:read'), async (req, res) => {
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query('SELECT id, username FROM users WHERE tenant_id = $1 ORDER BY username LIMIT 500', [req.tenant_id]));
    res.status(200).json({ success: true, users: r.rows, me: req.user_id || null });
  } catch (error) {
    console.error('Assignee listing failed:', error.message);
    apiError(res, 500, 'ASSIGNEES_ERROR', 'Failed to list users');
  }
});

// Assign to a user, or send { user_id: null } to unassign. Does not change the alert status.
router.put('/v1/alerts/:id/assignee', ...guarded('alerts:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid alert id');
  const body = req.body || {};
  if (!('user_id' in body) || (body.user_id !== null && !UUID_RE.test(String(body.user_id)))) {
    return apiError(res, 400, 'INVALID_BODY', 'user_id must be a user id, or null to unassign');
  }
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      let username = null;
      if (body.user_id !== null) {
        const u = await client.query('SELECT username FROM users WHERE id = $1 AND tenant_id = $2', [body.user_id, req.tenant_id]);
        if (!u.rows.length) return { code: 'USER' };
        username = u.rows[0].username;
      }
      const r = await client.query(
        'UPDATE alerts SET assignee_id = $2, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $3 RETURNING id, assignee_id',
        [id, body.user_id, req.tenant_id]);
      return r.rows.length ? { alert: { ...r.rows[0], assignee_name: username } } : { code: 'ALERT' };
    });
    if (out.code === 'USER') return apiError(res, 404, 'USER_NOT_FOUND', 'User not found in this tenant');
    if (out.code === 'ALERT') return apiError(res, 404, 'NOT_FOUND', 'Alert not found');
    res.status(200).json({ success: true, ...out });
  } catch (error) {
    console.error('Alert assign failed:', error.message);
    apiError(res, 500, 'ALERT_ASSIGN_ERROR', 'Failed to assign alert');
  }
});

router.get('/v1/alerts/:id/notes', ...guarded('alerts:read'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid alert id');
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        `SELECT id, author_name, body, created_at FROM alert_notes
         WHERE alert_id = $1 AND tenant_id = $2 ORDER BY created_at, id LIMIT 200`, [id, req.tenant_id]));
    res.status(200).json({ success: true, notes: r.rows });
  } catch (error) {
    console.error('Alert notes load failed:', error.message);
    apiError(res, 500, 'ALERT_NOTES_ERROR', 'Failed to load notes');
  }
});

router.post('/v1/alerts/:id/notes', ...guarded('alerts:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid alert id');
  const text = typeof (req.body || {}).body === 'string' ? req.body.body.trim() : '';
  if (!text || text.length > MAX_NOTE) return apiError(res, 400, 'INVALID_BODY', `body must be 1-${MAX_NOTE} characters`);
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const a = await client.query('SELECT 1 FROM alerts WHERE id = $1 AND tenant_id = $2', [id, req.tenant_id]);
      if (!a.rows.length) return null;
      let name = 'service account';
      if (req.user_id) {
        const u = await client.query('SELECT username FROM users WHERE id = $1 AND tenant_id = $2', [req.user_id, req.tenant_id]);
        if (u.rows.length) name = u.rows[0].username;
      }
      const n = await client.query(
        `INSERT INTO alert_notes (tenant_id, alert_id, author_id, author_name, body)
         VALUES ($1, $2, $3, $4, $5) RETURNING id, author_name, body, created_at`,
        [req.tenant_id, id, req.user_id || null, name, text]);
      return n.rows[0];
    });
    if (!out) return apiError(res, 404, 'NOT_FOUND', 'Alert not found');
    res.status(201).json({ success: true, note: out });
  } catch (error) {
    console.error('Alert note save failed:', error.message);
    apiError(res, 500, 'ALERT_NOTE_ERROR', 'Failed to save note');
  }
});

// Change the status of many alerts at once. Alerts that are not this tenant's are silently not matched.
router.post('/v1/alerts/bulk', ...guarded('alerts:write'), async (req, res) => {
  const { ids, status } = req.body || {};
  if (!ALERT_STATUSES.includes(status)) return apiError(res, 400, 'INVALID_BODY', 'status must be open, acknowledged or closed');
  if (!Array.isArray(ids) || !ids.length || !ids.every((i) => typeof i === 'string' && UUID_RE.test(i))) {
    return apiError(res, 400, 'INVALID_BODY', 'ids must be a non-empty array of alert ids');
  }
  const unique = [...new Set(ids)];
  if (unique.length > MAX_BULK) return apiError(res, 400, 'TOO_MANY', `Up to ${MAX_BULK} alerts at a time`);
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        'UPDATE alerts SET status = $2, updated_at = localtimestamp WHERE tenant_id = $3 AND id = ANY($1::uuid[]) AND status <> $2 RETURNING id',
        [unique, status, req.tenant_id]));
    res.status(200).json({ success: true, requested: unique.length, updated: r.rows.length });
  } catch (error) {
    console.error('Alert bulk update failed:', error.message);
    apiError(res, 500, 'ALERT_BULK_ERROR', 'Failed to update alerts');
  }
});

module.exports = router;
