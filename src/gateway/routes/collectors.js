const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');

// ---- Collectors + ingestion keys (installers) ---------------------------------------------
const { generateKey, hashKey, PLATFORMS: KEY_PLATFORMS } = require('../../ingest/http-ingest');
const CONNECTED_WITHIN_MIN = 15;

// Registered senders (collectors table) plus built-in ones that only appear in events
// (e.g. the in-cluster syslog collector), so the page shows everything that feeds the SIEM.
router.get('/v1/collectors', ...guarded('collectors:read'), async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  try {
    const all = await db.withTenant(req.tenant_id, async (client) => {
      const reg = await client.query(
        `SELECT c.id, c.name, c.alias, c.platform, c.os, c.version, c.last_ip, c.first_seen, c.last_seen,
                c.events_total::bigint AS events_total, k.name AS installer, 'registered' AS origin
         FROM collectors c LEFT JOIN ingestion_keys k ON k.id = c.key_id WHERE c.tenant_id = $1`, [req.tenant_id]);
      const built = await client.query(
        `SELECT NULL::uuid AS id, e.collector_id AS name, NULL AS alias, 'syslog' AS platform, NULL AS os, NULL AS version,
                NULL AS last_ip, MIN(e.received_at) AS first_seen, MAX(e.received_at) AS last_seen,
                COUNT(*)::bigint AS events_total, NULL AS installer, 'built-in' AS origin
         FROM events e
         WHERE e.tenant_id = $1 AND e.collector_id IS NOT NULL AND e.received_at > localtimestamp - interval '7 days'
           AND e.collector_id NOT IN (SELECT name FROM collectors WHERE tenant_id = $1)
         GROUP BY e.collector_id`, [req.tenant_id]);
      const day = await client.query(
        `SELECT collector_id, COUNT(*)::int AS n FROM events
         WHERE tenant_id = $1 AND collector_id IS NOT NULL AND received_at > localtimestamp - interval '24 hours'
         GROUP BY collector_id`, [req.tenant_id]);
      const d = new Map(day.rows.map((r) => [r.collector_id, r.n]));
      const cutoff = Date.now() - CONNECTED_WITHIN_MIN * 60000;
      return reg.rows.concat(built.rows).map((c) => ({
        ...c, events_total: Number(c.events_total), events_24h: d.get(c.name) || 0,
        status: new Date(String(c.last_seen).endsWith('Z') ? c.last_seen : c.last_seen + 'Z').getTime() >= cutoff ? 'connected' : 'disconnected',
      }));
    });
    const q = String(req.query.q || '').toLowerCase();
    const rows = all
      .filter((c) => (!req.query.status || c.status === req.query.status)
        && (!q || [c.name, c.alias, c.platform, c.os, c.last_ip, c.installer].some((v) => v && String(v).toLowerCase().includes(q))))
      .sort((a, b) => String(a.name).localeCompare(String(b.name)));
    res.status(200).json({ success: true, total: rows.length, overall: all.length, connected_within_minutes: CONNECTED_WITHIN_MIN,
      collectors: rows.slice(offset, offset + limit) });
  } catch (error) {
    console.error('Collector listing failed:', error.message);
    apiError(res, 500, 'COLLECTOR_LIST_ERROR', 'Failed to list collectors');
  }
});

router.patch('/v1/collectors/:id', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid collector id');
  const alias = req.body && req.body.alias;
  if (alias !== null && (typeof alias !== 'string' || alias.length > 200)) return apiError(res, 400, 'INVALID_BODY', 'alias must be a string up to 200 chars (or null to clear)');
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      'UPDATE collectors SET alias = $2 WHERE id = $1 AND tenant_id = $3 RETURNING id, alias', [req.params.id, alias ? alias.trim() : null, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Collector not found');
    res.status(200).json({ success: true, collector: r.rows[0] });
  } catch (error) {
    console.error('Collector update failed:', error.message);
    apiError(res, 500, 'COLLECTOR_UPDATE_ERROR', 'Failed to update collector');
  }
});

router.delete('/v1/collectors/:id', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid collector id');
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query('DELETE FROM collectors WHERE id = $1 AND tenant_id = $2 RETURNING id', [req.params.id, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Collector not found');
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Collector delete failed:', error.message);
    apiError(res, 500, 'COLLECTOR_DELETE_ERROR', 'Failed to delete collector');
  }
});

router.get('/v1/ingestion-keys', ...guarded('collectors:read'), async (req, res) => {
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      `SELECT k.id, k.name, k.description, k.platform, k.key_prefix, k.status, k.created_by, k.created_at, k.last_used_at, k.revoked_at,
              (SELECT COUNT(*)::int FROM collectors c WHERE c.key_id = k.id) AS collectors
       FROM ingestion_keys k WHERE k.tenant_id = $1 ORDER BY k.created_at DESC`, [req.tenant_id]));
    res.status(200).json({ success: true, keys: r.rows });
  } catch (error) {
    console.error('Ingestion key listing failed:', error.message);
    apiError(res, 500, 'KEY_LIST_ERROR', 'Failed to list installers');
  }
});

// The plaintext key is returned exactly once, here. Only its SHA-256 hash is stored.
router.post('/v1/ingestion-keys', ...guarded('collectors:write'), async (req, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim();
  const platform = String(b.platform || 'linux').toLowerCase();
  if (!/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$/.test(name)) return apiError(res, 400, 'INVALID_NAME', 'Name: 1-100 chars, letters, digits, space . _ -');
  if (!KEY_PLATFORMS.includes(platform)) return apiError(res, 400, 'INVALID_PLATFORM', 'platform must be one of ' + KEY_PLATFORMS.join(', '));
  const key = generateKey();
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      `INSERT INTO ingestion_keys (tenant_id, name, description, platform, key_prefix, key_hash, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, platform, key_prefix, created_at`,
      [req.tenant_id, name, b.description ? String(b.description).slice(0, 500) : null, platform, key.slice(0, 12), hashKey(key), req.user_id || null]));
    res.status(201).json({ success: true, key, installer: r.rows[0] });
  } catch (error) {
    if (error.code === '23505') return apiError(res, 409, 'NAME_IN_USE', 'An installer with that name already exists');
    console.error('Ingestion key create failed:', error.message);
    apiError(res, 500, 'KEY_CREATE_ERROR', 'Failed to create installer');
  }
});

router.post('/v1/ingestion-keys/:id/revoke', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid installer id');
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      "UPDATE ingestion_keys SET status = 'revoked', revoked_at = COALESCE(revoked_at, localtimestamp) WHERE id = $1 AND tenant_id = $2 RETURNING id, status",
      [req.params.id, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Installer not found');
    res.status(200).json({ success: true, installer: r.rows[0] });
  } catch (error) {
    console.error('Ingestion key revoke failed:', error.message);
    apiError(res, 500, 'KEY_REVOKE_ERROR', 'Failed to revoke installer');
  }
});

router.delete('/v1/ingestion-keys/:id', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid installer id');
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query('DELETE FROM ingestion_keys WHERE id = $1 AND tenant_id = $2 RETURNING id', [req.params.id, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Installer not found');
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Ingestion key delete failed:', error.message);
    apiError(res, 500, 'KEY_DELETE_ERROR', 'Failed to delete installer');
  }
});


module.exports = router;
