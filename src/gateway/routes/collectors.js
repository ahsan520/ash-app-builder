const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');

// ---- Collectors + ingestion keys (installers) ---------------------------------------------
const { generateKey, hashKey, PLATFORMS: KEY_PLATFORMS } = require('../../ingest/http-ingest');
const { getEventStore } = require('../../events');
const { DEFAULT_MINUTES, tsMs, effectiveMinutes, isCustom, statusOf } = require('../../collectors/status');

// Registered senders (collectors table) plus built-in ones that only appear in events
// (e.g. the in-cluster syslog collector), so the page shows everything that feeds the SIEM.
router.get('/v1/collectors', ...guarded('collectors:read'), async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  try {
    const reg = await db.withTenant(req.tenant_id, (client) => client.query(
      `SELECT c.id, c.name, c.alias, c.platform, c.os, c.version, c.last_ip, c.first_seen, c.last_seen,
              c.events_total::bigint AS events_total, c.connected_within_min, c.watch_disconnect, k.name AS installer,
              CASE WHEN c.key_id IS NULL THEN 'built-in' ELSE 'registered' END AS origin
       FROM collectors c LEFT JOIN ingestion_keys k ON k.id = c.key_id WHERE c.tenant_id = $1`, [req.tenant_id]));
    // Event counts come from the event store (one pass each): the last 7 days per collector, and the last 24 hours.
    const store = getEventStore();
    const [week, dayCounts] = await Promise.all([
      store.groupCounts(req.tenant_id, { by: 'collector_id', since: new Date(Date.now() - 7 * 86400000).toISOString() }),
      store.groupCounts(req.tenant_id, { by: 'collector_id', since: new Date(Date.now() - 86400000).toISOString() })]);
    // Senders that only appear in events (no key-less or keyed row of their own): the in-cluster syslog collector, for one.
    const keyed = new Set(reg.rows.filter((r) => r.origin === 'registered').map((r) => r.name));
    const built = week.filter((g) => !keyed.has(g.key)).map((g) => ({
      id: null, name: g.key, alias: null, platform: 'syslog', os: null, version: null, last_ip: null,
      first_seen: g.first_seen, last_seen: g.last_seen, events_total: g.events, installer: null, origin: 'built-in' }));
    const d = new Map(dayCounts.map((g) => [g.key, g.events]));
    const now = Date.now();
    // A built-in source (key-less row, kept alive by its heartbeat) also has event-derived stats:
    // merge them so an idle one stays Connected and still shows its event counts.
    const evByName = new Map(built.map((r) => [r.name, r]));
    const merged = reg.rows.map((c) => {
      const e = c.origin === 'built-in' ? evByName.get(c.name) : null;
      if (!e) return c;
      evByName.delete(c.name);
      return { ...c, events_total: e.events_total, first_seen: tsMs(e.first_seen) < tsMs(c.first_seen) ? e.first_seen : c.first_seen,
        last_seen: tsMs(e.last_seen) > tsMs(c.last_seen) ? e.last_seen : c.last_seen };
    });
    // Each collector is judged against its own threshold (collectors.connected_within_min), else the default.
    // Sources that only appear in events have no row to hold one, so they use the default.
    const all = merged.concat([...evByName.values()]).map((c) => ({
      ...c, events_total: Number(c.events_total), events_24h: d.get(c.name) || 0, watch_disconnect: c.watch_disconnect === true,
      connected_within_min: effectiveMinutes(c.connected_within_min), connected_custom: isCustom(c.connected_within_min),
      status: statusOf(c.last_seen, c.connected_within_min, now),
    }));
    const q = String(req.query.q || '').toLowerCase();
    const rows = all
      .filter((c) => (!req.query.status || c.status === req.query.status)
        && (!q || [c.name, c.alias, c.platform, c.os, c.last_ip, c.installer].some((v) => v && String(v).toLowerCase().includes(q))))
      .sort((a, b) => String(a.name).localeCompare(String(b.name)));
    res.status(200).json({ success: true, total: rows.length, overall: all.length, connected_within_minutes: DEFAULT_MINUTES,
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
