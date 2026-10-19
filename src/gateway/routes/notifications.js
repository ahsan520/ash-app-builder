const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');

// ---- Alert notifications (email / Slack / webhook) ---------------------------------------
const notifyBox = require('../../notifications/secret-box');
const notifyCh = require('../../notifications/channels');
const { testMessage, sendToChannel } = require('../../notifications/senders');
const recovered = require('../../notifications/recovered');

const CHANNEL_SELECT = `
  SELECT c.*,
    (SELECT d.status FROM notification_deliveries d WHERE d.channel_id = c.id ORDER BY d.created_at DESC LIMIT 1) AS last_delivery_status,
    (SELECT COALESCE(d.sent_at, d.created_at) FROM notification_deliveries d WHERE d.channel_id = c.id ORDER BY d.created_at DESC LIMIT 1) AS last_delivery_at
  FROM notification_channels c`;
const publicChannel = (row) => {
  try { return notifyCh.toPublic(row, notifyBox.decrypt(row.config_enc), recovered.enabled()); }
  catch { return { ...notifyCh.toPublic({ ...row }, { to: [] }, recovered.enabled()), config: {}, target: '(cannot be decrypted - encryption key changed?)', config_error: true }; }
};
const notifyError = (res, e, fallback) => {
  if (e.code === 'INVALID_CONFIG') return apiError(res, 400, 'INVALID_CONFIG', e.message);
  if (e.code === 'NO_KEY') return apiError(res, 503, 'NOTIFY_NOT_CONFIGURED', 'Notification encryption key is not configured on the server');
  if (e.code === '23505') return apiError(res, 409, 'NAME_IN_USE', 'A channel with that name already exists');
  console.error(fallback + ':', e.message);
  return apiError(res, 500, 'NOTIFY_ERROR', fallback);
};

router.get('/v1/notifications/channels', ...guarded('notify:read'), async (req, res) => {
  try {
    const r = await db.withTenant(req.tenant_id, (c) => c.query(`${CHANNEL_SELECT} WHERE c.tenant_id = $1 ORDER BY c.name`, [req.tenant_id]));
    res.status(200).json({ success: true, encryption_configured: notifyBox.configured(), channels: r.rows.map(publicChannel) });
  } catch (e) { notifyError(res, e, 'Failed to list channels'); }
});

router.post('/v1/notifications/channels', ...guarded('notify:write'), async (req, res) => {
  try {
    const b = req.body || {};
    const common = notifyCh.validateCommon(b);
    const config = notifyCh.normalizeConfig(b.type, b.config);
    const enc = notifyBox.encrypt(config);
    const r = await db.withTenant(req.tenant_id, (c) => c.query(
      `INSERT INTO notification_channels (tenant_id, name, type, enabled, min_severity, rule_filter, config_enc, notify_recovered)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, [req.tenant_id, common.name, b.type, common.enabled, common.min_severity, common.rule_filter, enc, common.notify_recovered]));
    const row = (await db.withTenant(req.tenant_id, (c) => c.query(`${CHANNEL_SELECT} WHERE c.id = $1`, [r.rows[0].id]))).rows[0];
    res.status(201).json({ success: true, channel: publicChannel(row) });
  } catch (e) { notifyError(res, e, 'Failed to create channel'); }
});

router.patch('/v1/notifications/channels/:id', ...guarded('notify:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid channel id');
  try {
    const b = req.body || {};
    const cur = (await db.withTenant(req.tenant_id, (c) => c.query('SELECT * FROM notification_channels WHERE id = $1 AND tenant_id = $2', [req.params.id, req.tenant_id]))).rows[0];
    if (!cur) return apiError(res, 404, 'NOT_FOUND', 'Channel not found');
    const common = notifyCh.validateCommon(b, cur);
    let enc = cur.config_enc;
    if (b.config !== undefined) enc = notifyBox.encrypt(notifyCh.normalizeConfig(cur.type, b.config, notifyBox.decrypt(cur.config_enc)));
    await db.withTenant(req.tenant_id, (c) => c.query(
      `UPDATE notification_channels SET name=$2, enabled=$3, min_severity=$4, rule_filter=$5, config_enc=$6, notify_recovered=$8, updated_at=localtimestamp WHERE id=$1 AND tenant_id=$7`,
      [cur.id, common.name, common.enabled, common.min_severity, common.rule_filter, enc, req.tenant_id, common.notify_recovered]));
    const row = (await db.withTenant(req.tenant_id, (c) => c.query(`${CHANNEL_SELECT} WHERE c.id = $1`, [cur.id]))).rows[0];
    res.status(200).json({ success: true, channel: publicChannel(row) });
  } catch (e) { notifyError(res, e, 'Failed to update channel'); }
});

router.delete('/v1/notifications/channels/:id', ...guarded('notify:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid channel id');
  try {
    const r = await db.withTenant(req.tenant_id, (c) => c.query('DELETE FROM notification_channels WHERE id = $1 AND tenant_id = $2 RETURNING id', [req.params.id, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Channel not found');
    res.status(200).json({ success: true });
  } catch (e) { notifyError(res, e, 'Failed to delete channel'); }
});

// Sends a clearly-marked test message right now (PagerDuty: trigger then immediately resolve).
router.post('/v1/notifications/channels/:id/test', ...guarded('notify:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid channel id');
  try {
    const row = (await db.withTenant(req.tenant_id, (c) => c.query('SELECT * FROM notification_channels WHERE id = $1 AND tenant_id = $2', [req.params.id, req.tenant_id]))).rows[0];
    if (!row) return apiError(res, 404, 'NOT_FOUND', 'Channel not found');
    const tn = (await db.query('SELECT name FROM tenants WHERE id = $1', [req.tenant_id])).rows[0];
    try {
      await sendToChannel(row.type, notifyBox.decrypt(row.config_enc), testMessage({ tenantName: tn && tn.name, baseUrl: process.env.ASIX_PUBLIC_URL }));
    } catch (e) {
      if (e.code === 'NO_KEY') throw e;
      return res.status(502).json({ success: false, error: { code: 'NOTIFY_TEST_FAILED', message: String(e.message || e).slice(0, 300) } });
    }
    res.status(200).json({ success: true });
  } catch (e) { notifyError(res, e, 'Failed to send test notification'); }
});

// The delivery log lists alert messages and, since "Resolved" messages exist, those too (kind 'alert' or 'resolved'; ?kind= filters).
// If the notification_recoveries table is not there yet (schema job not run) the log shows alert messages only instead of failing.
const DELIVERY_COLS = (kind) => `d.id, '${kind}'::text AS kind, d.status, d.attempts, d.last_error, d.sent_at, d.created_at, d.next_attempt_at,
                ch.name AS channel_name, ch.type AS channel_type, a.id AS alert_id, a.title, a.severity`;
const deliveryPart = (table, kind) => `SELECT ${DELIVERY_COLS(kind)}
         FROM ${table} d JOIN notification_channels ch ON ch.id = d.channel_id JOIN alerts a ON a.id = d.alert_id
         WHERE d.tenant_id = $1 AND ($2::text IS NULL OR d.status = $2)`;

router.get('/v1/notifications/deliveries', ...guarded('notify:read'), async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const status = ['pending', 'sent', 'failed', 'skipped'].includes(req.query.status) ? req.query.status : null;
  const kind = ['alert', 'resolved'].includes(req.query.kind) ? req.query.kind : null;
  const list = (withResolved) => {
    const parts = [];
    if (kind !== 'resolved') parts.push(deliveryPart('notification_deliveries', 'alert'));
    if (kind !== 'alert' && withResolved) parts.push(deliveryPart('notification_recoveries', 'resolved'));
    if (!parts.length) return Promise.resolve({ deliveries: [], total: 0 });
    const union = parts.join(' UNION ALL ');
    return db.withTenant(req.tenant_id, async (c) => {
      const rows = await c.query(`SELECT * FROM (${union}) u ORDER BY created_at DESC, id LIMIT ${limit} OFFSET ${offset}`, [req.tenant_id, status]);
      const total = await c.query(`SELECT COUNT(*)::int AS n FROM (${union}) u`, [req.tenant_id, status]);
      return { deliveries: rows.rows, total: total.rows[0].n };
    });
  };
  try {
    let r;
    try { r = await list(true); }
    catch (e) { if (e.code !== '42P01') throw e; r = await list(false); }
    res.status(200).json({ success: true, limit, offset, ...r });
  } catch (e) { notifyError(res, e, 'Failed to list deliveries'); }
});

router.post('/v1/notifications/deliveries/:id/retry', ...guarded('notify:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid delivery id');
  try {
    const retry = (table) => db.withTenant(req.tenant_id, (c) => c.query(
      `UPDATE ${table} SET status='pending', attempts=0, next_attempt_at=localtimestamp, last_error=NULL
       WHERE id=$1 AND tenant_id=$2 AND status IN ('failed','skipped') RETURNING id`, [req.params.id, req.tenant_id]));
    let r = await retry('notification_deliveries');
    if (!r.rows.length) {   // ids are UUIDs, so the id belongs to at most one of the two tables; try the Resolved messages next
      try { r = await retry('notification_recoveries'); } catch (e) { if (e.code !== '42P01') throw e; }
    }
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Delivery not found or not retryable');
    res.status(200).json({ success: true });
  } catch (e) { notifyError(res, e, 'Failed to retry delivery'); }
});


module.exports = router;
