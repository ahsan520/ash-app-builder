'use strict';
// History of the Windows events block of an agent group (docs/endpoints.md, task E11). Same rules as group-config-store.js: a row is written BEFORE the manager is called (result
// `failed`, "not finished") and settled after, so a crash between the two still leaves a trace and the whole file as it was; the newest 50 per tenant and group are kept.
// The credentials are the writer's of E10 (group-config-store.js); nothing is stored here that opens anything.
const isMissingTable = (e) => !!e && e.code === '42P01';
const HISTORY_KEEP = 50;
const ACTIONS = ['apply', 'remove', 'undo'], RESULTS = ['applied', 'rolled_back', 'failed'];

async function record(client, tenantId, group, h) {
  if (!ACTIONS.includes(h.action) || !RESULTS.includes(h.result)) throw new Error('bad history row');
  const r = await client.query(
    `INSERT INTO endpoint_group_winlog_history (tenant_id, group_name, action, result, channels_before, channels_after, policy_revision, before_sha256, after_sha256, before_content, note, actor)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9, $10, $11, $12) RETURNING id, created_at`,
    [tenantId, group, h.action, h.result, JSON.stringify(h.channels_before), JSON.stringify(h.channels_after), Number(h.policy_revision) || 0, h.before_sha256, h.after_sha256 || null, h.before_content, h.note || null, h.actor || null]);
  await client.query(
    `DELETE FROM endpoint_group_winlog_history WHERE tenant_id = $1 AND group_name = $2 AND id NOT IN
       (SELECT id FROM endpoint_group_winlog_history WHERE tenant_id = $1 AND group_name = $2 ORDER BY created_at DESC, id DESC LIMIT ${HISTORY_KEEP})`, [tenantId, group]);
  return r.rows[0];
}
async function settle(client, tenantId, id, result, afterSha, note) {
  if (!RESULTS.includes(result)) throw new Error('bad history result');
  return (await client.query('UPDATE endpoint_group_winlog_history SET result = $3, after_sha256 = $4, note = $5 WHERE tenant_id = $1 AND id = $2', [tenantId, id, result, afterSha || null, note || null])).rowCount;
}
async function list(client, tenantId, group, limit = 20) {
  const n = Math.max(1, Math.min(HISTORY_KEEP, Number(limit) || 20));
  return (await client.query(
    `SELECT h.id, h.group_name, h.action, h.result, h.channels_before, h.channels_after, h.policy_revision, h.before_sha256, h.after_sha256, h.note, h.actor, h.created_at, u.username AS actor_name
       FROM endpoint_group_winlog_history h LEFT JOIN users u ON u.id::text = h.actor
      WHERE h.tenant_id = $1 AND h.group_name = $2 ORDER BY h.created_at DESC, h.id DESC LIMIT ${n}`, [tenantId, group])).rows;
}
async function get(client, tenantId, group, id) {
  return (await client.query('SELECT id, group_name, action, result, channels_before, channels_after, policy_revision, before_sha256, after_sha256, note, actor, created_at FROM endpoint_group_winlog_history WHERE tenant_id = $1 AND group_name = $2 AND id = $3', [tenantId, group, id])).rows[0] || null;
}

module.exports = { HISTORY_KEEP, isMissingTable, record, settle, list, get };
