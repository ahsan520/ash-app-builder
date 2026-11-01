'use strict';
// Storage for the group configuration feature (docs/endpoints.md, task E10): the writer's credentials and the history of changes.
//
// The WRITER is a second manager API user, separate from the read-only one, whose role on the manager allows only reading groups and updating a group's configuration. Like the
// manager registration, NO HTTP ROUTE writes it: an operator registers it with `wazuh-manager-cli.js register-writer` (a password that can change what thousands of machines watch is not
// something a portal user may choose or replace). It is sealed with NOTIFY_ENCRYPTION_KEY exactly as the read-only password is.
//
// The HISTORY keeps, for every change (and every refused or rolled-back attempt that reached the manager), the entries and the whole file as they were before, who did it and what came
// of it. Undo does not paste an old file back (that would undo other people's changes to the rest of the file): it sets the ASIX block to the entries before.
const crypto = require('crypto');
const box = require('../notifications/secret-box');
const { USER_RE } = require('./wazuh-manager-store');

const isMissingTable = (e) => !!e && e.code === '42P01';
const HISTORY_KEEP = 50;   // per tenant and group; older rows are deleted when a new one is written

function parseRegistration(input) {
  const b = input && typeof input === 'object' && !Array.isArray(input) ? input : null;
  if (!b) return { error: 'The registration must be a JSON object: { "user", "password" }' };
  const extra = Object.keys(b).filter((k) => !['user', 'password'].includes(k)); if (extra.length) return { error: 'Unknown field "' + String(extra[0]).slice(0, 30) + '": the writer registration is only { "user", "password" } (the address and certificate are the manager\'s)' };
  if (typeof b.user !== 'string' || !USER_RE.test(b.user)) return { error: 'user must be 3 to 64 letters, digits, dots, dashes or underscores' };
  if (typeof b.password !== 'string' || b.password.length < 8 || b.password.length > 128 || /[\u0000-\u001f\u007f]/.test(b.password)) return { error: 'password must be 8 to 128 characters with no control characters' };
  return { reg: { api_user: b.user, password: b.password } };
}
async function readWriter(client, tenantId) { return (await client.query('SELECT tenant_id, api_user, api_secret_enc, updated_at FROM wazuh_manager_writers WHERE tenant_id = $1', [tenantId])).rows[0] || null; }
async function writeWriter(client, tenantId, reg, by) {
  await client.query(`INSERT INTO wazuh_manager_writers (tenant_id, api_user, api_secret_enc, updated_by) VALUES ($1, $2, $3, $4)
    ON CONFLICT (tenant_id) DO UPDATE SET api_user = EXCLUDED.api_user, api_secret_enc = EXCLUDED.api_secret_enc, updated_at = CURRENT_TIMESTAMP, updated_by = EXCLUDED.updated_by`,
  [tenantId, reg.api_user, box.encrypt({ password: reg.password }), by || null]);
}
async function clearWriter(client, tenantId) { return (await client.query('DELETE FROM wazuh_manager_writers WHERE tenant_id = $1', [tenantId])).rowCount; }
// What the client needs: the password opened. Throws { code: 'NO_KEY' } without the encryption key.
function writerCredentials(row) {
  const { password } = box.decrypt(row.api_secret_enc);
  return { api_user: row.api_user, api_password: password, hash: crypto.createHash('sha256').update(row.api_secret_enc).digest('hex').slice(0, 16) };
}
const writerView = (row) => (row ? { registered: true, api_user: row.api_user, updated_at: row.updated_at } : { registered: false });

const ACTIONS = ['apply', 'remove', 'undo'], RESULTS = ['applied', 'rolled_back', 'failed'];
async function record(client, tenantId, group, h) {
  if (!ACTIONS.includes(h.action) || !RESULTS.includes(h.result)) throw new Error('bad history row');
  const r = await client.query(
    `INSERT INTO endpoint_group_config_history (tenant_id, group_name, action, result, entries_before, entries_after, before_sha256, after_sha256, before_content, note, actor)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9, $10, $11) RETURNING id, created_at`,
    [tenantId, group, h.action, h.result, JSON.stringify(h.entries_before), JSON.stringify(h.entries_after), h.before_sha256, h.after_sha256 || null, h.before_content, h.note || null, h.actor || null]);
  await client.query(
    `DELETE FROM endpoint_group_config_history WHERE tenant_id = $1 AND group_name = $2 AND id NOT IN
       (SELECT id FROM endpoint_group_config_history WHERE tenant_id = $1 AND group_name = $2 ORDER BY created_at DESC, id DESC LIMIT ${HISTORY_KEEP})`, [tenantId, group]);
  return r.rows[0];
}
// A row is written BEFORE the manager is called (result `failed`, "not finished") and settled after, so a crash between the two still leaves a trace and the file as it was.
async function settle(client, tenantId, id, result, afterSha, note) {
  if (!RESULTS.includes(result)) throw new Error('bad history result');
  return (await client.query('UPDATE endpoint_group_config_history SET result = $3, after_sha256 = $4, note = $5 WHERE tenant_id = $1 AND id = $2', [tenantId, id, result, afterSha || null, note || null])).rowCount;
}
async function list(client, tenantId, group, limit = 20) {
  const n = Math.max(1, Math.min(HISTORY_KEEP, Number(limit) || 20));
  return (await client.query(
    `SELECT h.id, h.group_name, h.action, h.result, h.entries_before, h.entries_after, h.before_sha256, h.after_sha256, h.note, h.actor, h.created_at, u.username AS actor_name
       FROM endpoint_group_config_history h LEFT JOIN users u ON u.id::text = h.actor
      WHERE h.tenant_id = $1 AND h.group_name = $2 ORDER BY h.created_at DESC, h.id DESC LIMIT ${n}`, [tenantId, group])).rows;
}
async function get(client, tenantId, group, id) {
  return (await client.query('SELECT id, group_name, action, result, entries_before, entries_after, before_sha256, after_sha256, note, actor, created_at FROM endpoint_group_config_history WHERE tenant_id = $1 AND group_name = $2 AND id = $3', [tenantId, group, id])).rows[0] || null;
}

module.exports = { HISTORY_KEEP, isMissingTable, parseRegistration, readWriter, writeWriter, clearWriter, writerCredentials, writerView, record, settle, list, get };
