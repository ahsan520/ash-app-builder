'use strict';
// Database side of integrations (task SR1, docs/integrations.md). Each function takes an open tenant-scoped client and filters on tenant_id explicitly
// (the API connects as the table owner, which bypasses row-level security; same rule as src/cases/service.js).
// Credentials: sealed as one JSON object through src/secrets/provider.js, stored in credential_enc; the NAMES of the fields that are set are kept beside it
// (credential_fields) so the list and the status work without opening anything. No function here returns a secret, EXCEPT useCredentials, which is for the code
// that talks to the product, is not reachable from any route, and writes an audit row for every use (docs/plan.md H.7: access is audited; the audit holds names, never values).
const catalog = require('./catalog');
const model = require('./model');
const secrets = require('../secrets/provider');
const casesService = require('../cases/service');

const audit = (client, tenantId, actorId, action, resource) => client.query(
  'INSERT INTO audit_events (tenant_id, user_id, action, resource, result) VALUES ($1, $2, $3, $4, $5)',
  [tenantId, actorId, action, String(resource).slice(0, 255), 'success']);

const COLS = `i.id, i.definition_id, i.name, i.config, i.enabled, i.credential_fields, i.credential_set_at, i.credential_set_by_name, i.created_by_name, i.created_at, i.updated_at`;

// What a route may show: never credential_enc, and for each credential only whether it is set.
function shape(row) {
  const def = catalog.get(row.definition_id);
  const set = new Set(row.credential_fields || []);
  return {
    id: row.id, definition_id: row.definition_id, definition_name: def ? def.name : row.definition_id, category: def ? def.category : null, known_definition: !!def,
    name: row.name, config: row.config || {}, enabled: row.enabled, status: model.statusOf(def, row),
    credentials: def ? def.credentials.map((f) => ({ name: f.name, label: f.label, required: !!f.required, set: set.has(f.name) })) : [],
    credential_set_at: row.credential_set_at, credential_set_by_name: row.credential_set_by_name,
    created_by_name: row.created_by_name, created_at: row.created_at, updated_at: row.updated_at,
  };
}

async function listAll(client, tenantId) {
  const r = await client.query(`SELECT ${COLS} FROM integration_instances i WHERE i.tenant_id = $1 ORDER BY lower(i.name), i.id`, [tenantId]);
  return r.rows.map(shape);
}
async function getRow(client, tenantId, id, lock) {
  const r = await client.query(`SELECT ${COLS}, i.credential_enc FROM integration_instances i WHERE i.id = $1 AND i.tenant_id = $2${lock ? ' FOR UPDATE' : ''}`, [id, tenantId]);
  return r.rows[0] || null;
}
async function get(client, tenantId, id) { const row = await getRow(client, tenantId, id); return row ? shape(row) : null; }
const nameTaken = async (client, tenantId, name, exceptId) => (await client.query(
  'SELECT 1 FROM integration_instances WHERE tenant_id = $1 AND lower(name) = lower($2) AND ($3::uuid IS NULL OR id <> $3::uuid)', [tenantId, name, exceptId || null])).rows.length > 0;

async function create(client, tenantId, userId, def, v) {
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const n = await client.query('SELECT COUNT(*)::int AS n FROM integration_instances WHERE tenant_id = $1', [tenantId]);
  if (n.rows[0].n >= model.LIMITS.perTenant) return { code: 'TOO_MANY', message: `A tenant can have ${model.LIMITS.perTenant} integrations` };
  if (await nameTaken(client, tenantId, v.name)) return { code: 'NAME_TAKEN', message: 'An integration with this name already exists' };
  const r = await client.query(
    'INSERT INTO integration_instances (tenant_id, definition_id, name, config, created_by_name) VALUES ($1, $2, $3, $4::jsonb, $5) RETURNING id',
    [tenantId, def.id, v.name, JSON.stringify(v.config), actor.name]);
  await audit(client, tenantId, actor.id, 'soar:integration:create', `${v.name} definition=${def.id}`);
  return { integration: await get(client, tenantId, r.rows[0].id) };
}

async function update(client, tenantId, userId, id, patchOf) {
  const row = await getRow(client, tenantId, id, true); if (!row) return { code: 'NOT_FOUND' };
  const def = catalog.get(row.definition_id);
  if (!def) return { code: 'UNKNOWN_DEFINITION', message: 'ASIX no longer has a definition for this integration' };
  const parsed = patchOf(def); if (parsed.error) return { code: parsed.error.code, message: parsed.error.message };
  const patch = parsed.value;
  if (patch.name !== undefined && await nameTaken(client, tenantId, patch.name, id)) return { code: 'NAME_TAKEN', message: 'An integration with this name already exists' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const config = { ...(row.config || {}) };
  for (const [k, v] of Object.entries(patch.config || {})) { if (v === null) delete config[k]; else config[k] = v; }
  await client.query(
    `UPDATE integration_instances SET name = $3, config = $4::jsonb, enabled = $5, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2`,
    [id, tenantId, patch.name !== undefined ? patch.name : row.name, JSON.stringify(config), patch.enabled !== undefined ? patch.enabled : row.enabled]);
  await audit(client, tenantId, actor.id, 'soar:integration:update', `${patch.name || row.name} fields=${Object.keys(patch).join(',')}`);
  return { integration: await get(client, tenantId, id) };
}

// Sets some credentials and clears others. The rest stay as they were. -> { integration } or { code }: NOT_FOUND, SECRETS_NOT_CONFIGURED, SECRET_UNREADABLE.
async function setCredentials(client, tenantId, userId, id, { values, clear }) {
  const row = await getRow(client, tenantId, id, true); if (!row) return { code: 'NOT_FOUND' };
  const def = catalog.get(row.definition_id);
  if (!def) return { code: 'UNKNOWN_DEFINITION', message: 'ASIX no longer has a definition for this integration' };
  if (!secrets.configured()) return { code: 'SECRETS_NOT_CONFIGURED', message: 'The key that protects stored secrets is not configured on this deployment (NOTIFY_ENCRYPTION_KEY)' };
  let current = {};
  if (row.credential_enc) {
    try { current = secrets.open(row.credential_enc); } catch { return { code: 'SECRET_UNREADABLE', message: 'The stored credentials cannot be read (the key changed?). Clear them and enter them again.' }; }
  }
  for (const k of clear) delete current[k];
  Object.assign(current, values);
  const names = Object.keys(current).sort();
  const actor = await casesService.resolveActor(client, tenantId, userId);
  await client.query(
    `UPDATE integration_instances SET credential_enc = $3, credential_fields = $4::text[], credential_set_at = localtimestamp, credential_set_by_name = $5, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2`,
    [id, tenantId, names.length ? secrets.seal(current) : null, names, actor.name]);
  await audit(client, tenantId, actor.id, 'soar:integration:credentials-set', `${row.name} set=${Object.keys(values).sort().join(',') || '-'} cleared=${clear.slice().sort().join(',') || '-'}`);
  return { integration: await get(client, tenantId, id) };
}
// Clears every credential (works even when the stored ones can no longer be read).
async function clearCredentials(client, tenantId, userId, id) {
  const row = await getRow(client, tenantId, id, true); if (!row) return { code: 'NOT_FOUND' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  await client.query(`UPDATE integration_instances SET credential_enc = NULL, credential_fields = '{}', credential_set_at = localtimestamp, credential_set_by_name = $3, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2`, [id, tenantId, actor.name]);
  await audit(client, tenantId, actor.id, 'soar:integration:credentials-clear', `${row.name} fields=${(row.credential_fields || []).slice().sort().join(',') || '-'}`);
  return { integration: await get(client, tenantId, id) };
}

async function remove(client, tenantId, userId, id) {
  const row = await getRow(client, tenantId, id, true); if (!row) return { code: 'NOT_FOUND' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  await client.query('DELETE FROM integration_instances WHERE id = $1 AND tenant_id = $2', [id, tenantId]);
  await audit(client, tenantId, actor.id, 'soar:integration:delete', `${row.name} definition=${row.definition_id}`);
  return { removed: true };
}

// For the code that talks to the product (SR3, SR4), never for a route. Returns { config, credentials, definition_id } for an integration that is enabled and has
// every required credential; refuses otherwise. `purpose` (for example an action id) is written to the audit trail with the integration's name: names, never values.
async function useCredentials(client, tenantId, id, purpose) {
  const row = await getRow(client, tenantId, id, false); if (!row) return { code: 'NOT_FOUND' };
  const s = shape(row);
  if (s.status === 'disabled') return { code: 'DISABLED', message: 'This integration is switched off' };
  if (s.status !== 'configured') return { code: 'NOT_CONFIGURED', message: 'This integration has no account yet' };
  let credentials = {};
  if (row.credential_enc) { try { credentials = secrets.open(row.credential_enc); } catch { return { code: 'SECRET_UNREADABLE', message: 'The stored credentials cannot be read' }; } }
  await audit(client, tenantId, null, 'soar:integration:credentials-use', `${row.name} purpose=${String(purpose || 'unspecified').slice(0, 80)}`);
  return { definition_id: row.definition_id, config: row.config || {}, credentials };
}

module.exports = { listAll, get, create, update, setCredentials, clearCredentials, remove, useCredentials, shape };
