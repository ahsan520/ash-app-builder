'use strict';
// The registry of central Wazuh managers (docs/endpoints.md, task E4c): which manager API belongs to which tenant, and the credentials ASIX uses to read it.
//
// One row per tenant in wazuh_managers; NO ROW = no central manager. There is deliberately NO HTTP ROUTE that writes this table: the address is where ASIX's own API will
// connect (with a password), so letting a tenant user choose it would be a way to aim the API at things it can reach and they cannot (server-side request forgery). An
// operator registers a manager with src/endpoints/wazuh-manager-cli.js, which uses this module. The routes only read.
//
// What is stored: the API's address (https://host:port), the API user, the API password sealed with NOTIFY_ENCRYPTION_KEY (src/notifications/secret-box.js, AES-256-GCM, the same
// key as the notification channel secrets), the manager's own self-signed certificate (the one trusted certificate when connecting: wazuh-api.js) and its SHA-256 for display.
const crypto = require('crypto');
const box = require('../notifications/secret-box');
const wazuhApi = require('./wazuh-api');

const USER_RE = /^[A-Za-z0-9._-]{3,64}$/;
const isMissingTable = (e) => !!e && e.code === '42P01';   // undefined_table: the schema job has not run yet
const fail = (error) => ({ error });

// Input of a registration (from the CLI): { url, user, password, ca_pem, label? }. Returns { reg } or { error }.
function parseRegistration(input) {
  const b = input && typeof input === 'object' && !Array.isArray(input) ? input : null;
  if (!b) return fail('The registration must be a JSON object: { "url", "user", "password", "ca_pem", "label"? }');
  const u = wazuhApi.checkApiUrl(b.url);
  if (u.error) return fail(u.error);
  if (typeof b.user !== 'string' || !USER_RE.test(b.user)) return fail('user must be 3 to 64 letters, digits, dots, dashes or underscores');
  if (typeof b.password !== 'string' || b.password.length < 8 || b.password.length > 128 || /[\u0000-\u001f\u007f]/.test(b.password)) return fail('password must be 8 to 128 characters with no control characters');
  if (typeof b.ca_pem !== 'string' || b.ca_pem.length > 20000) return fail('ca_pem must be the manager API certificate in PEM form');
  let cert;
  try { cert = new crypto.X509Certificate(b.ca_pem); } catch { return fail('ca_pem is not a readable certificate (PEM, -----BEGIN CERTIFICATE-----)'); }
  const pems = b.ca_pem.match(/-----BEGIN CERTIFICATE-----/g) || [];
  if (pems.length !== 1) return fail('ca_pem must hold exactly one certificate: the manager API\'s own');
  const pem = b.ca_pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)[0] + '\n';   // only the certificate block is kept
  const now = Date.now();
  if (new Date(cert.validTo).getTime() < now) return fail('The certificate expired on ' + cert.validTo);
  if (new Date(cert.validFrom).getTime() > now + 86400000) return fail('The certificate is not valid until ' + cert.validFrom);
  let label = null;
  if (b.label !== undefined && b.label !== null && b.label !== '') {
    if (typeof b.label !== 'string' || b.label.length > 100 || /[\u0000-\u001f\u007f]/.test(b.label)) return fail('label must be text of at most 100 characters');
    label = b.label;
  }
  return { reg: { api_url: u.origin, api_user: b.user, password: b.password, ca_pem: pem, cert_sha256: cert.fingerprint256.replace(/:/g, '').toLowerCase(), not_after: cert.validTo, label } };
}

const COLS = 'tenant_id, api_url, api_user, api_secret_enc, ca_pem, cert_sha256, label, created_at, updated_at, updated_by';
async function readRow(client, tenantId) {
  const r = await client.query(`SELECT ${COLS} FROM wazuh_managers WHERE tenant_id = $1`, [tenantId]);
  return r.rows[0] || null;
}
async function writeRow(client, tenantId, reg, updatedBy) {
  const sealed = box.encrypt({ password: reg.password });
  await client.query(
    `INSERT INTO wazuh_managers (tenant_id, api_url, api_user, api_secret_enc, ca_pem, cert_sha256, label, updated_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (tenant_id) DO UPDATE SET api_url = EXCLUDED.api_url, api_user = EXCLUDED.api_user, api_secret_enc = EXCLUDED.api_secret_enc,
       ca_pem = EXCLUDED.ca_pem, cert_sha256 = EXCLUDED.cert_sha256, label = EXCLUDED.label, updated_at = CURRENT_TIMESTAMP, updated_by = EXCLUDED.updated_by`,
    [tenantId, reg.api_url, reg.api_user, sealed, reg.ca_pem, reg.cert_sha256, reg.label, updatedBy || null]);
}
async function clearRow(client, tenantId) {
  return (await client.query('DELETE FROM wazuh_managers WHERE tenant_id = $1', [tenantId])).rowCount;
}

// What a route may show: never the password, the sealed password or the certificate text.
function view(row, available = true) {
  if (!available) return { available: false, registered: false };
  if (!row) return { available: true, registered: false };
  const u = wazuhApi.checkApiUrl(row.api_url);
  return { available: true, registered: true, label: row.label || null, host: u.host || null, port: u.port || null, api_user: row.api_user, cert_sha256: row.cert_sha256, updated_at: row.updated_at };
}

// What the client needs to connect: the password opened. Throws { code: 'NO_KEY' } when NOTIFY_ENCRYPTION_KEY is not set, and an Error when the sealed text cannot be opened.
function credentials(row) {
  const { password } = box.decrypt(row.api_secret_enc);
  return { tenant_id: row.tenant_id, api_url: row.api_url, api_user: row.api_user, api_password: password, ca_pem: row.ca_pem, cert_sha256: row.cert_sha256,
    api_secret_enc_hash: crypto.createHash('sha256').update(row.api_secret_enc).digest('hex').slice(0, 16) };
}

module.exports = { parseRegistration, readRow, writeRow, clearRow, view, credentials, isMissingTable, USER_RE };
