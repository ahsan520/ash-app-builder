'use strict';
// The registry of the central Wazuh indexer, one row per tenant (docs/endpoints.md, task E6e): where the tenant's vulnerability findings are read from, and with which credentials.
//
// Why a row per tenant when the indexer is ONE shared machine: each tenant's manager writes to its OWN index (wazuh-states-vulnerabilities-<manager name>), and each row holds that exact
// index name and an indexer user whose role may read only that index (docs/wazuh-indexer.md). NO ROW = no vulnerability data for the tenant. Like the manager registry, there is deliberately
// NO HTTP ROUTE that writes this table: the address is where ASIX's own API connects, with a password, so a tenant user must not be able to choose it (server-side request forgery).
// An operator registers with src/endpoints/wazuh-indexer-cli.js, which uses this module. The routes only read.
//
// Stored: the address (https://host:port), the user, the password sealed with NOTIFY_ENCRYPTION_KEY (src/notifications/secret-box.js), the one certificate trusted when connecting (the
// indexer's root CA, or its own certificate) with its SHA-256 for display, the exact index name and a label.
const crypto = require('crypto');
const box = require('../notifications/secret-box');
const indexer = require('./wazuh-indexer');

const USER_RE = /^[A-Za-z0-9._-]{3,64}$/;
const isMissingTable = (e) => !!e && e.code === '42P01';   // undefined_table: the schema job has not run yet
const fail = (error) => ({ error });

// Input of a registration (from the CLI): { url, user, password, ca_pem, index, label? }. Returns { reg } or { error }.
function parseRegistration(input) {
  const b = input && typeof input === 'object' && !Array.isArray(input) ? input : null;
  if (!b) return fail('The registration must be a JSON object: { "url", "user", "password", "ca_pem", "index", "label"? }');
  const u = indexer.checkUrl(b.url);
  if (u.error) return fail(u.error);
  if (typeof b.user !== 'string' || !USER_RE.test(b.user)) return fail('user must be 3 to 64 letters, digits, dots, dashes or underscores');
  if (typeof b.password !== 'string' || b.password.length < 8 || b.password.length > 128 || /[\u0000-\u001f\u007f]/.test(b.password)) return fail('password must be 8 to 128 characters with no control characters');
  const ix = indexer.checkIndexName(b.index);
  if (ix.error) return fail(ix.error);
  if (typeof b.ca_pem !== 'string' || b.ca_pem.length > 20000) return fail('ca_pem must be the indexer\'s root CA (or its own certificate) in PEM form');
  let cert;
  try { cert = new crypto.X509Certificate(b.ca_pem); } catch { return fail('ca_pem is not a readable certificate (PEM, -----BEGIN CERTIFICATE-----)'); }
  const pems = b.ca_pem.match(/-----BEGIN CERTIFICATE-----/g) || [];
  if (pems.length !== 1) return fail('ca_pem must hold exactly one certificate: the root CA that signed the indexer\'s certificate, or the indexer\'s own');
  const pem = b.ca_pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)[0] + '\n';   // only the certificate block is kept
  const now = Date.now();
  if (new Date(cert.validTo).getTime() < now) return fail('The certificate expired on ' + cert.validTo);
  if (new Date(cert.validFrom).getTime() > now + 86400000) return fail('The certificate is not valid until ' + cert.validFrom);
  let label = null;
  if (b.label !== undefined && b.label !== null && b.label !== '') {
    if (typeof b.label !== 'string' || b.label.length > 100 || /[\u0000-\u001f\u007f]/.test(b.label)) return fail('label must be text of at most 100 characters');
    label = b.label;
  }
  return { reg: { index_url: u.origin, index_user: b.user, password: b.password, ca_pem: pem, cert_sha256: cert.fingerprint256.replace(/:/g, '').toLowerCase(), not_after: cert.validTo, index_name: ix.index, label } };
}

const COLS = 'tenant_id, index_url, index_user, secret_enc, ca_pem, cert_sha256, index_name, label, created_at, updated_at, updated_by';
async function readRow(client, tenantId) {
  const r = await client.query(`SELECT ${COLS} FROM wazuh_indexers WHERE tenant_id = $1`, [tenantId]);
  return r.rows[0] || null;
}
async function writeRow(client, tenantId, reg, updatedBy) {
  const sealed = box.encrypt({ password: reg.password });
  await client.query(
    `INSERT INTO wazuh_indexers (tenant_id, index_url, index_user, secret_enc, ca_pem, cert_sha256, index_name, label, updated_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     ON CONFLICT (tenant_id) DO UPDATE SET index_url = EXCLUDED.index_url, index_user = EXCLUDED.index_user, secret_enc = EXCLUDED.secret_enc,
       ca_pem = EXCLUDED.ca_pem, cert_sha256 = EXCLUDED.cert_sha256, index_name = EXCLUDED.index_name, label = EXCLUDED.label, updated_at = CURRENT_TIMESTAMP, updated_by = EXCLUDED.updated_by`,
    [tenantId, reg.index_url, reg.index_user, sealed, reg.ca_pem, reg.cert_sha256, reg.index_name, reg.label, updatedBy || null]);
}
async function clearRow(client, tenantId) {
  return (await client.query('DELETE FROM wazuh_indexers WHERE tenant_id = $1', [tenantId])).rowCount;
}

// What a route may show: never the password, the sealed password or the certificate text.
function view(row, available = true) {
  if (!available) return { available: false, registered: false };
  if (!row) return { available: true, registered: false };
  const u = indexer.checkUrl(row.index_url);
  return { available: true, registered: true, label: row.label || null, host: u.host || null, port: u.port || null, index: row.index_name, index_user: row.index_user, cert_sha256: row.cert_sha256, updated_at: row.updated_at };
}

// What the client needs to connect: the password opened. Throws { code: 'NO_KEY' } when NOTIFY_ENCRYPTION_KEY is not set, and an Error when the sealed text cannot be opened.
function credentials(row) {
  const { password } = box.decrypt(row.secret_enc);
  return { tenant_id: row.tenant_id, index_url: row.index_url, index_user: row.index_user, index_password: password, ca_pem: row.ca_pem, cert_sha256: row.cert_sha256, index_name: row.index_name };
}

module.exports = { parseRegistration, readRow, writeRow, clearRow, view, credentials, isMissingTable, USER_RE };
