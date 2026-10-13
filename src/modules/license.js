'use strict';
// Signed license file -> entitlements. A license is a compact JWS (EdDSA / Ed25519) signed by the
// vendor; the platform only holds the PUBLIC key. Claims: iss "asix", sub (customer), exp,
// features [string], limits { tenants, retention_days_max } (null = unlimited).
// Fails closed to the Home defaults: a missing, expired or tampered license never stops the platform
// and never touches data, it just does not unlock anything.
const fs = require('fs');
const { jwtVerify, importSPKI } = require('jose');

const DEFAULT_FILE = '/etc/asix/license.jwt';
const LIMIT_KEYS = ['tenants', 'retention_days_max'];

function readText(file) {
  try { return fs.readFileSync(file, 'utf8').trim(); } catch (e) { return e.code === 'ENOENT' ? null : undefined; }
}

function cleanLimits(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const k of LIMIT_KEYS) {
    if (!(k in raw)) continue;
    const v = raw[k];
    if (v === null) out[k] = null;
    else if (Number.isInteger(v) && v > 0) out[k] = v;
  }
  return out;
}

// env: { ASIX_LICENSE, ASIX_LICENSE_FILE, ASIX_LICENSE_PUBKEY, ASIX_LICENSE_PUBKEY_FILE }
async function load(env = process.env, now = new Date()) {
  const token = env.ASIX_LICENSE ? String(env.ASIX_LICENSE).trim() : readText(env.ASIX_LICENSE_FILE || DEFAULT_FILE);
  if (token === null) return { status: 'none', features: [], limits: {} };
  if (token === undefined || !token) return { status: 'unreadable', features: [], limits: {} };
  const pem = env.ASIX_LICENSE_PUBKEY || readText(env.ASIX_LICENSE_PUBKEY_FILE || '/etc/asix/license.pub');
  if (!pem) return { status: 'invalid', reason: 'no public key configured to verify the license', features: [], limits: {} };
  let key;
  try { key = await importSPKI(pem.replace(/\\n/g, '\n'), 'EdDSA'); } catch { return { status: 'invalid', reason: 'public key is not a valid Ed25519 key', features: [], limits: {} }; }
  try {
    const { payload } = await jwtVerify(token, key, { algorithms: ['EdDSA'], issuer: 'asix', currentDate: now });
    const features = Array.isArray(payload.features) ? payload.features.filter((f) => typeof f === 'string').slice(0, 50) : [];
    return {
      status: 'valid', customer: typeof payload.sub === 'string' ? payload.sub : null,
      expires_at: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
      features, limits: cleanLimits(payload.limits),
    };
  } catch (e) {
    if (e && e.code === 'ERR_JWT_EXPIRED') return { status: 'expired', reason: 'the license has expired', features: [], limits: {} };
    return { status: 'invalid', reason: 'the license signature or claims are not valid', features: [], limits: {} };
  }
}

module.exports = { load, cleanLimits };
