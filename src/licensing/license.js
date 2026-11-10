'use strict';
// Signed license file -> entitlements (docs/licensing.md). A license is a compact JWS (EdDSA / Ed25519) signed by the vendor; the platform holds only PUBLIC keys, built in (vendor-keys.js).
// Claims: iss "asix", sub (customer), exp, iid (the installation id it is for, or "*" for a license the vendor chose not to bind), features [string], limits { tenants, retention_days_max }
// (null = unlimited), kind ("residential" | "enterprise", informational). Header kid names the signing key.
// After expiry there is a GRACE period (claim grace_days, default 30, at most 90; a trial license can say 0): everything the license unlocked keeps working with a loud warning (status
// 'grace'). After it, status 'expired': search, reports, detections and alerts lock; ingestion, retention, backup and data export keep running, and nothing is deleted.
// Fails closed: a missing, expired, tampered, foreign or wrong-installation license never stops the platform and never touches data; it just unlocks nothing, so only the baseline runs.
const fs = require('fs');
const { jwtVerify, importSPKI, decodeProtectedHeader, decodeJwt } = require('jose');
const vendor = require('./vendor-keys');

const DEFAULT_FILE = '/etc/asix/license.jwt';
const LIMIT_KEYS = ['tenants', 'retention_days_max'];
const WARN_DAYS = 14;
const DEFAULT_GRACE_DAYS = 30, MAX_GRACE_DAYS = 90;
const none = (status, reason, extra = {}) => ({ status, ...(reason ? { reason } : {}), features: [], limits: {}, ...extra });

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

// env: { ASIX_LICENSE, ASIX_LICENSE_FILE }. opts: { token } (a stored license from the database, used before the environment or file), { keys: [{ kid, pem }] (tests only; the server uses vendor-keys.js), iid: this installation's id, clockBack: boolean }.
async function load(env = process.env, now = new Date(), opts = {}) {
  const token = opts.token ? String(opts.token).trim() : env.ASIX_LICENSE ? String(env.ASIX_LICENSE).trim() : readText(env.ASIX_LICENSE_FILE || DEFAULT_FILE);
  if (token === null) return none('none');
  if (token === undefined || !token) return none('unreadable');
  const keys = opts.keys || vendor.KEYS;
  if (!keys.length) return none('invalid', 'this build has no vendor key to verify a license with');
  let kid; try { kid = decodeProtectedHeader(token).kid; } catch { return none('invalid', 'the license is not readable'); }
  const k = keys.find((x) => x.kid === kid);
  if (!k) return none('invalid', 'the license was signed with a key this build does not know');
  let key; try { key = await importSPKI(String(k.pem).replace(/\\n/g, '\n'), 'EdDSA'); } catch { return none('invalid', 'the built-in vendor key is not valid'); }
  // grace_days is read before the signature is checked, but it only counts if the signature then verifies: a changed value breaks it.
  let grace = DEFAULT_GRACE_DAYS;
  try { const g = decodeJwt(token).grace_days; if (Number.isInteger(g) && g >= 0 && g <= MAX_GRACE_DAYS) grace = g; } catch { /* not readable: the verify below says so */ }
  let payload;
  try { ({ payload } = await jwtVerify(token, key, { algorithms: ['EdDSA'], issuer: 'asix', currentDate: now, clockTolerance: grace * 86400 })); }
  catch (e) {
    if (e && e.code === 'ERR_JWT_EXPIRED') return none('expired', 'the license has expired and its grace period is over');
    return none('invalid', 'the license signature or claims are not valid');
  }
  const customer = typeof payload.sub === 'string' ? payload.sub : null;
  const expires = payload.exp ? new Date(payload.exp * 1000) : null;
  const base = { customer, expires_at: expires ? expires.toISOString() : null, kind: payload.kind === 'enterprise' || payload.kind === 'residential' ? payload.kind : null };
  if (typeof payload.iid !== 'string' || !payload.iid) return none('invalid', 'the license is not made for an installation', base);
  if (payload.iid !== '*') {
    if (!opts.iid) return none('invalid', 'this installation has no id to check the license against', base);
    if (payload.iid !== opts.iid) return none('wrong_install', 'the license is for a different installation', base);
  }
  if (opts.clockBack) return none('clock_error', 'the server clock is behind the last time the platform ran; set the clock right', base);
  const daysLeft = expires ? Math.floor((expires.getTime() - now.getTime()) / 86400000) : null;
  const features = Array.isArray(payload.features) ? payload.features.filter((f) => typeof f === 'string').slice(0, 50) : [];
  const inGrace = expires !== null && expires.getTime() < now.getTime();
  const graceLeft = inGrace ? Math.max(0, grace - Math.floor((now.getTime() - expires.getTime()) / 86400000)) : null;
  return { status: inGrace ? 'grace' : 'valid', ...base, days_left: daysLeft, grace_days: grace, grace_days_left: graceLeft, expiring: !inGrace && daysLeft !== null && daysLeft <= WARN_DAYS, features, limits: cleanLimits(payload.limits) };
}

module.exports = { load, cleanLimits, WARN_DAYS, DEFAULT_GRACE_DAYS, MAX_GRACE_DAYS };
