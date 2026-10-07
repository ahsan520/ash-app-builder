'use strict';
// AES-256-GCM encryption for channel secrets (SMTP password, webhook URLs/tokens).
// Key: NOTIFY_ENCRYPTION_KEY (base64, 32 bytes) from the k8s secret 'asix-notify-secret'.
const crypto = require('crypto');

function key() {
  const raw = process.env.NOTIFY_ENCRYPTION_KEY;
  const k = raw ? Buffer.from(raw, 'base64') : null;
  if (!k || k.length !== 32) throw Object.assign(new Error('NOTIFY_ENCRYPTION_KEY is not configured (base64, 32 bytes)'), { code: 'NO_KEY' });
  return k;
}
const configured = () => { try { key(); return true; } catch { return false; } };

function encrypt(obj) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return ['v1', iv, c.getAuthTag(), ct].map((x) => (Buffer.isBuffer(x) ? x.toString('base64url') : x)).join('.');
}
function decrypt(s) {
  const [v, iv, tag, ct] = String(s).split('.');
  if (v !== 'v1' || !iv || !tag || !ct) throw new Error('Unrecognised secret format');
  const d = crypto.createDecipheriv('aes-256-gcm', key(), Buffer.from(iv, 'base64url'));
  d.setAuthTag(Buffer.from(tag, 'base64url'));
  return JSON.parse(Buffer.concat([d.update(Buffer.from(ct, 'base64url')), d.final()]).toString('utf8'));
}
module.exports = { encrypt, decrypt, configured };
