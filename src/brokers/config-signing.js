'use strict';
// Signed broker config. The broker config pull (src/ingest/broker-config.js) used to be protected only by the HTTPS connection and the
// broker's ingestion key. With a signing key set, every answer also carries a SIGNED copy of the setting, and a broker that has been given
// the matching public key (bootstrap-broker.sh --config-pubkey) acts on the signed copy only: an answer from something that is not ASIX, or
// one edited on the way, is refused. Nothing changes for a broker without a public key, or for an ASIX without a signing key.
//
// What is signed: the bytes of one small JSON text, `{"v":1,"collector":"broker-1"|null,"issued_at":<epoch seconds>,"syslog_port":N|null}`
// (this key order, no spaces), sent base64-encoded so the broker verifies exactly the bytes that were signed.
//   - collector: the broker the answer was made for, so an answer for one broker cannot be replayed to another
//   - issued_at: the broker refuses an answer more than ASIX_CONFIG_MAX_SKEW_S (default 600) seconds away from its own clock
// Algorithm: ECDSA on P-256 with SHA-256, DER signature, base64. A broker needs only `openssl dgst -sha256 -verify` for it.
// The private key comes from ASIX_CONFIG_SIGNING_KEY (PEM; the Kubernetes Secret asix-config-signing, see scripts/deploy/make-config-signing-key.sh).
// It protects against a spoofed or tampered answer and against anything that can write the database but cannot read that Secret. It does NOT
// protect against someone who can read the Secret: the key lives on ASIX (an offline signing key is not built).

const crypto = require('crypto');

const ALG = 'ecdsa-p256-sha256';
let cached = { src: undefined, value: null };

const keyIdOf = (publicKey) => crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 12);

// Reads the key from the environment. Returns null when no key is set, { error } when one is set but unusable (never thrown: the pull keeps
// answering, unsigned, and a broker that requires signatures refuses it), or { privateKey, publicPem, keyId }.
function load(env = process.env) {
  const raw = env.ASIX_CONFIG_SIGNING_KEY;
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  try {
    const privateKey = crypto.createPrivateKey(raw.includes('\\n') && !raw.includes('\n') ? raw.replace(/\\n/g, '\n') : raw);
    if (privateKey.asymmetricKeyType !== 'ec' || privateKey.asymmetricKeyDetails.namedCurve !== 'prime256v1') return { error: 'ASIX_CONFIG_SIGNING_KEY must be an EC P-256 (prime256v1) private key' };
    const publicKey = crypto.createPublicKey(privateKey);
    return { privateKey, publicPem: publicKey.export({ type: 'spki', format: 'pem' }), keyId: keyIdOf(publicKey) };
  } catch (e) {
    return { error: 'ASIX_CONFIG_SIGNING_KEY is set but is not a readable PEM private key' };
  }
}

// The key of this process, read once per value of the variable.
function current(env = process.env) {
  const src = env.ASIX_CONFIG_SIGNING_KEY;
  if (cached.src !== src || cached.value === undefined) { cached = { src, value: load(env) }; if (cached.value && cached.value.error) console.error('Broker config signing:', cached.value.error); }
  return cached.value;
}
const reset = () => { cached = { src: undefined, value: null }; };

// What the portal shows: whether answers are signed and with which key. The public key is public; the private key never leaves `load`.
function status(env = process.env) {
  const k = current(env);
  if (!k) return { enabled: false, key_id: null, public_key: null, error: null };
  if (k.error) return { enabled: false, key_id: null, public_key: null, error: k.error };
  return { enabled: true, key_id: k.keyId, public_key: k.publicPem, error: null };
}

const NAME_RE = /^[A-Za-z0-9._:-]{1,100}$/;
// The exact text that is signed. `collector` is the validated broker name or null; `port` a number or null.
function payloadText(collector, port, nowMs) {
  return JSON.stringify({ v: 1, collector: collector !== null && NAME_RE.test(collector) ? collector : null, issued_at: Math.floor(nowMs / 1000), syslog_port: port === undefined ? null : port });
}

function signedDocument(key, collector, port, nowMs = Date.now()) {
  const payload = Buffer.from(payloadText(collector, port, nowMs), 'utf8');
  const signature = crypto.sign('sha256', payload, key.privateKey);   // EC key: DER-encoded ECDSA
  return { v: 1, alg: ALG, key_id: key.keyId, payload: payload.toString('base64'), signature: signature.toString('base64') };
}

// The broker's checks, written in JavaScript so the tests can hold the shell script to the same rules (deploy/broker/asix-broker-config.sh does
// them with openssl). `publicPems` is one PEM or several (a key being replaced is trusted next to the new one). Returns { ok, port, reason }.
function verify(publicPems, doc, { expectCollector = null, nowMs = Date.now(), maxSkewS = 600 } = {}) {
  const fail = (reason) => ({ ok: false, reason });
  if (!doc || typeof doc.payload !== 'string' || typeof doc.signature !== 'string') return fail('not signed');
  const payload = Buffer.from(doc.payload, 'base64'), sig = Buffer.from(doc.signature, 'base64');
  const pems = (Array.isArray(publicPems) ? publicPems : [publicPems]).flatMap((p) => String(p).match(/-----BEGIN PUBLIC KEY-----[^-]+-----END PUBLIC KEY-----/g) || []);
  if (!pems.length) return fail('no public key');
  const good = pems.some((p) => { try { return crypto.verify('sha256', payload, crypto.createPublicKey(p), sig); } catch (e) { return false; } });
  if (!good) return fail('bad signature');
  let p; try { p = JSON.parse(payload.toString('utf8')); } catch (e) { return fail('unreadable payload'); }
  if (!p || p.v !== 1) return fail('unknown version');
  if (p.collector !== expectCollector) return fail('made for another broker');
  if (!Number.isInteger(p.issued_at) || Math.abs(nowMs / 1000 - p.issued_at) > maxSkewS) return fail('outside the allowed clock difference');
  if (p.syslog_port !== null && !Number.isInteger(p.syslog_port)) return fail('unreadable port');
  return { ok: true, port: p.syslog_port };
}

module.exports = { ALG, load, current, reset, status, keyIdOf, payloadText, signedDocument, verify };
