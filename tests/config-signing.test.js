'use strict';
// Signed broker config (src/brokers/config-signing.js): the key rules, what is signed, the checks a broker makes (the same rules the shell
// script applies, see tests/broker-config-signed-script.test.js), and the two routes that carry it.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const express = require('express');
const { execFileSync } = require('child_process');
const signing = require('../src/brokers/config-signing');

const pair = (curve = 'prime256v1') => crypto.generateKeyPairSync('ec', { namedCurve: curve, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
const A = pair(), B = pair();
const keyOf = (p) => signing.load({ ASIX_CONFIG_SIGNING_KEY: p.privateKey });
const NOW = 1_760_000_000_000;

describe('loading the signing key', () => {
  it('no key set is not an error: answers stay unsigned', () => {
    assert.strictEqual(signing.load({}), null); assert.strictEqual(signing.load({ ASIX_CONFIG_SIGNING_KEY: '  ' }), null);
    assert.deepStrictEqual(signing.status({}), { enabled: false, key_id: null, public_key: null, error: null }); signing.reset();
  });
  it('reads a PKCS8 or SEC1 P-256 key and gives its public half and a 12 hex key id', () => {
    const k = keyOf(A); assert.ok(k.privateKey && /^[0-9a-f]{12}$/.test(k.keyId)); assert.strictEqual(k.publicPem, A.publicKey);
    const sec1 = crypto.createPrivateKey(A.privateKey).export({ type: 'sec1', format: 'pem' });
    assert.strictEqual(signing.load({ ASIX_CONFIG_SIGNING_KEY: sec1 }).keyId, k.keyId);
  });
  it('accepts the key with literal \\n instead of newlines (some secret stores)', () => {
    assert.strictEqual(signing.load({ ASIX_CONFIG_SIGNING_KEY: A.privateKey.replace(/\n/g, '\\n') }).keyId, keyOf(A).keyId);
  });
  it('reports garbage, an RSA key and another curve as unusable, without throwing and without the key', () => {
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
    for (const bad of ['not a key', rsa, pair('secp384r1').privateKey]) {
      const k = signing.load({ ASIX_CONFIG_SIGNING_KEY: bad }); assert.ok(k.error && !k.privateKey, bad.slice(0, 20));
      const st = signing.status({ ASIX_CONFIG_SIGNING_KEY: bad }); assert.strictEqual(st.enabled, false); assert.ok(st.error); assert.ok(!JSON.stringify(st).includes('PRIVATE'));
    }
    signing.reset();
  });
  it('status() shows the public key and never the private one', () => {
    const st = signing.status({ ASIX_CONFIG_SIGNING_KEY: A.privateKey }); signing.reset();
    assert.strictEqual(st.enabled, true); assert.strictEqual(st.public_key, A.publicKey); assert.ok(!JSON.stringify(st).includes('PRIVATE'));
  });
  it('the key id equals what openssl computes from the public key file (what bootstrap-broker.sh prints)', () => {
    const out = execFileSync('bash', ['-c', 'openssl pkey -pubin -outform DER | openssl dgst -sha256 -hex | sed "s/^.*= //" | cut -c1-12'], { input: A.publicKey, encoding: 'utf8' }).trim();
    assert.strictEqual(out, keyOf(A).keyId);
  });
});

describe('what is signed and how it is checked', () => {
  it('the payload text has a fixed shape and key order', () => {
    assert.strictEqual(signing.payloadText('broker-1', 1514, NOW), '{"v":1,"collector":"broker-1","issued_at":1760000000,"syslog_port":1514}');
    assert.strictEqual(signing.payloadText(null, null, NOW), '{"v":1,"collector":null,"issued_at":1760000000,"syslog_port":null}');
    assert.strictEqual(signing.payloadText('bad"name', 1, NOW).includes('bad'), false, 'an odd name is never put in the text');
  });
  it('the text signed with a TLS port, and verify refuses an unreadable one', () => {
    assert.strictEqual(signing.payloadText('broker-1', 1514, NOW, 6514), '{"v":1,"collector":"broker-1","issued_at":1760000000,"syslog_port":1514,"tls_port":6514}');
    assert.strictEqual(signing.payloadText('broker-1', null, NOW, null), '{"v":1,"collector":"broker-1","issued_at":1760000000,"syslog_port":null,"tls_port":null}');
    assert.deepStrictEqual(signing.verify(A.publicKey, signing.signedDocument(keyOf(A), 'broker-1', 1514, NOW, 6514), { expectCollector: 'broker-1', nowMs: NOW }), { ok: true, port: 1514, tls_port: 6514 });
    refused('unreadable port', A.publicKey, signing.signedDocument(keyOf(A), 'broker-1', 1514, NOW, 'x'));
  });
  it('a good answer verifies and gives back the port (or null)', () => {
    for (const port of [1514, null]) {
      const d = signing.signedDocument(keyOf(A), 'broker-1', port, NOW);
      assert.deepStrictEqual(Object.keys(d), ['v', 'alg', 'key_id', 'payload', 'signature']);
      assert.deepStrictEqual(signing.verify(A.publicKey, d, { expectCollector: 'broker-1', nowMs: NOW }), { ok: true, port, tls_port: null });
    }
  });
  const refused = (why, pub, doc, opts) => assert.deepStrictEqual(signing.verify(pub, doc, { expectCollector: 'broker-1', nowMs: NOW, ...opts }), { ok: false, reason: why });
  it('refuses: unsigned, another key, a changed payload, a changed signature', () => {
    const d = signing.signedDocument(keyOf(A), 'broker-1', 1514, NOW);
    refused('not signed', A.publicKey, undefined); refused('not signed', A.publicKey, { config: { syslog_port: 1514 } });
    refused('bad signature', B.publicKey, d);
    const changed = Buffer.from(signing.payloadText('broker-1', 2514, NOW)).toString('base64'); refused('bad signature', A.publicKey, { ...d, payload: changed });
    const sig = Buffer.from(d.signature, 'base64'); sig[sig.length - 1] ^= 1; refused('bad signature', A.publicKey, { ...d, signature: sig.toString('base64') });
    refused('no public key', '', d);
  });
  it('refuses an answer made for another broker (or for none), and one far from the clock either way', () => {
    refused('made for another broker', A.publicKey, signing.signedDocument(keyOf(A), 'broker-2', 1514, NOW));
    refused('made for another broker', A.publicKey, signing.signedDocument(keyOf(A), null, 1514, NOW));
    assert.strictEqual(signing.verify(A.publicKey, signing.signedDocument(keyOf(A), null, 1514, NOW), { expectCollector: null, nowMs: NOW }).ok, true);
    const d = signing.signedDocument(keyOf(A), 'broker-1', 1514, NOW);
    assert.strictEqual(signing.verify(A.publicKey, d, { expectCollector: 'broker-1', nowMs: NOW + 600_000 }).ok, true, 'exactly at the limit is fine');
    refused('outside the allowed clock difference', A.publicKey, d, { nowMs: NOW + 601_000 }); refused('outside the allowed clock difference', A.publicKey, d, { nowMs: NOW - 601_000 });
    assert.strictEqual(signing.verify(A.publicKey, d, { expectCollector: 'broker-1', nowMs: NOW + 3_000_000, maxSkewS: 4000 }).ok, true);
  });
  it('several trusted keys: any one matches, so a key can be replaced without a gap', () => {
    const d = signing.signedDocument(keyOf(B), 'broker-1', 1514, NOW);
    assert.strictEqual(signing.verify(A.publicKey + B.publicKey, d, { expectCollector: 'broker-1', nowMs: NOW }).ok, true);
    assert.strictEqual(signing.verify(A.publicKey, d, { expectCollector: 'broker-1', nowMs: NOW }).ok, false);
  });
});

describe('the routes carry the signed copy', () => {
  let srv, base, stored = null, storedTls = null;
  const saved = process.env.ASIX_CONFIG_SIGNING_KEY;
  before(() => {
    const dbPath = require.resolve('../src/db');
    require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: {
      withTenant: async (tenant, fn) => fn({ query: async (sql) => (/^SELECT/.test(sql) ? { rows: [{ syslog_port: stored, tls_port: storedTls }] } : { rows: [] }) }),
      query: async () => ({ rows: [{ id: 'k1', tenant_id: 't1', name: 'broker-1', platform: 'linux' }] }),
    } };
    const shared = require('../src/gateway/shared');
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: require('../src/db'), guarded: () => [(req, res, next) => { req.tenant_id = 't1'; req.user_id = 'u1'; next(); }] };
    const app = express(); app.use(require('../src/ingest/broker-config').router); app.use(express.json()); app.use(require('../src/gateway/routes/broker-config'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); if (saved === undefined) delete process.env.ASIX_CONFIG_SIGNING_KEY; else process.env.ASIX_CONFIG_SIGNING_KEY = saved; signing.reset(); });
  beforeEach(() => { delete process.env.ASIX_CONFIG_SIGNING_KEY; signing.reset(); stored = null; storedTls = null; });
  const KEY = 'Bearer asix_ik_' + 'a'.repeat(40);
  const pull = async (q = '') => (await fetch(base + '/v1/ingest/broker-config' + q, { headers: { authorization: KEY } })).json();

  it('without a signing key the answer is exactly what it was before', async () => {
    stored = 1514; const r = await pull('?collector=broker-1'); assert.deepStrictEqual(r, { success: true, config: { syslog_port: 1514, tls_port: null }, interval_seconds: 300 });
  });
  it('with a signing key the answer adds a signed copy of the same setting, bound to the name sent', async () => {
    process.env.ASIX_CONFIG_SIGNING_KEY = A.privateKey; stored = 1514;
    const r = await pull('?collector=broker-1'); assert.deepStrictEqual(r.config, { syslog_port: 1514, tls_port: null });
    assert.deepStrictEqual(signing.verify(A.publicKey, r.signed, { expectCollector: 'broker-1' }), { ok: true, port: 1514, tls_port: null });
    const none = await pull(); assert.deepStrictEqual(signing.verify(A.publicKey, none.signed, { expectCollector: null }), { ok: true, port: 1514, tls_port: null }, 'no name sent: made for none');
    assert.strictEqual(signing.verify(A.publicKey, none.signed, { expectCollector: 'broker-1' }).ok, false);
    stored = null; assert.deepStrictEqual(signing.verify(A.publicKey, (await pull('?collector=broker-1')).signed, { expectCollector: 'broker-1' }), { ok: true, port: null, tls_port: null });
  });
  it('the signed copy carries the TLS port, and an answer from before it reads as none', async () => {
    process.env.ASIX_CONFIG_SIGNING_KEY = A.privateKey; stored = 1514; storedTls = 6514;
    const r = await pull('?collector=broker-1'); assert.deepStrictEqual(r.config, { syslog_port: 1514, tls_port: 6514 });
    assert.deepStrictEqual(signing.verify(A.publicKey, r.signed, { expectCollector: 'broker-1' }), { ok: true, port: 1514, tls_port: 6514 });
    assert.match(Buffer.from(r.signed.payload, 'base64').toString(), /"syslog_port":1514,"tls_port":6514\}$/, 'appended after the syslog port, last');
    const old = signing.signedDocument(keyOf(A), 'broker-1', 1514, Date.now()); assert.doesNotMatch(Buffer.from(old.payload, 'base64').toString(), /tls_port/);
    assert.deepStrictEqual(signing.verify(A.publicKey, old, { expectCollector: 'broker-1' }), { ok: true, port: 1514, tls_port: null });
    storedTls = null; assert.deepStrictEqual(signing.verify(A.publicKey, (await pull('?collector=broker-1')).signed, { expectCollector: 'broker-1' }), { ok: true, port: 1514, tls_port: null });
  });
  it('an unusable key leaves the answer unsigned and the pull working', async () => {
    process.env.ASIX_CONFIG_SIGNING_KEY = 'garbage'; stored = 1514; const r = await pull('?collector=broker-1');
    assert.strictEqual(r.success, true); assert.strictEqual(r.config.syslog_port, 1514); assert.strictEqual(r.signed, undefined);
  });
  it('the portal route says whether answers are signed, with the public key only', async () => {
    let r = await (await fetch(base + '/v1/broker-config')).json(); assert.deepStrictEqual(r.config.signing, { enabled: false, key_id: null, public_key: null, error: null });
    process.env.ASIX_CONFIG_SIGNING_KEY = A.privateKey; r = await (await fetch(base + '/v1/broker-config')).json();
    assert.strictEqual(r.config.signing.enabled, true); assert.strictEqual(r.config.signing.public_key, A.publicKey); assert.strictEqual(r.config.signing.key_id, keyOf(A).keyId);
    assert.ok(!JSON.stringify(r).includes('PRIVATE')); assert.ok(Array.isArray(r.config.reserved_ports), 'the rest of the view is unchanged');
  });
});
