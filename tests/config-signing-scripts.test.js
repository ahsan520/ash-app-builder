'use strict';
// The two shell scripts around signed config, with real openssl: scripts/deploy/make-config-signing-key.sh (k3s stubbed) and the argument
// checks of scripts/deploy/bootstrap-broker.sh --config-pubkey (they refuse before anything is installed, so this needs no root). The install
// itself is checked statically. Skips itself if openssl is missing.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const signing = require('../src/brokers/config-signing');

const ROOT = path.join(__dirname, '..');
const MAKE = path.join(ROOT, 'scripts', 'deploy', 'make-config-signing-key.sh');
const BOOT = path.join(ROOT, 'scripts', 'deploy', 'bootstrap-broker.sh');
const HAVE_OPENSSL = spawnSync('openssl', ['version']).status === 0;
const pubOf = (curve) => crypto.generateKeyPairSync('ec', { namedCurve: curve, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } }).publicKey;

describe('config signing scripts', { skip: !HAVE_OPENSSL && 'openssl not installed' }, () => {
  let tmp, bin, log;
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const run = (script, args, extra = {}) => spawnSync('bash', [script, ...args], { encoding: 'utf8', stdin: 'ignore', env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ...extra } });
  const calls = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'csig-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'k3s.log'); fs.mkdirSync(bin); stub('id', 'echo 0');
    stub('k3s', `echo "k3s $*" >> '${log}'; if [ "$4" = get ] && [ "$5" = secret ]; then [ -f '${tmp}/secret-exists' ]; exit $?; fi; exit 0`); });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  describe('make-config-signing-key.sh', () => {
    it('makes an owner-only P-256 private key and a public key that match, and prints the key id ASIX will show', () => {
      const d = path.join(tmp, 'keys'), r = run(MAKE, ['--dir', d]); assert.strictEqual(r.status, 0, r.stderr);
      const key = fs.readFileSync(path.join(d, 'config-signing.key'), 'utf8'), pub = fs.readFileSync(path.join(d, 'config-signing.pub'), 'utf8');
      assert.strictEqual(fs.statSync(path.join(d, 'config-signing.key')).mode & 0o777, 0o600);
      const k = signing.load({ ASIX_CONFIG_SIGNING_KEY: key }); assert.ok(k.privateKey, 'ASIX can load it'); assert.strictEqual(k.publicPem, pub, 'the public file is the other half');
      assert.ok(r.stdout.includes('Key id: ' + k.keyId)); assert.deepStrictEqual(calls(), [], 'without --apply nothing is sent to the cluster'); assert.match(r.stdout, /Not applied/);
      const doc = signing.signedDocument(k, 'broker-1', 1514); assert.strictEqual(signing.verify(pub, doc, { expectCollector: 'broker-1' }).ok, true);
    });
    it('never overwrites an existing key', () => {
      const d = path.join(tmp, 'keys'); assert.strictEqual(run(MAKE, ['--dir', d]).status, 0); const before = fs.readFileSync(path.join(d, 'config-signing.key'), 'utf8');
      const r = run(MAKE, ['--dir', d]); assert.strictEqual(r.status, 1); assert.match(r.stderr, /already exists/); assert.strictEqual(fs.readFileSync(path.join(d, 'config-signing.key'), 'utf8'), before);
    });
    it('--apply stores the private key as the Secret and restarts the API', () => {
      const d = path.join(tmp, 'keys'), r = run(MAKE, ['--dir', d, '--apply']); assert.strictEqual(r.status, 0, r.stderr);
      const c = calls(); assert.ok(c.some((x) => /create secret generic asix-config-signing --from-file=ASIX_CONFIG_SIGNING_KEY=.*config-signing\.key/.test(x)), c.join('\n'));
      assert.ok(c.some((x) => /rollout restart deployment\/asix-api/.test(x))); assert.ok(c.every((x) => x.includes('-n asix-platform')));
    });
    it('--apply refuses to replace an existing Secret (brokers pin the old public key) and makes no key files', () => {
      fs.writeFileSync(path.join(tmp, 'secret-exists'), ''); const d = path.join(tmp, 'keys'), r = run(MAKE, ['--dir', d, '--apply']);
      assert.strictEqual(r.status, 1); assert.match(r.stderr, /already exists/); assert.ok(!fs.existsSync(path.join(d, 'config-signing.key'))); assert.ok(!calls().some((x) => /create secret|rollout/.test(x)));
    });
    it('rejects unknown options', () => { assert.strictEqual(run(MAKE, ['--bogus']).status, 2); });
  });

  describe('bootstrap-broker.sh --config-pubkey (refusals happen before anything is installed)', () => {
    const base = ['--url', 'https://asix1:30443/v1/ingest/http', '--key', 'asix_ik_' + 'a'.repeat(30), '--name', 'broker-1'];
    const file = (name, text) => { const f = path.join(tmp, name); fs.writeFileSync(f, text); return f; };
    it('needs --accept-config', () => { const r = run(BOOT, [...base, '--config-pubkey', file('p.pub', pubOf('prime256v1'))]); assert.strictEqual(r.status, 2); assert.match(r.stderr, /only makes sense with --accept-config/); });
    it('needs a readable file with a PEM public key in it', () => {
      let r = run(BOOT, [...base, '--accept-config', '--config-pubkey', path.join(tmp, 'missing.pub')]); assert.strictEqual(r.status, 2); assert.match(r.stderr, /Cannot read/);
      r = run(BOOT, [...base, '--accept-config', '--config-pubkey', file('empty.pub', 'hello\n')]); assert.strictEqual(r.status, 2); assert.match(r.stderr, /no PEM public key/);
    });
    it('refuses a key that is not P-256 (a P-384 or RSA key would make the broker refuse everything), also when it is the second key in the file', () => {
      const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } }).publicKey;
      for (const f of [pubOf('secp384r1'), rsa, pubOf('prime256v1') + pubOf('secp384r1')]) { const r = run(BOOT, [...base, '--accept-config', '--config-pubkey', file('k.pub', f)]); assert.strictEqual(r.status, 2, f.slice(0, 40)); assert.match(r.stderr, /not an EC P-256 public key/); }
    });
    it('accepts a good key and goes on to the install steps (stopped here by Vector not being installed)', () => {
      const r = run(BOOT, [...base, '--no-install', '--accept-config', '--config-pubkey', file('p.pub', pubOf('prime256v1'))], { PATH: bin + ':/usr/bin:/bin' });
      assert.ok(!/config-pubkey|P-256|PEM/.test(r.stderr), r.stderr); assert.match(r.stdout + r.stderr, /Vector|vector/);
    });
    it('the install writes the file, the env line, prints the key id, and a re-run without the flag removes both', () => {
      const s = fs.readFileSync(BOT_PATH(), 'utf8');
      assert.match(s, /install -m 644 "\$CONFIG_PUBKEY" \/etc\/asix-broker\/config-signing\.pub/); assert.match(s, /echo "ASIX_CONFIG_PUBKEY_FILE=\/etc\/asix-broker\/config-signing\.pub"/);
      assert.match(s, /rm -f \/etc\/asix-broker\/config-signing\.pub/); assert.match(s, /trusting config signing key/);
      const inGroup = s.slice(s.indexOf('{\n  echo "ASIX_INGEST_URL'), s.indexOf('} > /etc/asix-broker/broker.env'));
      assert.ok(!/trusting config signing key/.test(inGroup), 'nothing printed inside the block that is written to broker.env');
    });
  });
});
function BOT_PATH() { return BOOT_FILE; }
const BOOT_FILE = path.join(__dirname, '..', 'scripts', 'deploy', 'bootstrap-broker.sh');
