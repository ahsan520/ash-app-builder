'use strict';
// deploy/broker/asix-broker-config.sh in SIGNED mode (ASIX_CONFIG_PUBKEY_FILE set), with the REAL openssl, base64 and awk: only id, vector,
// systemctl and curl are stubs. The answers are made by the real signer (src/brokers/config-signing.js), so this holds the shell checks and the
// server-side signing to each other. Skips itself if openssl is missing.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const signing = require('../src/brokers/config-signing');

const SCRIPT = path.join(__dirname, '..', 'deploy', 'broker', 'asix-broker-config.sh');
const HAVE_OPENSSL = spawnSync('openssl', ['version']).status === 0;
const pair = () => crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1', privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
const A = pair(), B = pair();
const keyOf = (p) => signing.load({ ASIX_CONFIG_SIGNING_KEY: p.privateKey });
const nowMs = () => Date.now();

describe('asix-broker-config.sh with signed config', { skip: !HAVE_OPENSSL && 'openssl not installed' }, () => {
  let tmp, bin, log, envFile, stateDir, pubFile, scratch;
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const all = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);
  const calls = () => all().filter((c) => !c.startsWith('report') && !c.startsWith('fetch'));
  const reports = () => all().filter((c) => c.startsWith('report'));
  const env = () => fs.readFileSync(envFile, 'utf8');
  // What ASIX answers: the unsigned config (what an attacker could edit) and, optionally, the signed copy.
  const answer = (config, signed) => fs.writeFileSync(path.join(tmp, 'answer'), JSON.stringify({ success: true, config: { syslog_port: config }, interval_seconds: 300, ...(signed ? { signed } : {}) }));
  const sign = (p, name, port, at = nowMs()) => signing.signedDocument(keyOf(p), name, port, at);
  const run = (extra = {}) => spawnSync('bash', [SCRIPT], { encoding: 'utf8', stdin: 'ignore',
    env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, TMPDIR: scratch, ASIX_BROKER_ENV: envFile, ASIX_VECTOR_DIR: path.join(tmp, 'vector'), ASIX_CONFIG_STATE_DIR: stateDir, ASIX_CONFIG_WAIT_S: '2', ...extra } });
  const BASE = (pub) => 'ASIX_INGEST_URL=https://asix1:30443/v1/ingest/http\nASIX_INGEST_KEY=asix_ik_secretsecret\nASIX_BROKER_NAME=broker-1\nASIX_SYSLOG_PORT=514\nASIX_ACCEPT_CONFIG=true\n' + (pub ? 'ASIX_CONFIG_PUBKEY_FILE=' + pub + '\n' : '');

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bsig-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); envFile = path.join(tmp, 'broker.env'); stateDir = path.join(tmp, 'state'); pubFile = path.join(tmp, 'config-signing.pub'); scratch = path.join(tmp, 'scratch');
    fs.mkdirSync(bin); fs.mkdirSync(scratch); fs.mkdirSync(path.join(tmp, 'vector')); fs.writeFileSync(path.join(tmp, 'vector', 'vector.yaml'), 'sources: {}\n');
    fs.writeFileSync(pubFile, A.publicKey); fs.writeFileSync(envFile, BASE(pubFile));
    stub('id', 'echo 0');
    stub('vector', `echo "validate port=$(grep '^ASIX_SYSLOG_PORT=' '${envFile}' | cut -d= -f2)" >> '${log}'; exit 0`);
    stub('systemctl', `echo "systemctl $* port=$(grep '^ASIX_SYSLOG_PORT=' '${envFile}' | cut -d= -f2)" >> '${log}'; exit 0`);
    stub('curl', `case "$*" in\n  *broker-config/report*) echo "report $*" >> '${log}'; exit 0;;\n  *broker-config*) echo "fetch $*" >> '${log}'; cat '${tmp}/answer'; exit 0;;\n  *health*) exit 0;;\nesac`);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const untouched = (r, why) => { assert.strictEqual(r.status, 1, r.stdout + r.stderr); assert.match(r.stderr, why); assert.strictEqual(env(), BASE(pubFile), 'broker.env unchanged'); assert.deepStrictEqual(calls(), [], 'no validate, no restart'); };

  it('a good signature: applies the signed port after validate and restart, and leaves no scratch files', () => {
    answer(1514, sign(A, 'broker-1', 1514)); const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /syslog port 514 -> 1514/);
    assert.match(env(), /^ASIX_SYSLOG_PORT=1514$/m); assert.match(calls()[0], /^validate port=1514/); assert.match(calls()[1], /^systemctl restart vector/);
    assert.deepStrictEqual(fs.readdirSync(scratch), [], 'scratch folder removed');
  });
  it('acts on the SIGNED port and ignores the unsigned config (an attacker editing config gets nothing)', () => {
    answer(2514, sign(A, 'broker-1', 1514)); assert.strictEqual(run().status, 0); assert.match(env(), /^ASIX_SYSLOG_PORT=1514$/m);
  });
  it('a signed null does nothing and is not an error, whatever the unsigned config says', () => {
    answer(2514, sign(A, 'broker-1', null)); const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(env(), BASE(pubFile)); assert.deepStrictEqual(calls(), []);
  });
  it('an unsigned answer is refused when a public key is set, and says why', () => {
    answer(1514); untouched(run(), /did not sign this answer/);
  });
  it('a changed payload, a changed signature and another key are refused', () => {
    const d = sign(A, 'broker-1', 1514);
    answer(2514, { ...d, payload: Buffer.from(signing.payloadText('broker-1', 2514, nowMs())).toString('base64') }); untouched(run(), /does not match the public key/);
    const sig = Buffer.from(d.signature, 'base64'); sig[sig.length - 1] ^= 1; answer(1514, { ...d, signature: sig.toString('base64') }); untouched(run(), /does not match the public key/);
    answer(1514, sign(B, 'broker-1', 1514)); untouched(run(), /does not match the public key/);
  });
  it('garbled base64 and a missing key file are refused', () => {
    answer(1514, { ...sign(A, 'broker-1', 1514), payload: '!!!' }); untouched(run(), /did not sign|not valid base64/);
    answer(1514, sign(A, 'broker-1', 1514)); fs.rmSync(pubFile); untouched(run(), /Cannot read the config public key/);
    fs.writeFileSync(pubFile, 'nothing useful here\n'); untouched(run(), /does not match the public key/);
  });
  it('an answer made for another broker, or for none, is refused (no replay between brokers)', () => {
    answer(1514, sign(A, 'broker-2', 1514)); untouched(run(), /made for another broker/);
    answer(1514, sign(A, null, 1514)); untouched(run(), /made for another broker/);
  });
  it('a broker with no usable name accepts only an answer made for none', () => {
    fs.writeFileSync(envFile, BASE(pubFile).replace('ASIX_BROKER_NAME=broker-1', 'ASIX_BROKER_NAME=bad name!'));
    answer(1514, sign(A, 'broker-1', 1514)); let r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /another broker/);
    answer(1514, sign(A, null, 1514)); r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(env(), /^ASIX_SYSLOG_PORT=1514$/m);
  });
  it('an old or a future answer is refused (replay), one inside the limit is not, and the limit can be changed', () => {
    answer(1514, sign(A, 'broker-1', 1514, nowMs() - 3_600_000)); untouched(run(), /away from this machine's clock/);
    answer(1514, sign(A, 'broker-1', 1514, nowMs() + 3_600_000)); untouched(run(), /away from this machine's clock/);
    answer(1514, sign(A, 'broker-1', 1514, nowMs() - 300_000)); assert.strictEqual(run().status, 0);
    fs.writeFileSync(envFile, BASE(pubFile)); fs.rmSync(path.join(stateDir), { recursive: true, force: true }); fs.writeFileSync(log, '');
    answer(1514, sign(A, 'broker-1', 1514, nowMs() - 300_000)); const r = run({ ASIX_CONFIG_MAX_SKEW_S: '60' }); assert.strictEqual(r.status, 1); assert.match(r.stderr, /limit 60s/);
    assert.strictEqual(run({ ASIX_CONFIG_MAX_SKEW_S: 'abc' }).status, 2);
  });
  it('a file with two keys: either one verifies (a signing key can be replaced without a gap)', () => {
    fs.writeFileSync(pubFile, A.publicKey + B.publicKey); answer(1514, sign(B, 'broker-1', 1514)); assert.strictEqual(run().status, 0); assert.match(env(), /^ASIX_SYSLOG_PORT=1514$/m);
    fs.writeFileSync(envFile, BASE(pubFile)); answer(2514, sign(A, 'broker-1', 2514)); assert.strictEqual(run().status, 0); assert.match(env(), /^ASIX_SYSLOG_PORT=2514$/m);
  });
  it('the broker still checks the signed port itself: a signed 22 is ignored', () => {
    answer(22, sign(A, 'broker-1', 22)); untouched(run(), /never uses for syslog/);
  });
  it('it still reports what it listens on after a refusal, and the scratch folder is gone', () => {
    answer(1514); run(); assert.strictEqual(reports().length, 1); assert.match(reports()[0], /"syslog_port":514/); assert.deepStrictEqual(fs.readdirSync(scratch), []);
  });
  it('the shell checks and the JavaScript checks agree on every case above', () => {
    const cases = [['good', sign(A, 'broker-1', 1514), A.publicKey], ['other key', sign(B, 'broker-1', 1514), A.publicKey], ['other broker', sign(A, 'broker-2', 1514), A.publicKey], ['old', sign(A, 'broker-1', 1514, nowMs() - 3_600_000), A.publicKey]];
    for (const [name, doc, pub] of cases) {
      fs.writeFileSync(envFile, BASE(pubFile)); fs.writeFileSync(log, ''); fs.rmSync(stateDir, { recursive: true, force: true }); fs.writeFileSync(pubFile, pub); answer(1514, doc);
      assert.strictEqual(run().status === 0, signing.verify(pub, doc, { expectCollector: 'broker-1' }).ok, name);
    }
  });
  it('without a public key the script behaves as before: the unsigned config is used (older brokers and brokers that did not ask for signatures)', () => {
    fs.writeFileSync(envFile, BASE(null)); answer(1514); const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(env(), /^ASIX_SYSLOG_PORT=1514$/m);
  });
});
