'use strict';
// What deploy/broker/asix-broker-config.sh tells ASIX about checking signatures (the `signature` field of its report), with the REAL openssl,
// base64 and awk; only id, vector, systemctl and curl are stubs, and the answers are made by the real signer (src/brokers/config-signing.js).
// The report body is read from the arguments the curl stub was given, so this holds the script and the server-side list of values
// (src/brokers/config.js) to each other: every value the script can send is accepted by checkReport.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const signing = require('../src/brokers/config-signing');
const config = require('../src/brokers/config');

const SCRIPT = path.join(__dirname, '..', 'deploy', 'broker', 'asix-broker-config.sh');
const HAVE_OPENSSL = spawnSync('openssl', ['version']).status === 0;
const pair = () => crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1', privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
const A = pair(), B = pair();
const keyOf = (p) => signing.load({ ASIX_CONFIG_SIGNING_KEY: p.privateKey });

describe('the signature field in the broker\'s report', { skip: !HAVE_OPENSSL && 'openssl not installed' }, () => {
  let tmp, bin, log, envFile, stateDir, pubFile, scratch, failFetch;
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const lines = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);
  const bodies = () => lines().filter((c) => c.startsWith('report ')).map((c) => JSON.parse(/--data (\{[^ ]*\})/.exec(c)[1]));
  const env = () => fs.readFileSync(envFile, 'utf8');
  const answer = (config_, signed) => fs.writeFileSync(path.join(tmp, 'answer'), JSON.stringify({ success: true, config: { syslog_port: config_ }, interval_seconds: 300, ...(signed ? { signed } : {}) }));
  const sign = (p, name, port, at = Date.now()) => signing.signedDocument(keyOf(p), name, port, at);
  const run = (extra = {}, PATH) => spawnSync('/bin/bash', [SCRIPT], { encoding: 'utf8', stdin: 'ignore',
    env: { PATH: PATH || bin + ':' + process.env.PATH, HOME: tmp, TMPDIR: scratch, ASIX_BROKER_ENV: envFile, ASIX_VECTOR_DIR: path.join(tmp, 'vector'), ASIX_CONFIG_STATE_DIR: stateDir, ASIX_CONFIG_WAIT_S: '2', ...extra } });
  const BASE = (pub) => 'ASIX_INGEST_URL=https://asix1:30443/v1/ingest/http\nASIX_INGEST_KEY=asix_ik_secretsecret\nASIX_BROKER_NAME=broker-1\nASIX_SYSLOG_PORT=514\nASIX_ACCEPT_CONFIG=true\n' + (pub ? 'ASIX_CONFIG_PUBKEY_FILE=' + pub + '\n' : '');
  const reported = (r) => { assert.ok(r.status === 0 || r.status === 1, r.stdout + r.stderr); const b = bodies(); assert.strictEqual(b.length, 1, 'one report per run: ' + JSON.stringify(b)); return b[0]; };

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bsigrep-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); envFile = path.join(tmp, 'broker.env'); stateDir = path.join(tmp, 'state'); pubFile = path.join(tmp, 'config-signing.pub'); scratch = path.join(tmp, 'scratch'); failFetch = path.join(tmp, 'failfetch');
    fs.mkdirSync(bin); fs.mkdirSync(scratch); fs.mkdirSync(path.join(tmp, 'vector')); fs.writeFileSync(path.join(tmp, 'vector', 'vector.yaml'), 'sources: {}\n');
    fs.writeFileSync(pubFile, A.publicKey); fs.writeFileSync(envFile, BASE(pubFile));
    stub('id', 'echo 0');
    stub('vector', `echo "validate" >> '${log}'; [ -e '${tmp}/vectorfail' ] && exit 1; exit 0`);
    stub('systemctl', `echo "systemctl $*" >> '${log}'; exit 0`);
    stub('curl', `case "$*" in\n  *broker-config/report*) echo "report $*" >> '${log}'; exit 0;;\n  *broker-config*) [ -e '${failFetch}' ] && exit 22; cat '${tmp}/answer'; exit 0;;\n  *health*) exit 0;;\nesac`);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('no public key: off (the broker checks nothing), and the plain answer is still used as before', () => {
    fs.writeFileSync(envFile, BASE(null)); answer(1514);
    const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(env(), /^ASIX_SYSLOG_PORT=1514$/m);
    assert.deepStrictEqual(bodies(), [{ collector: 'broker-1', syslog_port: 1514, rejected_port: null, signature: 'off' }]);
  });
  it('a good signature: ok, with the new port reported alongside', () => {
    answer(1514, sign(A, 'broker-1', 1514)); const r = run(); assert.strictEqual(r.status, 0, r.stderr);
    assert.deepStrictEqual(bodies(), [{ collector: 'broker-1', syslog_port: 1514, rejected_port: null, signature: 'ok' }]);
  });
  it('a signed null (nothing to change) is still a checked answer: ok', () => {
    answer(2514, sign(A, 'broker-1', null)); const r = run(); assert.strictEqual(r.status, 0, r.stderr);
    assert.strictEqual(reported(r).signature, 'ok'); assert.match(env(), /^ASIX_SYSLOG_PORT=514$/m);
  });
  it('a good signature but a port the broker\'s Vector rejects: signature ok, rejected port reported (the two are independent)', () => {
    fs.writeFileSync(path.join(tmp, 'vectorfail'), ''); answer(1514, sign(A, 'broker-1', 1514));
    const r = run(); assert.strictEqual(r.status, 1); assert.deepStrictEqual(bodies(), [{ collector: 'broker-1', syslog_port: 514, rejected_port: 1514, signature: 'ok' }]);
  });
  it('an unsigned answer: unsigned, and nothing changed', () => {
    answer(1514); const r = run(); assert.strictEqual(r.status, 1); assert.strictEqual(reported(r).signature, 'unsigned'); assert.strictEqual(env(), BASE(pubFile));
  });
  it('a changed payload, a changed signature and another key: bad_signature', () => {
    const d = sign(A, 'broker-1', 1514);
    answer(2514, { ...d, payload: Buffer.from(signing.payloadText('broker-1', 2514, Date.now())).toString('base64') }); assert.strictEqual(reported(run()).signature, 'bad_signature');
    fs.rmSync(log); const sig = Buffer.from(d.signature, 'base64'); sig[sig.length - 1] ^= 1; answer(1514, { ...d, signature: sig.toString('base64') }); assert.strictEqual(reported(run()).signature, 'bad_signature');
    fs.rmSync(log); answer(1514, sign(B, 'broker-1', 1514)); assert.strictEqual(reported(run()).signature, 'bad_signature');
    assert.strictEqual(env(), BASE(pubFile));
  });
  it('base64 that does not decode, or a signed text in another format: bad_format; a text far too long too', () => {
    answer(1514, { ...sign(A, 'broker-1', 1514), payload: 'A' }); assert.strictEqual(reported(run()).signature, 'bad_format');
    const odd = '{"v":2,"collector":"broker-1","issued_at":' + Math.floor(Date.now() / 1000) + ',"syslog_port":1514}';
    fs.rmSync(log); answer(1514, { ...sign(A, 'broker-1', 1514), payload: Buffer.from(odd).toString('base64'), signature: crypto.createSign('SHA256').update(odd).sign(A.privateKey).toString('base64') });
    assert.strictEqual(reported(run()).signature, 'bad_format');
    fs.rmSync(log); answer(1514, { ...sign(A, 'broker-1', 1514), payload: 'A'.repeat(2400) }); assert.strictEqual(reported(run()).signature, 'bad_format');
    assert.strictEqual(env(), BASE(pubFile));
  });
  it('an answer made for another broker, or for none: wrong_broker', () => {
    answer(1514, sign(A, 'broker-2', 1514)); assert.strictEqual(reported(run()).signature, 'wrong_broker');
    fs.rmSync(log); answer(1514, sign(A, null, 1514)); assert.strictEqual(reported(run()).signature, 'wrong_broker');
  });
  it('an old or a future answer: clock_skew', () => {
    answer(1514, sign(A, 'broker-1', 1514, Date.now() - 3600e3)); assert.strictEqual(reported(run()).signature, 'clock_skew');
    fs.rmSync(log); answer(1514, sign(A, 'broker-1', 1514, Date.now() + 3600e3)); assert.strictEqual(reported(run()).signature, 'clock_skew');
    fs.rmSync(log); answer(1514, sign(A, 'broker-1', 1514, Date.now() - 3600e3)); assert.strictEqual(reported(run({ ASIX_CONFIG_MAX_SKEW_S: '7200' })).signature, 'ok', 'inside a raised limit it is ok');
  });
  it('a public key file that cannot be read: no_key_file', () => {
    answer(1514, sign(A, 'broker-1', 1514)); fs.rmSync(pubFile); assert.strictEqual(reported(run()).signature, 'no_key_file');
  });
  it('openssl missing: no_openssl (checked with a PATH that has everything the script needs except openssl)', () => {
    const only = path.join(tmp, 'noopenssl'); fs.mkdirSync(only);
    for (const t of ['bash', 'sed', 'tr', 'cut', 'base64', 'awk', 'grep', 'date', 'mktemp', 'rm', 'cat', 'seq', 'sleep', 'mv', 'cp', 'head', 'wc', 'dirname', 'basename', 'sort', 'tail', 'env', 'printf', 'true', 'test'])
      { const w = spawnSync('which', [t], { encoding: 'utf8' }).stdout.trim(); if (w) fs.symlinkSync(w, path.join(only, t)); }
    for (const t of ['id', 'vector', 'systemctl', 'curl']) fs.symlinkSync(path.join(bin, t), path.join(only, t));
    assert.ok(!fs.existsSync(path.join(only, 'openssl')));
    answer(1514, sign(A, 'broker-1', 1514)); assert.strictEqual(reported(run({}, only)).signature, 'no_openssl');
    assert.strictEqual(env(), BASE(pubFile));
  });
  it('could not fetch an answer at all: unchecked (it has a key but checked nothing), not ok', () => {
    fs.writeFileSync(failFetch, ''); const r = run(); assert.strictEqual(r.status, 1); assert.strictEqual(reported(r).signature, 'unchecked');
  });
  it('every value the script can send is one the server accepts (the lists agree)', () => {
    const src = fs.readFileSync(SCRIPT, 'utf8');
    const sent = new Set([...src.matchAll(/SIG="?([a-z_]+)"?/g)].map((m) => m[1]));
    for (const v of sent) assert.ok(config.SIGNATURE_VALUES.includes(v), v + ' is sent by the script but not accepted by the server');
    for (const v of config.SIGNATURE_VALUES) assert.ok(sent.has(v), v + ' is accepted by the server but never sent by the script');
    for (const v of sent) assert.ok(config.checkReport({ collector: 'broker-1', syslog_port: 514, signature: v }).signature === v);
  });
});
