'use strict';
// deploy/broker/asix-broker-config.sh and paused inputs: the system commands are stubs on PATH (id, vector, systemctl, curl), as in broker-config-tls-script.test.js.
// What it takes out of VECTOR_CONFIG and puts back, the checks it makes itself, validate -> restart -> health, the way back, what it reports, and the signed path
// (real signer, real openssl).
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const signing = require('../src/brokers/config-signing');
const paused = require('../src/brokers/paused');
const config = require('../src/brokers/config');

const SCRIPT = path.join(__dirname, '..', 'deploy', 'broker', 'asix-broker-config.sh');
const hasOpenssl = spawnSync('openssl', ['version']).status === 0;

describe('asix-broker-config.sh: pause and resume optional inputs', () => {
  let tmp, bin, log, envFile, stateDir, vdir;
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const state = (f, v) => fs.writeFileSync(path.join(tmp, f), v);
  const all = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);
  const calls = () => all().filter((c) => !c.startsWith('report') && !c.startsWith('fetch'));
  const reports = () => all().filter((c) => c.startsWith('report')).map((c) => JSON.parse(c.slice(c.indexOf('{'), c.lastIndexOf('}') + 1)));
  const env = () => fs.readFileSync(envFile, 'utf8');
  const answer = (p) => state('answer', JSON.stringify({ success: true, config: { syslog_port: null, tls_port: null, ...(p === undefined ? {} : { paused_inputs: p }) }, interval_seconds: 300 }));
  const run = (extra = {}) => spawnSync('bash', [SCRIPT], { encoding: 'utf8', stdin: 'ignore',
    env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_BROKER_ENV: envFile, ASIX_VECTOR_DIR: vdir, ASIX_CONFIG_STATE_DIR: stateDir, ASIX_CONFIG_WAIT_S: '2', ...extra } });
  const list = (...names) => names.map((n) => path.join(vdir, n)).join(',');
  const BASE = () => 'ASIX_INGEST_URL=https://asix1:30443/v1/ingest/http\nASIX_INGEST_KEY=asix_ik_secretsecret\nASIX_BROKER_NAME=broker-1\nASIX_SYSLOG_PORT=514\nASIX_ACCEPT_CONFIG=true\nOTHER=keep-me\n'
    + 'VECTOR_CONFIG=' + list('vector.yaml', 'vector-file.yaml', 'vector-http.yaml', 'vector-journald.yaml') + '\n';

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bpause-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); envFile = path.join(tmp, 'broker.env'); stateDir = path.join(tmp, 'state'); vdir = path.join(tmp, 'vector');
    fs.mkdirSync(bin); fs.mkdirSync(vdir);
    for (const f of ['vector.yaml', 'vector-file.yaml', 'vector-http.yaml', 'vector-journald.yaml']) fs.writeFileSync(path.join(vdir, f), 'sources: {}\n');
    fs.writeFileSync(envFile, BASE(), { mode: 0o640 }); fs.chmodSync(envFile, 0o640);
    state('answer-rc', '0'); state('report-rc', '0'); state('validate', 'ok'); state('health', 'ok'); state('restart', 'ok');
    const vars = `vc=$(grep '^VECTOR_CONFIG=' '${envFile}' | cut -d= -f2) pz=$(grep '^ASIX_INPUTS_PAUSED=' '${envFile}' | cut -d= -f2)`;
    stub('id', 'echo 0');
    stub('vector', `if [ "$1" = "validate" ]; then echo "validate files=$(($#-2)) list=$(printf '%s,' "\${@:3}" | sed 's|${vdir}/||g;s/,$//') ${vars}" >> '${log}'; [ "$(cat '${tmp}/validate')" = ok ]; exit $?; fi`);
    stub('systemctl', `echo "systemctl $* ${vars}" >> '${log}'; [ "$(cat '${tmp}/restart')" = ok ]`);
    stub('curl', `case "$*" in
  *broker-config/report*) echo "report $*" >> '${log}'; exit $(cat '${tmp}/report-rc');;
  *broker-config*) echo "fetch $*" >> '${log}'; cat '${tmp}/answer'; exit $(cat '${tmp}/answer-rc');;
  *health*) [ "$(cat '${tmp}/health')" = ok ]; exit $?;;
esac`);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const vc = () => (env().match(/^VECTOR_CONFIG=(.*)$/m) || [])[1].split(',').map((p) => path.basename(p));

  it('pausing: takes the file out of VECTOR_CONFIG, validates the NEW list before restarting, keeps the mode, a backup, and other lines', () => {
    answer('file,journald'); const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /paused inputs 'file,journald' \(now 'none'\)/);
    assert.deepStrictEqual(vc(), ['vector.yaml', 'vector-http.yaml']); assert.match(env(), /^ASIX_INPUTS_PAUSED=file,journald$/m); assert.match(env(), /^OTHER=keep-me$/m);
    assert.strictEqual(fs.statSync(envFile).mode & 0o777, 0o640); assert.strictEqual(fs.readFileSync(envFile + '.before-config', 'utf8'), BASE());
    const c = calls(); assert.strictEqual(c.length, 2); assert.match(c[0], /^validate files=2 list=vector\.yaml,vector-http\.yaml /); assert.match(c[1], /^systemctl restart vector /);
    assert.ok(!fs.existsSync(path.join(stateDir, 'config-paused-rejected'))); assert.deepStrictEqual(fs.readdirSync(tmp).filter((n) => n.startsWith('broker.env.') && n !== 'broker.env.before-config'), []);
  });
  it('the report says what is paused now, read after the change', () => {
    answer('http'); assert.strictEqual(run().status, 0);
    const [rep] = reports(); assert.strictEqual(rep.paused_inputs, 'http'); assert.strictEqual(rep.rejected_paused_inputs, '');
    assert.strictEqual(rep.collector, 'broker-1');
  });
  it('resuming with an empty list: puts back exactly what it paused, in the list, and reports an empty list', () => {
    answer('file,http'); assert.strictEqual(run().status, 0); assert.deepStrictEqual(vc(), ['vector.yaml', 'vector-journald.yaml']);
    fs.writeFileSync(log, ''); answer(''); const r = run(); assert.strictEqual(r.status, 0, r.stderr);
    assert.deepStrictEqual(vc().sort(), ['vector-file.yaml', 'vector-http.yaml', 'vector-journald.yaml', 'vector.yaml']); assert.match(env(), /^ASIX_INPUTS_PAUSED=$/m);
    const c = calls(); assert.match(c[0], /^validate files=4 /); assert.match(c[1], /^systemctl restart/); assert.strictEqual(reports().at(-1).paused_inputs, '');
  });
  it('resuming one of two: only that one comes back', () => {
    answer('file,http'); assert.strictEqual(run().status, 0); answer('http'); assert.strictEqual(run().status, 0);
    assert.deepStrictEqual(vc().sort(), ['vector-file.yaml', 'vector-journald.yaml', 'vector.yaml'].sort()); assert.match(env(), /^ASIX_INPUTS_PAUSED=http$/m);
  });
  it('the same list again, no field at all, or a broker that never paused being told "": nothing happens', () => {
    answer('file'); assert.strictEqual(run().status, 0); const after = env(); fs.writeFileSync(log, '');
    assert.strictEqual(run().status, 0); assert.deepStrictEqual(calls(), []); assert.strictEqual(env(), after);
    answer(undefined); assert.strictEqual(run().status, 0); assert.deepStrictEqual(calls(), []); assert.strictEqual(env(), after);
    fs.writeFileSync(envFile, BASE()); answer(''); assert.strictEqual(run().status, 0); assert.deepStrictEqual(calls(), []); assert.strictEqual(env(), BASE(), 'no ASIX_INPUTS_PAUSED line is invented');
  });
  it('a pause of an input this broker does not run only records the setting: no validate, no restart', () => {
    fs.writeFileSync(envFile, BASE().replace(/VECTOR_CONFIG=.*/, 'VECTOR_CONFIG=' + list('vector.yaml', 'vector-journald.yaml')));
    answer('file'); const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /Vector was not restarted/);
    assert.deepStrictEqual(calls(), []); assert.match(env(), /^ASIX_INPUTS_PAUSED=file$/m); assert.deepStrictEqual(vc(), ['vector.yaml', 'vector-journald.yaml']); assert.strictEqual(reports().at(-1).paused_inputs, 'file');
  });
  it('a custom entry in VECTOR_CONFIG is kept, and a resume does not add a file it never paused', () => {
    const extra = path.join(vdir, 'mine.yaml'); fs.writeFileSync(extra, 'sources: {}\n');
    fs.writeFileSync(envFile, BASE().replace(/VECTOR_CONFIG=.*/, 'VECTOR_CONFIG=' + list('vector.yaml') + ',' + extra));
    answer('journald'); assert.strictEqual(run().status, 0); assert.deepStrictEqual(vc(), ['vector.yaml', 'mine.yaml']);
    answer(''); assert.strictEqual(run().status, 0); assert.deepStrictEqual(vc().sort(), ['mine.yaml', 'vector-journald.yaml', 'vector.yaml'], 'journald was paused by this script, so it comes back; file and http were never listed, so they do not');
  });
  it('a failed validate puts the old broker.env back, does not restart, remembers the list and does not retry it; a different list is tried', () => {
    state('validate', 'fail'); answer('file'); let r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /does not pass 'vector validate'/);
    assert.strictEqual(env(), BASE()); assert.ok(!calls().some((c) => c.startsWith('systemctl'))); assert.strictEqual(fs.readFileSync(path.join(stateDir, 'config-paused-rejected'), 'utf8').trim(), 'file');
    assert.strictEqual(reports().at(-1).rejected_paused_inputs, 'file'); assert.strictEqual(reports().at(-1).paused_inputs, '');
    fs.writeFileSync(log, ''); r = run(); assert.strictEqual(r.status, 0); assert.match(r.stdout, /tried before and failed/); assert.deepStrictEqual(calls(), []);
    state('validate', 'ok'); answer('http'); r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(env(), /^ASIX_INPUTS_PAUSED=http$/m); assert.ok(!fs.existsSync(path.join(stateDir, 'config-paused-rejected')), 'a good apply clears it');
  });
  it('a failed restart puts the old broker.env back and restarts Vector on it', () => {
    state('restart', 'fail'); answer('file'); const r = run(); assert.strictEqual(r.status, 1); assert.strictEqual(env(), BASE());
    assert.strictEqual(calls().filter((c) => c.startsWith('systemctl')).length, 2, 'the failed restart and the one on the old settings');
  });
  it('an unhealthy Vector after the restart puts everything back and restarts again', () => {
    state('health', 'fail'); answer('file'); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /did not become healthy/); assert.strictEqual(env(), BASE());
    assert.strictEqual(calls().filter((c) => c.startsWith('systemctl')).length, 2); assert.strictEqual(fs.readFileSync(path.join(stateDir, 'config-paused-rejected'), 'utf8').trim(), 'file');
  });
  it('what it will not do whatever ASIX says: syslog, anything unknown, a repeat, junk; nothing changes', () => {
    for (const bad of ['syslog', 'file,syslog-tls', 'file,file', 'FILE', 'file;rm', 'x'.repeat(41)]) {
      state('answer', JSON.stringify({ success: true, config: { syslog_port: null, tls_port: null, paused_inputs: bad }, interval_seconds: 300 })); const r = run(); assert.strictEqual(r.status, 1, bad); assert.strictEqual(env(), BASE(), bad);
    }
    assert.deepStrictEqual(calls(), []);
    state('answer', '{"success":true,"config":{"syslog_port":null,"tls_port":null,"paused_inputs":5},"interval_seconds":300}'); assert.strictEqual(run().status, 1);
    assert.strictEqual(env(), BASE());
  });
  it('a VECTOR_CONFIG it cannot edit safely is left alone', () => {
    fs.writeFileSync(envFile, BASE().replace(/VECTOR_CONFIG=.*/, 'VECTOR_CONFIG="/etc/vector/vector.yaml,/etc/vector/a b.yaml"'));
    const before = env(); answer('file'); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /does not edit safely/); assert.strictEqual(env(), before); assert.deepStrictEqual(calls(), []);
  });
  it('a pause and a port in one answer: the port first, then the pause, each with its own validate and restart', () => {
    state('answer', JSON.stringify({ success: true, config: { syslog_port: 1514, tls_port: null, paused_inputs: 'file' }, interval_seconds: 300 })); const r = run(); assert.strictEqual(r.status, 0, r.stderr);
    assert.match(env(), /^ASIX_SYSLOG_PORT=1514$/m); assert.match(env(), /^ASIX_INPUTS_PAUSED=file$/m); assert.strictEqual(calls().filter((c) => c.startsWith('systemctl')).length, 2);
  });
  it('a broker never asked to pause sends the report it always sent, with no paused fields', () => {
    answer(undefined); assert.strictEqual(run().status, 0); const [rep] = reports(); assert.ok(!('paused_inputs' in rep)); assert.ok(!('rejected_paused_inputs' in rep));
  });
  it('every body the script can send is accepted by the server-side rules', () => {
    for (const a of ['file', 'file,http,journald', '']) { answer(a); run(); }
    state('validate', 'fail'); answer('journald'); run();
    for (const rep of reports()) { const r = config.checkReport(rep); assert.ok(!r.error, JSON.stringify(rep) + ' ' + r.error); assert.ok(paused.checkReportText(r.paused).value !== undefined); }
  });

  describe('signed answers', { skip: !hasOpenssl }, () => {
    const pair = () => crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const sign = (priv, name, pz, nowMs = Date.now()) => ({ success: true, config: { syslog_port: null, tls_port: null, paused_inputs: 'http' }, signed: signing.signedDocument({ privateKey: priv, keyId: 'k1' }, name, null, nowMs, null, pz) });
    const pubFile = (publicKey) => { const f = path.join(tmp, 'pub.pem'); fs.writeFileSync(f, publicKey.export({ type: 'spki', format: 'pem' })); return f; };
    it('acts on the list inside the verified payload and ignores the unsigned config', () => {
      const { publicKey, privateKey } = pair(); state('answer', JSON.stringify(sign(privateKey, 'broker-1', 'journald')));
      const r = run({ ASIX_CONFIG_PUBKEY_FILE: pubFile(publicKey) }); assert.strictEqual(r.status, 0, r.stderr); assert.match(env(), /^ASIX_INPUTS_PAUSED=journald$/m, 'the "http" in `config` was not read');
    });
    it('a signed payload without the field changes nothing, even when the unsigned config has one', () => {
      const { publicKey, privateKey } = pair(); state('answer', JSON.stringify(sign(privateKey, 'broker-1', undefined)));
      assert.strictEqual(run({ ASIX_CONFIG_PUBKEY_FILE: pubFile(publicKey) }).status, 0); assert.strictEqual(env(), BASE()); assert.deepStrictEqual(calls(), []);
    });
    it('a list in an answer signed for another broker, with a bad signature or unsigned is not applied', () => {
      const { publicKey, privateKey } = pair(), other = pair(); const pub = pubFile(publicKey);
      state('answer', JSON.stringify(sign(privateKey, 'broker-2', 'file'))); assert.strictEqual(run({ ASIX_CONFIG_PUBKEY_FILE: pub }).status, 1);
      state('answer', JSON.stringify(sign(other.privateKey, 'broker-1', 'file'))); assert.strictEqual(run({ ASIX_CONFIG_PUBKEY_FILE: pub }).status, 1);
      answer('file'); assert.strictEqual(run({ ASIX_CONFIG_PUBKEY_FILE: pub }).status, 1);
      assert.strictEqual(env(), BASE());
    });
  });
});
