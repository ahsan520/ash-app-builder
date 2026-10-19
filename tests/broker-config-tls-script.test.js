'use strict';
// deploy/broker/asix-broker-config.sh and the syslog-over-TLS port: the system commands are stubs on PATH (id, vector, systemctl, curl), as in
// broker-config-script.test.js. What it acts on (only a broker that already has a TLS listener), the checks it makes itself, validate -> restart -> health,
// the way back, and how it behaves next to the syslog port in the same run. The signed path uses the real signer and the real openssl.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const signing = require('../src/brokers/config-signing');

const SCRIPT = path.join(__dirname, '..', 'deploy', 'broker', 'asix-broker-config.sh');
const hasOpenssl = spawnSync('openssl', ['version']).status === 0;

describe('asix-broker-config.sh: syslog-over-TLS port', () => {
  let tmp, bin, log, envFile, stateDir;
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const state = (f, v) => fs.writeFileSync(path.join(tmp, f), v);
  const all = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);
  const calls = () => all().filter((c) => !c.startsWith('report') && !c.startsWith('fetch'));
  const env = () => fs.readFileSync(envFile, 'utf8');
  const answer = (syslog, tls) => state('answer', JSON.stringify({ success: true, config: { syslog_port: syslog, tls_port: tls }, interval_seconds: 300 }));
  const run = (extra = {}) => spawnSync('bash', [SCRIPT], { encoding: 'utf8', stdin: 'ignore',
    env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_BROKER_ENV: envFile, ASIX_VECTOR_DIR: path.join(tmp, 'vector'), ASIX_CONFIG_STATE_DIR: stateDir, ASIX_CONFIG_WAIT_S: '2', ...extra } });
  const BASE = 'ASIX_INGEST_URL=https://asix1:30443/v1/ingest/http\nASIX_INGEST_KEY=asix_ik_secretsecret\nASIX_BROKER_NAME=broker-1\nASIX_SYSLOG_PORT=514\nASIX_ACCEPT_CONFIG=true\nASIX_SYSLOG_TLS_PORT=6514\nOTHER=keep-me\n';
  const withTls = (n) => BASE.replace('ASIX_SYSLOG_TLS_PORT=6514', 'ASIX_SYSLOG_TLS_PORT=' + n);

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bcfgtls-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); envFile = path.join(tmp, 'broker.env'); stateDir = path.join(tmp, 'state');
    fs.mkdirSync(bin); fs.mkdirSync(path.join(tmp, 'vector'));
    fs.writeFileSync(path.join(tmp, 'vector', 'vector.yaml'), 'sources: {}\n'); fs.writeFileSync(path.join(tmp, 'vector', 'vector-tls.yaml'), 'sources: {}\n');
    fs.writeFileSync(envFile, BASE, { mode: 0o640 }); fs.chmodSync(envFile, 0o640);
    answer(null, 6515); state('answer-rc', '0'); state('report-rc', '0'); state('validate', 'ok'); state('health', 'ok'); state('restart', 'ok');
    const ports = `port=$(grep '^ASIX_SYSLOG_PORT=' '${envFile}' | cut -d= -f2) tls=$(grep '^ASIX_SYSLOG_TLS_PORT=' '${envFile}' | cut -d= -f2)`;
    stub('id', 'echo 0');
    stub('vector', `if [ "$1" = "validate" ]; then echo "validate ${ports} files=$#" >> '${log}'; [ "$(cat '${tmp}/validate')" = ok ]; exit $?; fi`);
    stub('systemctl', `echo "systemctl $* ${ports}" >> '${log}'; [ "$(cat '${tmp}/restart')" = ok ]`);
    stub('curl', `case "$*" in
  *broker-config/report*) echo "report $*" >> '${log}'; exit $(cat '${tmp}/report-rc');;
  *broker-config*) echo "fetch $*" >> '${log}'; cat '${tmp}/answer'; exit $(cat '${tmp}/answer-rc');;
  *health*) [ "$(cat '${tmp}/health')" = ok ]; exit $?;;
esac`);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('a new TLS port: edits only that line, keeps the mode and a backup, validates with the TLS file BEFORE restarting', () => {
    const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /syslog-over-TLS port 6514 -> 6515/); assert.match(r.stdout, /Open 6515\/tcp/);
    assert.strictEqual(env(), BASE.replace('ASIX_SYSLOG_TLS_PORT=6514', 'ASIX_SYSLOG_TLS_PORT=6515'));
    assert.strictEqual(fs.statSync(envFile).mode & 0o777, 0o640); assert.strictEqual(fs.readFileSync(envFile + '.before-config', 'utf8'), BASE);
    const c = calls(); assert.strictEqual(c.length, 2); assert.match(c[0], /^validate port=514 tls=6515 files=4/, 'vector-tls.yaml is part of the check'); assert.match(c[1], /^systemctl restart vector port=514 tls=6515/);
    assert.ok(!fs.existsSync(path.join(stateDir, 'config-tls-rejected')));
    assert.deepStrictEqual(fs.readdirSync(tmp).filter((n) => n.startsWith('broker.env.') && n !== 'broker.env.before-config'), [], 'no temp file left behind');
  });
  it('null, an answer without the field, or the port already in use: nothing happens', () => {
    answer(null, null); assert.strictEqual(run().status, 0);
    state('answer', '{"success":true,"config":{"syslog_port":null},"interval_seconds":300}'); assert.strictEqual(run().status, 0);
    answer(null, 6514); assert.strictEqual(run().status, 0);
    assert.strictEqual(env(), BASE); assert.deepStrictEqual(calls(), []);
  });
  it('a broker WITHOUT a TLS listener ignores the port with a note: no change, no restart, exit 0', () => {
    fs.writeFileSync(envFile, BASE.replace('ASIX_SYSLOG_TLS_PORT=6514\n', ''));
    let r = run(); assert.strictEqual(r.status, 0); assert.match(r.stdout, /no TLS listener/); assert.strictEqual(env(), BASE.replace('ASIX_SYSLOG_TLS_PORT=6514\n', '')); assert.deepStrictEqual(calls(), []);
    fs.writeFileSync(envFile, BASE); fs.rmSync(path.join(tmp, 'vector', 'vector-tls.yaml'));   // the variable is there but the TLS file is not
    r = run(); assert.strictEqual(r.status, 0); assert.match(r.stdout, /no TLS listener/); assert.strictEqual(env(), BASE); assert.deepStrictEqual(calls(), []);
  });
  it('checks the port itself and ignores anything unsafe, with no change and no restart', () => {
    const body = (v) => state('answer', `{"success":true,"config":{"syslog_port":null,"tls_port":${v}}}`);
    for (const v of ['22', '443', '8686', '30443', '70000', '0', '00514', '99999999']) { body(v); const r = run(); assert.strictEqual(r.status, 1, v); assert.strictEqual(env(), BASE, v); }
    body('514'); const same = run(); assert.strictEqual(same.status, 1); assert.match(same.stderr, /syslog port this broker uses/); assert.strictEqual(env(), BASE);
    body('"6515; reboot"'); assert.strictEqual(run().status, 1, 'neither a port nor null: nothing changed'); assert.strictEqual(env(), BASE);
    assert.deepStrictEqual(calls(), []);
  });
  it('validate fails: old settings back, port remembered, no restart, exit 1; not retried until ASIX asks for another port', () => {
    state('validate', 'bad'); let r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /does not pass 'vector validate' with syslog-over-TLS port 6515/); assert.strictEqual(env(), BASE);
    assert.strictEqual(fs.readFileSync(path.join(stateDir, 'config-tls-rejected'), 'utf8').trim(), '6515'); assert.ok(!fs.existsSync(path.join(stateDir, 'config-rejected')), 'the syslog port is not blamed');
    assert.ok(!calls().some((c) => c.startsWith('systemctl')));
    state('validate', 'ok'); const n = calls().length; r = run(); assert.strictEqual(r.status, 0); assert.match(r.stdout, /tried before/); assert.strictEqual(calls().length, n); assert.strictEqual(env(), BASE);
    answer(null, 6516); r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(env(), /^ASIX_SYSLOG_TLS_PORT=6516$/m); assert.ok(!fs.existsSync(path.join(stateDir, 'config-tls-rejected')), 'a success clears the memory');
  });
  it('restart fails or Vector never gets healthy: old settings back AND Vector restarted on them', () => {
    state('restart', 'bad'); let r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /restart vector failed with syslog-over-TLS port 6515/); assert.strictEqual(env(), BASE);
    assert.strictEqual(calls().filter((c) => c.startsWith('systemctl')).length, 2); assert.match(calls().filter((c) => c.startsWith('systemctl'))[1], /tls=6514/);
    fs.rmSync(log); fs.rmSync(path.join(stateDir, 'config-tls-rejected')); state('restart', 'ok'); state('health', 'bad');
    r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /did not become healthy within 2s on syslog-over-TLS port 6515/); assert.strictEqual(env(), BASE);
    assert.strictEqual(calls().filter((c) => c.startsWith('systemctl')).length, 2); assert.match(calls().filter((c) => c.startsWith('systemctl'))[1], /tls=6514/);
  });
  it('both ports in one answer: the syslog port first, each validated and restarted on its own', () => {
    answer(1514, 6515); const r = run(); assert.strictEqual(r.status, 0, r.stderr);
    assert.strictEqual(env(), BASE.replace('ASIX_SYSLOG_PORT=514', 'ASIX_SYSLOG_PORT=1514').replace('ASIX_SYSLOG_TLS_PORT=6514', 'ASIX_SYSLOG_TLS_PORT=6515'));
    const c = calls(); assert.strictEqual(c.length, 4);
    assert.match(c[0], /^validate port=1514 tls=6514/); assert.match(c[1], /^systemctl restart vector port=1514 tls=6514/); assert.match(c[2], /^validate port=1514 tls=6515/); assert.match(c[3], /^systemctl restart vector port=1514 tls=6515/);
  });
  it('a rejected TLS port does not undo the syslog port that was applied, and the exit says something failed', () => {
    answer(1514, 6515); const real = fs.readFileSync(path.join(bin, 'vector'), 'utf8');
    stub('vector', `if [ "$1" = "validate" ] && grep -q '^ASIX_SYSLOG_TLS_PORT=6515' '${envFile}'; then exit 1; fi\n` + real.split('\n').slice(1).join('\n'));
    const r = run(); assert.strictEqual(r.status, 1); assert.match(env(), /^ASIX_SYSLOG_PORT=1514$/m); assert.match(env(), /^ASIX_SYSLOG_TLS_PORT=6514$/m);
    assert.ok(!fs.existsSync(path.join(stateDir, 'config-rejected'))); assert.strictEqual(fs.readFileSync(path.join(stateDir, 'config-tls-rejected'), 'utf8').trim(), '6515');
  });
  it('a syslog port remembered as failed does not stop the TLS port', () => {
    fs.mkdirSync(stateDir); fs.writeFileSync(path.join(stateDir, 'config-rejected'), '1514\n'); answer(1514, 6515);
    const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /Syslog port 1514 was tried before/); assert.match(env(), /^ASIX_SYSLOG_PORT=514$/m); assert.match(env(), /^ASIX_SYSLOG_TLS_PORT=6515$/m);
  });
  it('a TLS port equal to the syslog port the broker ends up with is refused after the syslog port was applied', () => {
    answer(1514, 1514); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /syslog port this broker uses/);
    assert.match(env(), /^ASIX_SYSLOG_PORT=1514$/m); assert.match(env(), /^ASIX_SYSLOG_TLS_PORT=6514$/m);
  });
  it('reports the syslog port in use and the TLS port of its listener', () => {
    run(); const rep = all().filter((c) => c.startsWith('report')); assert.strictEqual(rep.length, 1);
    assert.deepStrictEqual(JSON.parse(/--data (\{.*?\})/.exec(rep[0])[1]), { collector: 'broker-1', syslog_port: 514, rejected_port: null, signature: 'off', tls_port: 6515, rejected_tls_port: null });   // the default answer moves 6514 to 6515: the report is read AFTER the change
  });

  describe('signed answers', { skip: !hasOpenssl }, () => {
    const pair = () => crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const sign = (priv, name, syslog, tls, nowMs = Date.now()) => ({ success: true, config: { syslog_port: 9, tls_port: 9 }, signed: signing.signedDocument({ privateKey: priv, keyId: 'k1' }, name, syslog, nowMs, tls) });
    it('acts on the TLS port inside the verified payload and ignores the unsigned config', () => {
      const { publicKey, privateKey } = pair(); const pub = path.join(tmp, 'pub.pem'); fs.writeFileSync(pub, publicKey.export({ type: 'spki', format: 'pem' }));
      state('answer', JSON.stringify(sign(privateKey, 'broker-1', null, 6515)));
      const r = run({ ASIX_CONFIG_PUBKEY_FILE: pub }); assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(env(), BASE.replace('ASIX_SYSLOG_TLS_PORT=6514', 'ASIX_SYSLOG_TLS_PORT=6515'), 'the 9 and 9 in `config` were not read');
    });
    it('a payload from before the TLS port (or a null one) changes nothing about TLS', () => {
      const { publicKey, privateKey } = pair(); const pub = path.join(tmp, 'pub.pem'); fs.writeFileSync(pub, publicKey.export({ type: 'spki', format: 'pem' }));
      state('answer', JSON.stringify(sign(privateKey, 'broker-1', null, undefined))); assert.strictEqual(run({ ASIX_CONFIG_PUBKEY_FILE: pub }).status, 0);
      state('answer', JSON.stringify(sign(privateKey, 'broker-1', null, null))); assert.strictEqual(run({ ASIX_CONFIG_PUBKEY_FILE: pub }).status, 0);
      assert.strictEqual(env(), BASE); assert.deepStrictEqual(calls(), []);
    });
    it('a TLS port in an answer signed for another broker, or with a bad signature, is not applied', () => {
      const { publicKey, privateKey } = pair(); const other = pair(); const pub = path.join(tmp, 'pub.pem'); fs.writeFileSync(pub, publicKey.export({ type: 'spki', format: 'pem' }));
      state('answer', JSON.stringify(sign(privateKey, 'broker-2', null, 6515))); assert.strictEqual(run({ ASIX_CONFIG_PUBKEY_FILE: pub }).status, 1);
      state('answer', JSON.stringify(sign(other.privateKey, 'broker-1', null, 6515))); assert.strictEqual(run({ ASIX_CONFIG_PUBKEY_FILE: pub }).status, 1);
      assert.strictEqual(env(), BASE); assert.deepStrictEqual(calls(), []);
    });
  });
});
