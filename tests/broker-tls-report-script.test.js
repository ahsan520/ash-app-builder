'use strict';
// What deploy/broker/asix-broker-config.sh tells ASIX about its syslog-over-TLS listener (tls_port, rejected_tls_port in the report). The system commands are
// stubs on PATH (id, vector, systemctl, curl) as in broker-config-tls-script.test.js; the report body is what the stub curl was given.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const config = require('../src/brokers/config');

const SCRIPT = path.join(__dirname, '..', 'deploy', 'broker', 'asix-broker-config.sh');

describe('asix-broker-config.sh: the TLS part of the report', () => {
  let tmp, bin, log, envFile, stateDir;
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const state = (f, v) => fs.writeFileSync(path.join(tmp, f), v);
  const all = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);
  const reports = () => all().filter((c) => c.startsWith('report')).map((c) => JSON.parse(/--data (\{.*?\})/.exec(c)[1]));
  const answer = (syslog, tls) => state('answer', JSON.stringify({ success: true, config: { syslog_port: syslog, tls_port: tls }, interval_seconds: 300 }));
  const run = () => spawnSync('bash', [SCRIPT], { encoding: 'utf8', stdin: 'ignore',
    env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_BROKER_ENV: envFile, ASIX_VECTOR_DIR: path.join(tmp, 'vector'), ASIX_CONFIG_STATE_DIR: stateDir, ASIX_CONFIG_WAIT_S: '2' } });
  const BASE = 'ASIX_INGEST_URL=https://asix1:30443/v1/ingest/http\nASIX_INGEST_KEY=asix_ik_secretsecret\nASIX_BROKER_NAME=broker-1\nASIX_SYSLOG_PORT=514\nASIX_ACCEPT_CONFIG=true\nASIX_SYSLOG_TLS_PORT=6514\n';

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'btlsrep-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); envFile = path.join(tmp, 'broker.env'); stateDir = path.join(tmp, 'state');
    fs.mkdirSync(bin); fs.mkdirSync(path.join(tmp, 'vector'));
    fs.writeFileSync(path.join(tmp, 'vector', 'vector.yaml'), 'sources: {}\n'); fs.writeFileSync(path.join(tmp, 'vector', 'vector-tls.yaml'), 'sources: {}\n');
    fs.writeFileSync(envFile, BASE);
    answer(null, null); state('validate', 'ok'); state('health', 'ok'); state('restart', 'ok');
    stub('id', 'echo 0');
    stub('vector', `if [ "$1" = "validate" ]; then [ "$(cat '${tmp}/validate')" = ok ]; exit $?; fi`);
    stub('systemctl', `[ "$(cat '${tmp}/restart')" = ok ]`);
    stub('curl', `case "$*" in
  *broker-config/report*) echo "report $*" >> '${log}'; exit 0;;
  *broker-config*) cat '${tmp}/answer'; exit 0;;
  *health*) [ "$(cat '${tmp}/health')" = ok ]; exit $?;;
esac`);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('a broker with a TLS listener reports its port, and nothing rejected', () => {
    assert.strictEqual(run().status, 0);
    const r = reports(); assert.strictEqual(r.length, 1); assert.strictEqual(r[0].tls_port, 6514); assert.strictEqual(r[0].rejected_tls_port, null);
  });
  it('the port is read AFTER a change: 6514 moved to 6515 is reported as 6515', () => {
    answer(null, 6515); assert.strictEqual(run().status, 0); assert.strictEqual(reports()[0].tls_port, 6515);
  });
  it('a TLS port that failed validate is put back, reported as the OLD port, and the rejected one is reported', () => {
    answer(null, 6515); state('validate', 'fail');
    assert.strictEqual(run().status, 1);
    let r = reports()[0]; assert.strictEqual(r.tls_port, 6514); assert.strictEqual(r.rejected_tls_port, 6515);
    fs.writeFileSync(log, ''); assert.strictEqual(run().status, 0, 'not retried: the broker says so and exits clean');
    r = reports()[0]; assert.strictEqual(r.tls_port, 6514); assert.strictEqual(r.rejected_tls_port, 6515, 'still remembered on the next run');
    fs.writeFileSync(log, ''); state('validate', 'ok'); answer(null, 6516); assert.strictEqual(run().status, 0);
    r = reports()[0]; assert.strictEqual(r.tls_port, 6516); assert.strictEqual(r.rejected_tls_port, null, 'a later success clears it');
  });
  it('a broker with no TLS listener reports tls_port null (no variable, or the variable without the file)', () => {
    fs.writeFileSync(envFile, BASE.replace('ASIX_SYSLOG_TLS_PORT=6514\n', '')); assert.strictEqual(run().status, 0);
    assert.strictEqual(reports()[0].tls_port, null);
    fs.writeFileSync(log, ''); fs.writeFileSync(envFile, BASE); fs.rmSync(path.join(tmp, 'vector', 'vector-tls.yaml')); assert.strictEqual(run().status, 0);
    assert.strictEqual(reports()[0].tls_port, null, 'the variable is there but the TLS file is not: no listener');
  });
  it('a garbled TLS port in broker.env or in the state file is reported as null, never passed on', () => {
    fs.writeFileSync(envFile, BASE.replace('ASIX_SYSLOG_TLS_PORT=6514', 'ASIX_SYSLOG_TLS_PORT=65x14')); run();
    assert.strictEqual(reports()[0].tls_port, null);
    fs.writeFileSync(log, ''); fs.writeFileSync(envFile, BASE); fs.mkdirSync(stateDir); fs.writeFileSync(path.join(stateDir, 'config-tls-rejected'), '99999\n'); run();
    assert.strictEqual(reports()[0].rejected_tls_port, null, '99999 is not a port');
  });
  it('every body the script can send is accepted by the server-side rules, and the stored values are what the page expects', () => {
    for (const t of [6514, null]) {
      fs.writeFileSync(log, ''); fs.writeFileSync(envFile, t === null ? BASE.replace('ASIX_SYSLOG_TLS_PORT=6514\n', '') : BASE); run();
      const rep = config.checkReport(reports()[0]); assert.ok(!rep.error, rep.error); assert.strictEqual(rep.tls, t === null ? 0 : 6514, 'no listener is stored as 0');
    }
  });
});
