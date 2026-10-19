'use strict';
// deploy/broker/asix-broker-config.sh with every system command replaced by a stub on PATH (id, vector, systemctl, curl): what it
// asks ASIX, the checks it makes itself, the order validate -> restart -> health, and the way back when something fails.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, '..', 'deploy', 'broker', 'asix-broker-config.sh');

describe('asix-broker-config.sh', () => {
  let tmp, bin, log, envFile, stateDir;
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const state = (f, v) => fs.writeFileSync(path.join(tmp, f), v);
  const all = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);
  const calls = () => all().filter((c) => !c.startsWith('report'));          // the report to ASIX is checked on its own below
  const reports = () => all().filter((c) => c.startsWith('report')).map((c) => ({ line: c, body: JSON.parse(/--data (\{.*?\})/.exec(c)[1]) }));
  const env = () => fs.readFileSync(envFile, 'utf8');
  const asks = (port) => state('answer', JSON.stringify({ success: true, config: { syslog_port: port }, interval_seconds: 300 }));
  const run = (extra = {}) => spawnSync('bash', [SCRIPT], { encoding: 'utf8', stdin: 'ignore',
    env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_BROKER_ENV: envFile, ASIX_VECTOR_DIR: path.join(tmp, 'vector'), ASIX_CONFIG_STATE_DIR: stateDir, ASIX_CONFIG_WAIT_S: '2', ...extra } });
  const BASE = 'ASIX_INGEST_URL=https://asix1:30443/v1/ingest/http\nASIX_INGEST_KEY=asix_ik_secretsecret\nASIX_BROKER_NAME=broker-1\nASIX_SYSLOG_PORT=514\nASIX_ACCEPT_CONFIG=true\nOTHER=keep-me\n';

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bcfg-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); envFile = path.join(tmp, 'broker.env'); stateDir = path.join(tmp, 'state');
    fs.mkdirSync(bin); fs.mkdirSync(path.join(tmp, 'vector')); fs.writeFileSync(path.join(tmp, 'vector', 'vector.yaml'), 'sources: {}\n');
    fs.writeFileSync(envFile, BASE, { mode: 0o640 }); fs.chmodSync(envFile, 0o640);
    asks(1514); state('answer-rc', '0'); state('report-rc', '0'); state('validate', 'ok'); state('health', 'ok'); state('restart', 'ok');
    stub('id', 'echo 0');
    stub('vector', `if [ "$1" = "validate" ]; then echo "validate port=$(grep '^ASIX_SYSLOG_PORT=' '${envFile}' | cut -d= -f2) \\$*" >> '${log}'; [ "$(cat '${tmp}/validate')" = ok ]; exit $?; fi`);
    stub('systemctl', `echo "systemctl $* port=$(grep '^ASIX_SYSLOG_PORT=' '${envFile}' | cut -d= -f2)" >> '${log}'; [ "$(cat '${tmp}/restart')" = ok ]`);
    stub('curl', `case "$*" in
  *broker-config/report*) echo "report $*" >> '${log}'; exit $(cat '${tmp}/report-rc');;
  *broker-config*) echo "fetch $*" >> '${log}'; cat '${tmp}/answer'; exit $(cat '${tmp}/answer-rc');;
  *health*) [ "$(cat '${tmp}/health')" = ok ]; exit $?;;
esac`);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('refuses when not root or when broker.env is missing, and touches nothing', () => {
    stub('id', 'echo 1000'); assert.strictEqual(run().status, 1); assert.deepStrictEqual(all(), []);
    stub('id', 'echo 0'); fs.rmSync(envFile); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /bootstrap-broker\.sh/);
  });
  it('does nothing, and does not even ask ASIX, when the broker did not opt in', () => {
    fs.writeFileSync(envFile, BASE.replace('ASIX_ACCEPT_CONFIG=true\n', ''));
    const r = run(); assert.strictEqual(r.status, 0); assert.match(r.stdout, /not set up to accept config/); assert.deepStrictEqual(all(), []); assert.strictEqual(env(), BASE.replace('ASIX_ACCEPT_CONFIG=true\n', ''));
    fs.writeFileSync(envFile, BASE.replace('=true', '=yes')); assert.deepStrictEqual((run(), all()), []);
  });
  it('asks with its own key at the broker-config URL derived from the ingest URL', () => {
    run(); const f = calls().find((c) => c.startsWith('fetch'));
    assert.match(f, /Authorization: Bearer asix_ik_secretsecret/); assert.match(f, /https:\/\/asix1:30443\/v1\/ingest\/broker-config/);
  });
  it('null from ASIX, or the port already in use: nothing happens', () => {
    asks(null); let r = run(); assert.strictEqual(r.status, 0); assert.strictEqual(env(), BASE);
    asks(514); r = run(); assert.strictEqual(r.status, 0); assert.strictEqual(env(), BASE);
    assert.deepStrictEqual(calls().filter((c) => !c.startsWith('fetch')), []);
  });
  it('a new port: edits only that line, keeps owner-only mode and a backup, validates BEFORE restarting, then restarts', () => {
    const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /syslog port 514 -> 1514/);
    assert.strictEqual(env(), BASE.replace('ASIX_SYSLOG_PORT=514', 'ASIX_SYSLOG_PORT=1514'));
    assert.strictEqual(fs.statSync(envFile).mode & 0o777, 0o640); assert.strictEqual(fs.readFileSync(envFile + '.before-config', 'utf8'), BASE);
    const c = calls().filter((x) => !x.startsWith('fetch')); assert.match(c[0], /^validate port=1514/); assert.match(c[1], /^systemctl restart vector port=1514/); assert.strictEqual(c.length, 2);
    assert.ok(!fs.existsSync(path.join(stateDir, 'config-rejected')));
    assert.deepStrictEqual(fs.readdirSync(tmp).filter((n) => n.startsWith('broker.env.') && n !== 'broker.env.before-config'), [], 'no temp file left behind');
  });
  it('adds the line when broker.env had no port (the default 514 was in use)', () => {
    fs.writeFileSync(envFile, BASE.replace('ASIX_SYSLOG_PORT=514\n', '')); const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(env(), /^ASIX_SYSLOG_PORT=1514$/m);
  });
  it('checks the port itself and ignores anything unsafe, with no change and no restart', () => {
    const body = (v) => state('answer', `{"success":true,"config":{"syslog_port":${v}}}`);
    for (const v of ['22', '443', '8686', '30443', '70000', '0', '00514', '99999999']) { body(v); const r = run(); assert.strictEqual(r.status, 1, v); assert.strictEqual(env(), BASE, v); }
    state('answer', '{"success":true}'); assert.strictEqual(run().status, 1);
    state('answer', '<html>proxy error</html>'); assert.strictEqual(run().status, 1);
    state('answer', '{"config":{"syslog_port":"1514; reboot"}}'); assert.strictEqual(run().status, 1);
    assert.deepStrictEqual(calls().filter((c) => !c.startsWith('fetch')), []);
    asks(1514); fs.writeFileSync(envFile, BASE + 'ASIX_SYSLOG_TLS_PORT=1514\n'); const t = run(); assert.strictEqual(t.status, 1); assert.match(t.stderr, /TLS port/); assert.strictEqual(env(), BASE + 'ASIX_SYSLOG_TLS_PORT=1514\n');
  });
  it('cannot reach ASIX: exit 1, nothing changed', () => {
    state('answer-rc', '22'); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /Could not fetch/); assert.strictEqual(env(), BASE); assert.deepStrictEqual(calls().filter((c) => !c.startsWith('fetch')), []);
  });
  it('a config that fails vector validate: old env put back, Vector never restarted, port remembered and not retried', () => {
    state('validate', 'bad'); let r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /does not pass 'vector validate'/);
    assert.strictEqual(env(), BASE); assert.ok(!calls().some((c) => c.startsWith('systemctl')));
    assert.strictEqual(fs.readFileSync(path.join(stateDir, 'config-rejected'), 'utf8').trim(), '1514');
    const before = calls().length; r = run(); assert.strictEqual(r.status, 0); assert.match(r.stdout, /tried before and failed/); assert.strictEqual(calls().length, before + 1, 'only the fetch ran');
    asks(2514); state('validate', 'ok'); r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(env(), /^ASIX_SYSLOG_PORT=2514$/m);
    assert.ok(!fs.existsSync(path.join(stateDir, 'config-rejected')), 'a later success clears it');
  });
  it('Vector not healthy after the restart: old env put back and Vector restarted on it, port remembered', () => {
    state('health', 'bad'); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /did not become healthy/);
    assert.strictEqual(env(), BASE);
    const restarts = calls().filter((c) => c.startsWith('systemctl restart')); assert.strictEqual(restarts.length, 2);
    assert.match(restarts[0], /port=1514/); assert.match(restarts[1], /port=514/, 'the second restart already runs on the old settings');
    assert.strictEqual(fs.readFileSync(path.join(stateDir, 'config-rejected'), 'utf8').trim(), '1514');
  });
  it('the restart itself failing is handled the same way', () => {
    state('restart', 'bad'); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /restart vector failed/); assert.strictEqual(env(), BASE);
    assert.ok(fs.existsSync(path.join(stateDir, 'config-rejected')));
  });
  it('tells ASIX what it listens on after a change: the new port, nothing rejected, with its own key at /report', () => {
    const r = run(); assert.strictEqual(r.status, 0, r.stderr);
    const rep = reports(); assert.strictEqual(rep.length, 1);
    assert.deepStrictEqual(rep[0].body, { collector: 'broker-1', syslog_port: 1514, rejected_port: null, signature: 'off' }, 'read from broker.env after the change');
    assert.match(rep[0].line, /Authorization: Bearer asix_ik_secretsecret/); assert.match(rep[0].line, /Content-Type: application\/json/);
    assert.match(rep[0].line, /-X POST/); assert.match(rep[0].line, /https:\/\/asix1:30443\/v1\/ingest\/broker-config\/report/);
    assert.ok(all().findIndex((c) => c.startsWith('report')) > all().findIndex((c) => c.startsWith('systemctl restart')), 'the report comes after the restart');
  });
  it('reports on every run that asked, also when there is nothing to change (null, or the port already in use)', () => {
    asks(null); run(); asks(514); run();
    assert.deepStrictEqual(reports().map((x) => x.body), [{ collector: 'broker-1', syslog_port: 514, rejected_port: null, signature: 'off' }, { collector: 'broker-1', syslog_port: 514, rejected_port: null, signature: 'off' }]);
    assert.strictEqual(env(), BASE);
  });
  it('a port it rejected is reported as rejected, with the old port still in use, and again on the next run that does not retry it', () => {
    state('validate', 'bad'); run(); run();
    assert.deepStrictEqual(reports().map((x) => x.body), [{ collector: 'broker-1', syslog_port: 514, rejected_port: 1514, signature: 'off' }, { collector: 'broker-1', syslog_port: 514, rejected_port: 1514, signature: 'off' }]);
    asks(2514); state('validate', 'ok'); run();
    assert.deepStrictEqual(reports()[2].body, { collector: 'broker-1', syslog_port: 2514, rejected_port: null, signature: 'off' }, 'a later success clears the rejected port');
  });
  it('after an unhealthy restart is put back, the report says the old port and the rejected one', () => {
    state('health', 'bad'); run(); const rep = reports(); assert.strictEqual(rep.length, 1);
    assert.deepStrictEqual(rep[0].body, { collector: 'broker-1', syslog_port: 514, rejected_port: 1514, signature: 'off' });
  });
  it('reports even when it ignored an unsafe answer, but nothing when it never reached ASIX\'s answer for another reason than the fetch', () => {
    state('answer', '{"success":true,"config":{"syslog_port":22}}'); assert.strictEqual(run().status, 1);
    assert.deepStrictEqual(reports().map((x) => x.body), [{ collector: 'broker-1', syslog_port: 514, rejected_port: null, signature: 'off' }]);
  });
  it('a report that cannot be sent changes nothing: same exit status, same env, no retry loop', () => {
    state('report-rc', '22'); let r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(env(), /^ASIX_SYSLOG_PORT=1514$/m); assert.strictEqual(reports().length, 1);
    state('answer-rc', '22'); r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /Could not fetch/);
    assert.ok(!/report/.test(r.stderr), 'a failed report prints nothing');
  });
  it('the broker name in the report is cleaned like the heartbeat does and a missing name means no report', () => {
    fs.writeFileSync(envFile, BASE.replace('ASIX_BROKER_NAME=broker-1', `ASIX_BROKER_NAME='bro"ker-1'`)); run();
    assert.strictEqual(reports()[0].body.collector, 'broker-1');
    fs.writeFileSync(envFile, BASE.replace('ASIX_BROKER_NAME=broker-1\n', '')); const before = reports().length; run(); assert.strictEqual(reports().length, before, 'no name, no report');
  });
  it('the default port 514 is reported when broker.env has no port line, and a garbled port line is not reported', () => {
    asks(null); fs.writeFileSync(envFile, BASE.replace('ASIX_SYSLOG_PORT=514\n', '')); run();
    assert.deepStrictEqual(reports()[0].body, { collector: 'broker-1', syslog_port: 514, rejected_port: null, signature: 'off' });
    fs.writeFileSync(envFile, BASE.replace('ASIX_SYSLOG_PORT=514', 'ASIX_SYSLOG_PORT=abc')); const before = reports().length; run(); assert.strictEqual(reports().length, before);
  });
  it('is syntactically valid bash and ships with its service and timer', () => {
    assert.strictEqual(spawnSync('bash', ['-n', SCRIPT]).status, 0);
    const dir = path.dirname(SCRIPT);
    assert.match(fs.readFileSync(path.join(dir, 'asix-broker-config.service'), 'utf8'), /ExecStart=\/usr\/local\/lib\/asix-broker\/asix-broker-config\.sh/);
    assert.match(fs.readFileSync(path.join(dir, 'asix-broker-config.timer'), 'utf8'), /OnUnitActiveSec=5min/);
  });
  it('bootstrap-broker.sh installs it only with --accept-config and writes the opt-in line only then', () => {
    const b = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'deploy', 'bootstrap-broker.sh'), 'utf8');
    assert.match(b, /--accept-config\) ACCEPT_CONFIG=1/); assert.match(b, /\[ "\$ACCEPT_CONFIG" -eq 0 \] \|\| echo "ASIX_ACCEPT_CONFIG=true"/);
    assert.match(b, /if \[ "\$ACCEPT_CONFIG" -eq 1 \]; then\n\s+install -m 755 "\$SRC\/asix-broker-config\.sh"/); assert.match(b, /systemctl disable --now asix-broker-config\.timer/);
  });
  it('names itself in the request, so ASIX can answer with this broker\'s own port; an odd name is left out of the URL', () => {
    run(); let f = calls().find((c) => c.startsWith('fetch'));
    assert.match(f, /https:\/\/asix1:30443\/v1\/ingest\/broker-config\?collector=broker-1(\s|$)/);
    for (const odd of ["'bro ker'", "'a&b=c'", "'a/b'", "'x?y'"]) {
      fs.rmSync(log, { force: true }); fs.writeFileSync(envFile, BASE.replace('ASIX_BROKER_NAME=broker-1', 'ASIX_BROKER_NAME=' + odd)); run();
      f = calls().find((c) => c.startsWith('fetch')); assert.ok(f, odd); assert.ok(!/\?collector/.test(f), 'no name in the URL for ' + odd); assert.match(f, /broker-config(\s|$)/);
    }
    fs.rmSync(log, { force: true }); fs.writeFileSync(envFile, BASE.replace('ASIX_BROKER_NAME=broker-1\n', '')); run();
    assert.ok(!/\?collector/.test(calls().find((c) => c.startsWith('fetch'))), 'no name set, none sent');
  });
  it('a port for this broker alone is applied like any other: same checks, same order, same way back', () => {
    asks(2514); let r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(env(), /^ASIX_SYSLOG_PORT=2514$/m);
    const c = calls().filter((x) => !x.startsWith('fetch')); assert.match(c[0], /^validate port=2514/); assert.match(c[1], /^systemctl restart vector port=2514/);
    fs.writeFileSync(envFile, BASE); state('validate', 'bad'); r = run(); assert.strictEqual(r.status, 1); assert.strictEqual(env(), BASE, 'a failed check puts the old file back');
    assert.strictEqual(fs.readFileSync(path.join(stateDir, 'config-rejected'), 'utf8').trim(), '2514');
  });
});
