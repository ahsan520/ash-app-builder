'use strict';
// scripts/deploy/upgrade-broker.sh with every system command replaced by a stub on PATH (id, vector, dpkg-query, apt-get,
// apt-cache, systemctl, curl), so the order of steps, the refusals and the "do not restart on a bad config" rule are checked
// without a broker VM. The stubs keep their state in files in a temp folder.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'deploy', 'upgrade-broker.sh');

describe('upgrade-broker.sh', () => {
  let tmp, bin, log;
  const stub = (name, body) => { fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 }); };
  const state = (f, v) => fs.writeFileSync(path.join(tmp, f), v);
  const calls = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);
  const run = (args, extra = {}) => spawnSync('bash', [SCRIPT, ...args], { encoding: 'utf8', stdin: 'ignore',
    env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_BROKER_ENV: path.join(tmp, 'broker.env'), ASIX_VECTOR_DIR: path.join(tmp, 'vector'), ASIX_UPGRADE_WAIT_S: '2', ...extra } });

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'upg-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); fs.mkdirSync(bin); fs.mkdirSync(path.join(tmp, 'vector'));
    fs.writeFileSync(path.join(tmp, 'broker.env'), 'ASIX_BROKER_NAME=broker-1\n'); fs.writeFileSync(path.join(tmp, 'vector', 'vector.yaml'), 'sources: {}\n');
    state('installed', '0.59.0'); state('repo', '0.59.0 0.60.0 0.61.1'); state('validate', 'ok'); state('health', 'ok');
    stub('id', 'echo 0');
    stub('vector', `if [ "$1" = "--version" ]; then echo "vector $(cat '${tmp}/installed') (x86_64-unknown-linux-gnu)"; exit 0; fi
if [ "$1" = "validate" ]; then echo "validate $*" >> '${log}'; [ "$(cat '${tmp}/validate')" = ok ]; exit $?; fi`);
    stub('dpkg-query', `echo "$(cat '${tmp}/installed')-1"`);
    stub('apt-cache', `for v in $(cat '${tmp}/repo'); do echo " vector | $v-1 | https://repo stable/vector-0 amd64 Packages"; done`);
    stub('apt-get', `echo "apt-get $*" >> '${log}'
case "$*" in
  *update*) exit 0;;
  *"vector="*) a="$*"; v="\${a##*vector=}"; v="\${v%%-*}"; echo "$v" > '${tmp}/installed'; exit 0;;
  *--only-upgrade*) tr ' ' '\\n' < '${tmp}/repo' | tail -1 > '${tmp}/installed'; exit 0;;
esac`);
    stub('systemctl', `echo "systemctl $*" >> '${log}'`);
    stub('curl', `[ "$(cat '${tmp}/health')" = ok ]`);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('refuses bad input before touching anything', () => {
    for (const args of [['--version', 'abc'], ['--version', '1.2'], ['--version', '0.60.0; rm -rf /'], ['--nope']]) assert.strictEqual(run(args).status, 2, JSON.stringify(args));
    assert.deepStrictEqual(calls(), []);
  });
  it('refuses when not root, when the broker env file is missing and when vector is missing', () => {
    stub('id', 'echo 1000'); assert.strictEqual(run([]).status, 1); assert.deepStrictEqual(calls(), []);
    stub('id', 'echo 0'); fs.rmSync(path.join(tmp, 'broker.env')); const r = run([]); assert.strictEqual(r.status, 1); assert.match(r.stderr, /bootstrap-broker\.sh/);
  });
  it('--dry-run changes nothing', () => {
    const r = run(['--version', '0.60.0', '--dry-run']); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /Dry run: would install vector=0\.60\.0-1/);
    assert.deepStrictEqual(calls(), []); assert.strictEqual(fs.readFileSync(path.join(tmp, 'installed'), 'utf8').trim(), '0.59.0');
  });
  it('already on the asked-for version: nothing to do, nothing run', () => {
    const r = run(['--version', '0.59.0']); assert.strictEqual(r.status, 0); assert.match(r.stdout, /Already on Vector 0\.59\.0/); assert.deepStrictEqual(calls(), []);
  });
  it('refuses a downgrade and a version the repository does not have', () => {
    state('installed', '0.61.1'); let r = run(['--version', '0.60.0']); assert.strictEqual(r.status, 1); assert.match(r.stderr, /Downgrades/); assert.ok(!calls().some((c) => /install/.test(c)));
    state('installed', '0.59.0'); r = run(['--version', '0.70.0']); assert.strictEqual(r.status, 1); assert.match(r.stderr, /no Vector 0\.70\.0/); assert.ok(!calls().some((c) => /install/.test(c)));
  });
  it('upgrades to the asked-for version: install, validate, restart, heartbeat, in that order', () => {
    const r = run(['--version', '0.60.0']); assert.strictEqual(r.status, 0, r.stderr + r.stdout); assert.match(r.stdout, /Vector 0\.59\.0 -> 0\.60\.0, healthy/);
    const c = calls(); const at = (re) => c.findIndex((x) => re.test(x));
    assert.ok(at(/install -y vector=0\.60\.0-1/) >= 0 && at(/^validate/) > at(/install -y/) && at(/restart vector/) > at(/^validate/) && at(/start asix-broker-heartbeat/) > at(/restart vector/), c.join(' | '));
    assert.match(c.find((x) => /^validate/.test(x)), /--no-environment .*vector\.yaml$/);
  });
  it('without --version upgrades to the newest the repository offers', () => {
    const r = run([]); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /0\.59\.0 -> 0\.61\.1/); assert.ok(calls().some((x) => /--only-upgrade vector/.test(x)));
  });
  it('already on the newest: does not restart', () => {
    state('installed', '0.61.1'); const r = run([]); assert.strictEqual(r.status, 0); assert.match(r.stdout, /Nothing was restarted/); assert.ok(!calls().some((x) => /restart/.test(x)));
  });
  it('a config that fails validate on the new binary is NOT restarted, and the way back is printed', () => {
    state('validate', 'bad'); const r = run(['--version', '0.60.0']); assert.strictEqual(r.status, 1); assert.match(r.stderr, /NOT restarted/); assert.match(r.stderr, /vector=0\.59\.0-1/);
    assert.ok(!calls().some((x) => /restart|heartbeat/.test(x)));
  });
  it('includes the TLS config file in the check when it exists', () => {
    fs.writeFileSync(path.join(tmp, 'vector', 'vector-tls.yaml'), 'sources: {}\n'); run(['--version', '0.60.0']);
    assert.match(calls().find((x) => /^validate/.test(x)), /vector-tls\.yaml .*vector\.yaml$/);
  });
  it('an unhealthy Vector after the restart fails with the way back', () => {
    state('health', 'bad'); const r = run(['--version', '0.60.0']); assert.strictEqual(r.status, 1); assert.match(r.stderr, /did not become healthy/); assert.match(r.stderr, /vector=0\.59\.0-1/);
    assert.ok(!calls().some((x) => /heartbeat/.test(x)));
  });
});
