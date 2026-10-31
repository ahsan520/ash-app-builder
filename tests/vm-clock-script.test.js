'use strict';
// scripts/deploy/fix-vm-clock.sh with chronyc and systemctl replaced by stand-ins that record their calls.
const { describe, it, beforeEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const script = path.join(__dirname, '..', 'scripts', 'deploy', 'fix-vm-clock.sh');
let dir; let log;
const stub = (name, body) => { fs.writeFileSync(path.join(dir, 'bin', name), `#!/bin/bash\necho "${name} $*" >> "${log}"\n${body}\n`, { mode: 0o755 }); };
const run = (args, env = {}) => spawnSync('bash', [script, ...args], { encoding: 'utf8', env: { PATH: path.join(dir, 'bin') + ':/usr/bin:/bin', ASIX_ROOT: path.join(dir, 'root'), ASIX_CLOCK_WAIT: '0', ...env } });
const calls = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n') : []);
const tracking = (off) => `echo 'if [ "$1" = tracking ]; then echo "Reference ID    : 11223344 (ntp)"; echo "System time     : ${off} seconds fast of NTP time"; fi'`;

describe('fix-vm-clock.sh', () => {
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clock-')); fs.mkdirSync(path.join(dir, 'bin')); fs.mkdirSync(path.join(dir, 'root')); log = path.join(dir, 'calls.log'); stub('systemctl', ''); });
  it('--check steps the clock when the offset is above the limit (burst, then makestep)', () => {
    stub('chronyc', `if [ "$1" = tracking ]; then echo "System time     : 7234.5 seconds slow of NTP time"; fi`);
    const r = run(['--check']); assert.strictEqual(r.status, 0, r.stderr);
    assert.deepStrictEqual(calls().filter((c) => !/tracking/.test(c)), ['chronyc burst 4/4', 'chronyc makestep']);
  });
  it('--check does nothing when the offset is small, and does not guess when there is no offset', () => {
    stub('chronyc', `if [ "$1" = tracking ]; then echo "System time     : 0.000312 seconds fast of NTP time"; fi`); assert.strictEqual(run(['--check']).status, 0);
    assert.ok(!calls().some((c) => /makestep/.test(c)));
    stub('chronyc', `if [ "$1" = tracking ]; then echo "Reference ID    : 00000000 ()"; fi`); const r = run(['--check']); assert.strictEqual(r.status, 0); assert.ok(!calls().some((c) => /makestep/.test(c)));
  });
  it('--check honours ASIX_CLOCK_MAX_OFFSET and refuses a non-number; chronyd not answering is an error, not a step', () => {
    stub('chronyc', `if [ "$1" = tracking ]; then echo "System time     : 3.0 seconds fast of NTP time"; fi`);
    run(['--check'], { ASIX_CLOCK_MAX_OFFSET: '5' }); assert.ok(!calls().some((c) => /makestep/.test(c)));
    assert.strictEqual(run(['--check'], { ASIX_CLOCK_MAX_OFFSET: 'x' }).status, 2);
    stub('chronyc', 'exit 1'); assert.strictEqual(run(['--check']).status, 1);
  });
  it('--install writes the chrony drop-in, the service and timer, and enables the timer; --remove undoes it', () => {
    stub('chronyc', ''); const r = run(['--install']); assert.strictEqual(r.status, 0, r.stderr);
    const root = path.join(dir, 'root');
    assert.match(fs.readFileSync(path.join(root, 'etc/chrony/conf.d/asix-makestep.conf'), 'utf8'), /^makestep 1 -1$/m);
    assert.match(fs.readFileSync(path.join(root, 'etc/systemd/system/asix-fix-vm-clock.service'), 'utf8'), /ExecStart=\/usr\/local\/sbin\/asix-fix-vm-clock --check/);
    assert.match(fs.readFileSync(path.join(root, 'etc/systemd/system/asix-fix-vm-clock.timer'), 'utf8'), /OnUnitActiveSec=60/);
    assert.ok(fs.existsSync(path.join(root, 'usr/local/sbin/asix-fix-vm-clock'))); assert.ok(calls().includes('systemctl enable --now asix-fix-vm-clock.timer'));
    assert.strictEqual(run(['--remove']).status, 0);
    for (const f of ['etc/chrony/conf.d/asix-makestep.conf', 'etc/systemd/system/asix-fix-vm-clock.timer', 'usr/local/sbin/asix-fix-vm-clock']) assert.ok(!fs.existsSync(path.join(root, f)), f);
  });
  it('no argument prints usage and exits 2', () => { const r = run([]); assert.strictEqual(r.status, 2); assert.match(r.stdout, /--install/); });
});
