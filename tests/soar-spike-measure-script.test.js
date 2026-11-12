'use strict';
// scripts/deploy/soar-spike-measure.sh (task SR0): docker, kubectl, free, nproc and df are stubs on PATH; curl and node are the real ones, against the real stand-in.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, spawn } = require('child_process');
const { createStandIn } = require('../deploy/soar-spike/stand-in');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'deploy', 'soar-spike-measure.sh');

describe('soar-spike-measure.sh', () => {
  let tmp, bin;
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const run = (args, env = {}) => spawnSync('bash', [SCRIPT, ...args], { encoding: 'utf8', env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ...env } });
  const FAST = ['--samples', '2', '--interval', '0'];

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'spike-')); bin = path.join(tmp, 'bin'); fs.mkdirSync(bin);
    stub('nproc', 'echo 4');
    stub('free', 'echo "              total        used        free      shared  buff/cache   available"; echo "Mem:           7900        3000        2000          10        2900        4500"');
    stub('docker', `case "$1" in
  ps) exit 0;;
  stats) printf '%s\\n' 'tracecat-api|612.5MiB / 7.7GiB|3.20%' 'tracecat-temporal|1.1GiB / 7.7GiB|11.00%' 'tracecat-postgres|230MiB / 7.7GiB|0.50%' 'other-thing|900MiB / 7.7GiB|1.00%' 'tracecat-tiny|900kB / 7.7GiB|0.00%';;
  system) echo 'Images: 4.2GB'; echo 'Volumes: 300MB';;
esac`);
    stub('kubectl', `case "$*" in
  *"top pods"*) printf '%s\\n' 'api-0   25m   300Mi' 'worker-0   250m   1Gi' 'pg-0   1   200Mi';;
  *"get pods"*) printf '%s\\n' 'api-0 1/1 Running 2 3h' 'worker-0 1/1 Running 0 3h' 'pg-0 1/1 Running 1 3h';;
esac`);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('docker: sums the matching containers, converts units, sorts largest first, and judges against the budget', () => {
    const r = run(['--runtime', 'docker', '--match', 'tracecat', '--label', 'idle', ...FAST]); assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stdout, /#### Footprint: idle .*docker, 2 reading\(s\)/); assert.match(r.stdout, /4 CPUs, 7900 MiB memory, 4500 MiB available/);
    // 612.5 -> 613, 1.1 GiB -> 1127 (1126.4 rounded up), 230, 900 kB -> 1  => 1971
    assert.match(r.stdout, /4 container\(s\) or pod\(s\), highest total resident memory \*\*1971 MiB\*\* against a budget of 2048 MiB: \*\*within the budget\*\*/);
    assert.ok(!/other-thing/.test(r.stdout), 'a container that does not match is not counted');
    const rows = r.stdout.split('\n').filter((l) => /^\| tracecat-/.test(l)).map((l) => l.split('|')[1].trim()); assert.deepStrictEqual(rows, ['tracecat-temporal', 'tracecat-api', 'tracecat-postgres', 'tracecat-tiny']);
    assert.match(r.stdout, /\| tracecat-temporal \| 1127 \| 11.00 \|/); assert.match(r.stdout, /Docker disk: Images: 4\.2GB;Volumes: 300MB;/);
  });

  it('says OVER the budget when the total is above it, and the budget can be changed', () => {
    const r = run(['--runtime', 'docker', '--match', 'tracecat', '--budget-mb', '1500', ...FAST]); assert.match(r.stdout, /\*\*OVER the budget\*\*/);
    assert.match(run(['--runtime', 'docker', '--match', 'tracecat', '--budget-mb', '4096', ...FAST]).stdout, /within the budget/);
  });

  it('k3s: reads pods from the namespace, converts milli-CPU and Gi, and reports restarts', () => {
    const r = run(['--runtime', 'k3s', '--namespace', 'tracecat', ...FAST]); assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stdout, /3 container\(s\) or pod\(s\), highest total resident memory \*\*1524 MiB\*\*/);   // 300 + 1024 + 200
    assert.match(r.stdout, /\| worker-0 \| 1024 \| 25.0 \|/); assert.match(r.stdout, /\| pg-0 \| 200 \| 100.0 \|/); assert.match(r.stdout, /Pod restarts so far: 3\./);
  });

  it('takes the highest reading of each container, not the last or the average', () => {
    fs.writeFileSync(path.join(tmp, 'n'), '0');
    stub('docker', `n=$(cat '${tmp}/n'); echo $((n+1)) > '${tmp}/n'
case "$1" in ps) exit 0;; stats) if [ "$n" = 0 ]; then echo 'tracecat-a|900MiB / 8GiB|50%'; else echo 'tracecat-a|100MiB / 8GiB|5%'; fi;; esac`);
    const r = run(['--runtime', 'docker', '--match', 'tracecat', ...FAST]); assert.match(r.stdout, /\*\*900 MiB\*\*/); assert.match(r.stdout, /\| tracecat-a \| 900 \| 50 \|/);
  });

  it('exits 1 with a reason when nothing can be read, and writes no block', () => {
    stub('docker', 'case "$1" in ps) exit 0;; stats) exit 1;; esac');
    const r = run(['--runtime', 'docker', ...FAST]); assert.strictEqual(r.status, 1); assert.match(r.stderr, /nothing could be read/); assert.strictEqual(r.stdout, '');
    stub('kubectl', 'exit 1'); assert.strictEqual(run(['--runtime', 'k3s', ...FAST]).status, 1);
  });

  it('refuses wrong options with exit 2 (nothing is run)', () => {
    for (const a of [['--bogus'], ['--runtime', 'podman'], ['--samples', '0'], ['--samples', '61'], ['--samples', 'x'], ['--interval', '-1'], ['--budget-mb', '0'], ['--label', 'a b'], ['--label', 'x;rm'], ['--namespace', 'Bad_NS'], ['--match', 'a;b'], ['--match', '$(id)']]) {
      const r = run(a); assert.strictEqual(r.status, 2, a.join(' ') + ' -> ' + r.stdout + r.stderr);
    }
  });

  it('writes the block to --out as well, and picks docker when it answers and none was named', () => {
    const out = path.join(tmp, 'out.md'); const r = run(['--match', 'tracecat', '--out', out, ...FAST]); assert.strictEqual(r.status, 0);
    assert.strictEqual(fs.readFileSync(out, 'utf8'), r.stdout); assert.match(r.stdout, /docker, /);
    stub('docker', 'exit 1'); assert.match(run(['--out', out, ...FAST]).stdout, /k3s, /);
  });

  it('reads the verdict of a real stand-in: pass after a right run, and names each failed check after a wrong one', async () => {
    const s = createStandIn(); await new Promise((r) => s.server.listen(0, '127.0.0.1', r)); const url = 'http://127.0.0.1:' + s.server.address().port;
    const measure = (args) => new Promise((resolve) => { const p = spawn('bash', [SCRIPT, ...args], { env: { PATH: bin + ':' + process.env.PATH, HOME: tmp } }); let o = ''; p.stdout.on('data', (d) => (o += d)); p.on('close', (c) => resolve({ code: c, out: o })); });
    try {
      const base = ['--runtime', 'docker', '--match', 'tracecat', ...FAST, '--stand-in', url];
      let r = await measure(base); assert.match(r.out, /Scenario verdict from the stand-in: \*\*fail\*\*; blocked: none/); assert.match(r.out, /FAILED: the engine fetched the feed/);
      const post = (p, b) => fetch(url + p, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Basic ' + Buffer.from('spike-key:spike-secret').toString('base64') }, body: b ? JSON.stringify(b) : undefined });
      await fetch(url + '/feed.txt'); const id = (await (await post('/asix/approvals', { address: '203.0.113.10' })).json()).id; await post(`/asix/approvals/${id}/grant`); await post('/api/firewall/alias_util/add/asix_block', { address: '203.0.113.10' });
      r = await measure(base); assert.match(r.out, /\*\*pass\*\*; blocked: 203\.0\.113\.10/); assert.ok(!/FAILED/.test(r.out));
      r = await measure(['--runtime', 'docker', '--match', 'tracecat', ...FAST, '--stand-in', 'http://127.0.0.1:1']); assert.match(r.out, /did not answer/);
    } finally { await new Promise((r) => s.server.close(r)); }
  });
});
