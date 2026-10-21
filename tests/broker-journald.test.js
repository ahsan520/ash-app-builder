'use strict';
// The broker's optional systemd-journal input (deploy/broker/vector-journald.yaml; bootstrap-broker.sh --journald, --journald-priority).
//   1. static checks that the config, broker.env.example, the bootstrap script and the other scripts agree (always run);
//   2. the bootstrap script's own journal checks, run in bash with nothing installed or written (always run);
//   3. with a real Vector binary (VECTOR_BIN, or `vector` on PATH; written against 0.59.0) the config is validated and run against a stand-in
//      `journalctl` (tests/fixtures/fake-journalctl.js) and a stand-in for the ASIX HTTP lane. Skipped without Vector (CI has none).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const net = require('net');
const { spawn, spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const cfg = read('deploy/broker/vector-journald.yaml');
const envExample = read('deploy/broker/broker.env.example');
const bootstrap = read('scripts/deploy/bootstrap-broker.sh');
const code = (text) => text.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');

describe('broker journal input: the files agree', () => {
  it('reads the journal from now on, leaves out Vector\'s own unit, and sends source type "journald"', () => {
    assert.match(cfg, /^sources:\n {2}journald_in:\n {4}type: journald\n/m);
    assert.match(cfg, /since_now: true/);
    assert.match(cfg, /exclude_units:\n\s+- vector\b/, 'Vector must not read its own log back (a stuck sink would feed itself)');
    assert.match(cfg, /X-ASIX-Source-Type: journald\b/);
    assert.match(cfg, /X-ASIX-Collector: \$\{ASIX_BROKER_NAME\}/);
  });
  it('has no listener of its own and reads only what the bootstrap script writes (the priority limit, with a default)', () => {
    assert.ok(!/address:|enabled: true/.test(code(cfg)));
    assert.match(cfg, /\$\{ASIX_JOURNALD_MAX_PRIORITY:-6\}/);
    for (const v of new Set([...cfg.matchAll(/\$\{(ASIX_[A-Z_]+)/g)].map((m) => m[1]))) {
      if (['ASIX_INGEST_URL', 'ASIX_INGEST_KEY', 'ASIX_BROKER_NAME', 'ASIX_CA_FILE'].includes(v)) continue;
      assert.ok(envExample.includes('#' + v + '='), v + ' in broker.env.example');
      assert.match(bootstrap, new RegExp('echo "' + v + '='), v + ' written by bootstrap');
    }
  });
  it('the disk buffer is at least the 268435488 bytes Vector demands, and the sink matches the other lanes (batch under the lane limits, retries, CA file)', () => {
    for (const m of cfg.matchAll(/max_size: (\d+)/g)) assert.ok(Number(m[1]) >= 268435488, 'max_size ' + m[1]);
    assert.match(cfg, /uri: \$\{ASIX_INGEST_URL\}/); assert.match(cfg, /max_events: 500/); assert.match(cfg, /max_bytes: 900000/);
    assert.match(cfg, /ca_file: \$\{ASIX_CA_FILE:-\/etc\/ssl\/certs\/ca-certificates\.crt\}/);
    assert.match(cfg, /Authorization: "Bearer \$\{ASIX_INGEST_KEY\}"/);
  });
  it('the bootstrap script installs the file only with --journald, removes it on a re-run without, validates it and lists it in VECTOR_CONFIG', () => {
    assert.match(bootstrap, /if \[ "\$JOURNALD" -eq 1 \]; then\n {2}install -m 644 "\$SRC\/vector-journald\.yaml" \/etc\/vector\/vector-journald\.yaml/);
    assert.match(bootstrap, /else\n {2}rm -f \/etc\/vector\/vector-journald\.yaml/);
    assert.match(bootstrap, /\$\{JOURNALD_CFG\} \/etc\/vector\/vector\.yaml/);
    assert.match(bootstrap, /\[ "\$JOURNALD" -eq 0 \] \|\| CONFIGS="\$CONFIGS,\/etc\/vector\/vector-journald\.yaml"/);
    assert.ok(!/\$\{JOURNALD:\+/.test(bootstrap), 'JOURNALD is "0" or "1", both non-empty, so :+ would always add the file to the validation');
    assert.match(bootstrap, /usermod -aG systemd-journal vector/);
    for (const f of ['deploy/broker/asix-broker-config.sh', 'scripts/deploy/upgrade-broker.sh']) assert.match(read(f), /for f in vector-file\.yaml vector-http\.yaml vector-journald\.yaml/, f + ' validates the journal input too');
  });
  it('the heartbeat script, the server check and the portal all know the input', () => {
    assert.match(read('deploy/broker/asix-broker-heartbeat.sh'), /\*vector-journald\.yaml,\*\) INPUTS="\$INPUTS,journald"/);
    assert.ok(require('../src/brokers/inputs').KINDS.includes('journald'));
    assert.match(read('src/portal/index.html'), /journald: 'Journal'/);
  });
  it('the bootstrap script is valid bash', () => {
    assert.strictEqual(spawnSync('bash', ['-n', path.join(root, 'scripts/deploy/bootstrap-broker.sh')]).status, 0);
  });
});

describe('bootstrap validation of --journald (the real block, run in bash, nothing installed)', () => {
  const a = bootstrap.indexOf('# Extra input: the systemd journal.'); const b = bootstrap.indexOf('# (end of the journal checks)');
  assert.ok(a > 0 && b > a);
  const block = bootstrap.slice(a, b);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-jd-'));
  const withJournalctl = path.join(tmp, 'with'); const without = path.join(tmp, 'without');
  fs.mkdirSync(withJournalctl); fs.mkdirSync(without);
  fs.writeFileSync(path.join(withJournalctl, 'journalctl'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  // `command -v` is a builtin, so an empty directory stands for a machine with no journalctl.
  const run = (vars, bin = withJournalctl) => spawnSync('/bin/bash', ['-c', block + '\necho "CFG=[$JOURNALD_CFG]"'], { env: { PATH: bin, JOURNALD: '0', JOURNALD_PRIORITY: '6', ...vars }, encoding: 'utf8' });
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('off by default: nothing to validate and nothing refused', () => {
    const r = run({}); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /CFG=\[\]/);
  });
  it('--journald alone, and with every priority from 0 to 7, is accepted and names the file to validate', () => {
    let r = run({ JOURNALD: '1' }); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /CFG=\[\/etc\/vector\/vector-journald\.yaml\]/);
    for (const p of '01234567'.split('')) assert.strictEqual(run({ JOURNALD: '1', JOURNALD_PRIORITY: p }).status, 0, 'priority ' + p);
  });
  it('refuses a priority that is not 0 to 7 (letters, 8, 10, negative, empty, shell syntax)', () => {
    for (const p of ['8', '10', '-1', 'x', '', '6;id', '$(id)', ' 6', '6 ']) {
      const r = run({ JOURNALD: '1', JOURNALD_PRIORITY: p }); assert.strictEqual(r.status, 2, JSON.stringify(p)); assert.match(r.stderr, /--journald-priority must be a number from 0/);
    }
  });
  it('refuses --journald-priority without --journald, and --journald on a machine without journalctl', () => {
    let r = run({ JOURNALD_PRIORITY: '4' }); assert.strictEqual(r.status, 2); assert.match(r.stderr, /only makes sense with --journald/);
    r = run({ JOURNALD: '1' }, without); assert.strictEqual(r.status, 2); assert.match(r.stderr, /needs journalctl/);
  });
});

// ---- real Vector -------------------------------------------------------------------------------------------------------------------------
const VECTOR = process.env.VECTOR_BIN || (spawnSync('vector', ['--version']).status === 0 ? 'vector' : null);
const freePort = () => new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms) => { const end = Date.now() + ms; for (;;) { const v = await fn(); if (v) return v; if (Date.now() > end) return null; await sleep(200); } };

describe('real Vector: the config validates and carries journal entries to the ASIX lane', { skip: VECTOR ? false : 'no Vector binary (set VECTOR_BIN)' }, () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-jvec-'));
  const cfgDir = path.join(tmp, 'cfg'); const dataDir = path.join(tmp, 'data'); const bin = path.join(tmp, 'bin'); const jdir = path.join(tmp, 'journal');
  for (const d of [cfgDir, dataDir, bin, jdir]) fs.mkdirSync(d);
  const journal = path.join(jdir, 'journal.jsonl'); const argvLog = path.join(jdir, 'argv.log');
  const files = ['vector.yaml', 'vector-journald.yaml'].map((f) => path.join(cfgDir, f));
  let vec, lane, syslogPort, laneCalls = [], seq = 0;
  const BASE = Date.UTC(2026, 9, 21, 17, 40, 0);   // the journal's own times are in the past on purpose: the line must carry THEM, not the read time

  const entry = (o) => {
    seq += 1;
    const e = { __CURSOR: 's=test;i=' + seq, __REALTIME_TIMESTAMP: String(BASE * 1000 + seq * 1000000 + 123), _HOSTNAME: 'vm1', PRIORITY: '6', MESSAGE: 'm' + seq, ...o };
    for (const k of Object.keys(e)) if (e[k] === undefined) delete e[k];
    return e;
  };
  const add = (...es) => fs.appendFileSync(journal, es.map((e) => JSON.stringify(e)).join('\n') + '\n');
  const lines = () => laneCalls.filter((c) => c.h['x-asix-source-type'] === 'journald').flatMap((c) => c.body.split('\n').filter(Boolean));
  const has = (t) => lines().filter((x) => x.endsWith(t)).length;
  const argvCalls = () => (fs.existsSync(argvLog) ? fs.readFileSync(argvLog, 'utf8').split('\n').filter((l) => l && l !== '--version') : []);
  const envFor = (extra = {}) => ({ PATH: bin + ':' + process.env.PATH, FAKE_JOURNAL_DIR: jdir, VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: 'true', ASIX_INGEST_KEY: 'asix_ik_test', ASIX_BROKER_NAME: 'broker-test',
    ASIX_INGEST_URL: `http://127.0.0.1:${lane.address().port}/v1/ingest/http`, ASIX_SYSLOG_PORT: String(syslogPort), ...extra });
  const start = async (extra) => {
    const before = argvCalls().length;
    vec = spawn(VECTOR, files.flatMap((f) => ['--config', f]), { env: envFor(extra), stdio: 'ignore' });
    assert.ok(await until(() => argvCalls().length > before, 20000), 'Vector did not start journalctl');
    await sleep(500);
  };
  const stop = () => new Promise((res) => { vec.once('exit', res); vec.kill('SIGTERM'); });   // a graceful stop writes the cursor

  before(async () => {
    fs.writeFileSync(files[0], read('deploy/broker/vector.yaml').replace('data_dir: /var/lib/vector', 'data_dir: ' + dataDir).replace(/api:\n {2}enabled: true\n {2}address: 127.0.0.1:8686/, 'api:\n  enabled: false'));
    fs.copyFileSync(path.join(root, 'deploy/broker/vector-journald.yaml'), files[1]);
    const fake = path.join(bin, 'journalctl'); fs.copyFileSync(path.join(root, 'tests/fixtures/fake-journalctl.js'), fake); fs.chmodSync(fake, 0o755);
    lane = http.createServer((q, s) => { let b = ''; q.on('data', (d) => { b += d; }); q.on('end', () => { laneCalls.push({ h: q.headers, body: b }); s.writeHead(202, { 'content-type': 'application/json' }); s.end('{"success":true}'); }); });
    await new Promise((r) => lane.listen(0, '127.0.0.1', r));
    syslogPort = await freePort();
    add(entry({ MESSAGE: 'history before Vector starts', SYSLOG_IDENTIFIER: 'old' }), entry({ MESSAGE: 'more history', SYSLOG_IDENTIFIER: 'old' }));
  });
  after(() => { if (vec) vec.kill('SIGKILL'); lane.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

  it('validates alone with the base config, and together with the file and HTTP inputs (distinct sinks and buffers)', () => {
    let r = spawnSync(VECTOR, ['validate', '--no-environment', ...files], { env: envFor(), encoding: 'utf8' });
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    const all = [...files, path.join(root, 'deploy/broker/vector-file.yaml'), path.join(root, 'deploy/broker/vector-http.yaml')];
    r = spawnSync(VECTOR, ['validate', '--no-environment', ...all], { env: envFor({ ASIX_FILE_GLOB: path.join(tmp, '*.log'), ASIX_HTTP_USER: 'svc', ASIX_HTTP_PASSWORD: 's3cretpassword', ASIX_HTTP_PORT: '1' }), encoding: 'utf8' });
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  });

  it('starts, asks journalctl for entries from now on (not the history), and sends the entries written afterwards', async () => {
    await start();
    assert.match(argvCalls()[0], /--follow .*--since=now/, 'first start asks for entries from now: ' + argvCalls()[0]);
    add(
      entry({ SYSLOG_IDENTIFIER: 'sshd', _PID: '812', _SYSTEMD_UNIT: 'ssh.service', __REALTIME_TIMESTAMP: String(BASE * 1000 + 1000123), MESSAGE: 'Failed password for bob from 10.0.0.5 port 22 ssh2' }),
      entry({ _COMM: 'cron', _PID: '900', _SYSTEMD_UNIT: 'cron.service', PRIORITY: '7', MESSAGE: 'debug noise' }),
      entry({ SYSLOG_IDENTIFIER: 'vector', _PID: '55', _SYSTEMD_UNIT: 'vector.service', PRIORITY: '3', MESSAGE: 'Service call failed' }),
      entry({ _SYSTEMD_UNIT: 'foo.service', PRIORITY: '4', MESSAGE: 'only the unit names it' }),
      entry({ MESSAGE: 'nothing names it', PRIORITY: undefined }),
      entry({ SYSLOG_IDENTIFIER: 'kernel', MESSAGE: 'line one\nline two\r\nline three' }),
      entry({ SYSLOG_IDENTIFIER: 'bin', MESSAGE: [72, 105, 32, 226, 128] }),
      entry({ SYSLOG_IDENTIFIER: 'my app:x[1]', _PID: 'abc', _HOSTNAME: 'vm 2', MESSAGE: 'odd names' }),
      entry({ SYSLOG_IDENTIFIER: 'pidy', _PID: '7x7', MESSAGE: 'digits only in the pid' }),
      entry({ SYSLOG_IDENTIFIER: 'big', MESSAGE: 'x'.repeat(20000) }),
      entry({ SYSLOG_IDENTIFIER: 'sudo', PRIORITY: '2', MESSAGE: 'bob : TTY=pts/0 ; COMMAND=/bin/ls' }),
    );
    const got = await until(() => has('odd names') === 1 && has('digits only in the pid') === 1 && has('bob : TTY=pts/0 ; COMMAND=/bin/ls') === 1 && lines().some((x) => / big(\[|:)/.test(x)), 20000);
    assert.ok(got, 'lane got: ' + JSON.stringify(lines()).slice(0, 2000));
    await sleep(1500);
  });
  it('history is not sent', () => {
    assert.ok(!lines().some((x) => /history before Vector starts|more history/.test(x)));
  });
  it('each line is "ISO-time host app[pid]: message" with the JOURNAL\'s own time, the host from the entry and one line per entry', () => {
    const sshd = lines().find((x) => x.includes(' sshd['));
    assert.match(sshd, /^2026-10-21T17:40:01\.000123\+00:00 vm1 sshd\[812\]: Failed password for bob from 10\.0\.0\.5 port 22 ssh2$/);
    const ml = lines().find((x) => / kernel: /.test(x)); assert.match(ml, / vm1 kernel: line one line two line three$/, 'line breaks become spaces, still one line');
    assert.match(lines().find((x) => / bin: /.test(x)), / vm1 bin: Hi /, 'a binary message is turned into text, not refused');
    for (const x of lines()) assert.ok(!x.includes('\n') && /^\d{4}-\d{2}-\d{2}T\S+ \S+ \S+: /.test(x), x.slice(0, 120));
  });
  it('the app name is the identifier, else the command, else the unit without ".service", else "journald"; odd characters are tidied; a bad pid is left out', () => {
    assert.match(lines().find((x) => x.endsWith('only the unit names it')), / vm1 foo: only the unit names it$/);
    assert.match(lines().find((x) => x.endsWith('nothing names it')), / vm1 journald: nothing names it$/, 'an entry with no priority counts as 6 and is sent');
    assert.match(lines().find((x) => x.endsWith('odd names')), / vm_2 my_app_x_1_: odd names$/, 'spaces, colons and brackets in the name, spaces in the host, a pid with no digits');
    assert.match(lines().find((x) => x.endsWith('digits only in the pid')), / vm1 pidy\[77\]: digits only in the pid$/, 'a pid keeps only its digits, as in the syslog rewrite');
    assert.match(lines().find((x) => / sudo: /.test(x)), / vm1 sudo: bob : TTY=pts\/0 ; COMMAND=\/bin\/ls$/, 'a priority 2 entry is sent');
  });
  it('debug entries are dropped at the default limit (6), and Vector\'s own unit is never read back', () => {
    assert.strictEqual(has('debug noise'), 0);
    assert.ok(!lines().some((x) => /Service call failed/.test(x)));
  });
  it('a long message is cut to 8192 characters, so one entry cannot flood the lane', () => {
    const big = lines().find((x) => / big(\[\d+\])?: /.test(x)); assert.ok(big);
    const msg = big.slice(big.indexOf(': ') + 2); assert.strictEqual(msg.length, 8192);
  });
  it('the requests carry the key, the broker name and the source type, as text lines the lane accepts', () => {
    const mine = laneCalls.filter((c) => c.h['x-asix-source-type'] === 'journald'); assert.ok(mine.length > 0);
    for (const c of mine) {
      assert.strictEqual(c.h.authorization, 'Bearer asix_ik_test'); assert.strictEqual(c.h['x-asix-collector'], 'broker-test');
      assert.match(c.h['content-type'], /^text\/plain/); assert.ok(c.body.split('\n').filter(Boolean).length <= 500);
    }
  });
  it('the lines really parse in the ASIX lane (same parser the server uses): host, app name, pid and the journal\'s own time', () => {
    const { parseLine } = require('../src/ingest/http-ingest');
    const p = parseLine(lines().find((x) => x.includes(' sshd[')), 'broker-test');
    assert.strictEqual(p.parsed.format, 'syslog-file'); assert.strictEqual(p.parsed.host, 'vm1'); assert.strictEqual(p.parsed.app_name, 'sshd'); assert.strictEqual(String(p.parsed.proc_id), '812');
    assert.strictEqual(p.time, '2026-10-21T17:40:01.000Z'); assert.match(p.parsed.message, /^Failed password for bob/);
  });

  it('a restart carries on from the cursor: an entry written while Vector was down arrives once, nothing is sent twice, history still not sent', async () => {
    await stop();
    add(entry({ SYSLOG_IDENTIFIER: 'cron', MESSAGE: 'written while Vector was down' }));
    await start();
    const calls = argvCalls(); assert.match(calls[calls.length - 1], /--after-cursor=s=test;i=\d+/, 'second start asks for entries after the cursor: ' + calls[calls.length - 1]);
    add(entry({ SYSLOG_IDENTIFIER: 'cron', MESSAGE: 'written after the restart' }));
    assert.ok(await until(() => has('written while Vector was down') === 1 && has('written after the restart') === 1, 20000), 'both arrive');
    await sleep(6000);   // time for a duplicate to show up if there were one
    for (const t of ['written while Vector was down', 'written after the restart', 'odd names', 'only the unit names it']) assert.strictEqual(has(t), 1, t + ' exactly once');
    assert.ok(!lines().some((x) => /history before Vector starts/.test(x)));
  });
  it('ASIX_JOURNALD_MAX_PRIORITY=4 sends warnings and worse only; a value that is not a number falls back to 6', async () => {
    await stop(); await start({ ASIX_JOURNALD_MAX_PRIORITY: '4' });
    add(entry({ SYSLOG_IDENTIFIER: 'p', PRIORITY: '3', MESSAGE: 'p3 error' }), entry({ SYSLOG_IDENTIFIER: 'p', PRIORITY: '4', MESSAGE: 'p4 warning' }), entry({ SYSLOG_IDENTIFIER: 'p', PRIORITY: '5', MESSAGE: 'p5 notice' }),
      entry({ SYSLOG_IDENTIFIER: 'p', PRIORITY: '6', MESSAGE: 'p6 info' }), entry({ SYSLOG_IDENTIFIER: 'p', PRIORITY: '0', MESSAGE: 'p0 emerg' }));
    assert.ok(await until(() => has('p4 warning') === 1 && has('p0 emerg') === 1, 20000), 'warning and emerg arrive');
    await sleep(2500);
    assert.strictEqual(has('p3 error'), 1); assert.strictEqual(has('p5 notice'), 0); assert.strictEqual(has('p6 info'), 0);

    await stop(); await start({ ASIX_JOURNALD_MAX_PRIORITY: 'abc' });
    add(entry({ SYSLOG_IDENTIFIER: 'q', PRIORITY: '6', MESSAGE: 'q6 info' }), entry({ SYSLOG_IDENTIFIER: 'q', PRIORITY: '7', MESSAGE: 'q7 debug' }));
    assert.ok(await until(() => has('q6 info') === 1, 20000), 'info arrives');
    await sleep(2500);
    assert.strictEqual(has('q7 debug'), 0, 'debug still dropped');
  });
});
