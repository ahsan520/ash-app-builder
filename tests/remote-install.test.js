'use strict';
// E12: scripts/deploy/remote-install-broker-vm.sh, remote-install-indexer-vm.sh and scripts/lib/remote-ssh.sh, run for real in bash with a stand-in for `ssh`
// (tests/fixtures/fake-ssh.sh) that records every call. NOT tried against a real VM or a real sshd.
const { describe, it, beforeEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const BROKER = path.join(ROOT, 'scripts/deploy/remote-install-broker-vm.sh'), INDEXER = path.join(ROOT, 'scripts/deploy/remote-install-indexer-vm.sh'), LIB = path.join(ROOT, 'scripts/lib/remote-ssh.sh');
const PW = 'S3cret-pw!x', KEY = 'asix_ik_abcdef1234567890';
let tmp, rec, bin, out;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ri-')); rec = path.join(tmp, 'rec'); out = path.join(tmp, 'out'); bin = path.join(tmp, 'bin'); fs.mkdirSync(rec); fs.mkdirSync(bin);
  fs.copyFileSync(path.join(__dirname, 'fixtures/fake-ssh.sh'), path.join(bin, 'ssh')); fs.chmodSync(path.join(bin, 'ssh'), 0o755);
  fs.writeFileSync(path.join(tmp, 'key'), KEY + '\n', { mode: 0o600 });
  fs.writeFileSync(path.join(tmp, 'ca.pem'), 'CA\n'); fs.writeFileSync(path.join(tmp, 'tls.crt'), 'CRT\n'); fs.writeFileSync(path.join(tmp, 'tls.key'), 'TLSKEY\n');
});
const run = (script, args, env = {}) => spawnSync('bash', [script, ...args], { encoding: 'utf8', cwd: tmp, input: '', env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_SSH_PASSWORD: PW, FAKE_SSH_DIR: rec, TERM: 'dumb', ...env } });
const calls = () => { const n = Number(fs.existsSync(path.join(rec, 'n')) ? fs.readFileSync(path.join(rec, 'n'), 'utf8') : 0); return Array.from({ length: n }, (_, i) => { const raw = fs.readFileSync(path.join(rec, 'cmd.' + (i + 1)), 'utf8').trim(), inner = fs.readFileSync(path.join(rec, 'inner.' + (i + 1)), 'utf8').trim(); const parseErr = fs.readFileSync(path.join(rec, 'parse-err.' + (i + 1)), 'utf8').trim(); assert.strictEqual(parseErr, '', 'the remote shell must be able to parse: ' + raw);
  return { argv: fs.readFileSync(path.join(rec, 'argv.' + (i + 1)), 'utf8'), raw, cmd: inner || raw, stdin: fs.readFileSync(path.join(rec, 'stdin.' + (i + 1)), 'utf8') }; }); };   // cmd = what bash -c would run after the remote shell took the quotes off
const roots = () => calls().filter((c) => /^sudo -S/.test(c.raw));
const BASE = ['--host', '10.0.0.5', '--user', 'ash', '--out-dir', 'out'];
const BROKER_ARGS = [...BASE, '--url', 'https://asix1:30443/v1/ingest/http', '--name', 'broker-2', '--key-file', 'key'];
const auditFiles = () => fs.readdirSync(out).flatMap((d) => fs.readdirSync(path.join(out, d)).map((f) => path.join(out, d, f)));
const allText = () => fs.readdirSync(rec).map((f) => fs.readFileSync(path.join(rec, f), 'utf8')).join('\n');

describe('the files', () => {
  it('are executable and have valid shell syntax', () => {
    for (const f of [BROKER, INDEXER, LIB]) { assert.ok(fs.statSync(f).mode & 0o111, f); const r = spawnSync('bash', ['-n', f], { encoding: 'utf8' }); assert.strictEqual(r.status, 0, r.stderr); }
  });
  it('never put the password in an argument or echo it', () => {
    const src = fs.readFileSync(LIB, 'utf8') + fs.readFileSync(BROKER, 'utf8') + fs.readFileSync(INDEXER, 'utf8');
    assert.ok(!/sshpass\s+-p/.test(src)); assert.ok(!/echo\s+"?\$\{?RS_PW/.test(src)); assert.ok(!/ssh[^\n]*\$RS_PW/.test(src.replace(/printf '%s\\n' "\$RS_PW" \| rs_ssh/, '')));
    assert.ok(!/--key\s+"?\$KEY/.test(src), 'the ingest key is never put in the command text');
  });
});

describe('checks before any connection', () => {
  for (const [name, args] of [
    ['a host with a space', ['--host', 'a b', '--user', 'ash', '--url', 'https://x/y', '--name', 'b', '--key-file', 'key']],
    ['a host that starts with a dash', ['--host', '-oProxyCommand=x', '--user', 'ash', '--url', 'https://x/y', '--name', 'b', '--key-file', 'key']],
    ['a user with a semicolon', ['--host', 'h', '--user', 'a;b', '--url', 'https://x/y', '--name', 'b', '--key-file', 'key']],
    ['a bad port', [...BROKER_ARGS, '--ssh-port', '70000']],
    ['no url', [...BASE, '--name', 'b', '--key-file', 'key']],
    ['a url with a quote', [...BASE, '--url', "https://x/'y", '--name', 'b', '--key-file', 'key']],
    ['a name with a space', [...BASE, '--url', 'https://x/y', '--name', 'a b', '--key-file', 'key']],
    ['an unknown option', [...BROKER_ARGS, '--bogus']],
    ['a TLS cert without its key', [...BROKER_ARGS, '--tls-cert', 'tls.crt']],
    ['a config key without accept-config', [...BROKER_ARGS, '--config-pubkey', 'ca.pem']],
    ['an indexer url without a file', [...BROKER_ARGS, '--indexer-url', 'https://i:9200']],
    ['an extra option with a shell character', [...BROKER_ARGS, '--', '--file-glob', '/var/log/*;rm']],
    ['an extra option with a command substitution', [...BROKER_ARGS, '--', '--file-glob', '$(id)']],
    ['an extra option with a backtick', [...BROKER_ARGS, '--', '--file-glob', '`id`']],
    ['an extra option with a space', [...BROKER_ARGS, '--', '--file-glob', '/a b']],
    ['a file that does not exist', [...BROKER_ARGS, '--ca', 'nope.pem']],
    ['an option with no value', [...BASE, '--url']],
  ]) it('refuses ' + name + ' and makes no ssh call', () => { const r = run(BROKER, args); assert.notStrictEqual(r.status, 0, name); assert.strictEqual(calls().length, 0); assert.ok(!r.stdout.includes(PW) && !r.stderr.includes(PW)); });
  it('refuses an ingest key that is not one, and no terminal to ask on', () => {
    fs.writeFileSync(path.join(tmp, 'badkey'), 'hello\n', { mode: 0o600 }); let r = run(BROKER, [...BASE, '--url', 'https://x/y', '--name', 'b', '--key-file', 'badkey']);
    assert.notStrictEqual(r.status, 0); assert.match(r.stderr, /does not look like an ingest key/); assert.strictEqual(calls().length, 0);
    r = run(BROKER, [...BASE, '--url', 'https://x/y', '--name', 'b']); assert.notStrictEqual(r.status, 0); assert.match(r.stderr, /no ingest key/); assert.strictEqual(calls().length, 0);
    r = run(BROKER, BROKER_ARGS, { ASIX_SSH_PASSWORD: '' }); assert.notStrictEqual(r.status, 0); assert.match(r.stderr, /no password/); assert.strictEqual(calls().length, 0);
  });
  it('refuses a password file that others can read', () => {
    fs.writeFileSync(path.join(tmp, 'pw'), PW + '\n', { mode: 0o644 }); const r = run(BROKER, [...BROKER_ARGS, '--password-file', 'pw'], { ASIX_SSH_PASSWORD: '' });
    assert.notStrictEqual(r.status, 0); assert.match(r.stderr, /readable by you only/); assert.strictEqual(calls().length, 0);
  });
  it('indexer: needs an address; tenant and manager together; writer needs them', () => {
    for (const a of [[...BASE], [...BASE, '--address', 'idx.local', '--tenant-name', 'Acme'], [...BASE, '--address', 'idx.local', '--writer'], [...BASE, '--address', 'idx.local', '--manager-name', 'Bad Name', '--tenant-name', 'A'], [...BASE, '--address', 'idx;local']]) {
      const r = run(INDEXER, a); assert.notStrictEqual(r.status, 0, a.join(' ')); assert.strictEqual(calls().length, 0);
    }
  });
});

describe('the password', () => {
  it('is never in any ssh argument or in the audit log, even when the VM prints it; sudo gets it as the first line of standard input', () => {
    const r = run(BROKER, BROKER_ARGS, { FAKE_ECHO_PW: '1' }); assert.strictEqual(r.status, 0, r.stderr + r.stdout);
    for (const c of calls()) { assert.ok(!c.argv.includes(PW), c.argv); assert.ok(!c.raw.includes(PW)); }
    assert.ok(roots().length >= 2); for (const c of roots()) assert.ok(c.stdin.startsWith(PW + '\n'), 'sudo reads the password on stdin');
    assert.ok(r.stdout.includes('leaked: ********')); assert.ok(!r.stdout.includes(PW) && !r.stderr.includes(PW));
    for (const f of auditFiles()) assert.ok(!fs.readFileSync(f, 'utf8').includes(PW), f);
  });
  it('is handed to ssh through an askpass file in a private folder that is gone afterwards', () => {
    const r = run(BROKER, BROKER_ARGS); assert.strictEqual(r.status, 0, r.stderr);
    const ap = fs.readFileSync(path.join(rec, 'askpass-path'), 'utf8').trim(); assert.ok(!fs.existsSync(ap), 'askpass removed'); assert.ok(!fs.existsSync(path.dirname(ap)), 'folder removed');
    assert.ok(!fs.readFileSync(path.join(rec, 'askpass-script'), 'utf8').includes(PW), 'the askpass script holds a path, not the password');
  });
  it('the audit log and the key folder are private', () => { run(BROKER, BROKER_ARGS); const d = fs.readdirSync(out)[0]; assert.strictEqual(fs.statSync(path.join(out, d)).mode & 0o777, 0o700); assert.strictEqual(fs.statSync(path.join(out, d, 'audit-broker-vm.log')).mode & 0o777, 0o600); });
  it('a root login does not use sudo; a wrong sudo password stops before anything is copied', () => {
    let r = run(BROKER, [...BROKER_ARGS].map((x) => (x === 'ash' ? 'root' : x)), { FAKE_USER: 'root' }); assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(roots().length, 0); assert.ok(calls().some((c) => /^bash -c/.test(c.raw)));
    fs.rmSync(rec, { recursive: true }); fs.mkdirSync(rec);
    r = run(BROKER, BROKER_ARGS, { FAKE_SUDO_FAIL: '1' }); assert.notStrictEqual(r.status, 0); assert.match(r.stderr + r.stdout, /cannot become root with sudo/); assert.ok(!calls().some((c) => /tar xzf/.test(c.raw)));
  });
});

describe('the broker VM install', () => {
  it('copies the repo, runs bootstrap-broker.sh with the manager and alerts, reads the key from a file on the VM, and cleans up', () => {
    const r = run(BROKER, BROKER_ARGS); assert.strictEqual(r.status, 0, r.stderr + r.stdout);
    const up = calls().find((c) => /tar xzf/.test(c.raw)); assert.ok(up); assert.ok(up.stdin.length > 1000, 'a tarball went over stdin');
    const boot = roots().find((c) => /bootstrap-broker\.sh/.test(c.cmd)).cmd;
    assert.match(boot, /bootstrap-broker\.sh --wazuh-manager --wazuh-alerts --url 'https:\/\/asix1:30443\/v1\/ingest\/http' --name 'broker-2' --key "\$\(tr -d '\\r\\n' < files\/ingest\.key\)"/);
    for (const c of calls()) { assert.ok(!c.argv.includes(KEY) && !c.raw.includes(KEY) && !c.cmd.includes(KEY), 'the key is in no command'); } assert.ok(calls().some((c) => c.stdin.includes(KEY)), 'the key file went over stdin');
    assert.ok(!r.stdout.includes(KEY)); assert.match(r.stdout, /--key <key from file>/); assert.ok(fs.existsSync(path.join(rec, 'removed'))); assert.match(fs.readFileSync(path.join(rec, 'removed'), 'utf8'), /asix-remote-install/);
    assert.match(r.stdout, /1514\/tcp and 1515\/tcp/); assert.match(r.stdout, /\/var\/log\/asix-remote-install-/);
  });
  it('passes the options through: timezone, port, TLS, config, journald, no alerts, no-install, keep days, extras; copies the named files', () => {
    const r = run(BROKER, [...BROKER_ARGS, '--timezone', 'America/Toronto', '--port', '1514', '--ca', 'ca.pem', '--tls-cert', 'tls.crt', '--tls-key', 'tls.key', '--tls-port', '6514', '--accept-config', '--journald', '--no-alerts', '--no-install', '--wazuh-keep-days', '5', '--', '--file-glob', '/var/log/app/*.log']);
    assert.strictEqual(r.status, 0, r.stderr + r.stdout);
    const boot = roots().find((c) => /bootstrap-broker\.sh/.test(c.cmd)).cmd;
    for (const re of [/--journald/, /--no-install/, /--wazuh-keep-days 5/, /America\/Toronto/, /--port 1514/, /--ca files\/ca\.pem/, /--tls-cert files\/tls\.crt --tls-key files\/tls\.key/, /--tls-port 6514/, /--accept-config/, /--file-glob/]) assert.match(boot, re);
    assert.ok(!/--wazuh-alerts/.test(boot)); assert.ok(calls().some((c) => c.stdin.includes('TLSKEY')));
  });
  it('--indexer-file makes a second step that points the manager at the indexer', () => {
    fs.writeFileSync(path.join(tmp, 'idx.json'), '{"url":"https://i:9200"}\n', { mode: 0o600 });
    const r = run(BROKER, [...BROKER_ARGS, '--indexer-file', 'idx.json', '--indexer-url', 'https://127.0.0.1:9200']); assert.strictEqual(r.status, 0, r.stderr);
    const rs = roots().map((c) => c.cmd); const i = rs.findIndex((c) => /bootstrap-broker/.test(c)), j = rs.findIndex((c) => /install-wazuh-manager\.sh --indexer-file files\/indexer\.json --indexer-url/.test(c)); assert.ok(i >= 0 && j > i);
  });
  it('--check signs in, runs only the manager installer\'s --check, and needs no ingest key or url', () => {
    const r = run(BROKER, [...BASE, '--check']); assert.strictEqual(r.status, 0, r.stderr + r.stdout);
    const rs = roots().map((c) => c.cmd); assert.ok(rs.some((c) => /install-wazuh-manager\.sh --check/.test(c))); assert.ok(!rs.some((c) => /bootstrap-broker/.test(c)));
  });
  it('a failing installer stops the run, names both logs, and still removes the copied folder from the VM', () => {
    const r = run(BROKER, BROKER_ARGS, { FAKE_FAIL_ON: 'bootstrap-broker.sh' }); assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /bootstrap-broker\.sh failed on the VM/); const both = r.stdout + r.stderr; assert.match(both, /audit log on this machine: .*audit-broker-vm\.log/); assert.match(both, /\/var\/log\/asix-remote-install-/);
    assert.ok(fs.existsSync(path.join(rec, 'removed')), 'folder removed after the failure'); assert.ok(fs.readFileSync(auditFiles().find((f) => /audit-broker/.test(f)), 'utf8').includes('installer: something broke'));
  });
});

describe('the indexer VM install', () => {
  it('runs the indexer installer with the address; nothing about tenants without --tenant-name', () => {
    const r = run(INDEXER, [...BASE, '--address', 'idx.local', '--node-name', 'n1', '--heap-gb', '8', '--lab']); assert.strictEqual(r.status, 0, r.stderr + r.stdout);
    const ix = roots().find((c) => /install-wazuh-indexer\.sh/.test(c.cmd)).cmd; for (const re of [/--address/, /idx\.local/, /--node-name/, /--heap-gb 8/, /--lab/]) assert.match(ix, re);
    assert.ok(!roots().some((c) => /wazuh-indexer-tenant/.test(c.cmd))); assert.match(r.stdout, /9200\/tcp/);
  });
  it('makes the tenant user and fetches the registration file (mode 600) under the name the script writes; with --writer also the manager file', () => {
    const r = run(INDEXER, [...BASE, '--address', 'idx.local', '--tenant-name', 'Acme Corp', '--manager-name', 'acme_mgr.1', '--writer', '--writer-address', '127.0.0.1']); assert.strictEqual(r.status, 0, r.stderr + r.stdout);
    const d = path.join(out, fs.readdirSync(out)[0]); const reg = path.join(d, 'asix-indexer-registration-acme-mgr-1.json'), wr = path.join(d, 'asix-manager-indexer-acme-mgr-1.json');
    assert.ok(fs.existsSync(reg) && fs.existsSync(wr), fs.readdirSync(d).join()); assert.strictEqual(fs.statSync(reg).mode & 0o777, 0o600); assert.match(fs.readFileSync(wr, 'utf8'), /asix-mgr-x/);
    const t = roots().map((c) => c.cmd).filter((c) => /wazuh-indexer-tenant/.test(c)); assert.strictEqual(t.length, 2); assert.match(t[1], /--writer/); assert.match(t[1], /--address '127\.0\.0\.1'/); assert.ok(!/--writer/.test(t[0]));
  });
  it('--check runs only the indexer installer\'s --check', () => {
    const r = run(INDEXER, [...BASE, '--address', 'idx.local', '--check']); assert.strictEqual(r.status, 0, r.stderr); const rs = roots().map((c) => c.cmd);
    assert.ok(rs.some((c) => /install-wazuh-indexer\.sh .*--check/.test(c))); assert.ok(!rs.some((c) => /tenant/.test(c)));
  });
  it('a failure in the tenant step stops with the audit log named', () => {
    const r = run(INDEXER, [...BASE, '--address', 'idx.local', '--tenant-name', 'A', '--manager-name', 'm1'], { FAKE_FAIL_ON: 'wazuh-indexer-tenant.sh' }); assert.notStrictEqual(r.status, 0); assert.match(r.stdout + r.stderr, /audit-indexer-vm\.log/);
  });
});
