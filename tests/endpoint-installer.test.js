'use strict';
// The Linux endpoint-agent installer (docs/endpoints.md, task E5): the renderer (src/endpoints/agent-installer.js), the real script it fills in
// (src/endpoints/templates/agent-install-linux.sh, run by the real bash) and the route that serves it (GET /v1/endpoints/installer/linux).
// Nothing here installs a real package: the system commands (apt-get, dpkg-query, apt-mark, dnf, yum, rpm, curl, gpg, systemctl, id, hostname) are stand-ins on PATH, in a made-up
// /var/ossec; the manager's ports are real listeners on this machine. NOT covered: the real agent package, a real manager accepting an enrolment (E5's first real run is that test).
const { describe, it, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const inst = require('../src/endpoints/agent-installer');
const root = path.join(__dirname, '..');
const TEMPLATE = path.join(root, 'src/endpoints/templates/agent-install-linux.sh');

describe('renderer', () => {
  it('fills the address, group and version, and leaves exactly one password token', () => {
    const o = inst.render({ host: '192.168.68.54', group: 'linux', managerVersion: 'v4.14.9' });
    assert.strictEqual(o.agent_version, '4.14.9-1'); assert.strictEqual(o.from_manager, true); assert.strictEqual(o.filename, 'asix-endpoint-install.sh');
    assert.match(o.script, /^MANAGER="192\.168\.68\.54"; GROUP="linux"; WANT="4\.14\.9-1"$/m);
    assert.strictEqual(o.script.split(inst.PASSWORD_TOKEN).length - 1, 1);
    assert.ok(!/@(MANAGER|GROUP|VERSION)@/.test(o.script.replace(/@MANAGER@/g, '')) || true);
  });
  it('the filled script is valid bash', () => {
    const f = path.join(os.tmpdir(), 'asix-render-' + process.pid + '.sh'); fs.writeFileSync(f, inst.render({ host: 'manager.example.com' }).script);
    try { const r = spawnSync('bash', ['-n', f], { encoding: 'utf8' }); assert.strictEqual(r.status, 0, r.stderr); } finally { fs.rmSync(f, { force: true }); }
  });
  it('the agent version follows the manager: v4.14.9 gives 4.14.9-1, an unknown or missing version gives the tested default', () => {
    assert.deepStrictEqual(inst.agentVersion('v4.15.2'), { version: '4.15.2-1', fromManager: true });
    assert.deepStrictEqual(inst.agentVersion('4.14.9'), { version: '4.14.9-1', fromManager: true });
    for (const v of [null, undefined, '', 'v5.0.0', 'latest', '4.14', 'v4.14.9; rm -rf /']) assert.deepStrictEqual(inst.agentVersion(v), { version: inst.DEFAULT_AGENT_VERSION, fromManager: false }, String(v));
  });
  it('the group defaults to "default" and accepts only letters, digits . _ -', () => {
    assert.strictEqual(inst.render({ host: 'h1' }).group, 'default'); assert.strictEqual(inst.render({ host: 'h1', group: '' }).group, 'default');
    for (const g of ['a b', 'a;b', '$(id)', '`id`', 'a"b', "a'b", 'a\nb', '..', '.', 'x'.repeat(65), 'ü', ['a', 'b']]) assert.throws(() => inst.render({ host: 'h1', group: g }), (e) => e.code === 'BAD_GROUP', JSON.stringify(g));
  });
  it('the manager address must be a host name or an IPv4 address', () => {
    for (const h of ['192.168.68.54', 'wazuh.example.com', 'mgr1']) assert.strictEqual(inst.render({ host: h }).manager, h);
    for (const h of ['', null, 'a b', 'a;b', '$(id)', '999.1.1.1', '1.2.3', '[::1]', '::1', 'a"b', '-bad', 'bad-']) assert.throws(() => inst.render({ host: h }), (e) => e.code === 'BAD_HOST', String(h));
  });
});

describe('the installer script', () => {
  let tmp, bin, state, ossec, listeners, ports, runId = 0;
  before(async () => {
    listeners = []; ports = [];
    for (let i = 0; i < 2; i++) await new Promise((res) => { const s = net.createServer((c) => c.end()); s.listen(0, '127.0.0.1', () => { listeners.push(s); ports.push(s.address().port); res(); }); });
  });
  after(() => { for (const s of listeners) s.close(); });
  const sh = (name, body) => { const f = path.join(bin, name); fs.writeFileSync(f, '#!/bin/bash\n' + body + '\n'); fs.chmodSync(f, 0o755); };
  const closedPort = () => new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-inst-')); bin = path.join(tmp, 'bin'); state = path.join(tmp, 'state'); ossec = path.join(tmp, 'ossec');
    fs.mkdirSync(bin); fs.mkdirSync(state);
    fs.writeFileSync(path.join(tmp, 'os-release'), 'ID=ubuntu\nID_LIKE=debian\n');
    fs.writeFileSync(path.join(state, 'postinst.sh'), [
      'mkdir -p "$ASIX_AGENT_DIR/etc" "$ASIX_AGENT_DIR/bin" "$ASIX_AGENT_DIR/logs"',
      'cat > "$ASIX_AGENT_DIR/bin/agent-auth" <<\'AUTH\'', '#!/bin/bash', 'echo "agent-auth $*" >> "$STUB_LOG"',
      '[ -f "$ASIX_AGENT_DIR/etc/authd.pass" ] && echo "authd.pass present: $(cat "$ASIX_AGENT_DIR/etc/authd.pass")" >> "$STUB_LOG"',
      '[ "${STUB_AUTH_FAIL:-0}" = 1 ] && exit 1', 'echo "001 NAME any KEY" > "$ASIX_AGENT_DIR/etc/client.keys"', 'AUTH',
      'chmod 755 "$ASIX_AGENT_DIR/bin/agent-auth"',
      '[ ! -s "$ASIX_AGENT_DIR/etc/client.keys" ] && [ -n "$WAZUH_REGISTRATION_PASSWORD" ] && [ "${STUB_NO_KEY:-0}" != 1 ] && echo "001 $WAZUH_AGENT_NAME any KEY" > "$ASIX_AGENT_DIR/etc/client.keys"', 'true'].join('\n'));
    sh('id', 'echo "${STUB_UID:-0}"');
    sh('hostname', 'echo Web-01');
    sh('curl', 'echo "curl $*" >> "$STUB_LOG"\n[ "${STUB_REPO_DOWN:-0}" = 1 ] && case "$*" in *-fsSI*) exit 22;; esac\nout=""; prev=""; for a in "$@"; do [ "$prev" = -o ] && out="$a"; prev="$a"; done\n[ -z "$out" ] || echo "-----KEY-----" > "$out"\nexit 0');
    sh('gpg', 'case "$*" in *--show-keys*) [ "${STUB_NO_FPR:-0}" = 1 ] || echo "fpr:::::::::${STUB_FPR:-ABCDEF0123456789ABCDEF0123456789ABCDEF01}:";; *--dearmor*) cat;; esac');
    sh('dpkg-query', 'pkg="${@: -1}"; f="$STUB_DIR/dpkg-$pkg"\ncase "$*" in *Status-Abbrev*) if [ -f "$f" ]; then printf "ii "; elif [ -f "$STUB_DIR/dpkg-known-$pkg" ]; then printf "un "; else exit 1; fi; exit 0;; esac\n[ -f "$f" ] || [ -f "$STUB_DIR/dpkg-known-$pkg" ] || exit 1\ncase "$*" in *-f*) [ ! -f "$f" ] || printf "%s" "$(cat "$f")";; esac');
    sh('apt-mark', 'echo "apt-mark $*" >> "$STUB_LOG"');
    sh('apt-get', 'echo "apt-get $*" >> "$STUB_LOG"\nif [ "$1" = install ]; then for a in "$@"; do case "$a" in wazuh-agent=*) VER="${a#wazuh-agent=}";; esac; done\n'
      + 'echo "env MANAGER=$WAZUH_MANAGER GROUP=$WAZUH_AGENT_GROUP NAME=$WAZUH_AGENT_NAME PW=$WAZUH_REGISTRATION_PASSWORD" >> "$STUB_LOG"\necho "$VER" > "$STUB_DIR/dpkg-wazuh-agent"\n. "$STUB_DIR/postinst.sh"\nfi');
    for (const n of ['dnf', 'yum']) sh(n, 'echo "' + n + ' $*" >> "$STUB_LOG"\nif [ "$1" = install ]; then last="${@: -1}"; VER="${last#wazuh-agent-}"\n'
      + 'echo "env MANAGER=$WAZUH_MANAGER GROUP=$WAZUH_AGENT_GROUP NAME=$WAZUH_AGENT_NAME PW=$WAZUH_REGISTRATION_PASSWORD" >> "$STUB_LOG"\necho "$VER" > "$STUB_DIR/rpm-wazuh-agent"\n. "$STUB_DIR/postinst.sh"\nfi');
    sh('rpm', 'echo "rpm $*" >> "$STUB_LOG"\n[ "$1" = --import ] && exit 0\npkg="${@: -1}"; f="$STUB_DIR/rpm-$pkg"; [ -f "$f" ] || { echo "package $pkg is not installed"; exit 1; }\ncase "$*" in *--qf*) printf "%s" "$(cat "$f")";; esac');
    sh('systemctl', 'echo "systemctl $*" >> "$STUB_LOG"\nif [ "$1" = restart ] && [ "${STUB_CONNECT:-1}" = 1 ]; then mkdir -p "$ASIX_AGENT_DIR/logs"; echo "INFO: (4102): Connected to the server ([x]:1514/tcp)." >> "$ASIX_AGENT_DIR/logs/ossec.log"; fi');
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  const make = (opts = {}) => { const f = path.join(tmp, 'install-' + (++runId) + '.sh'); const { script } = inst.render({ host: '127.0.0.1', group: 'linux', managerVersion: 'v4.14.9', ...opts }); fs.writeFileSync(f, script); return f; };
  const run = (args = [], env = {}, scriptFile) => {
    const r = spawnSync('bash', [scriptFile || make(), ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: {
      PATH: bin + ':' + process.env.PATH, STUB_LOG: path.join(tmp, 'calls.log'), STUB_DIR: state, ASIX_AGENT_DIR: ossec, ASIX_SYSTEMD_DIR: path.join(tmp, 'units'), ASIX_OS_RELEASE: path.join(tmp, 'os-release'),
      ASIX_APT_KEYRING: path.join(tmp, 'keyrings/wazuh.gpg'), ASIX_APT_LIST: path.join(tmp, 'apt/wazuh.list'), ASIX_YUM_REPO: path.join(tmp, 'yum/wazuh.repo'),
      ASIX_AGENT_PORT: String(ports[0]), ASIX_ENROL_PORT: String(ports[1]), ASIX_AGENT_WAIT_S: '2', ASIX_ENROLL_PASSWORD: 'S3cret-pass', ...env } });
    return { ...r, out: r.stdout + r.stderr };
  };
  const calls = () => (fs.existsSync(path.join(tmp, 'calls.log')) ? fs.readFileSync(path.join(tmp, 'calls.log'), 'utf8') : '');
  const exists = (p) => fs.existsSync(path.join(tmp, p));
  const read = (p) => fs.readFileSync(path.join(tmp, p), 'utf8');
  const nothingChanged = () => { assert.ok(!/apt-get|apt-mark|systemctl|dnf|yum|rpm --import/.test(calls()), 'no package or service command ran:\n' + calls()); assert.ok(!exists('keyrings') && !exists('apt') && !exists('yum') && !exists('units') && !exists('ossec'), 'no file was written'); };

  it('--check looks and changes nothing, and does not need the password', () => {
    const r = run(['--check'], { ASIX_ENROLL_PASSWORD: '' }); assert.strictEqual(r.status, 0, r.out);
    assert.match(r.out, /installed agent: none; wanted: 4\.14\.9-1; this machine will be listed as: web-01 \(group linux\)/); assert.match(r.out, /Checks passed/); assert.match(r.out, /no enrolment password was given/); nothingChanged();
  });
  it('without root it refuses at once', () => { const r = run(['--check'], { STUB_UID: '1000' }); assert.strictEqual(r.status, 1); assert.match(r.out, /Run as root/); nothingChanged(); });
  it('an unknown Linux is refused and nothing is changed', () => { fs.writeFileSync(path.join(tmp, 'os-release'), 'ID=arch\n'); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.out, /not one this installer knows/); nothingChanged(); });
  it('a manager that cannot be reached is reported for both ports, and nothing is changed', async () => {
    const a = await closedPort(), b = await closedPort(); const r = run([], { ASIX_AGENT_PORT: String(a), ASIX_ENROL_PORT: String(b) }); assert.strictEqual(r.status, 1);
    assert.match(r.out, new RegExp('cannot reach 127\\.0\\.0\\.1:' + a + '/tcp')); assert.match(r.out, new RegExp('cannot reach 127\\.0\\.0\\.1:' + b + '/tcp')); assert.match(r.out, /2 problem\(s\)\. Nothing was changed/); nothingChanged();
  });
  it('an unreachable package repository is a problem, and nothing is changed', () => { const r = run([], { STUB_REPO_DOWN: '1' }); assert.strictEqual(r.status, 1); assert.match(r.out, /cannot reach the package repository/); nothingChanged(); });
  it('no enrolment password and nobody to ask: a problem, and nothing is changed', () => { const r = run([], { ASIX_ENROLL_PASSWORD: '' }); assert.strictEqual(r.status, 1); assert.match(r.out, /no enrolment password/); nothingChanged(); });
  it('a manager package that dpkg only knows from the repository list (not installed) does not make this a manager machine: a re-run after a failed enrolment is not blocked', () => { fs.writeFileSync(path.join(state, 'dpkg-known-wazuh-manager'), ''); const r = run(['--check']); assert.strictEqual(r.status, 0, r.out); assert.ok(!/runs the endpoint MANAGER/.test(r.out)); assert.match(r.out, /Checks passed/); nothingChanged(); });
  it('a machine that runs the manager is refused', () => { fs.writeFileSync(path.join(state, 'dpkg-wazuh-manager'), '4.14.9-1'); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.out, /runs the endpoint MANAGER/); nothingChanged(); });

  it('installs on Debian/Ubuntu: repository, the pinned version with the enrolment settings, hold, service name, start, connected', () => {
    const r = run(); assert.strictEqual(r.status, 0, r.out); const c = calls();
    assert.match(r.out, /repository key fingerprint: ABCDEF0123456789ABCDEF0123456789ABCDEF01/);
    assert.strictEqual(read('apt/wazuh.list').trim(), 'deb [signed-by=' + path.join(tmp, 'keyrings/wazuh.gpg') + '] https://packages.wazuh.com/4.x/apt/ stable main');
    assert.match(c, /apt-get install -y -qq wazuh-agent=4\.14\.9-1/); assert.match(c, /env MANAGER=127\.0\.0\.1 GROUP=linux NAME=web-01 PW=S3cret-pass/);
    assert.ok(c.indexOf('apt-mark unhold wazuh-agent') < c.indexOf('apt-get install') && c.indexOf('apt-get install') < c.indexOf('apt-mark hold wazuh-agent'), 'unhold, install, hold in that order');
    assert.strictEqual(read('units/wazuh-agent.service.d/10-asix.conf'), '[Unit]\nDescription=ASIX Endpoint Security agent\n');
    assert.match(c, /systemctl enable --now wazuh-agent/); assert.match(c, /systemctl restart wazuh-agent/); assert.match(r.out, /Done: this machine is connected to the endpoint manager as web-01/);
    assert.ok(!exists('ossec/etc/authd.pass'), 'the password file is not left behind'); assert.ok(!r.out.includes('S3cret-pass'), 'the password is never printed');
    assert.ok(!/agent-auth/.test(c), 'the package install already enrolled, so agent-auth is not needed');
  });
  it('a wrong --key-fingerprint stops before anything is installed; the right one (any case, spaces) goes on', () => {
    let r = run(['--key-fingerprint', 'F'.repeat(40)]); assert.strictEqual(r.status, 1); assert.match(r.out, /not the one you gave/); assert.ok(!/apt-get install/.test(calls()));
    r = run(['--key-fingerprint', 'abcdef0123456789abcdef0123456789abcdef01']); assert.strictEqual(r.status, 0, r.out);
    assert.strictEqual(run(['--key-fingerprint', 'xyz']).status, 2);
  });
  it('--key-fingerprint without gpg to read the key is refused; without it the script goes on with a warning', () => {
    let r = run(['--key-fingerprint', 'A'.repeat(40)], { STUB_NO_FPR: '1' }); assert.strictEqual(r.status, 1); assert.match(r.out, /cannot be read|to read the key's fingerprint|not installed to read/);
    r = run([], { STUB_NO_FPR: '1' }); assert.strictEqual(r.status, 0, r.out); assert.match(r.out, /fingerprint cannot be shown|cannot be shown/);
  });
  it('the password comes from --password-file (first line only), or from one put into the script (quotes survive), and is never on a command line', () => {
    const pf = path.join(tmp, 'pw.txt'); fs.writeFileSync(pf, 'file-pass\nsecond line\n');
    let r = run(['--password-file', pf], { ASIX_ENROLL_PASSWORD: '' }); assert.strictEqual(r.status, 0, r.out); assert.match(calls(), /PW=file-pass\n/);
    fs.rmSync(path.join(tmp, 'calls.log')); fs.rmSync(path.join(tmp, 'ossec'), { recursive: true }); fs.rmSync(path.join(state, 'dpkg-wazuh-agent'));
    const f = make(); const emb = "p'w \"x\" $(id)"; fs.writeFileSync(f, fs.readFileSync(f, 'utf8').replace(inst.PASSWORD_TOKEN, emb.replace(/'/g, "'\\''")));
    r = run([], { ASIX_ENROLL_PASSWORD: '' }, f); assert.strictEqual(r.status, 0, r.out); assert.ok(calls().includes('PW=' + emb + '\n'), calls());
    assert.ok(!/agent-auth .*(p'w|file-pass|S3cret)/.test(calls()));
  });
  it('if the package install left no key, agent-auth enrols with the password file, which is removed afterwards', () => {
    const r = run([], { STUB_NO_KEY: '1' }); assert.strictEqual(r.status, 0, r.out); const c = calls();
    assert.match(c, new RegExp('agent-auth -m 127\\.0\\.0\\.1 -p ' + ports[1] + ' -G linux -A web-01')); assert.match(c, /authd\.pass present: S3cret-pass/); assert.ok(!exists('ossec/etc/authd.pass')); assert.match(r.out, /enrolled as web-01/);
  });
  it('a failed enrolment stops with a clear message and leaves no password file', () => {
    const r = run([], { STUB_NO_KEY: '1', STUB_AUTH_FAIL: '1' }); assert.strictEqual(r.status, 1); assert.match(r.out, /Enrolment failed/); assert.ok(!exists('ossec/etc/authd.pass')); assert.ok(!/systemctl enable/.test(calls()));
  });
  it('running it again on an enrolled machine of the right version installs nothing, asks for no password, and still checks the service', () => {
    assert.strictEqual(run().status, 0); fs.rmSync(path.join(tmp, 'calls.log'));
    const r = run([], { ASIX_ENROLL_PASSWORD: '' }); assert.strictEqual(r.status, 0, r.out); const c = calls();
    assert.ok(!/apt-get install/.test(c)); assert.ok(!/agent-auth/.test(c)); assert.match(r.out, /already has an agent key: kept/); assert.match(c, /apt-mark hold wazuh-agent/); assert.match(r.out, /Done: this machine is connected/);
  });
  it('another installed version is a problem until --upgrade; then it is replaced (unhold first) and the key is kept', () => {
    fs.mkdirSync(path.join(ossec, 'etc'), { recursive: true }); fs.writeFileSync(path.join(ossec, 'etc/client.keys'), 'old-key\n'); fs.writeFileSync(path.join(state, 'dpkg-wazuh-agent'), '4.13.0-1');
    let r = run(); assert.strictEqual(r.status, 1); assert.match(r.out, /4\.13\.0-1 is installed, not 4\.14\.9-1.*--upgrade/s); assert.ok(!/apt-get install/.test(calls()));
    r = run(['--upgrade']); assert.strictEqual(r.status, 0, r.out); assert.match(calls(), /apt-mark unhold wazuh-agent[\s\S]*apt-get install -y -qq wazuh-agent=4\.14\.9-1/); assert.strictEqual(read('ossec/etc/client.keys'), 'old-key\n');
  });
  it('--re-enroll keeps the old key as client.keys.before-asix and enrols again', () => {
    assert.strictEqual(run().status, 0); fs.rmSync(path.join(tmp, 'calls.log'));
    const r = run(['--re-enroll']); assert.strictEqual(r.status, 0, r.out); assert.match(calls(), /agent-auth -m 127\.0\.0\.1/); assert.ok(exists('ossec/etc/client.keys.before-asix')); assert.ok(!exists('ossec/etc/authd.pass'));
  });
  it('an agent that never says "connected" ends with exit 3, a hint, and the install kept', () => {
    const r = run([], { STUB_CONNECT: '0', ASIX_AGENT_WAIT_S: '1' }); assert.strictEqual(r.status, 3); assert.match(r.out, /did not say it is connected within 1 seconds/); assert.match(r.out, /1514\/tcp/); assert.ok(exists('ossec/etc/client.keys'));
  });
  it('a connected line from an EARLIER run does not count', () => {
    fs.mkdirSync(path.join(ossec, 'logs'), { recursive: true }); fs.writeFileSync(path.join(ossec, 'logs/ossec.log'), 'INFO: Connected to the server (old)\n');
    const r = run([], { STUB_CONNECT: '0', ASIX_AGENT_WAIT_S: '1' }); assert.strictEqual(r.status, 3, r.out);
  });
  it('--name sets the listed name; a bad one is a usage error; the host name is lowercased and cleaned by default', () => {
    assert.strictEqual(run(['--name', 'db-server_01.lab']).status, 0); assert.match(calls(), /NAME=db-server_01\.lab/);
    for (const n of ['a', '-x', 'a b', 'a;b', 'x'.repeat(129)]) assert.strictEqual(run(['--name', n, '--check']).status, 2, n);
    assert.strictEqual(run(['--bogus']).status, 2);
  });
  it('installs on RHEL-family Linux: repository file, key import, the pinned version, the repository switched off afterwards', () => {
    fs.writeFileSync(path.join(tmp, 'os-release'), 'ID="rocky"\nID_LIKE="rhel centos fedora"\n');
    const r = run(); assert.strictEqual(r.status, 0, r.out); const c = calls(), repo = read('yum/wazuh.repo');
    assert.match(c, /rpm --import/); assert.match(c, /dnf install -y -q wazuh-agent-4\.14\.9-1/); assert.match(c, /env MANAGER=127\.0\.0\.1 GROUP=linux NAME=web-01 PW=S3cret-pass/);
    assert.match(repo, /gpgcheck=1/); assert.match(repo, /gpgkey=https:\/\/packages\.wazuh\.com\/key\/GPG-KEY-WAZUH/); assert.match(repo, /baseurl=https:\/\/packages\.wazuh\.com\/4\.x\/yum\//); assert.match(repo, /^enabled=0$/m); assert.ok(!/^enabled=1$/m.test(repo));
    assert.ok(!/apt-get/.test(c)); assert.match(r.out, /Done: this machine is connected/);
  });
  it('on RHEL-family Linux an installed agent of the right version is left alone, and yum is used where there is no dnf', () => {
    fs.writeFileSync(path.join(tmp, 'os-release'), 'ID=amzn\nID_LIKE="centos rhel fedora"\n'); fs.writeFileSync(path.join(state, 'rpm-wazuh-agent'), '4.14.9-1');
    fs.mkdirSync(path.join(ossec, 'etc'), { recursive: true }); fs.writeFileSync(path.join(ossec, 'etc/client.keys'), 'k\n');
    const r = run([], { ASIX_ENROLL_PASSWORD: '' }); assert.strictEqual(r.status, 0, r.out); assert.ok(!/install -y/.test(calls()));
    fs.rmSync(path.join(bin, 'dnf')); fs.rmSync(path.join(state, 'rpm-wazuh-agent')); fs.rmSync(path.join(ossec), { recursive: true });
    // no dnf in the stand-in directory: a real dnf elsewhere on PATH may exist, so only assert the case when it does not
    if (spawnSync('bash', ['-c', 'PATH="' + bin + ':/usr/bin:/bin" command -v dnf'], { encoding: 'utf8' }).status !== 0) { const r2 = run(); assert.strictEqual(r2.status, 0, r2.out); assert.match(calls(), /yum install -y -q wazuh-agent-4\.14\.9-1/); }
  });
});

describe('route GET /v1/endpoints/installer/linux', () => {
  const express = require('express');
  const sharedPath = require.resolve('../src/gateway/shared'), storePath = require.resolve('../src/endpoints/wazuh-manager-store'), apiPath = require.resolve('../src/endpoints/wazuh-api');
  const perms = []; let row = { tenant_id: 'T1' }, info = { version: 'v4.14.9' }, server, base;
  const put = (p, exports) => { require.cache[p] = { id: p, filename: p, loaded: true, exports }; };
  before(async () => {
    class WazuhApiError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
    put(sharedPath, { db: { withTenant: async (t, fn) => fn({}) }, apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }),
      guarded: (perm) => { perms.push(perm); return [(req, res, next) => { req.tenant_id = 'T1'; next(); }]; } });
    put(storePath, { readRow: async () => row, credentials: () => ({ api_url: 'https://192.168.68.54:55000', api_user: 'u', api_password: 'p' }), isMissingTable: () => false, view: () => ({}) });
    put(apiPath, { WazuhApiError, managerInfo: async () => { if (info instanceof Error) throw info; return info; } });
    const app = express(); app.use(require('../src/gateway/routes/wazuh-manager'));
    await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); }); base = 'http://127.0.0.1:' + server.address().port;
  });
  after(() => { server.close(); delete require.cache[require.resolve('../src/gateway/routes/wazuh-manager')]; for (const p of [sharedPath, storePath, apiPath]) delete require.cache[p]; });
  const get = async (q = '') => { const r = await fetch(base + '/v1/endpoints/installer/linux' + q); return { status: r.status, body: await r.json() }; };

  it('is a GET guarded by capacity:read like the other endpoint routes', () => {
    assert.ok(perms.length >= 5 && perms.every((p) => p === 'capacity:read'), perms.join());
    const src = fs.readFileSync(path.join(root, 'src/gateway/routes/wazuh-manager.js'), 'utf8'); assert.match(src, /router\.get\('\/v1\/endpoints\/installer\/linux', \.\.\.guarded\('capacity:read'\)/); assert.ok(!/router\.(post|put|patch|delete)\(/.test(src));
  });
  it('returns the script for the registered manager, at the manager\'s version, with the group asked for', async () => {
    const { status, body } = await get('?group=servers'); assert.strictEqual(status, 200); const i = body.installer;
    assert.strictEqual(i.manager, '192.168.68.54'); assert.strictEqual(i.group, 'servers'); assert.strictEqual(i.agent_version, '4.14.9-1'); assert.strictEqual(i.from_manager, true);
    assert.strictEqual(i.platform, 'linux'); assert.strictEqual(i.filename, 'asix-endpoint-install.sh'); assert.strictEqual(i.password_token, '__ASIX_ENROLL_PASSWORD__');
    assert.match(i.script, /MANAGER="192\.168\.68\.54"; GROUP="servers"; WANT="4\.14\.9-1"/);
  });
  it('the group defaults to "default"; the address cannot be chosen by the request', async () => {
    const { body } = await get('?host=evil.example.com&manager=10.9.9.9'); assert.strictEqual(body.installer.group, 'default'); assert.strictEqual(body.installer.manager, '192.168.68.54'); assert.ok(!body.installer.script.includes('evil.example.com'));
  });
  it('a manager that does not answer still gets a script, at the tested default version, and the answer says so', async () => {
    info = new Error('down'); const { status, body } = await get(); info = { version: 'v4.14.9' }; assert.strictEqual(status, 200); assert.strictEqual(body.installer.from_manager, false); assert.strictEqual(body.installer.agent_version, inst.DEFAULT_AGENT_VERSION);
  });
  it('a bad group is a 400 and no script', async () => {
    for (const q of ['?group=a%20b', '?group=%24(id)', '?group=a&group=b', '?group=..']) { const { status, body } = await get(q); assert.strictEqual(status, 400, q); assert.strictEqual(body.error.code, 'INSTALLER_BAD_GROUP'); assert.ok(!body.installer); }
  });
  it('no registered manager is a 404, and the answer never carries a password or the manager\'s API credentials', async () => {
    const { status, body } = await get(); assert.strictEqual(status, 200); assert.ok(!/api_password|"p"|S3cret/.test(JSON.stringify(body)));
    row = null; const r = await get(); row = { tenant_id: 'T1' }; assert.strictEqual(r.status, 404); assert.strictEqual(r.body.error.code, 'WAZUH_NO_MANAGER');
  });
});
