'use strict';
// scripts/deploy/wazuh-api-setup.sh (docs/endpoints.md, task E4c): the REAL script, with the REAL curl, openssl and python3, against a stand-in Wazuh API over HTTPS
// (tests/fixtures/fake-wazuh-api.js in its "fresh manager" mode: the default users wazuh and wazuh-wui, the default roles, the password policy). Only `id` is stubbed (so the
// test runs as any user) and `curl` is wrapped to record its arguments. NOT covered: a real Wazuh manager. The stand-in follows the documented Wazuh 4.x API from memory of
// its documentation; a real manager can differ, and the script stops with a message rather than going on when it does.
const { describe, it, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const fake = require('./fixtures/fake-wazuh-api');

const SCRIPT = path.join(__dirname, '..', 'scripts/deploy/wazuh-api-setup.sh');
const have = [['curl', '--version'], ['openssl', 'version'], ['python3', '--version']].every(([c, a]) => spawnSync(c, [a]).status === 0);
const CURL = (spawnSync('sh', ['-c', 'command -v curl'], { encoding: 'utf8' }).stdout || '').trim();

describe('wazuh-api-setup.sh', { skip: have ? false : 'needs curl, openssl and python3' }, () => {
  let M, tmp, bin, oss, out, curlLog;
  beforeEach(async () => {
    M = await fake.start({ security: true, tag: 'M' });
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wzsetup-')); bin = path.join(tmp, 'bin'); oss = path.join(tmp, 'ossec'); out = path.join(tmp, 'out'); curlLog = path.join(tmp, 'curl.log');
    fs.mkdirSync(bin); fs.mkdirSync(path.join(oss, 'etc'), { recursive: true });
    fs.writeFileSync(path.join(bin, 'id'), '#!/bin/sh\necho 0\n', { mode: 0o755 });
    fs.writeFileSync(path.join(bin, 'curl'), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${curlLog}'\nexec ${CURL} "$@"\n`, { mode: 0o755 });
  });
  afterEach(async () => { await M.stop(); fs.rmSync(tmp, { recursive: true, force: true }); });

  const run = (args, env = {}) => new Promise((resolve) => {
    const p = spawn('bash', [SCRIPT, ...args], { env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_WAZUH_DIR: oss, ASIX_WAZUH_API_BASE: M.url, ...env } });
    let so = '', se = ''; p.stdout.on('data', (d) => { so += d; }); p.stderr.on('data', (d) => { se += d; });
    p.on('close', (code) => resolve({ code, out: so, err: se, all: so + se }));
  });
  const full = (extra = []) => run(['--address', '10.9.8.7', '--cert-file', M.certFile, '--out-dir', out, '--label', 'Acme central', ...extra]);
  const pw = (f) => fs.readFileSync(path.join(oss, 'etc', f), 'utf8').trim();
  const mode = (f) => (fs.statSync(f).mode & 0o777).toString(8);
  const writes = () => M.state.requests.filter((r) => r.method !== 'GET' && !r.path.startsWith('/security/user/authenticate')).map((r) => r.method + ' ' + r.path.replace(/\?.*/, ''));

  it('--check on a fresh manager says what is wrong (both default passwords), exits 1, and changes and writes nothing', async () => {
    const r = await run(['--check', '--cert-file', M.certFile]);
    assert.strictEqual(r.code, 1, r.all); assert.match(r.err, /'wazuh' still has its DEFAULT password/); assert.match(r.err, /'wazuh-wui' still has its DEFAULT password/);
    assert.deepStrictEqual(writes(), []); assert.strictEqual(M.state.users.get('wazuh').password, 'wazuh'); assert.deepStrictEqual(fs.readdirSync(path.join(oss, 'etc')), []); assert.ok(!fs.existsSync(out));
  });

  it('a full run: both default passwords replaced, a read-only user with the read-only role, a registration file that works, and no secret on any command line or in any output', async () => {
    const r = await full(); assert.strictEqual(r.code, 0, r.all);
    const admin = pw('asix-api-admin.pass'), wui = pw('asix-api-wui.pass'), ro = pw('asix-api-readonly.pass');
    assert.deepStrictEqual([M.state.users.get('wazuh').password, M.state.users.get('wazuh-wui').password], [admin, wui]); assert.notStrictEqual(admin, 'wazuh'); assert.notStrictEqual(wui, 'wazuh-wui');
    const u = M.state.users.get('asix-readonly'); assert.ok(u, 'created'); assert.strictEqual(u.password, ro); assert.deepStrictEqual(u.roles, [2], 'the readonly role and nothing else');
    for (const p of [admin, wui, ro]) assert.ok(p.length >= 24 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p), 'a password the API policy accepts');
    assert.strictEqual(new Set([admin, wui, ro]).size, 3, 'three different passwords');
    for (const f of ['asix-api-admin.pass', 'asix-api-wui.pass', 'asix-api-readonly.pass']) assert.strictEqual(mode(path.join(oss, 'etc', f)), '600', f);
    const regf = path.join(out, 'asix-wazuh-registration.json'); assert.strictEqual(mode(regf), '600');
    const reg = JSON.parse(fs.readFileSync(regf, 'utf8'));
    assert.deepStrictEqual([reg.url, reg.user, reg.password, reg.label], ['https://10.9.8.7:55000', 'asix-readonly', ro, 'Acme central']); assert.strictEqual(reg.ca_pem.trim(), M.cert.trim());
    for (const secret of [admin, wui, ro]) { assert.ok(!r.all.includes(secret), 'a password in the output'); assert.ok(!fs.readFileSync(curlLog, 'utf8').includes(secret), 'a password on a curl command line'); }
    assert.ok(!r.all.includes('Bearer'), 'no token in the output'); assert.ok(!fs.readFileSync(curlLog, 'utf8').split('\n').some((l) => /eyJ|Bearer/.test(l)), 'no token on a command line');
    assert.match(r.out, /kubectl -n asix-platform exec -i deploy\/asix-api -- node src\/endpoints\/wazuh-manager-cli\.js register/);
  });

  it('the file it writes is what ASIX consumes: the registration is accepted, and the proxy client signs in with it and reads the manager', async () => {
    assert.strictEqual((await full()).code, 0);
    const reg = JSON.parse(fs.readFileSync(path.join(out, 'asix-wazuh-registration.json'), 'utf8'));
    process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true';
    const store = require('../src/endpoints/wazuh-manager-store'), api = require('../src/endpoints/wazuh-api');
    const p = store.parseRegistration(reg); assert.ok(p.reg, p.error);
    const info = await api.managerInfo({ tenant_id: 'T-setup', api_url: M.url, api_user: reg.user, api_password: reg.password, ca_pem: reg.ca_pem, cert_sha256: p.reg.cert_sha256, api_secret_enc_hash: 's' });
    assert.strictEqual(info.version, 'v4.14.9');
    assert.strictEqual((await api.agentsSummary({ tenant_id: 'T-setup', api_url: M.url, api_user: reg.user, api_password: reg.password, ca_pem: reg.ca_pem, cert_sha256: 'x', api_secret_enc_hash: 's' })).total, 4);
    await assert.rejects(() => api.listAgents({ tenant_id: 'T-setup', api_url: M.url, api_user: 'wazuh', api_password: 'wazuh', ca_pem: reg.ca_pem, cert_sha256: 'x', api_secret_enc_hash: 'd' }, api.parseAgentQuery({})), (e) => e.code === 'AUTH_FAILED', 'and the default password no longer works');
  });

  it('run again with nothing to do: no password changes, no user created, the same registration; --check is then clean', async () => {
    assert.strictEqual((await full()).code, 0); const before = { a: pw('asix-api-admin.pass'), w: pw('asix-api-wui.pass'), r: pw('asix-api-readonly.pass') }, reg1 = fs.readFileSync(path.join(out, 'asix-wazuh-registration.json'), 'utf8');
    M.state.requests.length = 0;
    const r = await full(); assert.strictEqual(r.code, 0, r.all); assert.deepStrictEqual(writes(), [], 'nothing was written to the API');
    assert.deepStrictEqual({ a: pw('asix-api-admin.pass'), w: pw('asix-api-wui.pass'), r: pw('asix-api-readonly.pass') }, before); assert.strictEqual(fs.readFileSync(path.join(out, 'asix-wazuh-registration.json'), 'utf8'), reg1);
    assert.match(r.out, /already off its default password/); assert.match(r.out, /exists and its saved password works/);
    const c = await run(['--check', '--cert-file', M.certFile]); assert.strictEqual(c.code, 0, c.all); assert.match(c.out, /Nothing to do/);
  });

  it('--rotate replaces only the read-only password, and the registration follows', async () => {
    assert.strictEqual((await full()).code, 0); const admin = pw('asix-api-admin.pass'), ro = pw('asix-api-readonly.pass');
    const r = await full(['--rotate']); assert.strictEqual(r.code, 0, r.all);
    assert.notStrictEqual(pw('asix-api-readonly.pass'), ro); assert.strictEqual(pw('asix-api-admin.pass'), admin);
    assert.strictEqual(M.state.users.get('asix-readonly').password, pw('asix-api-readonly.pass')); assert.strictEqual(JSON.parse(fs.readFileSync(path.join(out, 'asix-wazuh-registration.json'), 'utf8')).password, pw('asix-api-readonly.pass'));
  });

  it('a read-only user that exists with a password nobody has saved gets a new one (the registration must work)', async () => {
    M.state.users.set('asix-readonly', { id: 50, password: 'Unknown-pw-1!', roles: [] });
    const r = await full(); assert.strictEqual(r.code, 0, r.all); assert.strictEqual(M.state.users.get('asix-readonly').password, pw('asix-api-readonly.pass')); assert.deepStrictEqual(M.state.users.get('asix-readonly').roles, [2]);
  });

  it('a certificate other than the one pinned is refused before ANY request is made: nothing is sent to an impostor on port 55000', async () => {
    const other = fake.makeCert(tmp, { cn: 'impostor' });
    const r = await run(['--address', '10.9.8.7', '--cert-file', other.certFile, '--out-dir', out]);
    assert.strictEqual(r.code, 1); assert.match(r.err, /no answer from/); assert.strictEqual(M.state.requests.length, 0, 'the manager saw no request'); assert.ok(!fs.existsSync(out));
  });

  it('without a certificate file it reads the certificate from the running API', async () => {
    const r = await run(['--address', '10.9.8.7', '--cert-file', path.join(tmp, 'missing.crt'), '--out-dir', out]); assert.strictEqual(r.code, 0, r.all); assert.match(r.out, /reading the certificate from the running API/);
    assert.strictEqual(JSON.parse(fs.readFileSync(path.join(out, 'asix-wazuh-registration.json'), 'utf8')).ca_pem.trim(), M.cert.trim());
  });

  it('if the API refuses the new admin password, the default is left alone and no password file is left behind', async () => {
    M.state.refuse.add('PUT /security/users/1');
    const r = await full(); assert.strictEqual(r.code, 1); assert.match(r.err, /refused the new password of 'wazuh'/);
    assert.strictEqual(M.state.users.get('wazuh').password, 'wazuh'); assert.ok(!fs.existsSync(path.join(oss, 'etc', 'asix-api-admin.pass'))); assert.ok(!fs.existsSync(out));
  });

  it('no `readonly` role: it stops before creating anything that could do more than read', async () => {
    M.state.roles = M.state.roles.filter((x) => x.name !== 'readonly');
    const r = await full(); assert.strictEqual(r.code, 1); assert.match(r.err, /no role called 'readonly'/); assert.ok(!M.state.users.has('asix-readonly'));
  });

  it('a user that cannot read the manager (a role without the right) is caught by the last check, not left to fail in ASIX', async () => {
    M.state.roles = [{ id: 1, name: 'administrator' }, { id: 7, name: 'readonly' }];     // a `readonly` role that does not carry read rights in this stand-in (it only reads for id 2)
    const r = await full(); assert.strictEqual(r.code, 1); assert.match(r.err, /cannot read the manager's information \(HTTP 403\)/); assert.ok(!fs.existsSync(path.join(out, 'asix-wazuh-registration.json')), 'no registration file for a user that cannot work');
  });

  it('no API answering is a clear error; a wrong password for a changed admin is a clear error', async () => {
    const dead = await run(['--address', '10.9.8.7', '--cert-file', M.certFile, '--out-dir', out], { ASIX_WAZUH_API_BASE: 'https://127.0.0.1:1' }); assert.strictEqual(dead.code, 1); assert.match(dead.err, /no answer|could not read a certificate/);
    M.state.users.get('wazuh').password = 'Changed-By-Someone-1!';
    const r = await full(); assert.strictEqual(r.code, 1); assert.match(r.err, /cannot sign in to the API as 'wazuh'/); assert.deepStrictEqual(writes(), []);
  });

  it('usage errors exit 2 before anything is done', async () => {
    for (const args of [[], ['--address', '127.0.0.1'], ['--address', 'localhost'], ['--address', 'bad host'], ['--address', '10.9.8.7', '--port', '99999'], ['--address', '10.9.8.7', '--port', 'x'], ['--address', '10.9.8.7', '--user', 'a'], ['--bogus']]) { const r = await run(args); assert.strictEqual(r.code, 2, args.join(' ')); }
    assert.strictEqual(M.state.requests.length, 0);
  });

  it('it is not run by anyone but root', async () => {
    fs.writeFileSync(path.join(bin, 'id'), '#!/bin/sh\necho 1000\n', { mode: 0o755 });
    const r = await full(); assert.strictEqual(r.code, 1); assert.match(r.err, /Run as root/); assert.strictEqual(M.state.requests.length, 0);
  });
});
