'use strict';
// The manager side of the vulnerability tab (docs/endpoints.md, task E6g): (1) the ossec.conf editor's indexer mode, (2) install-wazuh-manager.sh --indexer-file /
// --indexer-off and the kept setting on a re-run, (3) wazuh-indexer-tenant.sh --writer. Stand-ins: apt-get, dpkg-query, systemctl, ss, curl, wazuh-keystore (installer
// tests) and a stand-in for the OpenSearch security API over HTTPS (writer tests); the editor, both scripts, bash, python3, openssl and curl are the real ones.
// NOT covered: a real Wazuh manager reading this configuration, a real keystore, a real indexer accepting the manager's writes (E6g's first real run is that test).
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { spawn, spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const EDIT = path.join(root, 'deploy/wazuh/ossec-edit.py'), INSTALL = path.join(root, 'scripts/deploy/install-wazuh-manager.sh'), TENANT = path.join(root, 'scripts/deploy/wazuh-indexer-tenant.sh');
const SAMPLE = fs.readFileSync(path.join(__dirname, 'fixtures/ossec-manager-default.conf'), 'utf8');
const hasPython = spawnSync('python3', ['--version']).status === 0;
const have = [['openssl', 'version'], ['python3', '--version'], ['curl', '--version']].every(([c, a]) => spawnSync(c, [a]).status === 0);
const lines = (t) => t.split('\n');
const changed = (a, b) => lines(a).map((l, i) => [i, l, lines(b)[i]]).filter(([, x, y]) => x !== y).map(([i, x, y]) => `${i + 1}: ${x.trim()} -> ${(y || '').trim()}`);
const URL = 'https://127.0.0.1:9200', CA = '/var/ossec/etc/indexer-root-ca.pem';

describe('ossec.conf editor, indexer mode (E6g)', { skip: hasPython ? false : 'no python3' }, () => {
  let tmp, f;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ossec-idx-')); f = path.join(tmp, 'ossec.conf'); });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const run = (text, args) => { fs.writeFileSync(f, text); const r = spawnSync('python3', [EDIT, f, ...args], { encoding: 'utf8' }); return { ...r, out: fs.readFileSync(f, 'utf8') }; };
  const ON = ['--indexer-url', URL, '--indexer-ca', CA];

  it('on a default-shaped config exactly the logall, the password, the host and the CA lines change; detection and indexer stay ON', () => {
    const r = run(SAMPLE, ON); assert.strictEqual(r.status, 0, r.stderr);
    assert.deepStrictEqual(changed(SAMPLE, r.out), ['11: <logall_json>no</logall_json> -> <logall_json>yes</logall_json>', `59: <host>https://0.0.0.0:9200</host> -> <host>${URL}</host>`, `63: <ca>/etc/filebeat/certs/root-ca.pem</ca> -> <ca>${CA}</ca>`, '79: <use_password>no</use_password> -> <use_password>yes</use_password>']);
    assert.match(r.stdout, /vulnerability-detection\/enabled: unchanged/); assert.match(r.stdout, /indexer\/hosts\/host: applied/); assert.ok(!/missing/.test(r.stdout));
  });
  it('a detection or indexer block that was switched OFF (by the default mode) is switched back ON; index-status is added when missing', () => {
    const off = run(SAMPLE, []).out; assert.match(off, /<vulnerability-detection>\s*<enabled>no</);
    const r = run(off.replace(/ {4}<index-status>yes<\/index-status>\n/, ''), ON); assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.out, /<vulnerability-detection>\n {4}<index-status>yes<\/index-status>\n {4}<enabled>yes<\/enabled>/); assert.match(r.out, /<indexer>\n {4}<enabled>yes<\/enabled>/);
    assert.strictEqual(run(r.out, ON).stdout.includes('applied'), false, 'and then it is stable');
  });
  it('the other way round: the default mode still switches both OFF after indexer mode (E4b behaviour unchanged)', () => {
    const on = run(SAMPLE, ON).out; const r = run(on, []); assert.strictEqual(r.status, 0); assert.match(r.stdout, /vulnerability-detection\/enabled: applied\nindexer\/enabled: applied/); assert.match(r.out, /<vulnerability-detection>\s*<enabled>no</);
  });
  it('a <certificate> and a <key> in the indexer ssl block are removed (whole lines); the host stays a single host', () => {
    const text = SAMPLE.replace('    </ssl>\n  </indexer>', '      <certificate>/etc/filebeat/certs/filebeat.pem</certificate>\n      <key>/etc/filebeat/certs/filebeat-key.pem</key>\n    </ssl>\n  </indexer>');
    assert.match(text, /filebeat-key/); const r = run(text, ON); assert.strictEqual(r.status, 0, r.stderr);
    const idx = r.out.slice(r.out.indexOf('<indexer>'), r.out.indexOf('</indexer>')); assert.ok(!/<certificate>|<key>|filebeat/.test(idx)); assert.match(r.out, /<key><\/key>/, 'the <key> of the auth block is not ours'); assert.match(r.stdout, /indexer\/ssl\/certificate: applied\nindexer\/ssl\/key: applied/);
    assert.strictEqual(lines(r.out).length, lines(SAMPLE).length + 0, 'two lines were removed, nothing else was added or lost');
    assert.match(r.out, /<certificate_authorities>\n {8}<ca>\/var\/ossec\/etc\/indexer-root-ca\.pem<\/ca>\n {6}<\/certificate_authorities>\n {4}<\/ssl>/);
  });
  it('a <key> or <certificate> OUTSIDE the indexer block is never touched', () => {
    const text = SAMPLE + '\n<ossec_config>\n  <other>\n    <ssl>\n      <key>/keep/this.pem</key>\n      <certificate>/keep/that.pem</certificate>\n    </ssl>\n  </other>\n</ossec_config>\n';
    const r = run(text, ON); assert.match(r.out, /<key>\/keep\/this\.pem<\/key>/); assert.match(r.out, /<certificate>\/keep\/that\.pem<\/certificate>/);
  });
  it('commented-out indexer blocks are never edited', () => {
    const text = SAMPLE.replace(/ {2}<indexer>[\s\S]*?<\/indexer>\n/, (m) => '<!--\n' + m + '-->\n'); const r = run(text, ON);
    assert.strictEqual(r.status, 3); assert.match(r.stderr, /vulnerability-detection or indexer block/); assert.strictEqual(r.out, text, 'nothing was written');
  });
  it('a missing block in indexer mode is exit 3 and the file is not written (not even the logall change)', () => {
    for (const re of [/ {2}<vulnerability-detection>[\s\S]*?<\/vulnerability-detection>\n/, / {2}<indexer>[\s\S]*?<\/indexer>\n/, / {6}<host>.*<\/host>\n/, / {8}<ca>.*<\/ca>\n/]) {
      const text = SAMPLE.replace(re, ''); const r = run(text, ON); assert.strictEqual(r.status, 3, String(re)); assert.strictEqual(r.out, text, String(re));
    }
  });
  it('--check reports and writes nothing in indexer mode', () => { const r = run(SAMPLE, [...ON, '--check']); assert.strictEqual(r.status, 0); assert.strictEqual(r.out, SAMPLE); assert.match(r.stdout, /indexer\/hosts\/host: applied/); });
  it('bad values are refused with exit 2 before anything is read: odd URLs, odd paths, one option alone, an unknown option', () => {
    for (const a of [['--indexer-url', 'http://x:9200', '--indexer-ca', CA], ['--indexer-url', 'https://x:9200/path', '--indexer-ca', CA], ['--indexer-url', 'https://x</host>', '--indexer-ca', CA], ['--indexer-url', 'https://a b', '--indexer-ca', CA],
      ['--indexer-url', URL, '--indexer-ca', 'relative.pem'], ['--indexer-url', URL, '--indexer-ca', '/a/../etc/x'], ['--indexer-url', URL, '--indexer-ca', '/a/<b>'], ['--indexer-url', URL], ['--indexer-ca', CA], ['--indexer-url'], ['--nope']]) {
      const r = run(SAMPLE, a); assert.strictEqual(r.status, 2, a.join(' ')); assert.strictEqual(r.out, SAMPLE, a.join(' '));
    }
  });
});

describe('install-wazuh-manager.sh --indexer-file (system commands stood in)', { skip: hasPython ? false : 'no python3' }, () => {
  let tmp, bin, log, env, idxFile;
  const sh = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const put = (f, v) => fs.writeFileSync(path.join(tmp, f), v);
  const logged = (re) => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n') : []).filter((l) => re.test(l));
  const FPR = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678', PW = 'Wr1ter-Secret-0123456789Aa1!';
  const CERT = '-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----';
  const conf = () => path.join(tmp, 'ossec/etc/ossec.conf');
  const writeIdx = (o = {}) => fs.writeFileSync(idxFile, JSON.stringify({ url: 'https://indexer.internal:9200', user: 'asix-mgr-acme', password: PW, ca_pem: CERT + '\n', index: 'wazuh-states-vulnerabilities-acme', ...o }), { mode: 0o600 });
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'inst-idx-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); idxFile = path.join(tmp, 'asix-manager-indexer-acme.json'); fs.mkdirSync(bin);
    for (const f of ['installed', 'listening', 'busy']) put(f, ''); put('nproc', '4'); put('mem', 'MemTotal:        8192000 kB\n'); put('disk', '120'); put('repo-rc', '0'); put('test-rc', '0'); put('start-rc', '0'); put('auth-http', '200'); put('ks-rc', '0');
    sh('id', 'echo 0');
    sh('nproc', `cat '${tmp}/nproc'`);
    sh('df', `printf 'Filesystem 1G-blocks Used Available Capacity Mounted\\n/dev/x 200G 80G %sG 40%% /\\n' "$(cat '${tmp}/disk')"`);
    // the stand-in curl logs its arguments; the credentials arrive through -K <fd>, so they are read here the way the real curl would (and never logged)
    sh('curl', `echo "curl $*" >> '${log}'; out=""; p=""; cfgfd=""; for a in "$@"; do [ "$p" = "-o" ] && out="$a"; [ "$p" = "-K" ] && cfgfd="$a"; p="$a"; done
[ -z "$cfgfd" ] || cat "$cfgfd" > '${tmp}/last-curl-config'
case "$*" in *InRelease*) exit $(cat '${tmp}/repo-rc');; *GPG-KEY*) echo "fake key" > "$out"; exit 0;; *authinfo*) printf '%s' "$(cat '${tmp}/auth-http')"; exit 0;; esac; exit 0`);
    sh('gpg', `echo "gpg $*" >> '${log}'; case "$*" in *--show-keys*) echo "fpr:::::::::${FPR}:";; *--dearmor*) cat;; esac`);
    sh('dpkg-query', `v=$(cat '${tmp}/installed'); [ -n "$v" ] && printf '%s' "$v" || exit 1`);
    sh('apt-get', `echo "apt-get $*" >> '${log}'
case "$*" in *"install"*) v="\${@: -1}"; v="\${v#wazuh-manager=}"; mkdir -p '${tmp}/ossec/etc' '${tmp}/ossec/bin' '${tmp}/ossec/logs'
  [ -e '${tmp}/ossec/etc/ossec.conf' ] || cp '${root}/tests/fixtures/ossec-manager-default.conf' '${tmp}/ossec/etc/ossec.conf'
  printf '#!/bin/bash\\nexit $(cat ${tmp}/test-rc)\\n' > '${tmp}/ossec/bin/wazuh-analysisd'; chmod +x '${tmp}/ossec/bin/wazuh-analysisd'
  printf '#!/bin/bash\\necho "keystore $*" >> ${log}\\nexit $(cat ${tmp}/ks-rc)\\n' > '${tmp}/ossec/bin/wazuh-keystore'; chmod +x '${tmp}/ossec/bin/wazuh-keystore'; echo "$v" > '${tmp}/installed';; esac; exit 0`);
    sh('apt-mark', `echo "apt-mark $*" >> '${log}'`);
    sh('systemctl', `echo "systemctl $*" >> '${log}'; case "$*" in *"restart wazuh-manager"*) [ "$(cat '${tmp}/start-rc')" = 0 ] && echo "1514 1515" > '${tmp}/listening' || exit 1;; esac; exit 0`);
    sh('ss', `for p in $(cat '${tmp}/busy') $(cat '${tmp}/listening'); do case "$*" in *":$p "*) echo "LISTEN 0 128 0.0.0.0:$p";; esac; done`);
    env = { PATH: bin + ':' + process.env.PATH, ASIX_WAZUH_DIR: path.join(tmp, 'ossec'), ASIX_ETC_DIR: path.join(tmp, 'etc-asix'), ASIX_LIB_DIR: path.join(tmp, 'lib-asix'), ASIX_SYSTEMD_DIR: path.join(tmp, 'units'),
      ASIX_APT_KEYRING: path.join(tmp, 'keyrings/wazuh.gpg'), ASIX_APT_LIST: path.join(tmp, 'wazuh.list'), ASIX_MEMINFO: path.join(tmp, 'mem'), ASIX_WAZUH_SRC: path.join(root, 'deploy/wazuh'), ASIX_WAZUH_WAIT_S: '2' };
    fs.mkdirSync(env.ASIX_SYSTEMD_DIR); writeIdx();
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const run = (...args) => spawnSync('bash', [INSTALL, ...args], { encoding: 'utf8', env, cwd: tmp });
  const ca = () => path.join(tmp, 'ossec/etc/indexer-root-ca.pem'), remember = () => path.join(tmp, 'ossec/etc/asix-indexer.url');

  it('a full run with --indexer-file: detection ON and pointed at the indexer, the CA kept, the user and password in the keystore (not in ossec.conf), the address remembered', () => {
    const r = run('--indexer-file', idxFile); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    const out = fs.readFileSync(conf(), 'utf8'); assert.match(out, /<host>https:\/\/indexer\.internal:9200<\/host>/); assert.match(out, new RegExp('<ca>' + ca() + '</ca>')); assert.match(out, /<vulnerability-detection>\s*<enabled>yes</); assert.match(out, /<indexer>\s*<enabled>yes</);
    assert.ok(!out.includes(PW) && !out.includes('asix-mgr-acme'), 'no credential in ossec.conf'); assert.strictEqual(fs.readFileSync(ca(), 'utf8'), CERT + '\n'); assert.strictEqual(fs.statSync(ca()).mode & 0o777, 0o640);
    assert.deepStrictEqual(logged(/^keystore/), ['keystore -f indexer -k username -v asix-mgr-acme', `keystore -f indexer -k password -v ${PW}`]); assert.strictEqual(fs.readFileSync(remember(), 'utf8'), 'https://indexer.internal:9200\n');
    assert.match(r.stdout, /indexer https:\/\/indexer\.internal:9200: asix-mgr-acme can sign in/); assert.match(r.stdout, /vulnerability detection ON/); assert.match(r.stdout, /_cat\/indices\/wazuh-states-vulnerabilities/);
    for (const s of [PW]) { assert.ok(!r.stdout.includes(s) && !r.stderr.includes(s), 'the password is never printed'); assert.ok(!fs.readFileSync(log, 'utf8').split('\n').filter((l) => /^curl/.test(l)).join('\n').includes(s), 'and never on a curl command line'); }
    assert.match(fs.readFileSync(path.join(tmp, 'last-curl-config'), 'utf8'), /user = "asix-mgr-acme:/);
    assert.ok(logged(/^curl .*--cacert \S+ .*https:\/\/indexer\.internal:9200\/_plugins\/_security\/authinfo/).length === 1);
  });
  it('the order matters: the sign-in check comes before the package and every change; the keystore is written after the config test and before the manager starts', () => {
    run('--indexer-file', idxFile); const calls = fs.readFileSync(log, 'utf8').split('\n'); const idx = (re) => calls.findIndex((l) => re.test(l));
    assert.ok(idx(/authinfo/) < idx(/^apt-get .*install/)); assert.ok(idx(/^apt-get .*install/) < idx(/^keystore/)); assert.ok(idx(/^keystore -f indexer -k password/) < idx(/^systemctl restart wazuh-manager/));
  });
  it('--indexer-url replaces the file\'s address (the lab: the indexer is on this machine)', () => {
    const r = run('--indexer-file', idxFile, '--indexer-url', 'https://127.0.0.1:9200'); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.match(fs.readFileSync(conf(), 'utf8'), /<host>https:\/\/127\.0\.0\.1:9200<\/host>/); assert.strictEqual(fs.readFileSync(remember(), 'utf8'), 'https://127.0.0.1:9200\n'); assert.ok(logged(/authinfo/)[0].includes('https://127.0.0.1:9200/'));
  });
  it('a re-run WITHOUT the option keeps detection on (the E4b default no longer undoes it), no keystore change, no sign-in check', () => {
    run('--indexer-file', idxFile); const before = fs.readFileSync(conf(), 'utf8'); fs.writeFileSync(log, ''); const r = run(); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.strictEqual(fs.readFileSync(conf(), 'utf8'), before); assert.deepStrictEqual(logged(/^keystore/), []); assert.deepStrictEqual(logged(/authinfo/), []); assert.match(r.stdout, /indexer: https:\/\/indexer\.internal:9200 kept from an earlier run/); assert.match(r.stdout, /vulnerability detection kept ON/);
  });
  it('without the option and without an earlier setup the default stays: detection and indexer OFF, nothing remembered', () => {
    const r = run(); assert.strictEqual(r.status, 0, r.stdout + r.stderr); const out = fs.readFileSync(conf(), 'utf8'); assert.match(out, /<vulnerability-detection>\s*<enabled>no</); assert.match(out, /<indexer>\s*<enabled>no</); assert.ok(!fs.existsSync(remember())); assert.deepStrictEqual(logged(/^keystore/), []); assert.match(r.stdout, /indexer: off/);
  });
  it('--indexer-off switches it off again and forgets the address and the CA', () => {
    run('--indexer-file', idxFile); const r = run('--indexer-off'); assert.strictEqual(r.status, 0, r.stdout + r.stderr); const out = fs.readFileSync(conf(), 'utf8');
    assert.match(out, /<vulnerability-detection>\s*<enabled>no</); assert.match(out, /<indexer>\s*<enabled>no</); assert.ok(!fs.existsSync(remember())); assert.ok(!fs.existsSync(ca()));
    assert.match(run().stdout, /indexer: off/, 'and a later plain run stays off');
  });
  it('--check with the file signs in and changes nothing', () => {
    const r = run('--check', '--indexer-file', idxFile); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /asix-mgr-acme can sign in/); assert.match(r.stdout, /Nothing was changed/);
    assert.deepStrictEqual(logged(/^(apt-get|apt-mark|systemctl|gpg|keystore)/), []); assert.ok(!fs.existsSync(path.join(tmp, 'ossec')));
  });
  it('an indexer that refuses the user, or cannot be reached, is a PROBLEM that stops everything before the package is installed', () => {
    for (const [code, re] of [['401', /refused the user asix-mgr-acme \(HTTP 401\)/], ['403', /refused the user asix-mgr-acme \(HTTP 403\)/], ['000', /cannot reach the indexer https:\/\/indexer\.internal:9200/], ['', /cannot reach the indexer/]]) {
      put('auth-http', code); const r = run('--indexer-file', idxFile); assert.strictEqual(r.status, 1, code); assert.match(r.stderr, re); assert.match(r.stderr, /Nothing was changed/); assert.deepStrictEqual(logged(/^(apt-get|systemctl|keystore)/), [], code);
    }
  });
  it('the manager\'s own config test failing puts ossec.conf back and the keystore is not touched', () => {
    put('test-rc', '1'); const r = run('--indexer-file', idxFile); assert.strictEqual(r.status, 1); assert.match(r.stderr, /config test \(wazuh-analysisd -t\) failed/); assert.strictEqual(fs.readFileSync(conf(), 'utf8'), SAMPLE);
    assert.deepStrictEqual(logged(/^keystore/), []); assert.ok(!fs.existsSync(remember())); assert.deepStrictEqual(logged(/^systemctl (enable|restart)/), []);
  });
  it('a keystore that refuses the user stops before the manager starts, and the address is NOT remembered', () => {
    put('ks-rc', '1'); const r = run('--indexer-file', idxFile); assert.strictEqual(r.status, 1); assert.match(r.stderr, /keystore refused/); assert.ok(!fs.existsSync(remember())); assert.deepStrictEqual(logged(/^systemctl restart/), []);
  });
  it('a manager without the keystore tool says so and does not start it', () => {
    sh('apt-get', `echo "apt-get $*" >> '${log}'
case "$*" in *"install"*) mkdir -p '${tmp}/ossec/etc' '${tmp}/ossec/bin' '${tmp}/ossec/logs'; cp '${root}/tests/fixtures/ossec-manager-default.conf' '${tmp}/ossec/etc/ossec.conf'; printf '#!/bin/bash\\nexit 0\\n' > '${tmp}/ossec/bin/wazuh-analysisd'; chmod +x '${tmp}/ossec/bin/wazuh-analysisd'; echo 4.14.9-1 > '${tmp}/installed';; esac; exit 0`);
    const r = run('--indexer-file', idxFile); assert.strictEqual(r.status, 1); assert.match(r.stderr, /has no keystore tool/); assert.deepStrictEqual(logged(/^systemctl restart/), []);
  });
  it('a bad file is refused with exit 2 and nothing is asked of the indexer or changed: not JSON, no url, odd url, odd user, short password, two certificates, a private key, missing file', () => {
    const bad = [['not json', 'nope'], ['no url', JSON.stringify({ user: 'u', password: PW, ca_pem: CERT })], ['http url', JSON.stringify({ url: 'http://x:9200', user: 'u', password: PW, ca_pem: CERT })], ['url with path', JSON.stringify({ url: 'https://x:9200/a', user: 'u', password: PW, ca_pem: CERT })],
      ['odd user', JSON.stringify({ url: 'https://x:9200', user: 'u v', password: PW, ca_pem: CERT })], ['short password', JSON.stringify({ url: 'https://x:9200', user: 'u', password: 'abc', ca_pem: CERT })], ['password with a space', JSON.stringify({ url: 'https://x:9200', user: 'u', password: 'abcdefgh ijkl', ca_pem: CERT })],
      ['two certificates', JSON.stringify({ url: 'https://x:9200', user: 'u', password: PW, ca_pem: CERT + '\n' + CERT })], ['a private key', JSON.stringify({ url: 'https://x:9200', user: 'u', password: PW, ca_pem: CERT + '\n-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----' })]];
    for (const [name, body] of bad) { fs.writeFileSync(idxFile, body); const r = run('--indexer-file', idxFile); assert.strictEqual(r.status, 2, name + ' -> ' + r.stderr); assert.deepStrictEqual(logged(/^(curl|apt-get|systemctl|keystore)/), [], name); assert.ok(!fs.existsSync(path.join(tmp, 'ossec')), name); }
    const r = run('--indexer-file', path.join(tmp, 'missing.json')); assert.strictEqual(r.status, 2); assert.match(r.stderr, /No such file/);
  });
  it('bad option combinations are refused with exit 2', () => {
    for (const a of [['--indexer-url', 'https://x:9200'], ['--indexer-file', idxFile, '--indexer-url', 'http://x'], ['--indexer-file', idxFile, '--indexer-url', 'https://x/y'], ['--indexer-file', idxFile, '--indexer-off']]) assert.strictEqual(run(...a).status, 2, a.join(' '));
  });
});

// ---- wazuh-indexer-tenant.sh --writer, against a stand-in for the OpenSearch security API ----
function makeCa(dir) {
  const key = path.join(dir, 'ca.key'), crt = path.join(dir, 'ca.crt');
  const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', crt, '-days', '30', '-subj', '/CN=root-ca', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
  return { key: fs.readFileSync(key, 'utf8'), cert: fs.readFileSync(crt, 'utf8'), certFile: crt };
}
function fakeSecurityApi(c, adminPw) {
  const state = { requests: [], roles: new Map(), users: new Map(), maps: new Map(), storeRole: null };
  const srv = https.createServer({ key: c.key, cert: c.cert }, (req, res) => {
    let raw = ''; req.on('data', (d) => { raw += d; });
    req.on('end', () => {
      const m = /^Basic (.+)$/.exec(req.headers.authorization || ''); const cred = m ? Buffer.from(m[1], 'base64').toString('utf8') : '';
      state.requests.push({ method: req.method, path: req.url, cred: cred.split(':')[0], body: raw ? JSON.parse(raw) : null });
      const send = (s, b) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(b)); };
      if (cred !== 'admin:' + adminPw) return send(401, { status: 'UNAUTHORIZED' });
      const mm = /^\/_plugins\/_security\/api\/(roles|internalusers|rolesmapping)\/([A-Za-z0-9_-]+)$/.exec(req.url); if (!mm) return send(404, { status: 'NOT_FOUND' });
      const [, kind, name] = mm; const table = kind === 'roles' ? state.roles : kind === 'internalusers' ? state.users : state.maps;
      if (req.method === 'GET') { if (!table.has(name)) return send(404, { status: 'NOT_FOUND' }); return send(200, { [name]: kind === 'internalusers' ? { hash: '', backend_roles: [], attributes: table.get(name).attributes || {} } : table.get(name) }); }
      if (req.method === 'PUT') { let b = JSON.parse(raw); if (kind === 'roles') b = { ...b, ...(state.storeRole || {}) }; const existed = table.has(name); table.set(name, kind === 'internalusers' ? { password: b.password, attributes: b.attributes } : b); return send(existed ? 200 : 201, { status: 'OK' }); }
      return send(405, {});
    });
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ state, port: srv.address().port, stop: () => new Promise((r) => srv.close(r)) })));
}

describe('wazuh-indexer-tenant.sh --writer (stand-in security API over HTTPS)', { skip: have ? false : 'needs openssl, python3 and curl' }, () => {
  const ADMIN = 'Adm1n-Pass!x'; const CURL = (spawnSync('sh', ['-c', 'command -v curl'], { encoding: 'utf8' }).stdout || '').trim();
  let tmp, bin, curlLog, api, ca, out;
  beforeEach(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'writer-')); bin = path.join(tmp, 'bin'); curlLog = path.join(tmp, 'curl.log'); out = path.join(tmp, 'out'); fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'id'), '#!/bin/sh\necho 0\n', { mode: 0o755 });
    fs.writeFileSync(path.join(bin, 'curl'), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${curlLog}'\nexec ${CURL} "$@"\n`, { mode: 0o755 });
    fs.mkdirSync(path.join(tmp, 'etc/certs'), { recursive: true }); ca = makeCa(tmp); fs.copyFileSync(ca.certFile, path.join(tmp, 'etc/certs/root-ca.pem')); fs.writeFileSync(path.join(tmp, 'etc/asix-admin.pass'), ADMIN + '\n');
    api = await fakeSecurityApi(ca, ADMIN);
  });
  afterEach(async () => { await api.stop(); fs.rmSync(tmp, { recursive: true, force: true }); });
  const run = (args) => new Promise((resolve) => {
    const p = spawn('bash', [TENANT, ...args], { env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_INDEXER_CONF_DIR: path.join(tmp, 'etc'), ASIX_INDEXER_BASE: 'https://127.0.0.1:' + api.port } });
    let so = '', se = ''; p.stdout.on('data', (d) => { so += d; }); p.stderr.on('data', (d) => { se += d; });
    p.on('close', (code) => resolve({ code, out: so, err: se, all: so + se }));
  });
  const W = ['--writer', '--tenant-name', 'Acme Corp', '--manager-name', 'acme-mgr', '--address', 'indexer.internal', '--out-dir'];
  const full = (extra = []) => run([...W, out, ...extra]);
  const file = () => path.join(out, 'asix-manager-indexer-acme-mgr.json');
  const pw = () => fs.readFileSync(path.join(tmp, 'etc/asix-mgr-acme-mgr.pass'), 'utf8').trim();
  const INDEX = 'wazuh-states-vulnerabilities-acme-mgr';

  it('a full run: a WRITE role on ONE index and nothing else, its own user and password, the mapping, read back, and a file for the manager; no secret on a command line or in the output', async () => {
    const r = await full(); assert.strictEqual(r.code, 0, r.all);
    assert.deepStrictEqual(api.state.roles.get('asix_vuln_write_acme_mgr'), { cluster_permissions: [], index_permissions: [{ index_patterns: [INDEX], allowed_actions: ['crud', 'create_index', 'manage'] }] });
    assert.deepStrictEqual(api.state.maps.get('asix_vuln_write_acme_mgr'), { users: ['asix-mgr-acme-mgr'] }); assert.strictEqual(api.state.users.get('asix-mgr-acme-mgr').password, pw()); assert.match(pw(), /^[0-9a-f]{28}Aa1!$/);
    assert.strictEqual(api.state.users.get('asix-mgr-acme-mgr').attributes.purpose, 'Wazuh manager, writes its own vulnerability index'); assert.ok(![...api.state.roles.keys()].some((k) => k.startsWith('asix_vuln_read_')), 'the read side is not touched');
    const f = JSON.parse(fs.readFileSync(file(), 'utf8')); assert.strictEqual(fs.statSync(file()).mode & 0o777, 0o600); assert.deepStrictEqual([f.url, f.user, f.password, f.index], ['https://indexer.internal:9200', 'asix-mgr-acme-mgr', pw(), INDEX]); assert.strictEqual(f.ca_pem.trim(), ca.cert.trim());
    for (const s of [ADMIN, pw()]) { assert.ok(!r.all.includes(s)); assert.ok(!fs.readFileSync(curlLog, 'utf8').includes(s)); }
    assert.match(r.out, /install-wazuh-manager\.sh --indexer-file asix-manager-indexer-acme-mgr\.json/); assert.ok(!/register --tenant/.test(r.out), 'no ASIX registration is offered for the writer');
    assert.ok(!fs.existsSync(path.join(out, 'asix-indexer-registration-acme-mgr.json')));
  });
  it('a loopback --address is allowed for the writer (the lab) and ends up in the file; the READ side still refuses it', async () => {
    const r = await run(['--writer', '--manager-name', 'acme-mgr', '--address', '127.0.0.1', '--out-dir', out]); assert.strictEqual(r.code, 0, r.all); assert.strictEqual(JSON.parse(fs.readFileSync(file(), 'utf8')).url, 'https://127.0.0.1:9200');
    const r2 = await run(['--manager-name', 'acme-mgr', '--address', '127.0.0.1', '--out-dir', out]); assert.strictEqual(r2.code, 2); assert.match(r2.err, /not this machine's loopback address/);
  });
  it('--templates adds the four template cluster permissions, read back as exactly that list; without it the role has none', async () => {
    const r = await full(['--templates']); assert.strictEqual(r.code, 0, r.all);
    assert.deepStrictEqual(api.state.roles.get('asix_vuln_write_acme_mgr').cluster_permissions.sort(), ['indices:admin/index_template/get', 'indices:admin/index_template/put', 'indices:admin/template/get', 'indices:admin/template/put']);
    assert.strictEqual((await run(['--templates', '--manager-name', 'acme-mgr', '--address', 'x'])).code, 2, '--templates alone (read side) is refused');
  });
  it('the writer and the reader of one manager are two roles and two users that do not share anything', async () => {
    await full(); const r = await run(['--tenant-name', 'Acme Corp', '--manager-name', 'acme-mgr', '--address', 'indexer.internal', '--out-dir', out]); assert.strictEqual(r.code, 0, r.all);
    assert.deepStrictEqual([...api.state.roles.keys()].sort(), ['asix_vuln_read_acme_mgr', 'asix_vuln_write_acme_mgr']); assert.deepStrictEqual(api.state.roles.get('asix_vuln_read_acme_mgr').index_permissions[0].allowed_actions, ['read']);
    assert.deepStrictEqual([...api.state.users.keys()].sort(), ['asix-mgr-acme-mgr', 'asix-vuln-acme-mgr']); assert.notStrictEqual(api.state.users.get('asix-mgr-acme-mgr').password, api.state.users.get('asix-vuln-acme-mgr').password);
  });
  it('a re-run keeps the password and the file; --rotate changes both; --check writes nothing', async () => {
    await full(); const first = pw(), body = fs.readFileSync(file(), 'utf8'); await full(); assert.strictEqual(pw(), first); assert.strictEqual(fs.readFileSync(file(), 'utf8'), body);
    await full(['--rotate']); assert.notStrictEqual(pw(), first); assert.strictEqual(JSON.parse(fs.readFileSync(file(), 'utf8')).password, pw());
    const before = api.state.requests.filter((q) => q.method !== 'GET').length; const c = await run(['--writer', '--check', '--manager-name', 'acme-mgr']); assert.strictEqual(c.code, 0, c.all); assert.match(c.out, /role asix_vuln_write_acme_mgr: exists; user asix-mgr-acme-mgr: exists/); assert.strictEqual(api.state.requests.filter((q) => q.method !== 'GET').length, before);
  });
  it('a role the indexer stored with MORE than the writer list (a wildcard index, an extra action, an extra cluster right) is caught by the read-back: no file for the manager', async () => {
    for (const extra of [{ index_permissions: [{ index_patterns: ['*'], allowed_actions: ['crud', 'create_index', 'manage'] }] }, { index_permissions: [{ index_patterns: [INDEX], allowed_actions: ['crud', 'create_index', 'manage', 'indices_all'] }] }, { cluster_permissions: ['cluster_all'] }]) {
      api.state.storeRole = extra; fs.rmSync(out, { recursive: true, force: true }); const r = await full(); assert.strictEqual(r.code, 1, JSON.stringify(extra)); assert.match(r.err, new RegExp("NOT 'write on " + INDEX + " and nothing else'")); assert.ok(!fs.existsSync(file()));
    }
  });
  it('the read side is unchanged: the same script without --writer still makes the read role and the ASIX registration file', async () => {
    const r = await run(['--tenant-name', 'Acme Corp', '--manager-name', 'acme-mgr', '--address', 'indexer.internal', '--out-dir', out]); assert.strictEqual(r.code, 0, r.all);
    assert.deepStrictEqual(api.state.roles.get('asix_vuln_read_acme_mgr').index_permissions[0].allowed_actions, ['read']); assert.ok(fs.existsSync(path.join(out, 'asix-indexer-registration-acme-mgr.json'))); assert.ok(!fs.existsSync(file()));
  });
});

describe('E6g files and the docs agree', () => {
  it('the scripts parse with bash -n; the editor, the installer and the writer are named in docs/wazuh-indexer.md and docs/endpoints.md', () => {
    for (const f of [INSTALL, TENANT]) assert.strictEqual(spawnSync('bash', ['-n', f]).status, 0, f);
    const doc = fs.readFileSync(path.join(root, 'docs/wazuh-indexer.md'), 'utf8'), tasks = fs.readFileSync(path.join(root, 'docs/endpoints.md'), 'utf8');
    for (const n of ['--indexer-file', '--writer', '--indexer-off', 'asix-manager-indexer-']) { assert.ok(doc.includes(n), n + ' in docs/wazuh-indexer.md'); assert.ok(tasks.includes(n), n + ' in docs/endpoints.md'); }
    assert.match(tasks, /E6g as built/);
  });
  it('the installer never puts the indexer password on a curl command line or prints it', () => {
    const t = fs.readFileSync(INSTALL, 'utf8'); assert.ok(!/curl[^\n]*-u\s/.test(t)); assert.ok(!/curl[^\n]*--user\s/.test(t)); assert.ok(!/echo[^\n]*\$IDX_PW/.test(t)); assert.ok(!/printf[^\n]*\$IDX_PW[^\n]*>&?\s*[12]/.test(t));
  });
});
