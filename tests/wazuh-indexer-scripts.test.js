'use strict';
// The two scripts that set up the central Wazuh indexer (docs/wazuh-indexer.md, task E6h): scripts/deploy/install-wazuh-indexer.sh (the real script with the real openssl, python3
// and bash; the system commands apt-get, dpkg-query, apt-mark, curl, gpg, systemctl, ss, sysctl, df, nproc are stand-ins on PATH, in a made-up /etc/wazuh-indexer) and
// scripts/deploy/wazuh-indexer-tenant.sh (the real script with the real curl against a stand-in for the OpenSearch security API over HTTPS).
// NOT covered: the real wazuh-indexer package, a real indexer starting, the real security plugin's answers (the stand-in follows its documented shape from memory).
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { spawn, spawnSync } = require('child_process');
const store = require('../src/endpoints/wazuh-indexer-store');

const root = path.join(__dirname, '..');
const INSTALL = path.join(root, 'scripts/deploy/install-wazuh-indexer.sh'), TENANT = path.join(root, 'scripts/deploy/wazuh-indexer-tenant.sh');
const have = [['openssl', 'version'], ['python3', '--version'], ['curl', '--version']].every(([c, a]) => spawnSync(c, [a]).status === 0);
const FPR = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678';
const HASH = '$2y$12$' + 'a'.repeat(53);
const USERS = 'admin:\n  hash: "$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO"\n  reserved: true\n  backend_roles:\n  - "admin"\n  description: "Admin user"\n\nkibanaserver:\n  hash: "$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H."\n  reserved: true\n';

describe('install-wazuh-indexer.sh (system commands stood in)', { skip: have ? false : 'needs openssl, python3 and curl' }, () => {
  let tmp, bin, log, env;
  const sh = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const put = (f, v) => fs.writeFileSync(path.join(tmp, f), v);
  const logged = (re) => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n') : []).filter((l) => re.test(l));
  const conf = (...p) => path.join(tmp, 'etc-indexer', ...p);
  const mem = (mb) => put('mem', `MemTotal:        ${mb * 1024} kB\n`);
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'idx-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); fs.mkdirSync(bin);
    for (const f of ['installed', 'listening', 'busy', 'loopback-fails']) put(f, ''); put('nproc', '4'); mem(16384); put('disk', '120'); put('repo-rc', '0'); put('start-rc', '0'); put('health', 'green'); put('hash', HASH); put('init-rc', '0');
    sh('id', 'if [ "$1" = "-u" ]; then echo 0; else exit 1; fi');
    sh('nproc', `cat '${tmp}/nproc'`);
    sh('hostname', 'echo idx-vm');
    sh('df', `printf 'Filesystem 1G-blocks Used Available Capacity Mounted\\n/dev/x 200G 80G %sG 40%% /\\n' "$(cat '${tmp}/disk')"`);
    sh('curl', `echo "curl $*" >> '${log}'; out=""; p=""; for a in "$@"; do [ "$p" = "-o" ] && out="$a"; p="$a"; done
case "$*" in *InRelease*) exit $(cat '${tmp}/repo-rc');; *GPG-KEY*) echo "fake key" > "$out"; exit 0;; esac
k=""; p=""; for a in "$@"; do [ "$p" = "-K" ] && k="$a"; p="$a"; done
if [ -n "$k" ]; then cfg="$(cat "$k")"; echo "health-url $(printf '%s' "$cfg" | sed -n 's/^url = "\\(.*\\)"$/\\1/p')" >> '${log}'; case "$cfg" in *127.0.0.1*) [ -s '${tmp}/loopback-fails' ] && exit 60;; esac; fi
echo "{\\"status\\":\\"$(cat '${tmp}/health')\\"}"`);
    sh('gpg', `echo "gpg $*" >> '${log}'; case "$*" in *--show-keys*) echo "fpr:::::::::${FPR}:";; *--dearmor*) cat;; esac`);
    sh('dpkg-query', `v=$(cat '${tmp}/installed'); [ -n "$v" ] && printf '%s' "$v" || exit 1`);
    sh('apt-get', `echo "apt-get $*" >> '${log}'
case "$*" in *install*) v="\${@: -1}"; v="\${v#wazuh-indexer=}"; mkdir -p '${tmp}/etc-indexer/opensearch-security' '${tmp}/share/plugins/opensearch-security/tools' '${tmp}/share/bin'
  printf '%s' '${USERS.replace(/'/g, "'\\''")}' > '${tmp}/etc-indexer/opensearch-security/internal_users.yml'
  printf '#!/bin/bash\\necho "$@" >> ${log}\\ncat ${tmp}/hash\\n' > '${tmp}/share/plugins/opensearch-security/tools/hash.sh'; chmod +x '${tmp}/share/plugins/opensearch-security/tools/hash.sh'
  printf '#!/bin/bash\\necho init >> ${log}\\nexit $(cat ${tmp}/init-rc)\\n' > '${tmp}/share/bin/indexer-security-init.sh'; chmod +x '${tmp}/share/bin/indexer-security-init.sh'
  echo "$v" > '${tmp}/installed';; esac; exit 0`);
    sh('apt-mark', `echo "apt-mark $*" >> '${log}'`);
    sh('sysctl', `echo "sysctl $*" >> '${log}'`);
    sh('systemctl', `echo "systemctl $*" >> '${log}'; case "$*" in *"restart wazuh-indexer"*) [ "$(cat '${tmp}/start-rc')" = 0 ] && echo "9200" > '${tmp}/listening' || exit 1;; esac; exit 0`);
    sh('ss', `for p in $(cat '${tmp}/busy') $(cat '${tmp}/listening'); do case "$*" in *":$p "*) echo "LISTEN 0 128 0.0.0.0:$p";; esac; done`);
    env = { PATH: bin + ':' + process.env.PATH, ASIX_INDEXER_CONF_DIR: conf(), ASIX_SYSCTL_DIR: path.join(tmp, 'sysctl.d'), ASIX_APT_KEYRING: path.join(tmp, 'keyrings/wazuh.gpg'), ASIX_APT_LIST: path.join(tmp, 'wazuh.list'),
      ASIX_MEMINFO: path.join(tmp, 'mem'), ASIX_INDEXER_SHARE: path.join(tmp, 'share'), ASIX_INDEXER_WAIT_S: '2' };
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const run = (...args) => spawnSync('bash', [INSTALL, ...args], { encoding: 'utf8', env, cwd: tmp });
  const text = (f) => fs.readFileSync(f, 'utf8');

  it('--check looks and changes nothing', () => {
    const r = run('--check'); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /4 CPU\(s\), 16384 MB memory, 120 GB free/); assert.match(r.stdout, /Checks passed/);
    assert.deepStrictEqual(logged(/^(apt-get|apt-mark|systemctl|gpg|sysctl)/), []); assert.ok(!fs.existsSync(env.ASIX_APT_LIST)); assert.ok(!fs.existsSync(conf()));
  });
  it('memory, CPU or disk under the minimum stops it before anything changes; --force goes on with a warning; the lab has lower minimums', () => {
    mem(8000); let r = run('--check'); assert.strictEqual(r.status, 1); assert.match(r.stderr, /only 8000 MB memory/); assert.match(r.stderr, /Nothing was changed/);
    r = run('--check', '--lab'); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stderr, /warning: 8000 MB memory works for a lab/);
    r = run('--check', '--force'); assert.strictEqual(r.status, 0); assert.match(r.stderr, /warning: only 8000 MB memory/);
    mem(16384); put('nproc', '2'); r = run('--check'); assert.match(r.stderr, /only 2 CPU/); assert.strictEqual(run('--check', '--lab').status, 0); put('nproc', '4'); put('disk', '5'); assert.match(run('--check').stderr, /only 5 GB free/);
    mem(4000); assert.strictEqual(run('--check', '--lab').status, 1, 'even the lab has a floor');
  });
  it('port 9200 or 9300 already in use is a problem before the indexer is installed (not after: then they are its own); an unreachable repository is a problem', () => {
    put('busy', '9200'); let r = run('--check'); assert.strictEqual(r.status, 1); assert.match(r.stderr, /port 9200\/tcp is already in use/);
    put('installed', '4.14.9-1'); assert.strictEqual(run('--check').status, 0); put('installed', ''); put('busy', '9300'); assert.match(run('--check').stderr, /port 9300\/tcp/);
    put('busy', ''); put('repo-rc', '22'); r = run('--check'); assert.strictEqual(r.status, 1); assert.match(r.stderr, /cannot reach https:\/\/packages\.wazuh\.com\/4\.x\/apt\//);
  });
  it('a different installed version is refused without --upgrade', () => {
    put('installed', '4.14.2-1'); let r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /4\.14\.2-1 is installed, not 4\.14\.9-1/); assert.deepStrictEqual(logged(/^apt-get .*install/), []);
    r = run('--upgrade'); assert.strictEqual(r.status, 0, r.stdout + r.stderr); assert.strictEqual(logged(/^apt-mark unhold/).length, 1);
  });
  it('bad arguments are refused with exit 2', () => {
    for (const a of [['--version', '4.14'], ['--heap-gb', '0'], ['--heap-gb', '32'], ['--heap-gb', 'a'], ['--node-name', 'bad name'], ['--address', '127.0.0.1'], ['--address', 'localhost'], ['--address', 'a b'], ['--key-fingerprint', 'abc'], ['--nope']]) assert.strictEqual(run(...a).status, 2, a.join(' '));
  });

  it('a full install: pinned package held, kernel setting, heap, certificates, opensearch.yml, a hashed admin password, started, and the instructions printed', () => {
    const r = run('--address', '10.20.30.40'); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.match(logged(/^apt-get .*install/)[0], /install -y -qq wazuh-indexer=4\.14\.9-1$/); assert.strictEqual(logged(/^apt-mark hold wazuh-indexer/).length, 1);
    assert.match(text(env.ASIX_APT_LIST), /^deb \[signed-by=.*wazuh\.gpg\] https:\/\/packages\.wazuh\.com\/4\.x\/apt\/ stable main\n$/);
    assert.strictEqual(text(path.join(tmp, 'sysctl.d/99-asix-indexer.conf')), 'vm.max_map_count=262144\n'); assert.ok(logged(/^sysctl -w vm.max_map_count=262144/).length === 1);
    assert.strictEqual(text(conf('jvm.options.d/asix-heap.options')), '-Xms8g\n-Xmx8g\n', 'half of 16 GB');
    for (const f of ['root-ca.pem', 'indexer.pem', 'indexer-key.pem', 'admin.pem', 'admin-key.pem']) { assert.ok(fs.existsSync(conf('certs', f)), f); assert.strictEqual(fs.statSync(conf('certs', f)).mode & 0o777, 0o400, f + ' mode'); }
    const san = spawnSync('openssl', ['x509', '-in', conf('certs/indexer.pem'), '-noout', '-ext', 'subjectAltName'], { encoding: 'utf8' }).stdout;
    for (const n of ['IP Address:10.20.30.40', 'IP Address:127.0.0.1', 'DNS:idx-vm', 'DNS:localhost']) assert.ok(san.includes(n), n + ' in ' + san);
    assert.strictEqual(spawnSync('openssl', ['verify', '-CAfile', conf('certs/root-ca.pem'), conf('certs/indexer.pem')], { encoding: 'utf8' }).status, 0, 'the node certificate is signed by the root CA');
    assert.strictEqual(spawnSync('openssl', ['verify', '-CAfile', conf('certs/root-ca.pem'), conf('certs/admin.pem')], { encoding: 'utf8' }).status, 0);
    assert.ok(!fs.readdirSync(conf('certs')).some((f) => /root-ca-key/.test(f)), 'the CA private key is not kept');
    const yml = text(conf('opensearch.yml')); assert.match(yml, /^discovery\.type: single-node$/m); assert.match(yml, /^node\.name: "asix-indexer-1"$/m); assert.match(yml, /^network\.host: "0\.0\.0\.0"$/m);
    assert.match(yml, /admin_dn:\n {2}- "CN=admin,/); assert.match(yml, /nodes_dn:\n {2}- "CN=asix-indexer-1,/); assert.match(yml, new RegExp('pemtrustedcas_filepath: ' + conf('certs/root-ca.pem').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    const pw = text(conf('asix-admin.pass')).trim(); assert.match(pw, /^[0-9a-f]{24}Aa1!$/); assert.strictEqual(fs.statSync(conf('asix-admin.pass')).mode & 0o777, 0o600);
    const users = text(conf('opensearch-security/internal_users.yml')); assert.ok(users.includes('hash: "' + HASH + '"'), 'the admin hash is the hasher\'s'); assert.ok(!users.includes('K/SpwjtB'), 'the default admin hash is gone');
    assert.ok(users.includes('kibanaserver:\n  hash: "$2a$12$4Acg'), 'the other users are untouched'); assert.ok(fs.existsSync(conf('opensearch-security/internal_users.yml.before-asix')));
    assert.ok(logged(/^init$/).length === 1, 'security initialisation ran'); assert.strictEqual(logged(/^systemctl restart wazuh-indexer/).length, 1);
    assert.ok(!r.stdout.includes(pw) && !r.stderr.includes(pw), 'the password is not printed'); assert.deepStrictEqual(logged(/./).filter((l) => l.includes(pw)), ['-p ' + pw], 'the password is on NO command line except the hasher\'s own -p (the security plugin\'s hash.sh takes it no other way; see the script header)');
    assert.match(r.stdout, /answers on https:\/\/10\.20\.30\.40:9200 with status green/); assert.match(r.stdout, /wazuh-indexer-tenant\.sh --tenant-name/);
  });
  // E6n: the closing check on a certificate set that does not name 127.0.0.1 (found on the lab 2026-11-04: certificates made by Wazuh's own tool named only the VM's address)
  const putCerts = (san) => {
    fs.mkdirSync(conf('certs'), { recursive: true });
    const o = (a) => spawnSync('openssl', a, { encoding: 'utf8', cwd: tmp });
    o(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(tmp, 'ca-key.pem'), '-out', conf('certs/root-ca.pem'), '-days', '30', '-subj', '/CN=root-ca']);
    o(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', conf('certs/indexer-key.pem'), '-out', path.join(tmp, 'n.csr'), '-subj', '/CN=asix-indexer-1']);
    put('san.ext', 'subjectAltName=' + san + '\n');
    o(['x509', '-req', '-in', path.join(tmp, 'n.csr'), '-CA', conf('certs/root-ca.pem'), '-CAkey', path.join(tmp, 'ca-key.pem'), '-CAcreateserial', '-out', conf('certs/indexer.pem'), '-days', '30', '-extfile', path.join(tmp, 'san.ext')]);
    fs.copyFileSync(conf('certs/indexer.pem'), conf('certs/admin.pem'));
    assert.ok(fs.statSync(conf('certs/indexer.pem')).size > 0, 'the test certificate was made');
  };
  const healthUrls = () => logged(/^health-url /).map((l) => l.slice('health-url '.length));
  it('certificates made by the script name 127.0.0.1: no warning, and the closing check is made on loopback', () => {
    const r = run('--address', '10.20.30.40'); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.ok(!/does not name 127\.0\.0\.1/.test(r.stderr + r.stdout), 'no warning');
    assert.deepStrictEqual(healthUrls(), ['https://127.0.0.1:9200/_cluster/health']);
  });
  it('certificates that were already there and do not name 127.0.0.1: a warning, and the closing check falls back to --address, so a healthy indexer is not called broken', () => {
    putCerts('IP:10.20.30.40,DNS:idx-vm'); put('loopback-fails', 'x');
    const r = run('--address', '10.20.30.40'); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stderr, /warning: the node certificate does not name 127\.0\.0\.1.*https:\/\/10\.20\.30\.40:9200.*--address 10\.20\.30\.40/);
    assert.deepStrictEqual(healthUrls(), ['https://10.20.30.40:9200/_cluster/health'], 'the address is tried first and answers; loopback is not needed');
    assert.match(r.stdout, /\(checked at https:\/\/10\.20\.30\.40:9200: the node certificate does not name 127\.0\.0\.1\)/);
    assert.match(r.stdout, /answers on https:\/\/10\.20\.30\.40:9200 with status green/);
    assert.ok(text(conf('certs/indexer.pem')).includes('BEGIN CERTIFICATE'), 'the certificates were left as they were');
  });
  it('a certificate that names loopback is checked on loopback even if it also names the address (nothing changes for the normal case)', () => {
    putCerts('IP:10.20.30.40,IP:127.0.0.1'); const r = run('--address', '10.20.30.40'); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.ok(!/does not name 127\.0\.0\.1/.test(r.stderr)); assert.deepStrictEqual(healthUrls(), ['https://127.0.0.1:9200/_cluster/health']);
  });
  it('when the check fails and the certificate does not name loopback, the message says to look at the certificate; when it does, it does not', () => {
    putCerts('IP:10.20.30.40'); put('health', ''); let r = run('--address', '10.20.30.40'); assert.strictEqual(r.status, 1);
    assert.match(r.stderr, /last answer: 'none'/); assert.match(r.stderr, /does not name 127\.0\.0\.1, so also check that 10\.20\.30\.40 is in its names/);
    assert.ok(healthUrls().includes('https://10.20.30.40:9200/_cluster/health') && healthUrls().includes('https://127.0.0.1:9200/_cluster/health'), 'both addresses were tried: ' + healthUrls());
    fs.rmSync(conf(), { recursive: true, force: true }); put('installed', ''); put('listening', ''); put('health', '');
    r = run('--address', '10.20.30.40'); assert.strictEqual(r.status, 1); assert.ok(!/also check that/.test(r.stderr), 'no certificate hint when loopback is named');
  });
  it('an address chosen with ASIX_INDEXER_BASE is the only one checked (no fallback is added behind the caller\'s back)', () => {
    putCerts('IP:10.20.30.40'); put('loopback-fails', 'x'); const saved = env.ASIX_INDEXER_BASE; env.ASIX_INDEXER_BASE = 'https://127.0.0.1:9200';
    try { const r = run('--address', '10.20.30.40'); assert.strictEqual(r.status, 1); assert.deepStrictEqual([...new Set(healthUrls())], ['https://127.0.0.1:9200/_cluster/health']); } finally { if (saved === undefined) delete env.ASIX_INDEXER_BASE; else env.ASIX_INDEXER_BASE = saved; }
  });
  it('a 127.0.0.10 name is not taken for 127.0.0.1', () => {
    putCerts('IP:10.20.30.40,IP:127.0.0.10'); put('loopback-fails', 'x'); const r = run('--address', '10.20.30.40'); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stderr, /does not name 127\.0\.0\.1/);
  });
  // E6o: a re-run must not reload the security configuration (that deletes every role and user made through the security API: found on the lab 2026-11-04, the manager's writer vanished)
  it('a re-run does NOT load the security configuration again when the admin already signs in; the first run did', () => {
    let r = run('--address', '10.20.30.40'); assert.strictEqual(r.status, 0, r.stdout + r.stderr); assert.strictEqual(logged(/^init$/).length, 1); assert.match(r.stdout, /loading the security configuration \(a new admin password was made\)/);
    r = run('--address', '10.20.30.40'); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.strictEqual(logged(/^init$/).length, 1, 'no second load'); assert.match(r.stdout, /security configuration NOT reloaded/); assert.match(r.stdout, /--reload-security/);
    assert.match(r.stdout, /answers on https:\/\/10\.20\.30\.40:9200 with status green/);
  });
  it('--reload-security loads it again on a re-run, and says why', () => {
    assert.strictEqual(run('--address', '10.20.30.40').status, 0); const r = run('--address', '10.20.30.40', '--reload-security'); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.strictEqual(logged(/^init$/).length, 2); assert.match(r.stdout, /loading the security configuration \(--reload-security was given\)/);
  });
  it('a re-run where the admin cannot sign in yet (a first run that stopped before the load) loads it', () => {
    assert.strictEqual(run('--address', '10.20.30.40').status, 0); assert.strictEqual(logged(/^init$/).length, 1);
    put('health', ''); const r = run('--address', '10.20.30.40'); assert.strictEqual(r.status, 1, 'the closing check still fails with no answer');
    assert.strictEqual(logged(/^init$/).length, 2, 'loaded because the admin could not sign in'); assert.match(r.stdout, /the admin cannot sign in with the stored password yet/);
  });
  it('--reload-security is accepted by --check and named in the usage', () => {
    assert.strictEqual(run('--check', '--reload-security').status, 0); assert.match(text(INSTALL), /--reload-security\s+load the security configuration/);
  });
  it('the heap: half of the memory (31 at most), a quarter and 8 at most in the lab, or --heap-gb; more than half of the memory is refused', () => {
    const heap = () => text(conf('jvm.options.d/asix-heap.options')).split('\n')[0];
    const fresh = () => { fs.rmSync(conf(), { recursive: true, force: true }); put('installed', ''); put('listening', ''); };
    mem(20480); assert.strictEqual(run().status, 0); assert.strictEqual(heap(), '-Xms10g');
    fresh(); mem(16384); assert.strictEqual(run('--lab').status, 0); assert.strictEqual(heap(), '-Xms4g', 'lab: a quarter');
    fresh(); mem(65536); assert.strictEqual(run('--lab').status, 0); assert.strictEqual(heap(), '-Xms8g', 'lab: 8 at most');
    fresh(); assert.strictEqual(run().status, 0); assert.strictEqual(heap(), '-Xms31g', 'never above 31');
    fresh(); mem(16384); assert.strictEqual(run('--heap-gb', '6').status, 0); assert.strictEqual(heap(), '-Xms6g');
    fresh(); const r = run('--heap-gb', '12'); assert.strictEqual(r.status, 1); assert.match(r.stderr, /more than half/);
  });
  it('running it again keeps the certificates and the admin password (and does not hash again), and asks the package manager for nothing new', () => {
    assert.strictEqual(run().status, 0); const before = ['certs/root-ca.pem', 'certs/indexer.pem', 'certs/admin-key.pem', 'asix-admin.pass', 'opensearch-security/internal_users.yml'].map((f) => text(conf(f)));
    fs.chmodSync(conf('certs'), 0o750); const r = run(); assert.strictEqual(r.status, 0, r.stdout + r.stderr); assert.match(r.stdout, /certificates already there/); assert.match(r.stdout, /admin password already exists/);
    assert.deepStrictEqual(['certs/root-ca.pem', 'certs/indexer.pem', 'certs/admin-key.pem', 'asix-admin.pass', 'opensearch-security/internal_users.yml'].map((f) => text(conf(f))), before);
    assert.strictEqual(logged(/^apt-get .*install/).length, 1, 'installed once');
  });
  it('the key fingerprint must match when given; a wrong one stops it before the package is installed', () => {
    let r = run('--key-fingerprint', 'B'.repeat(40)); assert.strictEqual(r.status, 1); assert.match(r.stderr, /not the one you gave/); assert.deepStrictEqual(logged(/^apt-get .*install/), []);
    r = run('--key-fingerprint', FPR.toLowerCase()); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  });
  it('a hasher that does not give a bcrypt hash stops it and leaves the users file as it was', () => {
    put('hash', 'not a hash'); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /did not give a bcrypt hash/); assert.strictEqual(text(conf('opensearch-security/internal_users.yml')), USERS); assert.deepStrictEqual(logged(/^systemctl restart/), []);
  });
  it('a users file without an admin entry stops it with a message; a missing hasher too', () => {
    const r1 = run('--check'); assert.strictEqual(r1.status, 0);
    // install, then break the layout and use a fresh admin password file so the hashing step runs again
    assert.strictEqual(run().status, 0); fs.writeFileSync(conf('opensearch-security/internal_users.yml'), 'someone:\n  hash: "x"\n'); fs.rmSync(conf('asix-admin.pass'));
    let r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /Could not set the admin hash/);
    fs.writeFileSync(conf('opensearch-security/internal_users.yml'), USERS); fs.rmSync(conf('asix-admin.pass')); fs.rmSync(path.join(tmp, 'share/plugins/opensearch-security/tools/hash.sh')); r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /Cannot find the password hasher/);
  });
  it('an indexer that never listens, a failing security initialisation and a cluster that is not green or yellow each stop it with a message', () => {
    put('start-rc', '1'); let r = run(); assert.strictEqual(r.status, 1);
    put('start-rc', '0'); put('init-rc', '1'); put('health', ''); /* the admin cannot sign in yet, so the load is tried */ r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /indexer-security-init\.sh failed/);
    put('init-rc', '0'); put('health', 'red'); r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /last answer: 'red'/);
    put('health', 'yellow'); r = run(); assert.strictEqual(r.status, 0, r.stdout + r.stderr); assert.match(r.stdout, /status yellow/);
  });
});

// ---- the per-tenant script, against a stand-in for the OpenSearch security API ----
function makeCa(dir) {
  const key = path.join(dir, 'ca.key'), crt = path.join(dir, 'ca.crt');
  const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', crt, '-days', '30', '-subj', '/CN=root-ca', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
  return { key: fs.readFileSync(key, 'utf8'), cert: fs.readFileSync(crt, 'utf8'), certFile: crt };
}
function fakeSecurityApi(c, adminPw) {
  const state = { requests: [], roles: new Map(), users: new Map(), maps: new Map(), storeRole: null, dropMapping: false };
  const srv = https.createServer({ key: c.key, cert: c.cert }, (req, res) => {
    let raw = ''; req.on('data', (d) => { raw += d; });
    req.on('end', () => {
      const m = /^Basic (.+)$/.exec(req.headers.authorization || ''); const cred = m ? Buffer.from(m[1], 'base64').toString('utf8') : '';
      state.requests.push({ method: req.method, path: req.url, cred: cred.split(':')[0], body: raw ? JSON.parse(raw) : null });
      const send = (s, b) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(b)); };
      if (cred !== 'admin:' + adminPw) return send(401, { status: 'UNAUTHORIZED' });
      const mm = /^\/_plugins\/_security\/api\/(roles|internalusers|rolesmapping)\/([A-Za-z0-9_-]+)$/.exec(req.url); if (!mm) return send(404, { status: 'NOT_FOUND' });
      const [, kind, name] = mm; const table = kind === 'roles' ? state.roles : kind === 'internalusers' ? state.users : state.maps;
      if (req.method === 'GET') { if (!table.has(name)) return send(404, { status: 'NOT_FOUND', message: 'not found' }); return send(200, { [name]: kind === 'internalusers' ? { hash: '', backend_roles: [], attributes: table.get(name).attributes || {} } : table.get(name) }); }
      if (req.method === 'PUT') {
        let b = JSON.parse(raw);
        if (kind === 'roles') { b = { ...b, ...(state.storeRole || {}) }; }
        if (kind === 'rolesmapping' && state.dropMapping) b = { users: [] };
        const existed = table.has(name); table.set(name, kind === 'internalusers' ? { password: b.password, attributes: b.attributes } : b); return send(existed ? 200 : 201, { status: existed ? 'OK' : 'CREATED', message: name });
      }
      return send(405, {});
    });
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ state, port: srv.address().port, stop: () => new Promise((r) => srv.close(r)) })));
}

describe('wazuh-indexer-tenant.sh (stand-in security API over HTTPS)', { skip: have ? false : 'needs openssl, python3 and curl' }, () => {
  const ADMIN = 'Adm1n-Pass!x'; const CURL = (spawnSync('sh', ['-c', 'command -v curl'], { encoding: 'utf8' }).stdout || '').trim();
  let tmp, bin, curlLog, api, ca, out;
  beforeEach(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tenant-')); bin = path.join(tmp, 'bin'); curlLog = path.join(tmp, 'curl.log'); out = path.join(tmp, 'out'); fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'id'), '#!/bin/sh\necho 0\n', { mode: 0o755 });
    fs.writeFileSync(path.join(bin, 'curl'), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${curlLog}'\nexec ${CURL} "$@"\n`, { mode: 0o755 });
    fs.mkdirSync(path.join(tmp, 'etc/certs'), { recursive: true }); ca = makeCa(tmp); fs.copyFileSync(ca.certFile, path.join(tmp, 'etc/certs/root-ca.pem')); fs.writeFileSync(path.join(tmp, 'etc/asix-admin.pass'), ADMIN + '\n');
    api = await fakeSecurityApi(ca, ADMIN);
  });
  afterEach(async () => { await api.stop(); fs.rmSync(tmp, { recursive: true, force: true }); });
  const run = (args, env = {}) => new Promise((resolve) => {
    const p = spawn('bash', [TENANT, ...args], { env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_INDEXER_CONF_DIR: path.join(tmp, 'etc'), ASIX_INDEXER_BASE: 'https://127.0.0.1:' + api.port, ...env } });
    let so = '', se = ''; p.stdout.on('data', (d) => { so += d; }); p.stderr.on('data', (d) => { se += d; });
    p.on('close', (code) => resolve({ code, out: so, err: se, all: so + se }));
  });
  const full = (extra = []) => run(['--tenant-name', 'Acme Corp', '--manager-name', 'acme-mgr', '--address', 'indexer.internal', '--out-dir', out, ...extra]);
  const regFile = () => path.join(out, 'asix-indexer-registration-acme-mgr.json');
  const writes = () => api.state.requests.filter((r) => r.method !== 'GET').map((r) => r.method + ' ' + r.path);
  const userPw = () => fs.readFileSync(path.join(tmp, 'etc/asix-vuln-acme-mgr.pass'), 'utf8').trim();

  it('--check says what exists, exits 0, and writes nothing anywhere', async () => {
    const r = await run(['--check', '--manager-name', 'acme-mgr']); assert.strictEqual(r.code, 0, r.all); assert.match(r.out, /role asix_vuln_read_acme_mgr: not there yet; user asix-vuln-acme-mgr: not there yet/); assert.deepStrictEqual(writes(), []);
    assert.ok(!fs.existsSync(path.join(tmp, 'etc/asix-vuln-acme-mgr.pass'))); assert.ok(!fs.existsSync(out));
  });
  it('a full run: a role that reads ONE index and nothing else, a user, the mapping, read back, and a registration file the operator tool accepts, with no secret on a command line or in the output', async () => {
    const r = await full(); assert.strictEqual(r.code, 0, r.all);
    const role = api.state.roles.get('asix_vuln_read_acme_mgr'); assert.deepStrictEqual(role, { cluster_permissions: [], index_permissions: [{ index_patterns: ['wazuh-states-vulnerabilities-acme-mgr'], allowed_actions: ['read'] }] });
    assert.deepStrictEqual(api.state.maps.get('asix_vuln_read_acme_mgr'), { users: ['asix-vuln-acme-mgr'] }); assert.strictEqual(api.state.users.get('asix-vuln-acme-mgr').password, userPw());
    assert.match(userPw(), /^[0-9a-f]{28}Aa1!$/); assert.strictEqual(fs.statSync(path.join(tmp, 'etc/asix-vuln-acme-mgr.pass')).mode & 0o777, 0o600);
    assert.ok(api.state.requests.every((q) => q.cred === 'admin'), 'every call was made as admin');
    const reg = JSON.parse(fs.readFileSync(regFile(), 'utf8')); assert.strictEqual(fs.statSync(regFile()).mode & 0o777, 0o600);
    assert.deepStrictEqual([reg.url, reg.user, reg.password, reg.index, reg.label], ['https://indexer.internal:9200', 'asix-vuln-acme-mgr', userPw(), 'wazuh-states-vulnerabilities-acme-mgr', 'Acme Corp']); assert.strictEqual(reg.ca_pem.trim(), ca.cert.trim());
    const p = store.parseRegistration(reg); assert.ok(!p.error, p.error); assert.strictEqual(p.reg.index_name, 'wazuh-states-vulnerabilities-acme-mgr'); assert.strictEqual(p.reg.index_user, 'asix-vuln-acme-mgr');
    for (const secret of [ADMIN, userPw()]) { assert.ok(!r.all.includes(secret), 'a password in the output'); assert.ok(!fs.readFileSync(curlLog, 'utf8').includes(secret), 'a password on a curl command line'); }
    assert.match(r.out, /wazuh-indexer-cli\.js register --tenant "Acme Corp" --no-check/);
  });
  it('running it again changes nothing that matters: the same password, the same role, no second user', async () => {
    await full(); const first = userPw(), file = fs.readFileSync(regFile(), 'utf8'); const r = await full(); assert.strictEqual(r.code, 0, r.all); assert.strictEqual(userPw(), first); assert.strictEqual(fs.readFileSync(regFile(), 'utf8'), file);
    assert.strictEqual(api.state.users.size, 1); assert.strictEqual(api.state.roles.size, 1); assert.match(r.out, /role asix_vuln_read_acme_mgr: exists; user asix-vuln-acme-mgr: exists/);
  });
  it('--rotate gives the user a new password, in the indexer and in the file', async () => {
    await full(); const first = userPw(); const r = await full(['--rotate']); assert.strictEqual(r.code, 0, r.all); assert.notStrictEqual(userPw(), first);
    assert.strictEqual(api.state.users.get('asix-vuln-acme-mgr').password, userPw()); assert.strictEqual(JSON.parse(fs.readFileSync(regFile(), 'utf8')).password, userPw());
  });
  it('two managers get two roles and two users, each reading only its own index', async () => {
    await full(); await run(['--tenant-name', 'Beta', '--manager-name', 'beta-mgr', '--address', 'indexer.internal', '--out-dir', out]);
    assert.deepStrictEqual([...api.state.roles.keys()].sort(), ['asix_vuln_read_acme_mgr', 'asix_vuln_read_beta_mgr']);
    assert.deepStrictEqual(api.state.roles.get('asix_vuln_read_beta_mgr').index_permissions[0].index_patterns, ['wazuh-states-vulnerabilities-beta-mgr']); assert.deepStrictEqual(api.state.maps.get('asix_vuln_read_beta_mgr'), { users: ['asix-vuln-beta-mgr'] });
  });
  it('the wrong admin password stops it at the first call: nothing written, no file', async () => {
    fs.writeFileSync(path.join(tmp, 'etc/asix-admin.pass'), 'wrong\n'); const r = await full(); assert.strictEqual(r.code, 1); assert.match(r.err, /refused admin \(HTTP 401\)/); assert.deepStrictEqual(writes(), []); assert.ok(!fs.existsSync(out));
  });
  it('an indexer that is not there, or whose certificate is not the CA given, stops it with a message', async () => {
    await api.stop(); let r = await full(); assert.strictEqual(r.code, 1); assert.match(r.err, /could not reach/);
    api = await fakeSecurityApi(ca, ADMIN); const other = makeCa(fs.mkdtempSync(path.join(os.tmpdir(), 'other-'))); fs.writeFileSync(path.join(tmp, 'etc/certs/root-ca.pem'), other.cert);
    r = await run(['--tenant-name', 'A', '--manager-name', 'acme-mgr', '--address', 'indexer.internal', '--out-dir', out], { ASIX_INDEXER_BASE: 'https://127.0.0.1:' + api.port }); assert.strictEqual(r.code, 1); assert.match(r.err, /could not reach/); assert.deepStrictEqual(writes(), []);
  });
  it('a role the indexer stored with MORE than read on one index is caught by the read-back: no registration file is written', async () => {
    for (const extra of [{ cluster_permissions: ['cluster_all'] }, { index_permissions: [{ index_patterns: ['*'], allowed_actions: ['read'] }] }, { index_permissions: [{ index_patterns: ['wazuh-states-vulnerabilities-acme-mgr'], allowed_actions: ['read', 'write'] }] }]) {
      api.state.storeRole = extra; fs.rmSync(out, { recursive: true, force: true }); const r = await full(); assert.strictEqual(r.code, 1, JSON.stringify(extra)); assert.match(r.err, /NOT 'read on wazuh-states-vulnerabilities-acme-mgr and nothing else'/); assert.ok(!fs.existsSync(regFile()));
    }
  });
  it('a mapping that does not hold exactly the user is caught by the read-back', async () => {
    api.state.dropMapping = true; const r = await full(); assert.strictEqual(r.code, 1); assert.match(r.err, /not mapped to exactly the user/); assert.ok(!fs.existsSync(regFile()));
  });
  it('bad arguments are refused with exit 2 and nothing is asked of the indexer', async () => {
    for (const a of [['--address', 'indexer.internal'], ['--manager-name', 'Acme'], ['--manager-name', 'acme*'], ['--manager-name', 'a b'], ['--manager-name', 'acme-mgr'], ['--manager-name', 'acme-mgr', '--address', '127.0.0.1'], ['--manager-name', 'acme-mgr', '--address', 'localhost'],
      ['--manager-name', 'acme-mgr', '--address', 'x', '--port', '0'], ['--manager-name', 'acme-mgr', '--address', 'x', '--slug', 'a_b'], ['--nope']]) { const r = await run(a); assert.strictEqual(r.code, 2, a.join(' ') + ' -> ' + r.all); }
    assert.deepStrictEqual(api.state.requests, []);
  });
  it('a CA file with two certificates, or none, is refused', async () => {
    fs.writeFileSync(path.join(tmp, 'etc/certs/root-ca.pem'), ca.cert + ca.cert); let r = await full(); assert.strictEqual(r.code, 1); assert.match(r.err, /exactly one certificate/);
    fs.writeFileSync(path.join(tmp, 'etc/certs/root-ca.pem'), 'nothing\n'); r = await full(); assert.strictEqual(r.code, 1); assert.deepStrictEqual(api.state.requests, []);
  });
});

describe('the scripts and the docs agree', () => {
  it('both scripts are executable, parse with bash -n, and are named in docs/wazuh-indexer.md and the task table', () => {
    for (const f of [INSTALL, TENANT]) { assert.ok(fs.statSync(f).mode & 0o100, f + ' is executable'); assert.strictEqual(spawnSync('bash', ['-n', f]).status, 0, f); }
    const doc = fs.readFileSync(path.join(root, 'docs/wazuh-indexer.md'), 'utf8'), tasks = fs.readFileSync(path.join(root, 'docs/endpoints.md'), 'utf8');
    for (const n of ['install-wazuh-indexer.sh', 'wazuh-indexer-tenant.sh']) { assert.ok(doc.includes(n), n + ' in docs/wazuh-indexer.md'); assert.ok(tasks.includes(n), n + ' in docs/endpoints.md'); }
  });
  it('neither script puts a password on a command line or prints one', () => {
    for (const f of [INSTALL, TENANT]) { const t = fs.readFileSync(f, 'utf8'); assert.ok(!/curl[^\n]*-u\s/.test(t), f + ' curl -u'); assert.ok(!/curl[^\n]*--user\s/.test(t), f + ' curl --user'); assert.ok(!/echo[^\n]*\$\(cat "\$(ADMIN_PW|PW|USER_PW)"\)/.test(t), f + ' echoes a password'); }
  });
});
