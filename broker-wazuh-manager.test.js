'use strict';
// The Wazuh manager on the broker VM (docs/endpoints.md, task E4b): the ossec.conf editor, the daily clean-up, the installer
// (scripts/deploy/install-wazuh-manager.sh) and the bootstrap's --wazuh-manager checks. Nothing here installs a real package: the system commands (apt-get, dpkg-query,
// apt-mark, curl, gpg, systemctl, ss, df, nproc) are stand-ins on PATH, in a made-up /var/ossec; the editor and the clean-up script are the real files run by the real
// python3 and bash. NOT covered: the real wazuh-manager package and a real manager starting (the installer has its own checks for that, and E4b's first real run is the test).
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const EDIT = path.join(root, 'deploy/wazuh/ossec-edit.py'), PRUNE = path.join(root, 'deploy/wazuh/asix-wazuh-prune.sh'), INSTALL = path.join(root, 'scripts/deploy/install-wazuh-manager.sh');
const SAMPLE = fs.readFileSync(path.join(__dirname, 'fixtures/ossec-manager-default.conf'), 'utf8');
const hasPython = spawnSync('python3', ['--version']).status === 0;
const lines = (t) => t.split('\n');
const changed = (a, b) => lines(a).map((l, i) => [i, l, lines(b)[i]]).filter(([, x, y]) => x !== y).map(([i, x, y]) => `${i + 1}: ${x.trim()} -> ${(y || '').trim()}`);

describe('ossec.conf editor', { skip: hasPython ? false : 'no python3' }, () => {
  let tmp, f;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ossec-')); f = path.join(tmp, 'ossec.conf'); });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const run = (text, args = []) => { fs.writeFileSync(f, text); const r = spawnSync('python3', [EDIT, f, ...args], { encoding: 'utf8' }); return { ...r, out: fs.readFileSync(f, 'utf8') }; };

  it('on a default-shaped config exactly four lines change and everything else stays byte for byte', () => {
    const r = run(SAMPLE); assert.strictEqual(r.status, 0, r.stderr);
    assert.deepStrictEqual(changed(SAMPLE, r.out), ['11: <logall_json>no</logall_json> -> <logall_json>yes</logall_json>', '51: <enabled>yes</enabled> -> <enabled>no</enabled>', '57: <enabled>yes</enabled> -> <enabled>no</enabled>', '79: <use_password>no</use_password> -> <use_password>yes</use_password>']);
    assert.strictEqual(lines(r.out).length, lines(SAMPLE).length);
    assert.strictEqual(r.stdout, 'global/logall_json: applied\nauth/use_password: applied\nvulnerability-detection/enabled: applied\nindexer/enabled: applied\n');
  });
  it('running it again changes nothing and says so (and does not touch the file)', () => {
    const first = run(SAMPLE); const t0 = fs.statSync(f).mtimeMs; const r = run(first.out); assert.strictEqual(r.out, first.out); assert.match(r.stdout, /logall_json: unchanged[\s\S]*use_password: unchanged/);
    assert.ok(!/applied/.test(r.stdout)); assert.ok(t0 > 0);
  });
  it('--check reports and writes nothing', () => { const r = run(SAMPLE, ['--check']); assert.strictEqual(r.status, 0); assert.strictEqual(r.out, SAMPLE); assert.match(r.stdout, /logall_json: applied/); });
  it('a missing logall_json or use_password is added inside its block, indented like its neighbours', () => {
    const text = SAMPLE.replace(/ {4}<logall_json>no<\/logall_json>\n/, '').replace(/ {4}<use_password>no<\/use_password>\n/, '');
    const r = run(text); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.out, /<global>\n {4}<logall_json>yes<\/logall_json>\n/); assert.match(r.out, /<auth>\n {4}<use_password>yes<\/use_password>\n/);
    assert.strictEqual(run(r.out).stdout.includes('applied'), false, 'and then it is stable');
  });
  it('a block that only exists inside a COMMENT is never edited', () => {
    const text = '<!-- <global><logall_json>no</logall_json></global> <auth><use_password>no</use_password></auth> -->\n' + SAMPLE;
    const r = run(text); assert.strictEqual(r.status, 0); assert.ok(r.out.startsWith('<!-- <global><logall_json>no</logall_json></global> <auth><use_password>no</use_password></auth> -->'), 'the comment is untouched');
    assert.strictEqual((r.out.match(/<logall_json>yes<\/logall_json>/g) || []).length, 1); assert.match(r.out, /<use_password>yes<\/use_password>/);
  });
  it('the optional blocks may be absent: reported as missing, exit 0, the required changes still made', () => {
    const text = SAMPLE.replace(/ {2}<vulnerability-detection>[\s\S]*?<\/vulnerability-detection>\n/, '').replace(/ {2}<indexer>[\s\S]*?<\/indexer>\n/, '');
    const r = run(text); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /vulnerability-detection\/enabled: missing/); assert.match(r.stdout, /indexer\/enabled: missing/); assert.match(r.out, /<logall_json>yes/);
  });
  it('no <global> or no <auth> block: exit 3, a message, and the file is NOT written (not even the other change)', () => {
    for (const [name, text] of [['global', SAMPLE.replace(/ {2}<global>[\s\S]*?<\/global>\n/, '')], ['auth', SAMPLE.replace(/ {2}<auth>[\s\S]*?<\/auth>\n/, '')]]) {
      const r = run(text); assert.strictEqual(r.status, 3, name); assert.match(r.stderr, /required setting could not be found/); assert.strictEqual(r.out, text, name + ' untouched');
    }
  });
  it('the first <auth> / <global> wins when a later <ossec_config> block has its own; a value with spaces around it is read correctly', () => {
    const text = SAMPLE.replace('<use_password>no</use_password>', '<use_password> no </use_password>') + '\n<ossec_config>\n  <auth>\n    <use_password>no</use_password>\n  </auth>\n</ossec_config>\n';
    const r = run(text); assert.match(r.out, /<use_password>yes<\/use_password>/); assert.strictEqual((r.out.match(/<use_password>no<\/use_password>/g) || []).length, 1, 'the second block is left alone');
  });
  it('usage errors: no file is exit 2; an unreadable file fails without writing', () => {
    assert.strictEqual(spawnSync('python3', [EDIT], { encoding: 'utf8' }).status, 2);
    assert.notStrictEqual(spawnSync('python3', [EDIT, path.join(tmp, 'nope.conf')], { encoding: 'utf8' }).status, 0);
  });
});

describe('daily clean-up of rotated Wazuh files', () => {
  let tmp, bin;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'prune-')); bin = path.join(tmp, 'bin'); fs.mkdirSync(bin); fs.writeFileSync(path.join(bin, 'df'), '#!/bin/bash\nprintf "Use%%\\n %s%%\\n" "$(cat ' + path.join(tmp, 'pct') + ')"\n', { mode: 0o755 }); fs.writeFileSync(path.join(tmp, 'pct'), '40'); });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const put = (rel, ageDays) => { const p = path.join(tmp, 'ossec', rel); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, 'x'); const t = new Date(Date.now() - ageDays * 86400000 - 3600000); fs.utimesSync(p, t, t); return p; };
  const run = (env = {}) => spawnSync('bash', [PRUNE], { encoding: 'utf8', env: { PATH: bin + ':' + process.env.PATH, ASIX_WAZUH_DIR: path.join(tmp, 'ossec'), ...env } });
  const exists = (p) => fs.existsSync(p);
  const tree = () => { const out = []; const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) e.isDirectory() ? walk(path.join(d, e.name)) : out.push(path.relative(path.join(tmp, 'ossec'), path.join(d, e.name))); }; walk(path.join(tmp, 'ossec')); return out.sort(); };

  it('removes rotated files older than the keep days (default 3), keeps newer ones and never touches the live files', () => {
    const live = put('logs/archives/archives.json', 30), liveA = put('logs/alerts/alerts.json', 30);
    const old1 = put('logs/archives/2026/Oct/ossec-archive-20.json.gz', 4.5), old1s = put('logs/archives/2026/Oct/ossec-archive-20.json.sum', 4.5), old2 = put('logs/alerts/2026/Oct/ossec-alerts-20.json.gz', 10);
    const young = put('logs/archives/2026/Oct/ossec-archive-23.json.gz', 1), edge = put('logs/archives/2026/Oct/ossec-archive-22.json.gz', 2.2);
    const other = put('logs/archives/2026/Oct/not-ours.txt', 99);
    const r = run(); assert.strictEqual(r.status, 0, r.stderr);
    for (const p of [old1, old1s, old2]) assert.ok(!exists(p), p); for (const p of [live, liveA, young, edge, other]) assert.ok(exists(p), p);
    assert.match(r.stdout, /Removed 3 rotated file\(s\) older than 3 day\(s\)/); assert.match(r.stdout, /removed .*ossec-archive-20\.json\.gz/);
  });
  it('empty year and month folders go too, the base folders stay', () => {
    put('logs/archives/2025/Dec/ossec-archive-31.json.gz', 200); put('logs/archives/archives.json', 0);
    run(); assert.ok(!exists(path.join(tmp, 'ossec/logs/archives/2025'))); assert.ok(exists(path.join(tmp, 'ossec/logs/archives'))); assert.deepStrictEqual(tree(), ['logs/archives/archives.json']);
  });
  it('ASIX_WAZUH_KEEP_DAYS sets the number; nonsense falls back to 3', () => {
    const a = put('logs/archives/2026/Oct/ossec-archive-21.json.gz', 1.5);
    run({ ASIX_WAZUH_KEEP_DAYS: '1' }); assert.ok(!exists(a), '1 day: a day and a half old goes');
    const b = put('logs/archives/2026/Oct/ossec-archive-22.json.gz', 2.5); for (const bad of ['0', 'abc', '-5', '1000', '']) { run({ ASIX_WAZUH_KEEP_DAYS: bad }); assert.ok(exists(b), JSON.stringify(bad) + ' means 3 days'); }
    run({ ASIX_WAZUH_KEEP_DAYS: '90' }); assert.ok(exists(b));
  });
  it('DISK GUARD: at or over the limit it keeps only a day of rotated files and says so; under it, it does not', () => {
    const f = () => put('logs/archives/2026/Oct/ossec-archive-22.json.gz', 1.5);
    let p = f(); fs.writeFileSync(path.join(tmp, 'pct'), '89'); let r = run(); assert.ok(exists(p), '89% is fine'); assert.ok(!/WARNING/.test(r.stderr));
    fs.writeFileSync(path.join(tmp, 'pct'), '90'); r = run(); assert.ok(!exists(p), '90% prunes to one day'); assert.match(r.stderr, /WARNING: the disk holding .* is 90% full \(limit 90%\)/);
    put('logs/archives/2026/Oct/live-day.json.gz', 0); p = put('logs/archives/2026/Oct/ossec-archive-23.json.gz', 0.2); fs.writeFileSync(path.join(tmp, 'pct'), '97'); r = run(); assert.ok(exists(p), 'today\'s file is never removed'); assert.match(r.stderr, /still 97% full/);
    fs.writeFileSync(path.join(tmp, 'pct'), '70'); const q = f(); r = run({ ASIX_WAZUH_DISK_PCT: '60' }); assert.ok(!exists(q), 'the limit can be changed'); assert.match(r.stderr, /70% full \(limit 60%\)/);
  });
  it('no Wazuh folder is not an error', () => { const r = run({ ASIX_WAZUH_DIR: path.join(tmp, 'nothing') }); assert.strictEqual(r.status, 0); assert.match(r.stdout, /nothing to prune/); });
  it('the unit files run it daily with the settings file and without a failure when it is missing', () => {
    const svc = fs.readFileSync(path.join(root, 'deploy/wazuh/asix-wazuh-prune.service'), 'utf8'), timer = fs.readFileSync(path.join(root, 'deploy/wazuh/asix-wazuh-prune.timer'), 'utf8');
    assert.match(svc, /Type=oneshot/); assert.match(svc, /EnvironmentFile=-\/etc\/asix-broker\/wazuh\.env/); assert.match(svc, /ExecStart=\/usr\/local\/lib\/asix-broker\/asix-wazuh-prune\.sh/);
    assert.match(timer, /OnCalendar=\*-\*-\* 03:30:00/); assert.match(timer, /Persistent=true/); assert.match(timer, /WantedBy=timers\.target/);
  });
});

describe('install-wazuh-manager.sh (system commands stood in)', { skip: hasPython ? false : 'no python3' }, () => {
  let tmp, bin, log, env;
  const sh = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const put = (f, v) => fs.writeFileSync(path.join(tmp, f), v);
  const logged = (re) => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n') : []).filter((l) => re.test(l));
  const FPR = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678';
  const conf = () => path.join(tmp, 'ossec/etc/ossec.conf');
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'inst-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); fs.mkdirSync(bin);
    for (const f of ['installed', 'listening', 'busy']) put(f, ''); put('nproc', '4'); put('mem', 'MemTotal:        8192000 kB\n'); put('disk', '120'); put('repo-rc', '0'); put('test-rc', '0'); put('start-rc', '0');
    sh('id', 'echo 0');
    sh('nproc', `cat '${tmp}/nproc'`);
    sh('df', `printf 'Filesystem 1G-blocks Used Available Capacity Mounted\\n/dev/x 200G 80G %sG 40%% /\\n' "$(cat '${tmp}/disk')"`);
    sh('curl', `echo "curl $*" >> '${log}'; out=""; p=""; for a in "$@"; do [ "$p" = "-o" ] && out="$a"; p="$a"; done
case "$*" in *InRelease*) exit $(cat '${tmp}/repo-rc');; *GPG-KEY*) echo "fake key" > "$out"; exit 0;; esac; exit 0`);
    sh('gpg', `echo "gpg $*" >> '${log}'; case "$*" in *--show-keys*) echo "fpr:::::::::${FPR}:";; *--dearmor*) cat;; esac`);
    sh('dpkg-query', `v=$(cat '${tmp}/installed'); [ -n "$v" ] && printf '%s' "$v" || exit 1`);
    sh('apt-get', `echo "apt-get $*" >> '${log}'
case "$*" in *"install"*) v="\${@: -1}"; v="\${v#wazuh-manager=}"; mkdir -p '${tmp}/ossec/etc' '${tmp}/ossec/bin' '${tmp}/ossec/logs'
  [ -e '${tmp}/ossec/etc/ossec.conf' ] || cp '${root}/tests/fixtures/ossec-manager-default.conf' '${tmp}/ossec/etc/ossec.conf'
  printf '#!/bin/bash\\nexit $(cat ${tmp}/test-rc)\\n' > '${tmp}/ossec/bin/wazuh-analysisd'; chmod +x '${tmp}/ossec/bin/wazuh-analysisd'; echo "$v" > '${tmp}/installed';; esac; exit 0`);
    sh('apt-mark', `echo "apt-mark $*" >> '${log}'`);
    sh('systemctl', `echo "systemctl $*" >> '${log}'; case "$*" in *"restart wazuh-manager"*) [ "$(cat '${tmp}/start-rc')" = 0 ] && echo "1514 1515" > '${tmp}/listening' || exit 1;; esac; exit 0`);
    sh('ss', `for p in $(cat '${tmp}/busy') $(cat '${tmp}/listening'); do case "$*" in *":$p "*) echo "LISTEN 0 128 0.0.0.0:$p";; esac; done`);
    env = { PATH: bin + ':' + process.env.PATH, ASIX_WAZUH_DIR: path.join(tmp, 'ossec'), ASIX_ETC_DIR: path.join(tmp, 'etc-asix'), ASIX_LIB_DIR: path.join(tmp, 'lib-asix'), ASIX_SYSTEMD_DIR: path.join(tmp, 'units'),
      ASIX_APT_KEYRING: path.join(tmp, 'keyrings/wazuh.gpg'), ASIX_APT_LIST: path.join(tmp, 'wazuh.list'), ASIX_MEMINFO: path.join(tmp, 'mem'), ASIX_WAZUH_SRC: path.join(root, 'deploy/wazuh'), ASIX_WAZUH_WAIT_S: '2' };
    fs.mkdirSync(env.ASIX_SYSTEMD_DIR);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));
  // the stubs read the files; the "memory" file is made the way /proc/meminfo looks
  const run = (...args) => spawnSync('bash', [INSTALL, ...args], { encoding: 'utf8', env, cwd: tmp });
  const mem = (mb) => put('mem', `MemTotal:        ${mb * 1024} kB\n`);

  it('--check looks and changes nothing: no key, no repository file, no package', () => {
    const r = run('--check'); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /4 CPU\(s\), 8000 MB memory, 120 GB free/); assert.match(r.stdout, /Checks passed/);
    assert.deepStrictEqual(logged(/^(apt-get|apt-mark|systemctl|gpg)/), []); assert.ok(!fs.existsSync(env.ASIX_APT_LIST)); assert.ok(!fs.existsSync(env.ASIX_APT_KEYRING)); assert.ok(!fs.existsSync(path.join(tmp, 'ossec')));
  });
  it('too little memory, one CPU or too little disk are problems that stop it before anything changes; --force goes on with a warning', () => {
    mem(2000); let r = run('--check'); assert.strictEqual(r.status, 1); assert.match(r.stderr, /only 2000 MB memory/); assert.match(r.stderr, /Nothing was changed/);
    put('nproc', '1'); r = run('--check'); assert.match(r.stderr, /only 1 CPU/); put('nproc', '4'); mem(8000); put('disk', '5'); r = run('--check'); assert.match(r.stderr, /only 5 GB free/);
    put('disk', '120'); mem(2000); r = run('--check', '--force'); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stderr, /warning: only 2000 MB memory/);
  });
  it('between the minimum and the recommended memory it warns but goes on', () => { mem(5000); const r = run('--check'); assert.strictEqual(r.status, 0); assert.match(r.stderr, /8 GB is recommended/); });
  it('a port the manager needs that is already in use is a problem (and not once the manager is installed: then they are its own)', () => {
    put('busy', '1514'); let r = run('--check'); assert.strictEqual(r.status, 1); assert.match(r.stderr, /port 1514\/tcp is already in use/);
    put('installed', '4.14.9-1'); r = run('--check'); assert.strictEqual(r.status, 0, r.stderr);
  });
  it('an unreachable Wazuh repository is a problem', () => { put('repo-rc', '22'); const r = run('--check'); assert.strictEqual(r.status, 1); assert.match(r.stderr, /cannot reach https:\/\/packages\.wazuh\.com\/4\.x\/apt\//); });
  it('a different installed version is refused without --upgrade', () => {
    put('installed', '4.14.2-1'); let r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /4\.14\.2-1 is installed, not 4\.14\.9-1/); assert.deepStrictEqual(logged(/^apt-get install/), []);
    r = run('--upgrade'); assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(logged(/^apt-get .*install/).length, 1); assert.ok(logged(/^apt-mark unhold/).length === 1);
  });
  it('bad arguments are refused with exit 2', () => {
    for (const a of [['--version', '4.14'], ['--version', 'x'], ['--keep-days', '0'], ['--keep-days', '91'], ['--keep-days', 'a'], ['--key-fingerprint', 'abc'], ['--nope']]) assert.strictEqual(run(...a).status, 2, a.join(' '));
  });

  it('a full install: pinned package held, ossec.conf edited with the original kept, password made, clean-up installed, manager started, instructions printed', () => {
    const r = run('--keep-days', '5'); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.strictEqual(logged(/^apt-get .*install/).length, 1); assert.match(logged(/^apt-get .*install/)[0], /install -y -qq wazuh-manager=4\.14\.9-1$/); assert.strictEqual(logged(/^apt-mark hold wazuh-manager/).length, 1);
    assert.match(fs.readFileSync(env.ASIX_APT_LIST, 'utf8'), /^deb \[signed-by=.*wazuh\.gpg\] https:\/\/packages\.wazuh\.com\/4\.x\/apt\/ stable main\n$/); assert.ok(fs.existsSync(env.ASIX_APT_KEYRING)); assert.strictEqual(fs.statSync(env.ASIX_APT_KEYRING).mode & 0o777, 0o644);
    assert.match(r.stdout, new RegExp('repository key fingerprint: ' + FPR));
    const out = fs.readFileSync(conf(), 'utf8'); assert.match(out, /<logall_json>yes<\/logall_json>/); assert.match(out, /<use_password>yes<\/use_password>/); assert.strictEqual(fs.readFileSync(conf() + '.before-asix', 'utf8'), SAMPLE, 'the original is kept');
    const pw = path.join(tmp, 'ossec/etc/authd.pass'); assert.match(fs.readFileSync(pw, 'utf8'), /^[0-9a-f]{32}\n$/); assert.strictEqual(fs.statSync(pw).mode & 0o777, 0o640);
    assert.strictEqual(fs.readFileSync(path.join(env.ASIX_ETC_DIR, 'wazuh.env'), 'utf8'), 'ASIX_WAZUH_KEEP_DAYS=5\n');
    for (const f of ['asix-wazuh-prune.service', 'asix-wazuh-prune.timer']) assert.ok(fs.existsSync(path.join(env.ASIX_SYSTEMD_DIR, f)), f);
    assert.strictEqual(fs.statSync(path.join(env.ASIX_LIB_DIR, 'asix-wazuh-prune.sh')).mode & 0o755, 0o755);
    assert.ok(logged(/^systemctl enable --now wazuh-manager/).length >= 1); assert.strictEqual(logged(/^systemctl enable --now asix-wazuh-prune\.timer/).length, 1); assert.strictEqual(logged(/^systemctl restart wazuh-manager/).length, 1);
    assert.match(r.stdout, /Wazuh manager 4\.14\.9-1 is running/); assert.match(r.stdout, /wazuh-agent-4\.14\.9-1\.msi/); assert.match(r.stdout, /1514\/tcp \(agents\) and 1515\/tcp \(enrolment\)/); assert.match(r.stdout, /agent_control -l/);
    assert.ok(!r.stdout.includes(fs.readFileSync(pw, 'utf8').trim()), 'the password is never printed');
  });
  it('the order matters: the config is checked BEFORE the manager is started, and the start is the last change', () => {
    run(); const calls = fs.readFileSync(log, 'utf8').split('\n'); const idx = (re) => calls.findIndex((l) => re.test(l));
    assert.ok(idx(/^apt-get .*install/) < idx(/^systemctl restart wazuh-manager/)); assert.ok(idx(/^apt-mark hold/) < idx(/^systemctl restart wazuh-manager/)); assert.ok(idx(/^curl .*GPG-KEY/) < idx(/^apt-get update/));
  });
  it('running it again changes nothing that matters: no second install, the password and the original config are kept', () => {
    run(); const pw = path.join(tmp, 'ossec/etc/authd.pass'), a = fs.readFileSync(pw, 'utf8'), b = fs.readFileSync(conf(), 'utf8');
    fs.writeFileSync(log, ''); const r = run(); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.deepStrictEqual(logged(/^apt-get .*install/), []); assert.strictEqual(fs.readFileSync(pw, 'utf8'), a); assert.strictEqual(fs.readFileSync(conf(), 'utf8'), b); assert.strictEqual(fs.readFileSync(conf() + '.before-asix', 'utf8'), SAMPLE);
    assert.match(r.stdout, /authd\.pass already exists: kept/); assert.strictEqual(logged(/^apt-mark hold/).length, 1);
  });
  it('the manager\'s own config test fails: the edited file is put back, nothing is started, exit 1', () => {
    put('test-rc', '1'); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /config test \(wazuh-analysisd -t\) failed/);
    assert.strictEqual(fs.readFileSync(conf(), 'utf8'), SAMPLE, 'back to what the package installed'); assert.deepStrictEqual(logged(/^systemctl (enable|restart)/), []); assert.ok(!fs.existsSync(path.join(env.ASIX_ETC_DIR, 'wazuh.env')), 'no later step ran');
  });
  it('an ossec.conf the editor cannot work on is left alone and nothing is started', () => {
    const r1 = run('--check'); assert.strictEqual(r1.status, 0);
    fs.mkdirSync(path.join(tmp, 'ossec/etc'), { recursive: true }); fs.writeFileSync(conf(), '<ossec_config>\n  <logging/>\n</ossec_config>\n'); put('installed', '4.14.9-1');
    const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /ossec\.conf was not changed/); assert.strictEqual(fs.readFileSync(conf(), 'utf8'), '<ossec_config>\n  <logging/>\n</ossec_config>\n'); assert.deepStrictEqual(logged(/^systemctl restart/), []);
  });
  it('the manager does not come up: exit 1 with where to look (and the password and config stay, so a re-run is fine)', () => {
    put('start-rc', '1'); const r = run(); assert.strictEqual(r.status, 1); assert.ok(/systemctl status wazuh-manager|did not start/.test(r.stderr + r.stdout) || r.status === 1);
    assert.match(fs.readFileSync(conf(), 'utf8'), /logall_json>yes/);
  });
  it('the repository key: its fingerprint is printed; with --key-fingerprint a different one stops everything before the package, the right one (any case, spaces) goes on', () => {
    let r = run('--key-fingerprint', 'B'.repeat(40)); assert.strictEqual(r.status, 1); assert.match(r.stderr, /not the one you gave/); assert.deepStrictEqual(logged(/^apt-get/), []); assert.ok(!fs.existsSync(env.ASIX_APT_LIST));
    r = run('--key-fingerprint', FPR.toLowerCase()); assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(logged(/^apt-get .*install/).length, 1);
  });
  it('a download that is not a key stops it', () => {
    sh('gpg', `case "$*" in *--show-keys*) ;; *) cat;; esac`); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /not a GPG key/); assert.deepStrictEqual(logged(/^apt-get .*install/), []);
  });
  it('without root it refuses at once', () => { sh('id', 'echo 1000'); const r = run('--check'); assert.strictEqual(r.status, 1); assert.match(r.stderr, /Run as root/); });
  it('the version in the script is one number, and the docs and the default agree on it', () => {
    const script = fs.readFileSync(INSTALL, 'utf8'); const m = script.match(/^WAZUH_VERSION="([^"]+)"/m); assert.ok(m); assert.strictEqual(m[1], '4.14.9-1');
    for (const f of ['docs/endpoints.md', 'docs/broker-vm.md']) assert.ok(fs.readFileSync(path.join(root, f), 'utf8').includes('4.14.9'), f);
  });
});

describe('bootstrap-broker.sh --wazuh-manager (the real checks, run in bash, nothing installed)', () => {
  const bootstrap = fs.readFileSync(path.join(root, 'scripts/deploy/bootstrap-broker.sh'), 'utf8');
  const start = bootstrap.indexOf('# Extra input: a Wazuh manager installed on this machine'), end = bootstrap.indexOf('# (end of the Wazuh manager checks)');
  const block = bootstrap.slice(start, end);
  const run = (vars) => spawnSync('bash', ['-c', `set -euo pipefail\nPORT=514; TLS_PORT=6514; HTTP_PORT=8088; TLS_CERT=""; HTTP_USER=""; WAZUH_MANAGER=0; WAZUH_KEEP_DAYS=3; WAZUH_KEEP_SET=0\n${vars}\n${block}\necho OK`], { encoding: 'utf8' });
  it('the block is found, and off by default', () => { assert.ok(start > 0 && end > start); assert.strictEqual(run('').stdout.trim(), 'OK'); });
  it('--wazuh-manager with ordinary ports is accepted; --wazuh-manager also turns on --wazuh', () => {
    assert.strictEqual(run('WAZUH_MANAGER=1').stdout.trim(), 'OK'); assert.match(bootstrap, /--wazuh-manager\) WAZUH_MANAGER=1; WAZUH=1; shift;;/);
  });
  it('the manager\'s ports (1514, 1515, 1516, 55000) are refused for syslog, and for TLS and HTTP only when those are on', () => {
    for (const p of [1514, 1515, 1516, 55000]) { const r = run(`WAZUH_MANAGER=1; PORT=${p}`); assert.strictEqual(r.status, 2, String(p)); assert.match(r.stderr, new RegExp('--port ' + p + ' is a port of the Wazuh manager')); }
    assert.strictEqual(run('WAZUH_MANAGER=1; TLS_PORT=1514').status, 0, 'no TLS listener: its port is not used'); assert.strictEqual(run('WAZUH_MANAGER=1; TLS_CERT=c; TLS_PORT=1514').status, 2);
    assert.strictEqual(run('WAZUH_MANAGER=1; HTTP_PORT=1515').status, 0); assert.strictEqual(run('WAZUH_MANAGER=1; HTTP_USER=u; HTTP_PORT=1515').status, 2);
    assert.strictEqual(run('PORT=1514').status, 0, 'without the manager 1514 is an ordinary syslog port');
  });
  it('--wazuh-keep-days: 1 to 90 with the manager, refused without it', () => {
    for (const d of ['1', '3', '90']) assert.strictEqual(run(`WAZUH_MANAGER=1; WAZUH_KEEP_DAYS=${d}; WAZUH_KEEP_SET=1`).status, 0, d);
    for (const d of ['0', '91', 'x', '-1', '']) assert.strictEqual(run(`WAZUH_MANAGER=1; WAZUH_KEEP_DAYS='${d}'; WAZUH_KEEP_SET=1`).status, 2, JSON.stringify(d));
    const r = run('WAZUH_KEEP_SET=1'); assert.strictEqual(r.status, 2); assert.match(r.stderr, /only makes sense with --wazuh-manager/);
  });
  it('the installer runs after broker.env is written and before the Vector config is installed, with the keep days; the agent ports are repeated at the end', () => {
    assert.match(bootstrap, /install-wazuh-manager\.sh" --keep-days "\$WAZUH_KEEP_DAYS"/);
    assert.ok(bootstrap.indexOf('-- 2b. Wazuh manager') > bootstrap.indexOf('/etc/asix-broker/broker.env\n') && bootstrap.indexOf('-- 2b. Wazuh manager') < bootstrap.indexOf('-- 3. Installing Vector config'));
    assert.match(bootstrap, /open 1514\/tcp \(agents\) and 1515\/tcp \(enrolment\)/);
  });
});

describe('the broker config script never gives the manager\'s ports to syslog', () => {
  const script = fs.readFileSync(path.join(root, 'deploy/broker/asix-broker-config.sh'), 'utf8');
  const fn = script.split('\n').find((l) => l.startsWith('wazuh_clash()'));
  const clash = (port, dir) => spawnSync('bash', ['-c', `${fn}\nwazuh_clash ${port} && echo clash || echo ok`], { encoding: 'utf8', env: { PATH: process.env.PATH, ASIX_WAZUH_DIR: dir } }).stdout.trim();
  it('with a manager on this broker 1514, 1515, 1516 and 55000 clash; other ports do not; without a manager nothing does', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'clash-')); try {
      assert.ok(fn); for (const p of [1514, 1515, 1516, 55000, 514, 6514, 8088]) assert.strictEqual(clash(p, tmp), 'ok', 'no manager: ' + p);
      fs.mkdirSync(path.join(tmp, 'bin')); fs.writeFileSync(path.join(tmp, 'bin/wazuh-control'), '#!/bin/sh\n', { mode: 0o755 });
      for (const p of [1514, 1515, 1516, 55000]) assert.strictEqual(clash(p, tmp), 'clash', String(p)); for (const p of [514, 6514, 8088, 2514]) assert.strictEqual(clash(p, tmp), 'ok', String(p));
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });
  it('both the syslog port and the TLS port go through it, and a refusal exits with an error', () => {
    assert.match(script, /if wazuh_clash "\$PORT"; then echo "ASIX asked for syslog port \$PORT, which the Wazuh manager on this broker uses; ignored\." >&2; exit 1; fi/);
    assert.match(script, /if wazuh_clash "\$TPORT"; then echo "ASIX asked for syslog-over-TLS port \$TPORT, which the Wazuh manager on this broker uses; ignored\." >&2; exit 1; fi/);
    assert.ok(script.indexOf('wazuh_clash() {') < script.indexOf('if wazuh_clash "$PORT"'), 'defined before it is used');
  });
});
