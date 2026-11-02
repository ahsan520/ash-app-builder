'use strict';
// E6i: the reporter that runs on the indexer VM (deploy/indexer/asix-indexer-health.sh) and its installer (scripts/deploy/install-indexer-health.sh), docs/endpoints.md, "E6i as built".
// The REAL scripts run with the REAL curl, python3, awk and bash against two stand-ins over HTTPS: the indexer's API (cluster health and index settings, admin sign-in) and ASIX's
// ingest lane (the ingestion key, the headers and the body). Only `df` (a known disk), `hostname`, `id` and `systemctl` are stand-ins on PATH. NOT covered: a real indexer, a real
// systemd timer firing, the real ASIX lane and database (the body is fed to the real parsing rules and rules in tests/indexer-health-rules.test.js and at the end of this file).
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { spawn, spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const SCRIPT = path.join(root, 'deploy/indexer/asix-indexer-health.sh'), INSTALL = path.join(root, 'scripts/deploy/install-indexer-health.sh');
const have = [['openssl', 'version'], ['python3', '--version'], ['curl', '--version']].every(([c, a]) => spawnSync(c, [a]).status === 0);
const CURL = (spawnSync('sh', ['-c', 'command -v curl'], { encoding: 'utf8' }).stdout || '').trim();
const ADMIN = 'Adm1n-Pass!x', KEY = 'asix_ik_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6', KEY2 = 'asix_ik_' + 'Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4';

function makeCert(dir, name) {
  const key = path.join(dir, name + '.key'), crt = path.join(dir, name + '.crt');
  const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', crt, '-days', '30', '-subj', '/CN=' + name, '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
  return { key: fs.readFileSync(key, 'utf8'), cert: fs.readFileSync(crt, 'utf8'), certFile: crt };
}
const listen = (srv) => new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ port: srv.address().port, stop: () => new Promise((r) => srv.close(r)) })));
// the indexer: Basic admin, GET /_cluster/health and GET /_all/_settings/index.blocks.*
function fakeIndexer(c) {
  const state = { requests: [], status: 'green', indices: { 'idx-a': {}, 'idx-b': {} }, healthCode: 200, settingsCode: 200, rawHealth: null };
  const srv = https.createServer({ key: c.key, cert: c.cert }, (req, res) => {
    const m = /^Basic (.+)$/.exec(req.headers.authorization || ''); const cred = m ? Buffer.from(m[1], 'base64').toString('utf8') : '';
    state.requests.push({ method: req.method, path: req.url, cred: cred.split(':')[0] });
    const send = (s, b) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(typeof b === 'string' ? b : JSON.stringify(b)); };
    if (cred !== 'admin:' + ADMIN) return send(401, { status: 'UNAUTHORIZED' });
    if (req.method !== 'GET') return send(405, {});
    if (req.url === '/_cluster/health') return send(state.healthCode, state.rawHealth !== null ? state.rawHealth : { cluster_name: 'x', status: state.status });
    if (req.url === '/_all/_settings/index.blocks.*?flat_settings=true') return send(state.settingsCode, Object.fromEntries(Object.entries(state.indices).map(([k, v]) => [k, { settings: v }])));
    return send(404, {});
  });
  return listen(srv).then((l) => ({ ...l, state }));
}
// ASIX's lane: Bearer key, headers, JSON body
function fakeAsix(c) {
  const state = { requests: [], code: 202 };
  const srv = https.createServer({ key: c.key, cert: c.cert }, (req, res) => {
    let raw = ''; req.on('data', (d) => { raw += d; });
    req.on('end', () => {
      state.requests.push({ method: req.method, path: req.url, auth: req.headers.authorization, headers: req.headers, body: raw ? JSON.parse(raw) : null });
      res.writeHead(state.code, { 'content-type': 'application/json' }); res.end(JSON.stringify({ success: state.code < 300 }));
    });
  });
  return listen(srv).then((l) => ({ ...l, state }));
}

describe('asix-indexer-health.sh and install-indexer-health.sh (stand-ins over HTTPS)', { skip: have ? false : 'needs openssl, python3 and curl' }, () => {
  let tmp, bin, curlLog, sysLog, idx, asix, idxCa, asixCa, env;
  const sh = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const put = (f, v) => { fs.mkdirSync(path.dirname(path.join(tmp, f)), { recursive: true }); fs.writeFileSync(path.join(tmp, f), v); };
  const setDisk = (total, avail) => put('df-numbers', `${total} ${avail}`);   // in KiB
  beforeEach(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ih-')); bin = path.join(tmp, 'bin'); curlLog = path.join(tmp, 'curl.log'); sysLog = path.join(tmp, 'systemctl.log'); fs.mkdirSync(bin);
    sh('id', 'echo 0'); sh('hostname', 'echo idx-vm.lab.local');
    sh('curl', `printf '%s\\n' "$*" >> '${curlLog}'\nexec ${CURL} "$@"`);
    sh('df', `read t a < '${tmp}/df-numbers'; printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/x %s %s %s 80%% /\\n' "$t" "$((t - a))" "$a"`);
    sh('systemctl', `echo "systemctl $*" >> '${sysLog}'; exit 0`);
    setDisk(104857600, 20971520);   // 100 GiB total, 20 GiB free: 80.0% used
    put('data/.keep', ''); put('idx/admin.pass', ADMIN + '\n');
    idxCa = makeCert(tmp, 'idx-ca'); asixCa = makeCert(tmp, 'asix-ca'); put('idx/root-ca.pem', idxCa.cert);
    idx = await fakeIndexer(idxCa); asix = await fakeAsix(asixCa);
    put('key.txt', KEY + '\n');
    env = { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_HEALTH_ENV: '/nonexistent', ASIX_HEALTH_URL: 'https://127.0.0.1:' + asix.port, ASIX_HEALTH_KEY_FILE: path.join(tmp, 'key.txt'), ASIX_HEALTH_CA: asixCa.certFile,
      ASIX_HEALTH_DATA_PATH: path.join(tmp, 'data'), ASIX_HEALTH_INDEXER_URL: 'https://127.0.0.1:' + idx.port, ASIX_HEALTH_INDEXER_CA: path.join(tmp, 'idx/root-ca.pem'), ASIX_HEALTH_ADMIN_PW: path.join(tmp, 'idx/admin.pass') };
  });
  afterEach(async () => { await idx.stop().catch(() => {}); await asix.stop().catch(() => {}); fs.rmSync(tmp, { recursive: true, force: true }); });
  const go = (file, args = [], over = {}) => new Promise((resolve) => {
    const p = spawn('bash', [file, ...args], { env: { ...env, ...over }, cwd: tmp }); let so = '', se = ''; p.stdout.on('data', (d) => { so += d; }); p.stderr.on('data', (d) => { se += d; });
    p.on('close', (code) => resolve({ code, out: so, err: se, all: so + se }));
  });
  const report = (args = [], over = {}) => go(SCRIPT, args, over);
  const printed = async (over = {}) => { const r = await report(['--print'], over); assert.strictEqual(r.code, 0, r.all); return JSON.parse(r.out); };
  const sent = () => asix.state.requests;

  describe('the report', () => {
    it('--print builds one event from the disk and the indexer, sends nothing, and needs no ASIX address or key', async () => {
      const b = await printed({ ASIX_HEALTH_URL: '', ASIX_HEALTH_KEY_FILE: '/nonexistent', ASIX_HEALTH_CA: '' });
      assert.strictEqual(b.length, 1); assert.strictEqual(b[0].host, 'idx-vm');
      assert.deepStrictEqual(b[0].fields, { disk_path: path.join(tmp, 'data'), cluster_status: 'green', disk_used_pct: 80.0, disk_free_gb: 20.0, disk_total_gb: 100.0, write_blocked_indices: 0 });
      assert.strictEqual(b[0].message, 'Findings indexer idx-vm: disk 80.0% used (20.0 GB free of 100.0 GB), indexer green, 0 index(es) refusing writes');
      assert.deepStrictEqual(sent(), []);
    });
    it('the disk number is (total - available) / total, to one decimal, with the sizes in GiB', async () => {
      setDisk(1000000, 37000); let f = (await printed())[0].fields; assert.strictEqual(f.disk_used_pct, 96.3); assert.strictEqual(f.disk_total_gb, 1.0); assert.strictEqual(f.disk_free_gb, 0.0);
      setDisk(209715200, 125829120); f = (await printed())[0].fields; assert.deepStrictEqual([f.disk_used_pct, f.disk_free_gb, f.disk_total_gb], [40.0, 120.0, 200.0]);
    });
    it('the indexer\'s own answer is passed on: green, yellow, red', async () => {
      for (const s of ['green', 'yellow', 'red']) { idx.state.status = s; assert.strictEqual((await printed())[0].fields.cluster_status, s); }
    });
    it('indices the indexer made read-only are counted (read_only_allow_delete and read_only, true as text or boolean), others are not', async () => {
      idx.state.indices = { a: { 'index.blocks.read_only_allow_delete': 'true' }, b: { 'index.blocks.read_only': 'true' }, c: { 'index.blocks.read_only_allow_delete': 'false' }, d: {}, e: { 'index.blocks.read_only_allow_delete': true } };
      assert.strictEqual((await printed())[0].fields.write_blocked_indices, 3);
      assert.ok(idx.state.requests.every((q) => q.cred === 'admin' && q.method === 'GET'), 'two read calls as admin, nothing else');
      assert.deepStrictEqual(idx.state.requests.map((q) => q.path), ['/_cluster/health', '/_all/_settings/index.blocks.*?flat_settings=true']);
    });
    it('an indexer that does not answer is "unreachable" and the disk is still reported, with no blocked count', async () => {
      await idx.stop(); const f = (await printed())[0].fields; assert.strictEqual(f.cluster_status, 'unreachable'); assert.strictEqual(f.disk_used_pct, 80.0); assert.ok(!('write_blocked_indices' in f));
    });
    it('a certificate that is not the indexer\'s CA is "unreachable"; a server error is "unreachable"', async () => {
      put('idx/root-ca.pem', asixCa.cert); assert.strictEqual((await printed())[0].fields.cluster_status, 'unreachable');
      put('idx/root-ca.pem', idxCa.cert); idx.state.healthCode = 503; assert.strictEqual((await printed())[0].fields.cluster_status, 'unreachable');
    });
    it('a refused admin password is "unknown", never "unreachable" (it says nothing about the indexer\'s health): the unhealthy alert must not fire for it', async () => {
      put('idx/admin.pass', 'wrong\n'); const f = (await printed())[0].fields; assert.strictEqual(f.cluster_status, 'unknown'); assert.ok(!('write_blocked_indices' in f)); assert.strictEqual(f.disk_used_pct, 80.0);
    });
    it('no admin password file, or an answer that is not JSON, is "unknown" and the disk is still reported', async () => {
      fs.rmSync(path.join(tmp, 'idx/admin.pass')); let f = (await printed())[0].fields; assert.strictEqual(f.cluster_status, 'unknown'); assert.deepStrictEqual(idx.state.requests, []);
      put('idx/admin.pass', ADMIN + '\n'); idx.state.rawHealth = '<html>nope</html>'; f = (await printed())[0].fields; assert.strictEqual(f.cluster_status, 'unknown');
      idx.state.rawHealth = JSON.stringify({ status: 'purple' }); assert.strictEqual((await printed())[0].fields.cluster_status, 'unknown', 'a status that is not one of the three');
    });
    it('a settings answer that is not JSON leaves the blocked count out but keeps the health', async () => {
      idx.state.settingsCode = 200; const orig = idx.state.indices; idx.state.indices = orig; // settings stay valid here; the next line breaks them
      idx.state.settingsCode = 500; const f = (await printed())[0].fields; assert.strictEqual(f.cluster_status, 'green'); assert.ok(!('write_blocked_indices' in f));
    });
    it('a data path that does not exist leaves the disk out and says so; the report is still sent in the right shape', async () => {
      const b = await printed({ ASIX_HEALTH_DATA_PATH: path.join(tmp, 'nothing-here') }); assert.ok(!('disk_used_pct' in b[0].fields)); assert.match(b[0].message, /disk not measured/);
    });
    it('a host name with a domain is cut to its first label; the collector defaults to indexer-<host>', async () => {
      const r = await report([]); assert.strictEqual(r.code, 0, r.all); assert.strictEqual(sent()[0].headers['x-asix-collector'], 'indexer-idx-vm'); assert.strictEqual(sent()[0].body[0].host, 'idx-vm');
    });
  });

  describe('sending it', () => {
    it('POSTs one JSON array to /v1/ingest/http with the key, the collector, platform, source type and version, and exits 0 with a line for the journal', async () => {
      const r = await report([], { ASIX_HEALTH_COLLECTOR: 'indexer-lab' }); assert.strictEqual(r.code, 0, r.all); assert.strictEqual(sent().length, 1);
      const q = sent()[0]; assert.strictEqual(q.method, 'POST'); assert.strictEqual(q.path, '/v1/ingest/http'); assert.strictEqual(q.auth, 'Bearer ' + KEY);
      assert.deepStrictEqual([q.headers['x-asix-collector'], q.headers['x-asix-platform'], q.headers['x-asix-source-type'], q.headers['x-asix-version'], q.headers['content-type']], ['indexer-lab', 'linux', 'indexer-health', 'asix-indexer-health-1', 'application/json']);
      assert.ok(Array.isArray(q.body) && q.body.length === 1 && q.body[0].fields.disk_used_pct === 80.0);
      assert.match(r.out, /reported to ASIX as indexer-lab \(HTTP 202\): Findings indexer idx-vm: disk 80\.0% used/);
    });
    it('neither the ingestion key nor the admin password is on a command line or in the output', async () => {
      const r = await report([]); assert.strictEqual(r.code, 0, r.all); const log = fs.readFileSync(curlLog, 'utf8');
      for (const secret of [KEY, ADMIN]) { assert.ok(!log.includes(secret), 'a secret on a curl command line'); assert.ok(!r.all.includes(secret), 'a secret in the output'); }
      assert.strictEqual((log.match(/-K \/dev\/fd\/\d+/g) || []).length, 3, 'all three calls (health, settings, send) take their secrets from a config on a file descriptor');
    });
    it('the key is read from the file and trimmed (spaces, a Windows line end)', async () => {
      put('key.txt', '  ' + KEY + '\r\n'); const r = await report([]); assert.strictEqual(r.code, 0, r.all); assert.strictEqual(sent()[0].auth, 'Bearer ' + KEY);
    });
    it('ASIX refusing the key (401) or rate limiting (429) is exit 1 with what to look at', async () => {
      asix.state.code = 401; let r = await report([]); assert.strictEqual(r.code, 1); assert.match(r.err, /refused the report \(HTTP 401\).*ingestion key active/);
      asix.state.code = 429; r = await report([]); assert.strictEqual(r.code, 1); assert.match(r.err, /HTTP 429/); asix.state.code = 500; r = await report([]); assert.strictEqual(r.code, 1); assert.match(r.err, /answered HTTP 500/);
    });
    it('ASIX not there, or its certificate not the one given, is exit 1 with a message that names the address and the CA setting', async () => {
      await asix.stop(); let r = await report([]); assert.strictEqual(r.code, 1); assert.match(r.err, /could not reach https:\/\/127\.0\.0\.1:\d+/); assert.match(r.err, /ASIX_HEALTH_CA/);
      asix = await fakeAsix(asixCa); r = await report([], { ASIX_HEALTH_URL: 'https://127.0.0.1:' + asix.port, ASIX_HEALTH_CA: idxCa.certFile }); assert.strictEqual(r.code, 1); assert.deepStrictEqual(sent(), []);
    });
  });

  describe('its settings', () => {
    it('every wrong or missing setting is exit 2 with a message and nothing is sent', async () => {
      const cases = [
        [{ ASIX_HEALTH_URL: '' }, /ASIX_HEALTH_URL/], [{ ASIX_HEALTH_URL: 'http://127.0.0.1:1' }, /ASIX_HEALTH_URL/], [{ ASIX_HEALTH_URL: 'https://x/path' }, /ASIX_HEALTH_URL/], [{ ASIX_HEALTH_URL: 'https://x:99999999' }, /ASIX_HEALTH_URL/],
        [{ ASIX_HEALTH_KEY_FILE: path.join(tmp, 'no-such') }, /no ingestion key/], [{ ASIX_HEALTH_COLLECTOR: 'bad name' }, /ASIX_HEALTH_COLLECTOR/], [{ ASIX_HEALTH_COLLECTOR: 'x'.repeat(101) }, /ASIX_HEALTH_COLLECTOR/],
        [{ ASIX_HEALTH_DATA_PATH: 'relative/path' }, /ASIX_HEALTH_DATA_PATH/], [{ ASIX_HEALTH_DATA_PATH: '/a b' }, /ASIX_HEALTH_DATA_PATH/], [{ ASIX_HEALTH_CA: path.join(tmp, 'no-such') }, /ASIX_HEALTH_CA/],
      ];
      for (const [over, re] of cases) { const r = await report([], over); assert.strictEqual(r.code, 2, JSON.stringify(over) + ' -> ' + r.all); assert.match(r.err, re, JSON.stringify(over)); }
      for (const bad of ['not-a-key', 'asix_ik_short', 'asix_ik_' + 'a'.repeat(30) + '"', 'asix_ik_' + 'a'.repeat(30) + '\nheader = "X: y']) { put('key.txt', bad + '\n'); const r = await report([]); assert.strictEqual(r.code, 2, JSON.stringify(bad)); }
      assert.deepStrictEqual(sent(), []); assert.strictEqual((await report(['--nope'])).code, 2);
    });
    it('a settings file is read for ASIX_HEALTH_ names only, never overrides the environment, and ignores everything else', async () => {
      put('health.env', `# comment\nASIX_HEALTH_COLLECTOR=from-file\nASIX_HEALTH_DATA_PATH="${path.join(tmp, 'data')}"\nPATH=/evil\nFOO=bar\nASIX_HEALTH_URL=https://127.0.0.1:1\n`);
      const r = await report(['--env', path.join(tmp, 'health.env')]); assert.strictEqual(r.code, 0, r.all);
      assert.strictEqual(sent()[0].headers['x-asix-collector'], 'from-file', 'taken from the file'); assert.strictEqual(sent().length, 1, 'ASIX_HEALTH_URL in the environment won over the file (port 1 was never tried)');
    });
  });

  describe('the whole chain: what the script sends is what the rules read', () => {
    const { compile, apply } = require('../src/ingestion/parsing-rules');
    const { jsonEvent } = require('../src/ingest/http-ingest');
    const { MemoryEventStore } = require('../src/events/memory-store');
    const { BUILTIN_RULES } = require('../src/detection/rule-runner');
    const { buildRuleMatch } = require('../src/detection/rule-query');
    const defaults = compile(require('../src/ingestion/default-parsing-rules'));
    const TENANT = '11111111-1111-4111-8111-111111111111', NOW = new Date('2026-11-01T12:00:00.000Z');
    const fire = async (bodies) => {
      const store = new MemoryEventStore(); const at = new Date(NOW - 60000).toISOString(); let n = 0;
      await store.insertBatch(TENANT, bodies.flatMap((body) => body.map((e) => { const x = jsonEvent(e, 'indexer-vm'); const out = apply([defaults.rules], { source_type: 'indexer-health', raw: x.raw, time: x.time, parsed: x.parsed }); n += 1;
        return { id: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`, source_type: 'indexer-health', collector_id: 'indexer-vm', received_at: at, event_time: at, raw: x.raw, parsed: out.parsed }; })));
      const o = {}; for (const r of BUILTIN_RULES.filter((b) => b.definition.source_type === 'indexer-health')) {
        const rows = (await store.matchGroups(TENANT, buildRuleMatch(r.definition, { now: NOW }))).filter((g) => g.n >= r.definition.threshold); if (rows.length) o[r.key] = rows.map((g) => g.key);
      } return o;
    };
    it('80% and healthy: the filling rule; 92%: nearly full; 97% with blocked indices: nearly full and writes refused; 50%: nothing', async () => {
      assert.deepStrictEqual(await fire([await printed()]), { 'indexer-disk-filling': ['idx-vm'] });
      setDisk(104857600, 8388608); assert.deepStrictEqual(await fire([await printed()]), { 'indexer-disk-nearly-full': ['idx-vm'] });
      setDisk(104857600, 3145728); idx.state.indices = { a: { 'index.blocks.read_only_allow_delete': 'true' } };
      assert.deepStrictEqual(await fire([await printed()]), { 'indexer-disk-nearly-full': ['idx-vm'], 'indexer-writes-refused': ['idx-vm'] });
      setDisk(104857600, 52428800); idx.state.indices = {}; assert.deepStrictEqual(await fire([await printed()]), {});
    });
    it('a stopped indexer reported twice raises "unhealthy"; once does not; a refused password never does', async () => {
      setDisk(104857600, 52428800); await idx.stop(); const one = await printed(); assert.deepStrictEqual(await fire([one]), {}); assert.deepStrictEqual(await fire([one, one]), { 'indexer-unhealthy': ['idx-vm'] });
      idx = await fakeIndexer(idxCa); env.ASIX_HEALTH_INDEXER_URL = 'https://127.0.0.1:' + idx.port; put('idx/admin.pass', 'wrong\n'); const refused = await printed(); assert.deepStrictEqual(await fire([refused, refused, refused]), {});
    });
  });

  describe('the installer', () => {
    const E = () => ({ ASIX_HEALTH_ETC: path.join(tmp, 'etc-asix'), ASIX_HEALTH_LIB: path.join(tmp, 'lib-asix'), ASIX_SYSTEMD_DIR: path.join(tmp, 'units'), ASIX_HEALTH_ENV: '/nonexistent' });
    const inst = (args = [], over = {}) => { fs.mkdirSync(path.join(tmp, 'units'), { recursive: true }); return go(INSTALL, args, { ...E(), ...over }); };
    const base = () => ['--url', 'https://127.0.0.1:' + asix.port, '--key-file', path.join(tmp, 'key.txt'), '--ca-file', asixCa.certFile, '--data-path', path.join(tmp, 'data')];
    const mode = (p) => fs.statSync(p).mode & 0o777; const etc = (f) => path.join(tmp, 'etc-asix', f); const calls = () => (fs.existsSync(sysLog) ? fs.readFileSync(sysLog, 'utf8').split('\n').filter(Boolean) : []);

    it('--check measures and prints what would be sent, and changes and sends nothing', async () => {
      const r = await inst([...base(), '--check']); assert.strictEqual(r.code, 0, r.all); assert.match(r.out, /"disk_used_pct": 80\.0/); assert.match(r.out, /Nothing was installed and nothing was sent/);
      assert.ok(!fs.existsSync(path.join(tmp, 'etc-asix'))); assert.ok(!fs.existsSync(path.join(tmp, 'lib-asix'))); assert.deepStrictEqual(sent(), []); assert.deepStrictEqual(calls(), []);
    });
    it('a full install: files with the right modes and contents, the key copied, the timer interval written, the timer enabled, a first report sent, the key never printed', async () => {
      const r = await inst([...base(), '--collector', 'indexer-lab', '--interval-min', '3']); assert.strictEqual(r.code, 0, r.all);
      const lib = path.join(tmp, 'lib-asix/asix-indexer-health.sh'); assert.strictEqual(mode(lib), 0o755); assert.strictEqual(fs.readFileSync(lib, 'utf8'), fs.readFileSync(SCRIPT, 'utf8'));
      assert.strictEqual(mode(etc('health.key')), 0o600); assert.strictEqual(fs.readFileSync(etc('health.key'), 'utf8'), KEY + '\n'); assert.strictEqual(mode(etc('health.env')), 0o640);
      assert.strictEqual(fs.readFileSync(etc('health.env'), 'utf8'), `ASIX_HEALTH_URL=https://127.0.0.1:${asix.port}\nASIX_HEALTH_COLLECTOR=indexer-lab\nASIX_HEALTH_DATA_PATH=${path.join(tmp, 'data')}\nASIX_HEALTH_KEY_FILE=${etc('health.key')}\nASIX_HEALTH_CA=${etc('asix-ca.pem')}\n`);
      assert.strictEqual(fs.readFileSync(etc('asix-ca.pem'), 'utf8'), asixCa.cert);
      const timer = fs.readFileSync(path.join(tmp, 'units/asix-indexer-health.timer'), 'utf8'); assert.match(timer, /^OnUnitActiveSec=3min$/m); assert.match(timer, /^OnBootSec=2min$/m); assert.match(timer, /WantedBy=timers\.target/);
      assert.strictEqual(fs.readFileSync(path.join(tmp, 'units/asix-indexer-health.service'), 'utf8'), fs.readFileSync(path.join(root, 'deploy/indexer/asix-indexer-health.service'), 'utf8'));
      assert.deepStrictEqual(calls(), ['systemctl daemon-reload', 'systemctl enable --now asix-indexer-health.timer']);
      assert.strictEqual(sent().length, 1, 'the first report is sent at the end'); assert.strictEqual(sent()[0].headers['x-asix-collector'], 'indexer-lab'); assert.match(r.out, /indexer-lab now reports every 3 minutes/);
      assert.ok(!r.all.includes(KEY), 'the key is never printed');
    });
    it('the shipped timer says 5 minutes and the shipped service reads the settings file and runs the installed script', () => {
      const t = fs.readFileSync(path.join(root, 'deploy/indexer/asix-indexer-health.timer'), 'utf8'), s = fs.readFileSync(path.join(root, 'deploy/indexer/asix-indexer-health.service'), 'utf8');
      assert.match(t, /^OnUnitActiveSec=5min$/m); assert.match(s, /Type=oneshot/); assert.match(s, /EnvironmentFile=-\/etc\/asix-indexer\/health\.env/); assert.match(s, /ExecStart=\/usr\/local\/lib\/asix-indexer\/asix-indexer-health\.sh/);
    });
    it('the collector defaults to indexer-<host>; running it again replaces the key and removes a CA that is no longer given', async () => {
      let r = await inst(base()); assert.strictEqual(r.code, 0, r.all); assert.match(fs.readFileSync(etc('health.env'), 'utf8'), /ASIX_HEALTH_COLLECTOR=indexer-idx-vm\n/);
      asix.state.requests.length = 0; await asix.stop(); asix = await fakeAsix(asixCa); put('key.txt', KEY2 + '\n');
      r = await inst(['--url', 'https://127.0.0.1:' + asix.port, '--key-file', path.join(tmp, 'key.txt'), '--data-path', path.join(tmp, 'data')], { ASIX_HEALTH_CA: '' });
      assert.strictEqual(fs.readFileSync(etc('health.key'), 'utf8'), KEY2 + '\n'); assert.ok(!fs.existsSync(etc('asix-ca.pem'))); assert.ok(!/ASIX_HEALTH_CA/.test(fs.readFileSync(etc('health.env'), 'utf8')));
      assert.strictEqual(r.code, 1, 'without the CA the self-signed stand-in is refused: the install stays, the first report fails'); assert.match(r.err, /did not reach ASIX/);
    });
    it('a first report ASIX refuses leaves everything installed, says so, and exits 1', async () => {
      asix.state.code = 401; const r = await inst(base()); assert.strictEqual(r.code, 1); assert.match(r.err, /The timer is installed, but the first report did not reach ASIX/); assert.match(r.err, /HTTP 401/);
      assert.ok(fs.existsSync(etc('health.env'))); assert.ok(calls().includes('systemctl enable --now asix-indexer-health.timer'));
    });
    it('--remove stops the timer and removes the files; running it on a machine that has nothing is fine', async () => {
      await inst(base()); fs.writeFileSync(sysLog, ''); const r = await inst(['--remove']); assert.strictEqual(r.code, 0, r.all);
      for (const f of [etc('health.env'), etc('health.key'), path.join(tmp, 'lib-asix/asix-indexer-health.sh'), path.join(tmp, 'units/asix-indexer-health.timer'), path.join(tmp, 'units/asix-indexer-health.service')]) assert.ok(!fs.existsSync(f), f);
      assert.deepStrictEqual(calls(), ['systemctl disable --now asix-indexer-health.timer', 'systemctl daemon-reload']); assert.strictEqual((await inst(['--remove'])).code, 0);
    });
    it('bad arguments are refused with exit 2 and nothing is written, installed or sent', async () => {
      put('empty.txt', ''); put('badkey.txt', 'asix_ik_short\n');
      const b = base(); const without = (flag) => { const a = [...b]; const i = a.indexOf(flag); a.splice(i, 2); return a; }; const swap = (flag, v) => { const a = [...b]; a[a.indexOf(flag) + 1] = v; return a; };
      const cases = [without('--url'), without('--key-file'), swap('--url', 'http://127.0.0.1:1'), swap('--url', 'https://x/p'), swap('--url', 'https://x y'), swap('--key-file', path.join(tmp, 'nope')), swap('--key-file', path.join(tmp, 'empty.txt')), swap('--key-file', path.join(tmp, 'badkey.txt')),
        swap('--ca-file', path.join(tmp, 'nope')), swap('--data-path', 'relative'), [...b, '--interval-min', '0'], [...b, '--interval-min', '61'], [...b, '--interval-min', 'x'], [...b, '--collector', 'a b'], [...b, '--nope']];
      for (const a of cases) { const r = await inst(a); assert.strictEqual(r.code, 2, a.join(' ') + ' -> ' + r.all); }
      assert.ok(!fs.existsSync(path.join(tmp, 'etc-asix'))); assert.ok(!fs.existsSync(path.join(tmp, 'lib-asix'))); assert.deepStrictEqual(sent(), []); assert.deepStrictEqual(calls(), []);
    });
    it('an interval over 7 minutes warns that the unhealthy alert could never fire; a data path that does not exist warns', async () => {
      let r = await inst([...base(), '--check', '--interval-min', '10']); assert.strictEqual(r.code, 0, r.all); assert.match(r.err, /can never fire/);
      r = await inst([...base().slice(0, -2), '--data-path', path.join(tmp, 'gone'), '--check']); assert.match(r.err, /does not exist on this machine/);
    });
    it('without root it refuses at once', async () => { sh('id', 'echo 1000'); const r = await inst([...base(), '--check']); assert.strictEqual(r.code, 1); assert.match(r.err, /Run as root/); });
  });
});

describe('the scripts and the docs agree', () => {
  it('both scripts are executable and parse with bash -n; the files are named in docs/wazuh-indexer.md and docs/endpoints.md', () => {
    for (const f of [SCRIPT, INSTALL]) { assert.ok(fs.statSync(f).mode & 0o100, f + ' is executable'); assert.strictEqual(spawnSync('bash', ['-n', f]).status, 0, f); }
    const doc = fs.readFileSync(path.join(root, 'docs/wazuh-indexer.md'), 'utf8'), tasks = fs.readFileSync(path.join(root, 'docs/endpoints.md'), 'utf8');
    for (const n of ['install-indexer-health.sh', 'asix-indexer-health.sh']) { assert.ok(doc.includes(n), n + ' in docs/wazuh-indexer.md'); assert.ok(tasks.includes(n), n + ' in docs/endpoints.md'); }
    assert.ok(tasks.includes('E6i'));
  });
  it('neither script puts a secret on a curl command line (a curl -u or --user), and neither echoes the key or the admin password', () => {
    for (const f of [SCRIPT, INSTALL]) { const t = fs.readFileSync(f, 'utf8'); assert.ok(!/curl[^\n]*(\s-u\s|--user\s)/.test(t), f + ' curl -u'); assert.ok(!/echo[^\n]*\$(\{KEY\}|KEY\b|\(cat "\$ADMIN_PW"\))/.test(t), f + ' echoes a secret'); }
  });
  it('the source type and the field names the script sends are the ones the built-in rules read', () => {
    const script = fs.readFileSync(SCRIPT, 'utf8'); const { BUILTIN_RULES } = require('../src/detection/rule-runner');
    const rules = BUILTIN_RULES.filter((r) => r.definition.source_type === 'indexer-health'); assert.strictEqual(rules.length, 4);
    assert.match(script, /X-ASIX-Source-Type: indexer-health/);
    const used = new Set(rules.flatMap((r) => r.definition.xql.match(/\b[a-z_]+(?= *(?:>=|<|>|=))/g)));
    assert.deepStrictEqual([...used].sort(), ['cluster_status', 'disk_used_pct', 'write_blocked_indices']); for (const f of used) assert.ok(script.includes(f), f + ' is produced by the script');
  });
});
