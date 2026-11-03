'use strict';
// E6j: scripts/deploy/wazuh-indexer-prune.sh (removes the indices of managers that no longer exist) and the `indices` command of src/endpoints/wazuh-indexer-cli.js that makes its keep list
// (docs/endpoints.md, "E6j as built"). The REAL script runs with the REAL curl, python3 and bash against a stand-in indexer over HTTPS (the _cat/indices listing and DELETE, admin sign-in);
// `id` is a stub. NOT covered: a real indexer's answers, and the CLI's database part (that is in tests/wazuh-indexer-db.test.js, which needs PostgreSQL).
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { spawn, spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const SCRIPT = path.join(root, 'scripts/deploy/wazuh-indexer-prune.sh');
const have = [['openssl', 'version'], ['python3', '--version'], ['curl', '--version']].every(([c, a]) => spawnSync(c, [a]).status === 0);
const CURL = (spawnSync('sh', ['-c', 'command -v curl'], { encoding: 'utf8' }).stdout || '').trim();
const ADMIN = 'Adm1n-Pass!x';
const P = 'wazuh-states-vulnerabilities-';
const DAY = 86400000;

function makeCert(dir) {
  const key = path.join(dir, 'k.key'), crt = path.join(dir, 'c.crt');
  const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', crt, '-days', '30', '-subj', '/CN=idx', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'subjectAltName=IP:127.0.0.1'], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
  return { key: fs.readFileSync(key, 'utf8'), cert: fs.readFileSync(crt, 'utf8'), file: crt };
}
// the indexer: Basic admin; GET /_cat/indices/wazuh-states-vulnerabilities-*; DELETE /<exact index>
function fakeIndexer(c, indices) {
  const state = { requests: [], indices, failDelete: new Set(), listCode: 200, rawList: null };
  const srv = https.createServer({ key: c.key, cert: c.cert }, (req, res) => {
    const m = /^Basic (.+)$/.exec(req.headers.authorization || ''); const cred = m ? Buffer.from(m[1], 'base64').toString('utf8') : '';
    state.requests.push({ method: req.method, path: req.url, cred: cred.split(':')[0] });
    const send = (s, b) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(typeof b === 'string' ? b : JSON.stringify(b)); };
    if (cred !== 'admin:' + ADMIN) return send(401, { status: 'UNAUTHORIZED' });
    if (req.method === 'GET' && req.url === '/_cat/indices/wazuh-states-vulnerabilities-*?format=json&bytes=b&h=index,docs.count,store.size,creation.date') {
      if (state.rawList !== null) return send(state.listCode, state.rawList);
      return send(state.listCode, Object.entries(state.indices).map(([index, v]) => ({ index, 'docs.count': String(v.docs), 'store.size': String(v.bytes), 'creation.date': String(Date.now() - v.ageDays * DAY) })));
    }
    if (req.method === 'DELETE' && /^\/[A-Za-z0-9._-]+$/.test(req.url)) {
      const n = req.url.slice(1);
      if (state.failDelete.has(n)) return send(500, { error: 'boom' });
      if (!state.indices[n]) return send(404, { error: 'index_not_found_exception' });
      delete state.indices[n]; return send(200, { acknowledged: true });
    }
    return send(400, { error: 'unexpected ' + req.method + ' ' + req.url });
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ port: srv.address().port, state, stop: () => new Promise((r) => srv.close(r)) })));
}

describe('wazuh-indexer-prune.sh against a stand-in indexer', { skip: have ? false : 'needs openssl, python3 and curl' }, () => {
  let tmp, bin, curlLog, idx, cert, env;
  const put = (f, v) => { fs.mkdirSync(path.dirname(path.join(tmp, f)), { recursive: true }); fs.writeFileSync(path.join(tmp, f), v); };
  const sh = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const keep = (...names) => put('keep.txt', names.join('\n') + '\n');
  const deleted = () => idx.state.requests.filter((r) => r.method === 'DELETE').map((r) => r.path.slice(1));
  const run = (args = [], over = {}) => new Promise((resolve) => {
    const urlArgs = over.NO_URL ? [] : ['--url', 'https://127.0.0.1:' + idx.port]; delete over.NO_URL;
    const p = spawn('bash', [SCRIPT, '--keep-file', path.join(tmp, 'keep.txt'), ...urlArgs, ...args], { env: { ...env, ...over }, cwd: tmp }); let so = '', se = '';
    p.stdout.on('data', (d) => { so += d; }); p.stderr.on('data', (d) => { se += d; }); p.on('close', (code) => resolve({ code, out: so, err: se, all: so + se }));
  });
  beforeEach(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'prune-')); bin = path.join(tmp, 'bin'); curlLog = path.join(tmp, 'curl.log'); fs.mkdirSync(bin);
    sh('id', 'echo 0'); sh('curl', `printf '%s\\n' "$*" >> '${curlLog}'\nexec ${CURL} "$@"`);
    cert = makeCert(tmp); put('admin.pass', ADMIN + '\n');
    idx = await fakeIndexer(cert, {
      [P + 'mgr-a']: { docs: 9000, bytes: 50 * 1048576, ageDays: 40 },        // registered
      [P + 'old-mgr']: { docs: 1200, bytes: 8 * 1048576, ageDays: 90 },        // orphan
      [P + 'gone-2']: { docs: 300, bytes: 2 * 1048576, ageDays: 30 },          // orphan
      [P + 'new-mgr']: { docs: 5, bytes: 100000, ageDays: 1 },                 // not registered yet but new
    });
    keep(P + 'mgr-a');
    env = { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_PRUNE_CA: cert.file, ASIX_PRUNE_ADMIN_PW: path.join(tmp, 'admin.pass'), ASIX_PRUNE_HEALTH_ENV: path.join(tmp, 'no-health.env') };
  });
  afterEach(async () => { await idx.stop().catch(() => {}); fs.rmSync(tmp, { recursive: true, force: true }); });

  describe('the preview (the default)', () => {
    it('lists keep, skip and ORPHAN with documents, size and age, says how much it would reclaim, and deletes nothing', async () => {
      const r = await run(); assert.strictEqual(r.code, 0, r.all);
      assert.match(r.out, new RegExp('keep +' + P + 'mgr-a +9000 docs, 50\\.0 MB, 40 day\\(s\\) old +\\(registered in ASIX\\)'));
      assert.match(r.out, new RegExp('ORPHAN +' + P + 'old-mgr +1200 docs, 8\\.0 MB, 90 day'));
      assert.match(r.out, new RegExp('ORPHAN +' + P + 'gone-2'));
      assert.match(r.out, new RegExp('skip +' + P + 'new-mgr .*younger than --min-age-days 7'));
      assert.match(r.out, /2 orphaned index\(es\), 10\.0 MB to reclaim\./); assert.match(r.out, /Preview only\. Nothing was removed/);
      assert.deepStrictEqual(deleted(), []); assert.ok(Object.keys(idx.state.indices).length === 4);
    });
    it('nothing orphaned: says so, exit 0', async () => {
      keep(P + 'mgr-a', P + 'old-mgr', P + 'gone-2'); const r = await run(); assert.strictEqual(r.code, 0, r.all); assert.match(r.out, /Nothing to remove\./); assert.deepStrictEqual(deleted(), []);
    });
  });

  describe('--delete', () => {
    it('deletes exactly the orphans older than --min-age-days, one exact name each, and nothing else', async () => {
      const r = await run(['--delete']); assert.strictEqual(r.code, 0, r.all);
      assert.deepStrictEqual(deleted().sort(), [P + 'gone-2', P + 'old-mgr']); assert.deepStrictEqual(Object.keys(idx.state.indices).sort(), [P + 'mgr-a', P + 'new-mgr']);
      assert.match(r.out, /removed +wazuh-states-vulnerabilities-old-mgr/); assert.match(r.out, /Done: removed 2 index\(es\), about 10\.0 MB\./);
      assert.ok(idx.state.requests.every((q) => !/[*?]/.test(q.path) || q.method === 'GET'), 'no wildcard in any delete');
    });
    it('--min-age-days 0 includes the young one; a larger number protects the older ones', async () => {
      let r = await run(['--delete', '--min-age-days', '0']); assert.strictEqual(r.code, 0, r.all); assert.deepStrictEqual(deleted().sort(), [P + 'gone-2', P + 'new-mgr', P + 'old-mgr']);
    });
    it('--min-age-days 60 leaves the 30 day old orphan alone', async () => {
      const r = await run(['--delete', '--min-age-days', '60']); assert.strictEqual(r.code, 0, r.all); assert.deepStrictEqual(deleted(), [P + 'old-mgr']);
    });
    it('a delete the indexer fails is reported, the others are still tried, and the exit code is 1', async () => {
      idx.state.failDelete.add(P + 'old-mgr'); const r = await run(['--delete']); assert.strictEqual(r.code, 1); assert.match(r.err, /FAILED +wazuh-states-vulnerabilities-old-mgr/); assert.match(r.err, /1 index\(es\) could not be removed/);
      assert.deepStrictEqual(Object.keys(idx.state.indices).sort(), [P + 'mgr-a', P + 'new-mgr', P + 'old-mgr']);
    });
  });

  describe('the guards', () => {
    it('an empty keep file, or one with only comments, is refused and nothing is deleted even with --delete', async () => {
      for (const body of ['', '\n\n', '# nothing\n  # here\n']) { put('keep.txt', body); const r = await run(['--delete']); assert.strictEqual(r.code, 1, JSON.stringify(body)); assert.match(r.err, /holds no index names/); }
      assert.deepStrictEqual(idx.state.requests, []);
    });
    it('a line that is not an exact index name is refused before anything is asked of the indexer', async () => {
      for (const bad of [P + '*', 'wazuh-alerts-4.x-2026.11.01', '_all', P + 'UPPER', P + 'a b', '../x', P]) {
        put('keep.txt', P + 'mgr-a\n' + bad + '\n'); const r = await run(['--delete']); assert.strictEqual(r.code, 2, JSON.stringify(bad)); assert.match(r.err, /is not an index name/);
      }
      assert.deepStrictEqual(idx.state.requests, []);
    });
    it('comments, blank lines, spaces and Windows line ends in the keep file are fine', async () => {
      put('keep.txt', '# from ASIX\r\n\r\n  ' + P + 'mgr-a  # the lab manager\r\n'); const r = await run(['--delete']); assert.strictEqual(r.code, 0, r.all); assert.deepStrictEqual(deleted().sort(), [P + 'gone-2', P + 'old-mgr']);
    });
    it('a keep file none of whose names exists here is refused (the wrong file or the wrong indexer): nothing is deleted', async () => {
      keep(P + 'some-other-manager'); const r = await run(['--delete']); assert.strictEqual(r.code, 1); assert.match(r.err, /None of the 1 registered index name\(s\) exists on this indexer/); assert.deepStrictEqual(deleted(), []);
    });
    it('more candidates than --max-delete is refused; raising it on purpose works', async () => {
      let r = await run(['--delete', '--max-delete', '1']); assert.strictEqual(r.code, 1); assert.match(r.err, /2 indices would be removed, more than --max-delete 1/); assert.deepStrictEqual(deleted(), []);
      r = await run(['--delete', '--max-delete', '2']); assert.strictEqual(r.code, 0, r.all); assert.strictEqual(deleted().length, 2);
    });
    it('names that only look like ours are never touched: a listing entry that is not a valid index name is left alone', async () => {
      idx.state.indices[P + 'UPPER-case'] = { docs: 1, bytes: 1, ageDays: 99 }; idx.state.indices[P + 'x'.repeat(120)] = { docs: 1, bytes: 1, ageDays: 99 };
      const r = await run(['--delete']); assert.strictEqual(r.code, 0, r.all); assert.ok(!deleted().includes(P + 'UPPER-case')); assert.match(r.out, /\?  wazuh-states-vulnerabilities-UPPER-case/);
    });
    it('only indices of the vulnerability family are listed from the indexer (the path is fixed), so other data is out of reach', async () => {
      await run(['--delete']); const gets = idx.state.requests.filter((q) => q.method === 'GET'); assert.deepStrictEqual(gets.map((q) => q.path), ['/_cat/indices/wazuh-states-vulnerabilities-*?format=json&bytes=b&h=index,docs.count,store.size,creation.date']);
    });
  });

  describe('talking to the indexer', () => {
    it('signs in as admin with the password file, which never appears on a command line or in the output', async () => {
      const r = await run(['--delete']); assert.ok(idx.state.requests.every((q) => q.cred === 'admin')); const log = fs.readFileSync(curlLog, 'utf8');
      assert.ok(!log.includes(ADMIN) && !r.all.includes(ADMIN)); assert.ok((log.match(/-K \/dev\/fd\/\d+/g) || []).length >= 3);
    });
    it('a wrong password, an unreachable indexer, a wrong CA and an answer that is not a list are each exit 1 with nothing deleted', async () => {
      put('admin.pass', 'wrong\n'); let r = await run(['--delete']); assert.strictEqual(r.code, 1); assert.match(r.err, /Could not list the indices/); assert.match(r.err, /HTTP 401/);
      put('admin.pass', ADMIN + '\n'); const other = makeCert(fs.mkdtempSync(path.join(os.tmpdir(), 'pr2-'))); r = await run(['--delete'], { ASIX_PRUNE_CA: other.file }); assert.strictEqual(r.code, 1);
      idx.state.rawList = '<html>'; r = await run(['--delete']); assert.strictEqual(r.code, 1); assert.match(r.err, /not a list of indices/);
      await idx.stop(); r = await run(['--delete']); assert.strictEqual(r.code, 1); assert.deepStrictEqual(deleted(), []);
    });
    it('the address defaults to the one the health reporter uses (health.env), else loopback; --url wins', async () => {
      put('health.env', 'ASIX_HEALTH_INDEXER_URL=https://127.0.0.1:' + idx.port + '\n');
      const r = await run([], { NO_URL: true, ASIX_PRUNE_HEALTH_ENV: path.join(tmp, 'health.env') });
      assert.strictEqual(r.code, 0, r.all); assert.match(r.out, new RegExp('Indices on https://127\\.0\\.0\\.1:' + idx.port));
    });
  });

  describe('its arguments', () => {
    it('wrong options and files are exit 2 and ask nothing of the indexer', async () => {
      const cases = [['--min-age-days', 'x'], ['--max-delete', '-1'], ['--url', 'http://127.0.0.1:9200'], ['--url', 'https://x/path'], ['--nope']];
      for (const a of cases) { const r = await run(a); assert.strictEqual(r.code, 2, a.join(' ') + ' -> ' + r.all); }
      let p = spawnSync('bash', [SCRIPT], { env, encoding: 'utf8' }); assert.strictEqual(p.status, 2); assert.match(p.stderr, /--keep-file is required/);
      p = spawnSync('bash', [SCRIPT, '--keep-file', path.join(tmp, 'nope.txt')], { env, encoding: 'utf8' }); assert.strictEqual(p.status, 2);
      assert.deepStrictEqual(idx.state.requests, []);
    });
    it('without root it refuses at once; a missing CA or password file is refused with the path named', async () => {
      sh('id', 'echo 1000'); let r = await run(); assert.strictEqual(r.code, 1); assert.match(r.err, /Run as root/); sh('id', 'echo 0');
      r = await run([], { ASIX_PRUNE_CA: path.join(tmp, 'nope.pem') }); assert.strictEqual(r.code, 1); assert.match(r.err, /No CA file/);
      r = await run([], { ASIX_PRUNE_ADMIN_PW: path.join(tmp, 'nope.pass') }); assert.strictEqual(r.code, 1); assert.match(r.err, /No admin password file/);
    });
  });
});

describe('the indices command of the operator CLI (arguments only; the database part is in wazuh-indexer-db.test.js)', () => {
  const cli = require('../src/endpoints/wazuh-indexer-cli');
  it('takes no --tenant, and every other command still needs one', () => {
    assert.deepStrictEqual(cli.parseArgs(['indices']), { cmd: 'indices', tenant: null, noCheck: false });
    assert.match(cli.parseArgs(['indices', '--tenant', 'x']).error, /does not take --tenant/);
    assert.match(cli.parseArgs(['indices', '--no-check']).error, /--no-check only goes with register/);
    for (const c of ['register', 'show', 'check', 'remove']) assert.match(cli.parseArgs([c]).error, /--tenant is required/, c);
  });
  it('is named in the usage text', async () => {
    const errs = []; const code = await cli.run(['nope'], { err: (l) => errs.push(l), out: () => {} }); assert.strictEqual(code, 2); assert.match(errs.join('\n'), /wazuh-indexer-cli\.js indices/);
  });
});

describe('the prune script and the docs agree', () => {
  it('the script is executable, parses with bash -n, and is named in docs/wazuh-indexer.md and docs/endpoints.md next to E6j', () => {
    assert.ok(fs.statSync(SCRIPT).mode & 0o100); assert.strictEqual(spawnSync('bash', ['-n', SCRIPT]).status, 0);
    const doc = fs.readFileSync(path.join(root, 'docs/wazuh-indexer.md'), 'utf8'), tasks = fs.readFileSync(path.join(root, 'docs/endpoints.md'), 'utf8');
    for (const t of [doc, tasks]) assert.ok(t.includes('wazuh-indexer-prune.sh'));
    assert.ok(tasks.includes('E6j'));
  });
  it('the script never puts the admin password on a curl command line', () => {
    const t = fs.readFileSync(SCRIPT, 'utf8'); assert.ok(!/curl[^\n]*(\s-u\s|--user\s)/.test(t)); assert.ok(/-K <\(printf/.test(t));
  });
  it('the index-name pattern in the script is the one the database enforces for a registration', () => {
    const t = fs.readFileSync(SCRIPT, 'utf8'); const m = /NAME_RE='\^(.+)\$'/.exec(t); assert.ok(m);
    const schema = fs.readFileSync(path.join(root, 'k8s/12-schema-init.yaml'), 'utf8'); assert.ok(schema.includes("'^" + m[1] + "$'"), 'same pattern as the wazuh_indexers CHECK');
  });
});
