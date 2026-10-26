'use strict';
// The broker's optional file and HTTP inputs (deploy/broker/vector-file.yaml, vector-http.yaml; bootstrap-broker.sh --file-glob, --http-user ...).
//   1. static checks that the files, broker.env.example and the bootstrap script agree (always run);
//   2. the bootstrap script's own validation block, run in bash with nothing installed or written (always run);
//      More than one --file-glob: the flag collects them, the block checks each one, and the generated vector-file.yaml has one include line per glob.
//   3. with a real Vector binary (VECTOR_BIN, or `vector` on PATH; written against 0.59.0) the configs are validated and run: a file is
//      appended to and JSON is POSTed, and what reaches a stand-in for the ASIX HTTP lane is checked. Skipped without Vector.
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
const fileCfg = read('deploy/broker/vector-file.yaml');
const httpCfg = read('deploy/broker/vector-http.yaml');
const envExample = read('deploy/broker/broker.env.example');
const bootstrap = read('scripts/deploy/bootstrap-broker.sh');

describe('broker file and HTTP inputs: the files agree', () => {
  it('the file input reads one glob from ASIX_FILE_GLOB, skips history on the first start, and sends source type "file"', () => {
    assert.match(fileCfg, /include:\n\s+- "\$\{ASIX_FILE_GLOB\}"/);
    assert.match(fileCfg, /read_from: end/);
    assert.match(fileCfg, /X-ASIX-Source-Type: file\b/);
    assert.match(fileCfg, /X-ASIX-Collector: \$\{ASIX_BROKER_NAME\}/);
  });
  it('the HTTP input has NO default for the user or the password (Vector refuses to start without them), only POST on /events', () => {
    assert.match(httpCfg, /username: "\$\{ASIX_HTTP_USER\}"/);
    assert.match(httpCfg, /password: "\$\{ASIX_HTTP_PASSWORD\}"/);
    assert.ok(!/ASIX_HTTP_(USER|PASSWORD):-/.test(httpCfg));
    assert.match(httpCfg, /path: \/events/); assert.match(httpCfg, /strict_path: true/); assert.match(httpCfg, /method: POST/);
    assert.match(httpCfg, /codec: json/);
    assert.match(httpCfg, /X-ASIX-Source-Type: http\b/);
    assert.match(httpCfg, /enabled: \$\{ASIX_HTTP_TLS:-false\}/);
  });
  it('every disk buffer is at least the 268435488 bytes Vector demands (vector validate does not check it, starting Vector does)', () => {
    for (const f of ['vector', 'vector-file', 'vector-http']) {
      for (const m of read(`deploy/broker/${f}.yaml`).matchAll(/max_size: (\d+)/g)) assert.ok(Number(m[1]) >= 268435488, `${f}.yaml max_size ${m[1]}`);
    }
  });
  it('both configs end at the same HTTP lane sink settings as the syslog one (batch under the lane limits, retries, CA file)', () => {
    for (const cfg of [fileCfg, httpCfg]) {
      assert.match(cfg, /uri: \$\{ASIX_INGEST_URL\}/); assert.match(cfg, /max_events: 500/); assert.match(cfg, /max_bytes: 900000/);
      assert.match(cfg, /ca_file: \$\{ASIX_CA_FILE:-\/etc\/ssl\/certs\/ca-certificates\.crt\}/);
      assert.match(cfg, /Authorization: "Bearer \$\{ASIX_INGEST_KEY\}"/);
    }
  });
  it('every setting the two files read is documented in broker.env.example and written by the bootstrap script', () => {
    for (const v of ['ASIX_FILE_GLOB', 'ASIX_HTTP_USER', 'ASIX_HTTP_PASSWORD', 'ASIX_HTTP_PORT', 'ASIX_HTTP_TLS']) {
      assert.match(envExample, new RegExp('#' + v + '='), v + ' in broker.env.example');
      assert.match(bootstrap, new RegExp('echo "' + v + '='), v + ' written by bootstrap');
    }
  });
  it('the bootstrap script installs each file only when asked, removes it on a re-run without, validates it, and lists it in VECTOR_CONFIG', () => {
    for (const [flag, file] of [['FILE_GLOB', 'vector-file.yaml'], ['HTTP_USER', 'vector-http.yaml']]) {
      // the HTTP config is copied as it is; the file config is generated from its template (one include line per glob), see the tests below
      const installed = flag === 'FILE_GLOB' ? 'install -m 644 "\\$FILE_CFG_TMP" /etc/vector/' + file + '; rm -f "\\$FILE_CFG_TMP"\\n  # --- end file input config ---' : 'install -m 644 "\\$SRC/' + file + '" /etc/vector/' + file;
      assert.match(bootstrap, new RegExp(`if \\[ -n "\\$${flag}" \\]; then\\n[\\s\\S]*?  ${installed}\\nelse\\n  rm -f /etc/vector/${file}`));
      assert.match(bootstrap, new RegExp('\\$\\{' + flag + ':\\+/etc/vector/' + file.replace('.', '\\.') + '\\}'));
      assert.match(bootstrap, new RegExp('CONFIGS="\\$CONFIGS,/etc/vector/' + file.replace('.', '\\.') + '"'));
    }
    for (const f of ['deploy/broker/asix-broker-config.sh', 'scripts/deploy/upgrade-broker.sh']) {
      const s = read(f);
      assert.match(s, /for f in vector-file\.yaml vector-http\.yaml vector-journald\.yaml/, f + ' validates the optional inputs too');
    }
  });
  it('the password goes in a file, never on the command line', () => {
    assert.ok(!/--http-password\)/.test(bootstrap)); assert.match(bootstrap, /--http-password-file\) HTTP_PW_FILE="\$2"; shift 2;;/);
  });
});

describe('bootstrap validation of the new flags (the real block, run in bash, nothing installed)', () => {
  const a = bootstrap.indexOf('# Extra inputs: files and HTTP.'); const b = bootstrap.indexOf('SRC="$(cd');
  assert.ok(a > 0 && b > a);
  const block = bootstrap.slice(a, b);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-inputs-'));
  const pw = (name, text) => { const f = path.join(tmp, name); fs.writeFileSync(f, text); return f; };
  const good = pw('good.pw', 'Sup3rS3cretPw-01\n');
  const run = (vars) => spawnSync('bash', ['-c', block], { env: { PATH: process.env.PATH, PORT: '514', TLS_PORT: '6514', TLS_CERT: '', FILE_GLOB: '', HTTP_USER: '', HTTP_PW_FILE: '', HTTP_PORT: '8088', HTTP_TLS: '0', ...vars }, encoding: 'utf8' });
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('accepts nothing, a plain glob, a glob with ? and [], and a full HTTP setup', () => {
    assert.strictEqual(run({}).status, 0);
    for (const g of ['/var/log/app/*.log', '/var/log/my-app/[ab]*.log', '/var/log/a?.txt', '/srv/x_y.z/log-*']) assert.strictEqual(run({ FILE_GLOB: g }).status, 0, g);
    assert.strictEqual(run({ HTTP_USER: 'svc', HTTP_PW_FILE: good }).status, 0);
    assert.strictEqual(run({ HTTP_USER: 'svc', HTTP_PW_FILE: good, HTTP_TLS: '1', TLS_CERT: '/x.crt', HTTP_PORT: '8443' }).status, 0);
  });
  it('refuses globs that are relative, have spaces, "..", quotes, $, ; or {}', () => {
    for (const g of ['relative/*.log', '/var/log/a b/*', '/var/log/../etc/*', '/var/log/"q"/*', "/var/log/'q'/*", '/var/log/$(id)/*', '/var/log/x;y', '/var/log/{a,b}/*', '/var/log/a\\b'])
      { const r = run({ FILE_GLOB: g }); assert.strictEqual(r.status, 2, g); assert.match(r.stderr, /--file-glob must be an absolute path glob/); }
  });
  it('needs the HTTP user and the password file together, a sane user, a sane port, a readable file and a strong-enough password', () => {
    let r = run({ HTTP_USER: 'svc' }); assert.strictEqual(r.status, 2); assert.match(r.stderr, /needed together/);
    r = run({ HTTP_PW_FILE: good }); assert.strictEqual(r.status, 2); assert.match(r.stderr, /needed together/);
    r = run({ HTTP_USER: 'bad user', HTTP_PW_FILE: good }); assert.strictEqual(r.status, 2); assert.match(r.stderr, /--http-user/);
    for (const p of ['0', '65536', 'abc', '']) { r = run({ HTTP_USER: 'svc', HTTP_PW_FILE: good, HTTP_PORT: p }); assert.strictEqual(r.status, 2, 'port ' + p); assert.match(r.stderr, /--http-port must be a number/); }
    r = run({ HTTP_USER: 'svc', HTTP_PW_FILE: good, HTTP_PORT: '514' }); assert.strictEqual(r.status, 2); assert.match(r.stderr, /must differ from --port/);
    r = run({ HTTP_USER: 'svc', HTTP_PW_FILE: good, HTTP_PORT: '6514' }); assert.strictEqual(r.status, 2); assert.match(r.stderr, /must differ from --port/);
    r = run({ HTTP_USER: 'svc', HTTP_PW_FILE: path.join(tmp, 'missing') }); assert.strictEqual(r.status, 2); assert.match(r.stderr, /Cannot read/);
    for (const [name, text] of [['short', 'short\n'], ['space', 'has a space 12345\n'], ['quote', 'abcdefghijkl"mn\n'], ['dollar', 'abcdefghijkl$mn\n'], ['hash', 'abcdefghijkl#mn\n'], ['empty', '\n'], ['long', 'a'.repeat(129) + '\n']]) {
      r = run({ HTTP_USER: 'svc', HTTP_PW_FILE: pw(name + '.pw', text) }); assert.strictEqual(r.status, 2, name); assert.match(r.stderr, /HTTP password/);
    }
    assert.strictEqual(run({ HTTP_USER: 'svc', HTTP_PW_FILE: pw('crlf.pw', 'Sup3rS3cretPw-01\r\nsecond line ignored\r\n') }).status, 0, 'only the first line counts, a CR is dropped');
  });
  it('--http-tls needs a certificate and an HTTP input', () => {
    let r = run({ HTTP_USER: 'svc', HTTP_PW_FILE: good, HTTP_TLS: '1' }); assert.strictEqual(r.status, 2); assert.match(r.stderr, /--http-tls needs --tls-cert/);
    r = run({ HTTP_TLS: '1' }); assert.strictEqual(r.status, 2); assert.match(r.stderr, /only makes sense with/);
  });
});

describe('more than one --file-glob (the real argument line and the real blocks of bootstrap-broker.sh, run in bash; nothing installed)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-globs-'));
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const NL = '\n';
  // The one line of the argument loop that takes --file-glob, cut out of the script and run for a list of arguments.
  const flagLine = bootstrap.split(NL).find((l) => l.trimStart().startsWith('--file-glob)'));
  const collect = (...globs) => {
    const code = 'FILE_GLOB=""\nset -- ' + globs.map((g) => "--file-glob '" + g + "'").join(' ') + '\nwhile [ $# -gt 0 ]; do case "$1" in\n' + flagLine + '\n*) exit 9;; esac; done\nprintf "%s" "$FILE_GLOB"';
    return spawnSync('bash', ['-c', code], { encoding: 'utf8' }).stdout;
  };
  const a = bootstrap.indexOf('# Extra inputs: files and HTTP.'); const b = bootstrap.indexOf('SRC="$(cd');
  const validate = (list) => spawnSync('bash', ['-c', bootstrap.slice(a, b) + '\nprintf "%s" "$FILE_GLOB"'], { env: { PATH: process.env.PATH, PORT: '514', TLS_PORT: '6514', TLS_CERT: '', FILE_GLOB: list, HTTP_USER: '', HTTP_PW_FILE: '', HTTP_PORT: '8088', HTTP_TLS: '0' }, encoding: 'utf8' });
  const c0 = bootstrap.indexOf('  # --- file input config:'); const c1 = bootstrap.indexOf('  # --- end file input config ---');
  const generateArg = (list, template) => {   // the same, but FILE_GLOB handed over as an environment variable
    const dest = path.join(tmp, 'o-' + Math.random().toString(16).slice(2) + '.yaml');
    const src = path.join(tmp, 's-' + Math.random().toString(16).slice(2)); fs.mkdirSync(src);
    fs.writeFileSync(path.join(src, 'vector-file.yaml'), template === undefined ? fileCfg : template);
    const code = 'SRC="' + src + '"\n' + bootstrap.slice(c0, c1).split('/etc/vector/vector-file.yaml').join(dest);
    return { r: spawnSync('bash', ['-c', code], { env: { PATH: process.env.PATH, FILE_GLOB: list }, encoding: 'utf8' }), dest };
  };

  it('the flag can be repeated: every glob is kept, one per line, in order', () => {
    assert.ok(flagLine, 'the --file-glob line exists');
    assert.strictEqual(collect('/var/log/a/*.log'), '/var/log/a/*.log');
    assert.strictEqual(collect('/var/log/a/*.log', '/srv/b/*.txt', '/opt/c/log-?'), ['/var/log/a/*.log', '/srv/b/*.txt', '/opt/c/log-?'].join(NL));
  });
  it('each glob is checked: one bad one among good ones refuses the lot (exit 2, nothing written)', () => {
    for (const bad of ['relative/*.log', '/var/log/a b/*', '/var/log/../etc/*', '/var/log/$(id)/*', '/var/log/x;y', '/var/log/{a,b}/*', '']) {
      const r = validate(['/var/log/a/*.log', bad, '/srv/b/*.log'].join(NL));
      assert.strictEqual(r.status, 2, JSON.stringify(bad)); assert.match(r.stderr, /--file-glob must be an absolute path glob/);
    }
  });
  it('the same glob twice counts once; the list comes back without duplicates and without changing the order', () => {
    const r = validate(['/a/*.log', '/b/*.log', '/a/*.log', '/b/*.log', '/c/*.log'].join(NL));
    assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(r.stdout, ['/a/*.log', '/b/*.log', '/c/*.log'].join(NL));
    // and a glob that is only a prefix of another is NOT a duplicate of it
    assert.strictEqual(validate(['/a/*', '/a/*.log'].join(NL)).stdout, ['/a/*', '/a/*.log'].join(NL));
  });
  it('at most 10 different globs; the 11th is refused, ten are fine, eleven with a repeat are ten', () => {
    const many = (n) => Array.from({ length: n }, (_, i) => '/var/log/app' + i + '/*.log');
    assert.strictEqual(validate(many(10).join(NL)).status, 0);
    const r = validate(many(11).join(NL)); assert.strictEqual(r.status, 2); assert.match(r.stderr, /at most 10 times \(got 11\)/);
    assert.strictEqual(validate(many(10).concat(many(10)[3]).join(NL)).status, 0, 'a repeat is not a new glob');
  });
  it('generates ONE include line per glob in the installed file and nothing else changes', () => {
    const globs = ['/var/log/myapp/*.log', '/srv/other/[ab]*.log', '/opt/x/log-?'];
    const { r, dest } = generateArg(globs.join(NL));
    assert.strictEqual(r.status, 0, r.stderr);
    const out = fs.readFileSync(dest, 'utf8');
    const want = fileCfg.replace('      - "${ASIX_FILE_GLOB}"', globs.map((g) => '      - "' + g + '"').join(NL));
    assert.strictEqual(out, want);
    assert.ok(!out.includes('${ASIX_FILE_GLOB}'), 'the placeholder is gone');
    assert.strictEqual(fs.statSync(dest).mode & 0o777, 0o644);
    // one glob: only the placeholder's line differs
    const one = generateArg('/var/log/myapp/*.log'); assert.strictEqual(fs.readFileSync(one.dest, 'utf8'), fileCfg.replace('${ASIX_FILE_GLOB}', '/var/log/myapp/*.log'));
  });
  it('refuses to install when the template has no single include line to fill in (a template that was edited by hand)', () => {
    const none = generateArg('/a/*.log', fileCfg.replace('      - "${ASIX_FILE_GLOB}"', '      - "/etc/fixed.log"'));
    assert.strictEqual(none.r.status, 1); assert.match(none.r.stderr, /no single include line/); assert.ok(!fs.existsSync(none.dest), 'nothing installed');
    const two = generateArg('/a/*.log', fileCfg.replace('      - "${ASIX_FILE_GLOB}"', '      - "${ASIX_FILE_GLOB}"\n      - "${ASIX_FILE_GLOB}"'));
    assert.strictEqual(two.r.status, 1); assert.ok(!fs.existsSync(two.dest));
  });
  it('broker.env gets all globs on one line, comma separated; the script says which globs it reads', () => {
    assert.match(bootstrap, /echo "ASIX_FILE_GLOB=\$\(printf '%s\\n' "\$FILE_GLOB" \| paste -sd, -\)"/);
    const line = bootstrap.split(NL).find((l) => /ASIX_FILE_GLOB=\$\(printf/.test(l)).trim().replace(/^\[ -z "\$FILE_GLOB" \] \|\| /, '').replace(/\s+#.*$/, '');
    const r = spawnSync('bash', ['-c', line], { env: { PATH: process.env.PATH, FILE_GLOB: ['/a/*.log', '/b/*.log'].join(NL) }, encoding: 'utf8' });
    assert.strictEqual(r.stdout, 'ASIX_FILE_GLOB=/a/*.log,/b/*.log\n');
    assert.match(bootstrap, /Reading files matching \$\{FILE_GLOB\/\/\$'\\n'\/, \}/);
  });
});

// ---- real Vector -------------------------------------------------------------------------------------------------------------------------
const VECTOR = process.env.VECTOR_BIN || (spawnSync('vector', ['--version']).status === 0 ? 'vector' : null);
const freePort = () => new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms) => { const end = Date.now() + ms; for (;;) { const v = await fn(); if (v) return v; if (Date.now() > end) return null; await sleep(200); } };

describe('real Vector: the configs validate, refuse to start without a password, and carry file lines and JSON to the ASIX lane', { skip: VECTOR ? false : 'no Vector binary (set VECTOR_BIN)' }, () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-vec-'));
  const logs = path.join(tmp, 'logs'); fs.mkdirSync(logs);
  const cfgDir = path.join(tmp, 'cfg'); fs.mkdirSync(cfgDir);
  const dataDir = path.join(tmp, 'data'); fs.mkdirSync(dataDir);
  let vec, lane, httpPort, laneCalls = [];
  const baseEnv = { PATH: process.env.PATH, VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: 'true', ASIX_INGEST_KEY: 'asix_ik_test', ASIX_BROKER_NAME: 'broker-test', ASIX_FILE_GLOB: path.join(logs, '*.log'), ASIX_HTTP_USER: 'svc', ASIX_HTTP_PASSWORD: 's3cretpassword' };
  const files = ['vector.yaml', 'vector-file.yaml', 'vector-http.yaml'].map((f) => path.join(cfgDir, f));
  const auth = (pwd) => 'Basic ' + Buffer.from('svc:' + pwd).toString('base64');
  const post = (p, body, pwd = 's3cretpassword') => fetch(`http://127.0.0.1:${httpPort}${p}`, { method: 'POST', headers: { 'content-type': 'application/json', ...(pwd === null ? {} : { authorization: auth(pwd) }) }, body });
  const lines = (type) => laneCalls.filter((c) => c.h['x-asix-source-type'] === type).flatMap((c) => c.body.split('\n').filter(Boolean));

  before(async () => {
    // A private copy: Vector's own data directory and API port must not be the machine's.
    fs.writeFileSync(files[0], read('deploy/broker/vector.yaml').replace('data_dir: /var/lib/vector', 'data_dir: ' + dataDir).replace(/api:\n  enabled: true\n  address: 127.0.0.1:8686/, 'api:\n  enabled: false'));
    fs.copyFileSync(path.join(root, 'deploy/broker/vector-file.yaml'), files[1]); fs.copyFileSync(path.join(root, 'deploy/broker/vector-http.yaml'), files[2]);
    lane = http.createServer((q, s) => { let b = ''; q.on('data', (d) => { b += d; }); q.on('end', () => { laneCalls.push({ h: q.headers, body: b }); s.writeHead(202, { 'content-type': 'application/json' }); s.end('{"success":true}'); }); });
    await new Promise((r) => lane.listen(0, '127.0.0.1', r));
    httpPort = await freePort();
    fs.writeFileSync(path.join(logs, 'app.log'), 'a line written before Vector starts\n');
  });
  after(() => { if (vec) vec.kill('SIGKILL'); lane.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

  const envFor = (extra = {}) => ({ ...baseEnv, ASIX_INGEST_URL: `http://127.0.0.1:${lane.address().port}/v1/ingest/http`, ASIX_SYSLOG_PORT: String(syslogPort), ASIX_HTTP_PORT: String(httpPort), ...extra });
  let syslogPort;
  it('validates the file config, the HTTP config and all of them together', async () => {
    syslogPort = await freePort();
    for (const set of [[files[0], files[1]], [files[0], files[2]], files]) {
      const r = spawnSync(VECTOR, ['validate', '--no-environment', ...set], { env: envFor(), encoding: 'utf8' });
      assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    }
  });
  it('refuses to load the HTTP config without the password (so there is never an open listener)', () => {
    const e = envFor(); delete e.ASIX_HTTP_PASSWORD;
    const r = spawnSync(VECTOR, ['validate', '--no-environment', files[0], files[2]], { env: e, encoding: 'utf8' });
    assert.notStrictEqual(r.status, 0); assert.match(r.stdout + r.stderr, /ASIX_HTTP_PASSWORD/);
  });
  it('starts with all three configs, and the file input reads new lines (not the history), the HTTP input answers 401/400/405/200', async () => {
    vec = spawn(VECTOR, files.flatMap((f) => ['--config', f]), { env: envFor(), stdio: 'ignore' });
    const up = await until(async () => { try { return (await post('/events', '{}', null)).status === 401; } catch { return false; } }, 20000);
    assert.ok(up, 'Vector did not start listening');
    assert.strictEqual((await post('/events', '{"a":1}', 'wrong')).status, 401);
    assert.strictEqual((await post('/events', 'hello, not json')).status, 400);
    assert.strictEqual((await post('/other', '{"a":1}')).status, 405);
    assert.strictEqual((await fetch(`http://127.0.0.1:${httpPort}/events`, { headers: { authorization: auth('s3cretpassword') } })).status, 405);
    assert.strictEqual((await post('/events', '{"host":"app 1","message":"login failed","user":"bob"}')).status, 200);
    assert.strictEqual((await post('/events', '[{"message":"one"},{"message":"two","hostname":"h2"}]')).status, 200);
    assert.strictEqual((await post('/events', '{"message":"n1"}\n{"message":"n2"}')).status, 200);
    fs.appendFileSync(path.join(logs, 'app.log'), '2026-10-20T14:03:11Z worker started\nplain line, no time\n');
    fs.writeFileSync(path.join(logs, 'new.log'), 'first line of a new file\n');
    const got = await until(() => lines('http').length >= 5 && lines('file').length >= 3, 20000);
    assert.ok(got, 'lane got: ' + JSON.stringify({ http: lines('http'), file: lines('file') }));
  });
  it('the HTTP lines are "ISO-time host http: {json}", one per object, with the host from the object, and never the sender\'s password', () => {
    const l = lines('http');
    const re = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+00:00) (\S+) http: (\{.*\})$/;
    for (const x of l) assert.match(x, re, x);
    const byHost = Object.fromEntries(l.map((x) => { const m = x.match(re); return [m[2] + ':' + JSON.parse(m[3]).message, JSON.parse(m[3])]; }));
    assert.deepStrictEqual(byHost['app_1:login failed'], { host: 'app 1', message: 'login failed', user: 'bob' });
    assert.ok(byHost['unknown-host:one'] && byHost['h2:two'] && byHost['unknown-host:n1'] && byHost['unknown-host:n2']);
    assert.ok(!l.some((x) => /s3cretpassword|authorization|source_type|"path"/i.test(x)), 'no credentials or Vector internals in the stored line');
  });
  it('the file lines are "ISO-time host file-name: line"; a leading time WITH a zone is the event time, otherwise the read time; old content is skipped; a new file is read from its start', () => {
    const l = lines('file');
    assert.ok(!l.some((x) => /before Vector starts/.test(x)), 'history is not sent');
    const timed = l.find((x) => /worker started/.test(x));
    assert.match(timed, /^2026-10-20T14:03:11\+00:00 \S+ app\.log: 2026-10-20T14:03:11Z worker started$/);
    const plain = l.find((x) => /plain line/.test(x)); assert.match(plain, /^\d{4}-\d{2}-\d{2}T\S+ \S+ app\.log: plain line, no time$/);
    assert.ok(Math.abs(Date.parse(plain.split(' ')[0]) - Date.now()) < 60000, 'read time is about now');
    assert.match(l.find((x) => /new file/.test(x)), / new\.log: first line of a new file$/);
  });
  it('the requests carry the key, the broker name and the source type, as text lines the lane accepts', () => {
    for (const c of laneCalls) {
      assert.strictEqual(c.h.authorization, 'Bearer asix_ik_test'); assert.strictEqual(c.h['x-asix-collector'], 'broker-test');
      assert.match(c.h['content-type'], /^text\/plain/); assert.ok(['http', 'file'].includes(c.h['x-asix-source-type']));
      assert.ok(c.body.split('\n').filter(Boolean).length <= 500);
    }
  });
  it('a restart carries on where Vector was: a line written while it was down arrives once, nothing is sent twice', async () => {
    const log = path.join(logs, 'app.log'); const count = (t) => lines('file').filter((x) => x.endsWith(t)).length;
    fs.appendFileSync(log, 'line A\n');
    assert.ok(await until(() => count('line A') === 1, 20000), 'A arrives');
    await new Promise((res) => { vec.once('exit', res); vec.kill('SIGTERM'); });   // a graceful stop writes the checkpoint
    fs.appendFileSync(log, 'line B, written while Vector is down\n');
    vec = spawn(VECTOR, files.flatMap((f) => ['--config', f]), { env: envFor(), stdio: 'ignore' });
    assert.ok(await until(async () => { try { return (await post('/events', '{}', null)).status === 401; } catch { return false; } }, 20000), 'Vector is back');
    fs.appendFileSync(log, 'line C\n');
    assert.ok(await until(() => count('line B, written while Vector is down') === 1 && count('line C') === 1, 20000), 'B and C arrive');
    await sleep(6000);   // time for a duplicate to show up if there were one
    assert.strictEqual(count('line A'), 1); assert.strictEqual(count('line B, written while Vector is down'), 1); assert.strictEqual(count('line C'), 1);
    assert.ok(!lines('file').some((x) => /before Vector starts/.test(x)), 'history is still not sent after the restart');
  });
  it('the lines really parse in the ASIX lane (same parser the server uses)', () => {
    const { parseLine } = require('../src/ingest/http-ingest');
    const p = parseLine(lines('file').find((x) => /worker started/.test(x)), 'broker-test');
    assert.strictEqual(p.parsed.format, 'syslog-file'); assert.strictEqual(p.parsed.app_name, 'app.log'); assert.strictEqual(p.time, '2026-10-20T14:03:11.000Z');
    const q = parseLine(lines('http').find((x) => /login failed/.test(x)), 'broker-test');
    assert.strictEqual(q.parsed.format, 'syslog-file'); assert.strictEqual(q.parsed.host, 'app_1'); assert.strictEqual(q.parsed.app_name, 'http');
    assert.deepStrictEqual(JSON.parse(q.parsed.message), { host: 'app 1', message: 'login failed', user: 'bob' });
  });
});

describe('real Vector: a file config generated for several globs validates and reads every glob (and only those)', { skip: VECTOR ? false : 'no Vector binary (set VECTOR_BIN)' }, () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-multi-'));
  const dirA = path.join(tmp, 'a'); const dirB = path.join(tmp, 'b'); const dirC = path.join(tmp, 'c'); const dataDir = path.join(tmp, 'data'); const cfgDir = path.join(tmp, 'cfg');
  for (const d of [dirA, dirB, dirC, dataDir, cfgDir]) fs.mkdirSync(d);
  const globs = [path.join(dirA, '*.log'), path.join(dirB, 'app-?.txt')];
  let vec, lane; const calls = [];
  after(() => { if (vec) vec.kill('SIGKILL'); if (lane) lane.close(); fs.rmSync(tmp, { recursive: true, force: true }); });
  const got = (t) => calls.flatMap((c) => c.split('\n')).filter((l) => l.endsWith(t));

  it('the template, filled in the way bootstrap-broker.sh fills it, passes `vector validate` with the main config', async () => {
    fs.writeFileSync(path.join(cfgDir, 'vector.yaml'), read('deploy/broker/vector.yaml').replace('data_dir: /var/lib/vector', 'data_dir: ' + dataDir).replace(/api:\n  enabled: true\n  address: 127.0.0.1:8686/, 'api:\n  enabled: false'));
    fs.writeFileSync(path.join(cfgDir, 'vector-file.yaml'), fileCfg.replace('      - "${ASIX_FILE_GLOB}"', globs.map((g) => '      - "' + g + '"').join('\n')));
    lane = http.createServer((q, s) => { let b = ''; q.on('data', (d) => { b += d; }); q.on('end', () => { calls.push(b); s.writeHead(202, { 'content-type': 'application/json' }); s.end('{"success":true}'); }); });
    await new Promise((r) => lane.listen(0, '127.0.0.1', r));
    const r = spawnSync(VECTOR, ['validate', '--no-environment', path.join(cfgDir, 'vector.yaml'), path.join(cfgDir, 'vector-file.yaml')], { env: env(), encoding: 'utf8' });
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  });
  const env = () => ({ PATH: process.env.PATH, VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: 'true', ASIX_INGEST_KEY: 'asix_ik_test', ASIX_BROKER_NAME: 'broker-test', ASIX_SYSLOG_PORT: '0', ASIX_INGEST_URL: `http://127.0.0.1:${lane.address().port}/v1/ingest/http` });
  it('lines appended to files matching EITHER glob arrive; a file matching neither does not', async () => {
    fs.writeFileSync(path.join(dirA, 'one.log'), 'old line in A\n'); fs.writeFileSync(path.join(dirB, 'app-1.txt'), 'old line in B\n');
    const sp = await new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });
    vec = spawn(VECTOR, ['--config', path.join(cfgDir, 'vector.yaml'), '--config', path.join(cfgDir, 'vector-file.yaml')], { env: { ...env(), ASIX_SYSLOG_PORT: String(sp) }, stdio: 'ignore' });
    await sleep(6000);   // Vector needs a moment to find the files it starts from the end of
    fs.appendFileSync(path.join(dirA, 'one.log'), 'new line in A\n');
    fs.appendFileSync(path.join(dirB, 'app-1.txt'), 'new line in B\n');
    fs.writeFileSync(path.join(dirB, 'other.txt'), 'line in a file no glob matches\n');
    fs.writeFileSync(path.join(dirC, 'x.log'), 'line in a directory no glob names\n');
    assert.ok(await until(() => got('new line in A').length === 1 && got('new line in B').length === 1, 30000), 'both globs are read: ' + JSON.stringify(calls));
    await sleep(3000);
    assert.match(got('new line in A')[0], / one\.log: new line in A$/); assert.match(got('new line in B')[0], / app-1\.txt: new line in B$/);
    assert.strictEqual(got('old line in A').length + got('old line in B').length, 0, 'history is still not sent');
    assert.strictEqual(got('line in a file no glob matches').length + got('line in a directory no glob names').length, 0, 'only the named globs are read');
  });
});
