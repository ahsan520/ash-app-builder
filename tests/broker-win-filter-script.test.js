'use strict';
// deploy/broker/asix-broker-config.sh, step 4: the Windows event filter (docs/endpoints.md, task E3). The system commands are stubs on PATH (id, systemctl, curl) as in
// broker-config-script.test.js; `vector` is the REAL binary when there is one (VECTOR_BIN, or `vector` on PATH; written against 0.59.0) and a stub that logs otherwise,
// so the cases that must see a real program compiled skip without it. The signed cases use the real signer and the real openssl.
// What it checks: the hash announced is the hash of the program installed; a program that does not match, does not compile, has control characters or fails the
// Vector restart changes nothing (or is put back); nothing is retried until ASIX announces a different one; no restart when nothing reads the file; the report says what the broker has.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const signing = require('../src/brokers/config-signing');
const wf = require('../src/endpoints/win-filter');
const wb = require('../src/endpoints/win-filter-broker');

const SCRIPT = path.join(__dirname, '..', 'deploy', 'broker', 'asix-broker-config.sh');
const hasOpenssl = spawnSync('openssl', ['version']).status === 0;
const REAL_VECTOR = process.env.VECTOR_BIN || (spawnSync('vector', ['--version']).status === 0 ? spawnSync('which', ['vector'], { encoding: 'utf8' }).stdout.trim() : null);
const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');
const PROGRAM = wb.program(wf.toInput(wf.validate(wf.presetNoisySecurity()).policy)).text;
const PROGRAM_SHA = sha(PROGRAM);
const OTHER = wb.program(wf.toInput(wf.validate({ rules: [{ id: 'a', action: 'drop', channel: 'System', event_ids: [7036] }] }).policy)).text;

describe('asix-broker-config.sh: Windows event filter', () => {
  let tmp, bin, log, envFile, stateDir, vecDir;
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const put = (f, v) => fs.writeFileSync(path.join(tmp, f), v);
  const lines = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);
  const calls = (re) => lines().filter((c) => re.test(c));
  const reports = () => calls(/^report /).map((c) => JSON.parse(c.replace(/^report /, '')));
  const installed = () => path.join(vecDir, 'win-filter.vrl');
  const rejected = () => path.join(stateDir, 'win-filter-rejected');
  const answer = (hash) => put('answer', JSON.stringify({ success: true, config: { syslog_port: null, tls_port: null, ...(hash === undefined ? {} : { win_filter: hash }) }, interval_seconds: 300 }));
  const serve = (text) => put('program', text);
  const run = (extra = {}) => spawnSync('bash', [SCRIPT], { encoding: 'utf8', stdin: 'ignore',
    env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_BROKER_ENV: envFile, ASIX_VECTOR_DIR: vecDir, ASIX_CONFIG_STATE_DIR: stateDir, ASIX_CONFIG_WAIT_S: '2', ...extra } });
  const BASE = 'ASIX_INGEST_URL=https://asix1:30443/v1/ingest/http\nASIX_INGEST_KEY=asix_ik_secretsecret\nASIX_BROKER_NAME=broker-1\nASIX_SYSLOG_PORT=514\nASIX_ACCEPT_CONFIG=true\nVECTOR_CONFIG=%CFG%\nOTHER=keep-me\n';
  const setEnv = (cfg) => fs.writeFileSync(envFile, BASE.replace('%CFG%', cfg || path.join(vecDir, 'vector.yaml')), { mode: 0o640 });
  const consumer = () => { fs.writeFileSync(path.join(vecDir, 'vector-winevents.yaml'), `sources:\n  wazuh_in: { type: demo_logs, format: json, count: 1 }\ntransforms:\n  win_filter: { type: remap, inputs: [wazuh_in], file: ${installed()}, drop_on_abort: true }\nsinks:\n  win_out: { type: blackhole, inputs: [win_filter] }\n`); setEnv(path.join(vecDir, 'vector.yaml') + ',' + path.join(vecDir, 'vector-winevents.yaml')); };

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bcfgwf-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); envFile = path.join(tmp, 'broker.env'); stateDir = path.join(tmp, 'state'); vecDir = path.join(tmp, 'vector');
    fs.mkdirSync(bin); fs.mkdirSync(vecDir);
    // a small config a REAL Vector accepts (the script validates the real list when something reads the file, or the port changes)
    fs.writeFileSync(path.join(vecDir, 'vector.yaml'), `data_dir: ${tmp}\nsources:\n  base_in: { type: demo_logs, format: json, count: 1 }\nsinks:\n  base_out: { type: blackhole, inputs: [base_in] }\n`); setEnv();
    answer(PROGRAM_SHA); serve(PROGRAM); put('answer-rc', '0'); put('download-rc', '0'); put('report-rc', '0'); put('health', 'ok'); put('restart', 'ok'); put('validate', 'ok');
    stub('id', 'echo 0');
    stub('systemctl', `echo "systemctl $* file=$(sha256sum < '${installed()}' 2>/dev/null | cut -c1-12)" >> '${log}'; [ "$(cat '${tmp}/restart')" = ok ]`);
    // curl: the answer, the report, the program download (-o FILE), the health check
    stub('curl', `out=""; prev=""; for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
case "$*" in
  *broker-config/report*) echo "report $(printf '%s\\n' "$*" | sed 's/.*--data //; s/ https.*//')" >> '${log}'; exit $(cat '${tmp}/report-rc');;
  *broker-config/win-filter*) echo "download $*" >> '${log}'; [ "$(cat '${tmp}/download-rc')" = 0 ] || exit 22; cat '${tmp}/program' > "$out"; exit 0;;
  *broker-config*) echo "fetch $*" >> '${log}'; cat '${tmp}/answer'; exit $(cat '${tmp}/answer-rc');;
  *health*) [ "$(cat '${tmp}/health')" = ok ]; exit $?;;
esac`);
    // vector: the real one when there is one, else a stub that says yes or no
    if (REAL_VECTOR) stub('vector', `echo "vector $* " >> '${log}'; '${REAL_VECTOR}' "$@" >/dev/null 2>&1; rc=$?; echo "vector-rc $rc" >> '${log}'; [ "$(cat '${tmp}/validate')" = ok ] && exit $rc || exit 78`);
    else stub('vector', `echo "vector $*" >> '${log}'; [ "$(cat '${tmp}/validate')" = ok ]`);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('installs the announced program: the file is exactly what ASIX served, readable by the vector user, and no Vector restart because nothing reads it yet', () => {
    const r = run(); assert.strictEqual(r.status, 0, r.stderr);
    assert.strictEqual(fs.readFileSync(installed(), 'utf8'), PROGRAM); assert.strictEqual(fs.statSync(installed()).mode & 0o777, 0o644);
    assert.match(r.stdout, /Windows filter none -> [0-9a-f]{12}\. No Vector config reads .* yet, so Vector was not restarted/);
    assert.deepStrictEqual(calls(/^systemctl/), [], 'no restart'); assert.ok(!fs.existsSync(rejected()));
    assert.ok(!fs.existsSync(installed() + '.before-config'), 'there was no earlier file to keep');
    assert.deepStrictEqual(fs.readdirSync(vecDir).sort(), ['vector.yaml', 'win-filter.vrl'], 'no temp file left behind');
    assert.strictEqual(fs.readFileSync(envFile, 'utf8'), BASE.replace('%CFG%', path.join(vecDir, 'vector.yaml')), 'broker.env untouched');
  });
  it('downloads with the broker\'s own key and nothing else, from <ingest URL>/../broker-config/win-filter', () => {
    run(); const d = calls(/^download /)[0];
    assert.match(d, /-H Authorization: Bearer asix_ik_secretsecret/); assert.match(d, /https:\/\/asix1:30443\/v1\/ingest\/broker-config\/win-filter$/); assert.match(d, /--max-filesize 1048576/);
  });
  it('validates a one-transform config that loads the CANDIDATE file, before the real file is touched', () => {
    run(); const v = calls(/^vector validate/); assert.strictEqual(v.length, 1); assert.match(v[0], /--no-environment .*wf-check\.yaml/);
  });
  it('the same program again: nothing downloaded, nothing validated, nothing changed; an old rejection no longer shows', () => {
    fs.writeFileSync(installed(), PROGRAM); fs.mkdirSync(stateDir); fs.writeFileSync(rejected(), HEX_OF('c')); const r = run(); assert.strictEqual(r.status, 0, r.stderr);
    assert.deepStrictEqual(calls(/^(download|vector|systemctl)/), []); assert.ok(!fs.existsSync(rejected()), 'applied: a rejection of something else is moot');
  });
  it('replaces an earlier program and keeps it as win-filter.vrl.before-config', () => {
    fs.writeFileSync(installed(), OTHER); const r = run(); assert.strictEqual(r.status, 0, r.stderr);
    assert.strictEqual(fs.readFileSync(installed(), 'utf8'), PROGRAM); assert.strictEqual(fs.readFileSync(installed() + '.before-config', 'utf8'), OTHER);
  });
  it('a program that does not match the announced hash changes nothing and is NOT remembered as rejected (the policy may just have been saved again)', () => {
    serve(OTHER); fs.writeFileSync(installed(), PROGRAM.replace('4656', '4657')); const before = fs.readFileSync(installed(), 'utf8');
    const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /is not the one it announced/); assert.strictEqual(fs.readFileSync(installed(), 'utf8'), before);
    assert.ok(!fs.existsSync(rejected())); assert.deepStrictEqual(calls(/^(vector|systemctl)/), []);
    serve(PROGRAM); assert.strictEqual(run().status, 0); assert.strictEqual(fs.readFileSync(installed(), 'utf8'), PROGRAM, 'the next pull gets it');
  });
  it('a failed download changes nothing and is retried at the next pull', () => {
    put('download-rc', '22'); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /Could not download the Windows filter/); assert.ok(!fs.existsSync(installed())); assert.ok(!fs.existsSync(rejected()));
    put('download-rc', '0'); assert.strictEqual(run().status, 0); assert.ok(fs.existsSync(installed()));
  });
  it('an empty program, one with a control character or a NUL byte is refused before Vector is asked', () => {
    for (const bad of ['', 'x = 1\u0001\n', 'x = 1\u0000\n', 'x\u001b[31m\n']) {
      serve(bad); answer(sha(bad)); const r = run(); assert.strictEqual(r.status, 1, JSON.stringify(bad)); assert.match(r.stderr, /empty or too large|control characters/, JSON.stringify(bad)); assert.ok(!fs.existsSync(installed()));
    }
    assert.deepStrictEqual(calls(/^vector/), []);
  });
  it('tabs, newlines and non-ASCII text in a regex are fine', () => {
    const ok = PROGRAM.replace("r'", "r'\té\\n"); serve(ok); answer(sha(ok)); put('validate', 'ok');
    const r = run(); if (!REAL_VECTOR) assert.strictEqual(r.status, 0, r.stderr); else assert.ok([0, 1].includes(r.status)); assert.ok(!/control characters/.test(r.stderr));
  });
  it('vector validate says no: nothing installed, the hash remembered, no restart; not retried until ASIX announces another; a different one is tried', () => {
    put('validate', 'bad'); let r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /does not pass 'vector validate'/);
    assert.ok(!fs.existsSync(installed())); assert.strictEqual(fs.readFileSync(rejected(), 'utf8').trim(), PROGRAM_SHA); assert.deepStrictEqual(calls(/^systemctl/), []);
    put('validate', 'ok'); const n = lines().length; r = run(); assert.strictEqual(r.status, 0); assert.match(r.stdout, /tried before/); assert.strictEqual(lines().filter((l) => /^(download|vector)/.test(l)).length, calls(/^(download|vector)/).length); assert.strictEqual(calls(/^download/).length, 1, 'not downloaded again');
    assert.ok(lines().length >= n); assert.ok(!fs.existsSync(installed()));
    serve(OTHER); answer(sha(OTHER)); r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(fs.readFileSync(installed(), 'utf8'), OTHER); assert.ok(!fs.existsSync(rejected()), 'a success clears the rejection');
  });
  it('when a Vector config reads the file: the whole config is validated, Vector restarted on the NEW file, health waited for', () => {
    consumer(); const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /Vector healthy/);
    const v = calls(/^vector validate/); assert.strictEqual(v.length, 2, 'the candidate alone, then the real list'); assert.match(v[1], /vector\.yaml .*vector-winevents\.yaml/);
    const s = calls(/^systemctl/); assert.strictEqual(s.length, 1); assert.match(s[0], new RegExp('^systemctl restart vector file=' + PROGRAM_SHA.slice(0, 12)));
    assert.ok(!fs.existsSync(rejected()));
  });
  it('the real config fails validate: the old file back (or none), no restart, remembered', () => {
    consumer(); fs.writeFileSync(installed(), OTHER);
    // the candidate check passes, the second validate (the real list) fails: the stub fails on the second call
    stub('vector', `n=$(grep -c '^vector validate' '${log}' 2>/dev/null); echo "vector validate $* " >> '${log}'; [ "$n" -lt 1 ]`);
    const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /config does not pass 'vector validate' with Windows filter/); assert.match(r.stderr, /Putting the old Windows filter back/);
    assert.strictEqual(fs.readFileSync(installed(), 'utf8'), OTHER); assert.deepStrictEqual(calls(/^systemctl/), []); assert.strictEqual(fs.readFileSync(rejected(), 'utf8').trim(), PROGRAM_SHA);
  });
  it('the restart fails: the old file is back, Vector is restarted on it, the hash is remembered, exit 1', () => {
    consumer(); fs.writeFileSync(installed(), OTHER); put('restart', 'bad');
    const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /systemctl restart vector failed with Windows filter/);
    assert.strictEqual(fs.readFileSync(installed(), 'utf8'), OTHER); const s = calls(/^systemctl/); assert.strictEqual(s.length, 2, 'once on the new file, once more on the old one');
    assert.match(s[0], new RegExp('file=' + PROGRAM_SHA.slice(0, 12))); assert.match(s[1], new RegExp('file=' + sha(OTHER).slice(0, 12))); assert.strictEqual(fs.readFileSync(rejected(), 'utf8').trim(), PROGRAM_SHA);
  });
  it('Vector does not become healthy: the same way back, and with no earlier file the new one is removed', () => {
    consumer(); put('health', 'bad'); const r = run(); assert.strictEqual(r.status, 1); assert.match(r.stderr, /did not become healthy within 2s with Windows filter/);
    assert.ok(!fs.existsSync(installed()), 'there was no earlier file'); assert.strictEqual(calls(/^systemctl/).length, 2); assert.strictEqual(fs.readFileSync(rejected(), 'utf8').trim(), PROGRAM_SHA);
  });
  it('a policy that was REMOVED: ASIX announces the keep-everything program and the broker takes the filter away the same way', () => {
    fs.writeFileSync(installed(), PROGRAM); serve(wb.IDENTITY_TEXT); answer(wb.IDENTITY_SHA);
    const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(fs.readFileSync(installed(), 'utf8'), wb.IDENTITY_TEXT); assert.strictEqual(fs.readFileSync(installed() + '.before-config', 'utf8'), PROGRAM);
    assert.strictEqual(reports().pop().win_filter, wb.IDENTITY_SHA);
  });
  it('no win_filter in the answer: nothing happens and the file the broker has is left alone', () => {
    answer(undefined); fs.writeFileSync(installed(), OTHER); const r = run(); assert.strictEqual(r.status, 0); assert.strictEqual(fs.readFileSync(installed(), 'utf8'), OTHER); assert.deepStrictEqual(calls(/^(download|vector|systemctl)/), []);
  });
  it('a value that is not a 64-character hash is refused with no download and no change', () => {
    for (const bad of ['"abc"', '"A' + 'a'.repeat(63) + '"', '"' + 'a'.repeat(65) + '"', '5', 'null', '"' + 'a'.repeat(63) + ';"']) {
      put('answer', `{"success":true,"config":{"syslog_port":null,"tls_port":null,"win_filter":${bad}}}`); const r = run(); assert.strictEqual(r.status, 1, bad); assert.match(r.stderr, /Unexpected win_filter/, bad);
    }
    assert.deepStrictEqual(calls(/^download/), []); assert.ok(!fs.existsSync(installed()));
  });
  it('the syslog port and the filter in one answer: both are applied, the port first', () => {
    put('answer', JSON.stringify({ success: true, config: { syslog_port: 1514, tls_port: null, win_filter: PROGRAM_SHA } }));
    const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(fs.readFileSync(envFile, 'utf8'), /^ASIX_SYSLOG_PORT=1514$/m); assert.strictEqual(fs.readFileSync(installed(), 'utf8'), PROGRAM);
    assert.ok(r.stdout.indexOf('syslog port') < r.stdout.indexOf('Windows filter'));
  });
  it('a refused syslog port stops the run before the filter (nothing is half applied)', () => {
    put('answer', JSON.stringify({ success: true, config: { syslog_port: 22, tls_port: null, win_filter: PROGRAM_SHA } }));
    const r = run(); assert.strictEqual(r.status, 1); assert.ok(!fs.existsSync(installed())); assert.deepStrictEqual(calls(/^download/), []);
  });

  describe('the report', () => {
    it('a broker with no file and nothing rejected sends no Windows filter fields (its report is what it always was)', () => {
      answer(undefined); run(); const b = reports().pop(); assert.ok(b, 'a report was sent'); assert.ok(!('win_filter' in b)); assert.ok(!('rejected_win_filter' in b));
    });
    it('after installing it says the hash of the FILE it has (computed from the file, not from what it was told)', () => {
      run(); const b = reports().pop(); assert.strictEqual(b.win_filter, PROGRAM_SHA); assert.strictEqual(b.rejected_win_filter, '');
      fs.writeFileSync(installed(), OTHER); answer(undefined); run(); assert.strictEqual(reports().pop().win_filter, sha(OTHER), 'a file changed by hand shows as what it is');
    });
    it('after a rejection it says which hash it rejected and what it still has', () => {
      fs.writeFileSync(installed(), OTHER); put('validate', 'bad'); run(); const b = reports().pop(); assert.strictEqual(b.win_filter, sha(OTHER)); assert.strictEqual(b.rejected_win_filter, PROGRAM_SHA);
    });
    it('a broker that rejected and has no file reports an empty hash and the rejected one', () => {
      put('validate', 'bad'); run(); const b = reports().pop(); assert.strictEqual(b.win_filter, ''); assert.strictEqual(b.rejected_win_filter, PROGRAM_SHA);
    });
    it('the report is valid JSON the server accepts', () => {
      const config = require('../src/brokers/config'); run(); const b = reports().pop(); const c = config.checkReport(b); assert.ok(!c.error, c.error); assert.strictEqual(c.winFilter, PROGRAM_SHA);
    });
  });

  describe('signed mode (real signer, real openssl)', { skip: hasOpenssl ? false : 'no openssl' }, () => {
    const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const key = signing.load({ ASIX_CONFIG_SIGNING_KEY: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }) });
    const signed = (hash, collector = 'broker-1', nowMs = Date.now()) => put('answer', JSON.stringify({ success: true, config: { syslog_port: null, tls_port: null, win_filter: HEX_OF('9') }, signed: signing.signedDocument(key, collector, null, nowMs, null, undefined, hash) }));
    const withKey = () => { fs.writeFileSync(path.join(tmp, 'pub.pem'), key.publicPem); return { ASIX_CONFIG_PUBKEY_FILE: path.join(tmp, 'pub.pem') }; };
    it('acts on the hash INSIDE the signature and ignores the unsigned config part (which here names another hash)', () => {
      signed(PROGRAM_SHA); const r = run(withKey()); assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(fs.readFileSync(installed(), 'utf8'), PROGRAM); assert.strictEqual(reports().pop().signature === undefined, false);
    });
    it('a signed answer that says nothing about the filter leaves the file alone even if the unsigned part announces one', () => {
      put('answer', JSON.stringify({ success: true, config: { syslog_port: null, win_filter: PROGRAM_SHA }, signed: signing.signedDocument(key, 'broker-1', null, Date.now(), null) }));
      const r = run(withKey()); assert.strictEqual(r.status, 0, r.stderr); assert.ok(!fs.existsSync(installed())); assert.deepStrictEqual(calls(/^download/), []);
    });
    it('an answer whose hash was changed after signing is refused: bad signature, nothing downloaded', () => {
      const doc = signing.signedDocument(key, 'broker-1', null, Date.now(), null, undefined, PROGRAM_SHA);
      const swapped = Buffer.from(Buffer.from(doc.payload, 'base64').toString().replace(PROGRAM_SHA, sha(OTHER))).toString('base64');
      put('answer', JSON.stringify({ success: true, config: {}, signed: { ...doc, payload: swapped } })); const r = run(withKey()); assert.strictEqual(r.status, 1); assert.match(r.stderr, /signature on ASIX's answer does not match/);
      assert.deepStrictEqual(calls(/^download/), []); assert.ok(!fs.existsSync(installed()));
    });
    it('a program that is not the one the SIGNED hash names is refused even if it is a perfectly good program', () => {
      signed(PROGRAM_SHA); serve(OTHER); const r = run(withKey()); assert.strictEqual(r.status, 1); assert.match(r.stderr, /is not the one it announced/); assert.ok(!fs.existsSync(installed()));
    });
    it('an answer made for another broker, or an old one, is refused before anything', () => {
      signed(PROGRAM_SHA, 'broker-2'); assert.strictEqual(run(withKey()).status, 1);
      signed(PROGRAM_SHA, 'broker-1', Date.now() - 3600 * 1000); assert.strictEqual(run(withKey()).status, 1);
      assert.deepStrictEqual(calls(/^download/), []); assert.ok(!fs.existsSync(installed()));
    });
  });
});

function HEX_OF(c) { return c.repeat(64); }

// ---- the installed file, in a real Vector, as a transform that reads it ----
describe('the installed program in a real Vector (a transform with file:, drop_on_abort)', { skip: REAL_VECTOR ? false : 'no Vector binary (set VECTOR_BIN or put `vector` on PATH)' }, () => {
  const POLICY = { version: 1, default: 'keep', rules: [{ id: 'noisy', action: 'drop', channel: 'Security', event_ids: [4656, '5150-5160'] }, { id: 'regex', action: 'drop', channel: 'System', match: { field: 'message', regex: 'foo$|\\$\\{HOME\\}' } }], strip_message: false, message_strip: [{ regex: 'This event is generated.*$' }] };
  const prog = (policy) => wb.program(wf.toInput(wf.validate(policy).policy)).text;
  function vectorTest(programText, cases) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bcfgwfv-')), vrl = path.join(dir, 'win-filter.vrl'), cfg = path.join(dir, 'v.yaml');
    fs.writeFileSync(vrl, programText);
    const tests = cases.map((c, i) => `  - name: case-${i}
    inputs:
      - insert_at: win_filter
        type: log
        log_fields: ${JSON.stringify(c.in)}
    ${c.keep ? 'outputs:\n      - extract_from: win_filter\n        conditions:\n          - type: vrl\n            source: ' + JSON.stringify(c.check) : 'no_outputs_from: [win_filter]'}
`).join('');
    fs.writeFileSync(cfg, `data_dir: ${dir}\nsources:\n  wazuh_in: { type: demo_logs, format: json, count: 1 }\ntransforms:\n  win_filter: { type: remap, inputs: [wazuh_in], file: ${vrl}, drop_on_abort: true }\nsinks:\n  out: { type: blackhole, inputs: [win_filter] }\ntests:\n${tests}`);
    const v = spawnSync(REAL_VECTOR, ['validate', '--no-environment', cfg], { encoding: 'utf8' }), t = spawnSync(REAL_VECTOR, ['test', cfg], { encoding: 'utf8' });
    fs.rmSync(dir, { recursive: true, force: true }); return { v, t, text: v.stdout + v.stderr + t.stdout + t.stderr };
  }
  const ev = (ch, id, msg) => ({ 'data.win.system.channel': ch, 'data.win.system.eventID': String(id), ...(msg === undefined ? {} : { 'data.win.system.message': msg }) });
  it('a program installed as a FILE keeps, drops and strips as the policy says; `$` and `${...}` in a regex reach it as written (a file is not interpolated)', () => {
    const r = vectorTest(prog(POLICY), [
      { in: ev('Security', 4656), keep: false }, { in: ev('Security', 5155), keep: false }, { in: ev('Security', 4624, 'ok\n\nThis event is generated when a logon occurs.'), keep: true, check: '.data.win.system.message == "ok\\n\\n"' },
      { in: ev('System', 7036, 'ends in foo'), keep: false }, { in: ev('System', 7036, 'has ${HOME} in it'), keep: false }, { in: ev('System', 7036, 'fine'), keep: true, check: '.data.win.system.message == "fine"' }]);
    assert.strictEqual(r.v.status, 0, r.text); assert.strictEqual(r.t.status, 0, r.text); assert.ok(!/warning\[/.test(r.text), r.text);
  });
  it('the keep-everything program changes nothing (and compiles without a warning)', () => {
    const r = vectorTest(wb.IDENTITY_TEXT, [{ in: ev('Security', 4656, 'x'), keep: true, check: '.data.win.system.message == "x"' }, { in: ev('System', 1), keep: true, check: '.data.win.system.eventID == "1"' }]);
    assert.strictEqual(r.v.status, 0, r.text); assert.strictEqual(r.t.status, 0, r.text); assert.ok(!/warning\[/.test(r.text), r.text);
  });
  it('a program with a syntax error does not validate (this is what the broker\'s own check relies on)', () => {
    const r = vectorTest(wb.HEADER + 'if (\n', []); assert.notStrictEqual(r.v.status, 0);
  });
  it('the test can fail: an expectation the program does not meet is reported', () => {
    const r = vectorTest(prog(POLICY), [{ in: ev('Security', 4624, 'ok'), keep: true, check: '.data.win.system.message == "something else"' }]); assert.notStrictEqual(r.t.status, 0);
  });
});
