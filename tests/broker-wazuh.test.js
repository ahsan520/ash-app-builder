'use strict';
// The broker's Windows events input (deploy/broker/vector-wazuh.yaml; bootstrap-broker.sh --wazuh, --wazuh-archives; docs/endpoints.md, task E4a).
//   1. static checks that the config, the identity filter, broker.env.example and every script agree (always run);
//   2. the bootstrap script's own Wazuh checks, run in bash with nothing installed or written (always run);
//   3. the parsing rules for Wazuh events against the sample events in tests/fixtures/wazuh-windows.js, and the ingest lane's JSON array body (always run);
//   4. with a real Vector binary (VECTOR_BIN, or `vector` on PATH; written against 0.59.0) the config is validated and run against a real archive file and a
//      stand-in for the ASIX HTTP lane, with the REAL filter programs ASIX generates. Skipped without Vector (CI has none).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { spawn, spawnSync } = require('child_process');
const express = require('express');
const F = require('./fixtures/wazuh-windows');
const wf = require('../src/endpoints/win-filter');
const wb = require('../src/endpoints/win-filter-broker');
const inputs = require('../src/brokers/inputs');
const paused = require('../src/brokers/paused');
const { compile, apply } = require('../src/ingestion/parsing-rules');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const cfg = read('deploy/broker/vector-wazuh.yaml');
const bootstrap = read('scripts/deploy/bootstrap-broker.sh');
const code = (text) => text.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');
const VECTOR = process.env.VECTOR_BIN || (spawnSync('vector', ['--version']).status === 0 ? 'vector' : null);
const policyProgram = (p) => wb.program(wf.toInput(wf.validate(p).policy)).text;

describe('broker Wazuh input: the files agree', () => {
  it('reads the standard archive path from its end, sends source type "windows-event" as a JSON array, buffers on disk', () => {
    assert.match(cfg, /^sources:\n {2}wazuh_in:\n {4}type: file\n/m);
    assert.match(cfg, /\$\{ASIX_WAZUH_ARCHIVES:-\/var\/ossec\/logs\/archives\/archives\.json\}/, 'Wazuh\'s standard path is the default');
    assert.match(cfg, /read_from: end/); assert.match(cfg, /max_line_bytes: 262144/);
    assert.match(cfg, /X-ASIX-Source-Type: windows-event\b/); assert.match(cfg, /X-ASIX-Collector: \$\{ASIX_BROKER_NAME\}/);
    assert.match(cfg, /codec: json/); assert.match(cfg, /Content-Type: application\/json/); assert.match(cfg, /buffer:\n {6}type: disk/);
  });
  it('the chain is parse -> filter -> event, the filter reads a FILE (no interpolation of the policy) and drops with abort', () => {
    assert.match(cfg, /wazuh_parse:[\s\S]*inputs: \[wazuh_in\]/); assert.match(cfg, /win_filter:[\s\S]*inputs: \[wazuh_parse\][\s\S]*file: "\$\{ASIX_WIN_FILTER_VRL:-\/etc\/vector\/win-filter\.vrl\}"[\s\S]*drop_on_abort: true/);
    assert.match(cfg, /wazuh_to_event:[\s\S]*inputs: \[win_filter\]/); assert.match(cfg, /asix_wazuh:[\s\S]*inputs: \[wazuh_to_event\]/);
  });
  it('comments hold no dollar-brace text (Vector interpolates inside comments too and would refuse to start), and every variable is a known one', () => {
    for (const l of cfg.split('\n')) if (l.trim().startsWith('#')) assert.ok(!l.includes('${'), l);
    const known = new Set(['ASIX_WAZUH_ARCHIVES', 'ASIX_WIN_FILTER_VRL', 'ASIX_INGEST_URL', 'ASIX_INGEST_KEY', 'ASIX_BROKER_NAME', 'ASIX_CA_FILE']);
    for (const m of code(cfg).matchAll(/\$\{([A-Z_]+)/g)) assert.ok(known.has(m[1]), m[1]);
  });
  it('the keep-everything filter bootstrap installs is byte for byte the program ASIX announces for "no policy"', () => {
    assert.strictEqual(read('deploy/broker/win-filter-identity.vrl'), wb.IDENTITY_TEXT);
  });
  it('asix-broker-config.sh will find this file a reader of win-filter.vrl, so a change to the policy restarts Vector with a way back', () => {
    assert.match(cfg, /win-filter\.vrl/); const script = read('deploy/broker/asix-broker-config.sh');
    assert.match(script, /grep -q 'win-filter\\\.vrl' "\$e"/);
    assert.match(script, /for f in vector-file\.yaml vector-http\.yaml vector-journald\.yaml vector-wazuh\.yaml; do/, 'and validates it with the others');
  });
  it('the bootstrap script installs the file only with --wazuh, never over a policy already in place, removes it on a re-run without, validates it and lists it', () => {
    assert.match(bootstrap, /--wazuh\) WAZUH=1; shift;;/); assert.match(bootstrap, /--wazuh-archives\) WAZUH_ARCHIVES="\$2"; WAZUH_ARCHIVES_SET=1; shift 2;;/);
    assert.match(bootstrap, /install -m 644 "\$SRC\/vector-wazuh\.yaml" \/etc\/vector\/vector-wazuh\.yaml/);
    assert.match(bootstrap, /\[ -e \/etc\/vector\/win-filter\.vrl \] \|\| install -m 644 "\$SRC\/win-filter-identity\.vrl" \/etc\/vector\/win-filter\.vrl/);
    assert.match(bootstrap, /rm -f \/etc\/vector\/vector-wazuh\.yaml/); assert.doesNotMatch(bootstrap, /rm -f[^\n#]*win-filter\.vrl/, 're-running without --wazuh leaves the filter file');
    assert.match(bootstrap, /\$\{WAZUH_CFG\} \$\{JOURNALD_CFG\} \/etc\/vector\/vector\.yaml/); assert.match(bootstrap, /CONFIGS="\$CONFIGS,\/etc\/vector\/vector-wazuh\.yaml"/);
    assert.match(bootstrap, /echo "ASIX_WAZUH_ARCHIVES=\$WAZUH_ARCHIVES"/); assert.match(bootstrap, /usermod -aG wazuh vector/);
  });
  it('upgrade-broker.sh and the heartbeat know the input; the env example documents it', () => {
    assert.match(read('scripts/deploy/upgrade-broker.sh'), /vector-journald\.yaml vector-wazuh\.yaml; do/);
    assert.match(read('deploy/broker/asix-broker-heartbeat.sh'), /\*vector-wazuh\.yaml,\*\) INPUTS="\$INPUTS,wazuh"/);
    const env = read('deploy/broker/broker.env.example'); assert.match(env, /#ASIX_WAZUH_ARCHIVES=\/var\/ossec\/logs\/archives\/archives\.json/); assert.match(env, /vector-journald\.yaml,\/etc\/vector\/vector-wazuh\.yaml/);
  });
  it('the server knows the input: reported by the heartbeat, labelled, and one of the inputs that can be paused (and the pause list order is fixed)', () => {
    assert.strictEqual(inputs.parseInputs('syslog:514,wazuh'), 'syslog:514,wazuh'); assert.strictEqual(inputs.parseInputs('wazuh:99'), null, 'it has no port');
    assert.strictEqual(inputs.label({ kind: 'wazuh', port: null }), 'Windows events');
    assert.deepStrictEqual(paused.KINDS, ['file', 'http', 'journald', 'wazuh']); assert.ok(('file,http,journald,wazuh').length <= 40);
    const html = read('src/portal/index.html'); assert.match(html, /const BROKER_PAUSABLE = \['file', 'http', 'journald', 'wazuh'\];/); assert.match(html, /wazuh: 'Windows events'/);
    assert.match(read('deploy/broker/asix-broker-config.sh'), /case "\$t" in file\|http\|journald\|wazuh\) ;;/);
  });
});

describe('bootstrap validation of --wazuh (the real block, run in bash, nothing installed)', () => {
  const start = bootstrap.indexOf('# Extra input: Windows events from a Wazuh manager'), end = bootstrap.indexOf('# (end of the Wazuh checks)');
  const block = bootstrap.slice(start, end);
  const run = (vars) => spawnSync('bash', ['-c', `set -euo pipefail\nWAZUH=0; WAZUH_ARCHIVES="/var/ossec/logs/archives/archives.json"; WAZUH_ARCHIVES_SET=0\n${vars}\n${block}\necho "CFG=[$WAZUH_CFG] PATH=[$WAZUH_ARCHIVES]"`], { encoding: 'utf8' });
  it('the block is found', () => { assert.ok(start > 0 && end > start); });
  it('off by default: nothing to validate and nothing refused', () => { const r = run(''); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /CFG=\[\] PATH=\[\/var\/ossec\/logs\/archives\/archives\.json\]/); });
  it('--wazuh alone names the file to validate and keeps the standard path; --wazuh-archives changes the path', () => {
    let r = run('WAZUH=1'); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /CFG=\[\/etc\/vector\/vector-wazuh\.yaml\] PATH=\[\/var\/ossec\/logs\/archives\/archives\.json\]/);
    r = run('WAZUH=1; WAZUH_ARCHIVES=/srv/wazuh/archives.json; WAZUH_ARCHIVES_SET=1'); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /PATH=\[\/srv\/wazuh\/archives\.json\]/);
  });
  it('--wazuh-archives without --wazuh is refused', () => { const r = run('WAZUH_ARCHIVES=/x/a.json; WAZUH_ARCHIVES_SET=1'); assert.strictEqual(r.status, 2); assert.match(r.stderr, /only makes sense with --wazuh/); });
  it('a path that is not absolute, has spaces, `..`, a dollar sign, quotes or newlines is refused (it goes into broker.env and a YAML string)', () => {
    for (const bad of ['relative/a.json', '/has space/a.json', '/a/../b.json', '/a/$HOME/b', '/a/"b"', "/a/'b'", '/a;b', '/a\nb', '']) {
      const r = run(`WAZUH=1; WAZUH_ARCHIVES=$'${bad.replace(/\n/g, '\\n').replace(/'/g, "\\'")}'; WAZUH_ARCHIVES_SET=1`); assert.strictEqual(r.status, 2, JSON.stringify(bad)); assert.match(r.stderr, /plain characters/, JSON.stringify(bad));
    }
  });
});

// The sample events as the lane stores them before the rules run (src/ingest/http-ingest.js jsonEvent), the way wazuh_to_event builds them.
const cap = (k) => k[0].toUpperCase() + k.slice(1);
const { jsonEvent } = require('../src/ingest/http-ingest');
function laneEvent(ev, { strip = false, via = true } = {}) {
  const s = ev.data.win.system, text = strip ? '' : String(s.message || '').replace(/\s+/g, ' ').trim().replace(/^"|"$/g, '').trim();
  const fields = Object.fromEntries(Object.entries(ev.data.win.eventdata).map(([k, v]) => [cap(k), String(v)]));
  if (via) Object.assign(fields, { asix_via: 'wazuh', win_event_id: String(s.eventID), win_record_id: String(s.eventRecordID), agent_name: ev.agent.name, agent_id: ev.agent.id, agent_ip: ev.agent.ip });
  const e = jsonEvent({ message: '[' + s.channel + '] ' + s.providerName + ' id=' + s.eventID + ' ' + text, time: s.systemTime, host: s.computer, fields }, 'broker-test');
  return { source_type: 'windows-event', raw: e.raw, time: e.time, parsed: e.parsed };
}
const defaults = compile(require('../src/ingestion/default-parsing-rules'));
const parse = (rec) => apply([defaults.rules], rec);

describe('parsing rules for Wazuh events', () => {
  it('every field-based rule gives the same normalised fields as the message-based rule for the same event (the only differences are the content id and what the old rule could not read)', () => {
    const skip = /^(message|_content_id|asix_via|win_event_id|win_record_id|agent_.*)$/; const known = { groupAdd: ['group_name'], cleared: ['user', 'user_domain'] };
    for (const [name, ev] of Object.entries(F.events)) {
      const a = parse(laneEvent(ev, { via: false })), b = parse(laneEvent(ev, { strip: true })), c = parse(laneEvent(ev, { strip: false }));
      for (const [label, other] of [['stripped', b], ['with text', c]]) for (const k of new Set([...Object.keys(a.parsed), ...Object.keys(other.parsed)])) {
        if (skip.test(k) || (known[name] || []).includes(k) && label === 'stripped') continue;
        if (name === 'groupAdd' && k === 'group_name') continue;
        assert.strictEqual(String(other.parsed[k]), String(a.parsed[k]), `${name} (${label}) ${k}`);
      }
    }
  });
  it('each kind lands on its own Wazuh rule, or falls through to the message rules that already existed', () => {
    const want = { failedLogon: 'wazuh_windows_logon', logon: 'wazuh_windows_logon', process: 'wazuh_windows_process', userCreated: 'wazuh_windows_account', groupAdd: 'wazuh_windows_group', task: 'wazuh_windows_scheduled_task', service: 'wazuh_windows_service', sysmonProcess: 'sysmon_process', noise: 'windows_generic', cleared: 'windows_log_cleared' };
    for (const [name, ev] of Object.entries(F.events)) for (const strip of [true, false]) assert.strictEqual(parse(laneEvent(ev, { strip })).matched.content_id, want[name], name + (strip ? ' stripped' : ''));
  });
  it('a failed logon with the message stripped still says who, from where, how and why (the suggested starting point strips every message)', () => {
    const p = parse(laneEvent(F.events.failedLogon, { strip: true })).parsed;
    assert.deepStrictEqual([p.event_id, p.channel, p.provider, p.event_category, p.event_outcome, p.target_user, p.target_domain, p.logon_type, p.failure_reason, p.auth_package, p.workstation, p.src_ip, p.src_port],
      [4625, 'Security', 'Microsoft-Windows-Security-Auditing', 'authentication', 'failure', 'admin', 'CORP', 3, 'Unknown user name or bad password.', 'NTLM', 'WIN-PC', '10.0.0.99', 51234]);
  });
  it('a successful logon, a process, an account, a group, a task and a service with the message stripped', () => {
    let p = parse(laneEvent(F.events.logon, { strip: true })).parsed;
    assert.deepStrictEqual([p.event_outcome, p.target_user, p.target_sid, p.logon_type, p.process_path, p.src_ip], ['success', 'alice', 'S-1-5-21-111-222-333-1105', 10, 'C:\\Windows\\System32\\svchost.exe', '10.0.0.50']);
    p = parse(laneEvent(F.events.process, { strip: true })).parsed;
    assert.deepStrictEqual([p.event_category, p.user, p.process_name, p.parent_name, p.parent_pid, p.command_line], ['process', 'alice', 'cmd.exe', 'explorer.exe', '0x9d8', 'cmd.exe /c whoami /all']);
    p = parse(laneEvent(F.events.userCreated, { strip: true })).parsed; assert.deepStrictEqual([p.event_action, p.user, p.target_user, p.target_sid], ['user_created', 'Administrator', 'backdoor', 'S-1-5-21-111-222-333-1190']);
    p = parse(laneEvent(F.events.groupAdd, { strip: true })).parsed; assert.deepStrictEqual([p.event_action, p.member_name, p.group_name, p.group_sid], ['member_added', 'CN=backdoor,CN=Users,DC=corp,DC=local', 'Administrators', 'S-1-5-32-544']);
    p = parse(laneEvent(F.events.task, { strip: true })).parsed; assert.deepStrictEqual([p.event_action, p.task_name, p.command_line], ['task_created', '\\Updater', 'C:\\Temp\\u.exe -q']);
    p = parse(laneEvent(F.events.service, { strip: true })).parsed; assert.deepStrictEqual([p.service_name, p.service_path, p.service_account, p.user], ['Updater Svc', 'C:\\Temp\\svc.exe -k run', 'LocalSystem', undefined]);
  });
  it('Sysmon needs nothing new: its rules read the same named fields and only the first part of the message', () => {
    const p = parse(laneEvent(F.events.sysmonProcess, { strip: true })).parsed;
    assert.deepStrictEqual([p.event_id, p.process_name, p.command_line, p.user, p.user_domain, p.parent_name], [1, 'powershell.exe', 'powershell -enc AAAA', 'alice', 'CORP', 'explorer.exe']);
  });
  it('the failure reasons Windows names with a code are spelled out; an unknown code is kept as it is', () => {
    const ev = JSON.parse(JSON.stringify(F.events.failedLogon)); const reason = (code) => { ev.data.win.eventdata.failureReason = code; return parse(laneEvent(ev, { strip: true })).parsed.failure_reason; };
    assert.strictEqual(reason('%%2307'), 'Account locked out.'); assert.strictEqual(reason('%%2310'), 'Account currently disabled.'); assert.strictEqual(reason('%%2313'), 'Unknown user name or bad password.'); assert.strictEqual(reason('%%9999'), '%%9999');
  });
  it('a "-" for an unknown user or address is empty, not a user called "-"', () => {
    const p = parse(laneEvent(F.events.failedLogon, { strip: true })).parsed; assert.ok(!('user' in p));
    const ev = JSON.parse(JSON.stringify(F.events.logon)); ev.data.win.eventdata.ipAddress = '-'; ev.data.win.eventdata.targetUserName = '-';
    const q = parse(laneEvent(ev, { strip: true })).parsed; assert.ok(q.src_ip === undefined || q.src_ip === null); assert.ok(q.target_user === undefined || q.target_user === null);
  });
  it('an event that did not come through Wazuh (no asix_via) is parsed by the message rules exactly as before', () => {
    const r = parse(laneEvent(F.events.failedLogon, { via: false })); assert.strictEqual(r.matched.content_id, 'windows_logon'); assert.strictEqual(r.parsed.target_user, 'admin');
  });
  it('a record that merely has a field called win_event_id is not claimed unless it also says asix_via = wazuh', () => {
    const rec = laneEvent(F.events.logon, { strip: true }); delete rec.parsed.asix_via; assert.notStrictEqual(parse(rec).matched.content_id, 'wazuh_windows_logon');
  });
});

describe('the ingest lane takes a JSON array of events', () => {
  let srv, base, stored, parseCalls;
  before(() => {
    const dbp = require.resolve('../src/db');
    require.cache[dbp] = { id: dbp, filename: dbp, loaded: true, exports: { query: async () => ({ rows: [{ id: 'k1', tenant_id: 't1', name: 'broker-key', platform: 'linux' }] }), withTenant: async (t, fn) => fn({ query: async () => ({ rows: [] }) }) } };
    const ps = require.resolve('../src/ingestion/parse-service');
    require.cache[ps] = { id: ps, filename: ps, loaded: true, exports: { parseForIngest: async (t, st, items) => { parseCalls.push({ st, n: items.length }); return { kept: items, dropped: 0 }; }, STORE_UNPARSED: new Set() } };
    const ev = require.resolve('../src/events');
    require.cache[ev] = { id: ev, filename: ev, loaded: true, exports: { getEventStore: () => ({ insertBatch: async (t, rows) => { stored.push(...rows); } }) } };
    delete require.cache[require.resolve('../src/ingest/http-ingest')];
    const app = express(); app.use(require('../src/ingest/http-ingest').router);
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => srv.close());
  const post = async (body, headers = {}, type = 'application/json') => { stored = []; parseCalls = []; const r = await fetch(base + '/v1/ingest/http', { method: 'POST', headers: { authorization: 'Bearer asix_ik_' + 'a'.repeat(40), 'content-type': type, ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const H = { 'x-asix-collector': 'broker-test', 'x-asix-source-type': 'windows-event', 'x-asix-platform': 'linux', 'x-asix-version': 'vector-broker' };
  it('collector and source type come from the headers; fields, host and time are kept', async () => {
    const e = { message: '[Security] P id=4625 ', time: '2026-10-24T13:00:00.1234567Z', host: 'WIN-DC01', fields: { TargetUserName: 'admin', asix_via: 'wazuh' } };
    const r = await post([e], H); assert.strictEqual(r.status, 202); assert.strictEqual(r.json.accepted, 1);
    assert.deepStrictEqual(parseCalls, [{ st: 'windows-event', n: 1 }]); const row = stored[0];
    assert.strictEqual(row.source_type, 'windows-event'); assert.strictEqual(row.collector_id, 'broker-test'); assert.strictEqual(row.raw, '[Security] P id=4625 ');
    assert.strictEqual(row.event_time, '2026-10-24T13:00:00.123Z'); assert.strictEqual(row.parsed.TargetUserName, 'admin'); assert.strictEqual(row.parsed.host, 'WIN-DC01'); assert.strictEqual(row.parsed.message, '[Security] P id=4625 ');
  });
  it('without headers the key\'s name is the collector and the source type is "json"; elements that are not objects or have no message are skipped', async () => {
    const r = await post([{ message: 'one' }, 5, null, 'text', { fields: {} }, { message: '   ' }, { raw: 'two' }]); assert.strictEqual(r.status, 202); assert.strictEqual(r.json.accepted, 2);
    assert.deepStrictEqual(stored.map((s) => [s.source_type, s.collector_id, s.raw]), [['json', 'broker-key', 'one'], ['json', 'broker-key', 'two']]);
  });
  it('an empty array, an array with nothing usable and one with more than 1000 events are refused with the lane\'s usual codes', async () => {
    assert.strictEqual((await post([], H)).json.error.code, 'INGEST_NO_EVENTS'); assert.strictEqual((await post([1, 2], H)).json.error.code, 'INGEST_NO_EVENTS');
    const r = await post(Array.from({ length: 1001 }, () => ({ message: 'x' })), H); assert.strictEqual(r.status, 413); assert.strictEqual(r.json.error.code, 'INGEST_BATCH_TOO_LARGE');
  });
  it('a bad collector or source type in the headers is refused as it is for text lines', async () => {
    assert.strictEqual((await post([{ message: 'x' }], { ...H, 'x-asix-collector': 'bad name!' })).json.error.code, 'INGEST_INVALID_COLLECTOR');
    assert.strictEqual((await post([{ message: 'x' }], { ...H, 'x-asix-source-type': 'bad type!' })).json.error.code, 'INGEST_INVALID_SOURCE');
  });
  it('the two older body shapes still work: text lines, and {collector, source_type, events}', async () => {
    let r = await post('2026-10-24T13:00:00Z host1 app: hello', { 'x-asix-collector': 'c1' }, 'text/plain'); assert.strictEqual(r.status, 202); assert.strictEqual(stored[0].parsed.app_name, 'app');
    r = await post({ collector: { name: 'c2' }, source_type: 'custom', events: [{ message: 'm' }] }); assert.strictEqual(r.status, 202); assert.strictEqual(stored[0].source_type, 'custom'); assert.strictEqual(stored[0].collector_id, 'c2');
    r = await post({ nothing: true }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INGEST_INVALID_BODY'); assert.match(r.json.error.message, /JSON array/);
  });
});

describe('real Vector: the Wazuh input, the filter file and what ASIX receives', { skip: VECTOR ? false : 'no Vector binary (set VECTOR_BIN or put `vector` on PATH)' }, () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const until = async (fn, ms = 25000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(150); } return false; };
  const tmps = []; let lane, laneCalls;
  before(async () => {
    lane = http.createServer((q, s) => { let b = ''; q.on('data', (d) => { b += d; }); q.on('end', () => { laneCalls.push({ h: q.headers, body: b }); s.writeHead(202, { 'content-type': 'application/json' }); s.end('{"success":true}'); }); });
    await new Promise((r) => lane.listen(0, '127.0.0.1', r));
  });
  after(() => { lane.close(); for (const t of tmps) fs.rmSync(t, { recursive: true, force: true }); });

  // One broker: its own folder, an archive file with a line of history, a filter file, Vector started, the sample lines appended; returns what the lane got.
  async function scenario({ program, extra = [], waitFor = (events) => events.length >= 1 }) {
    laneCalls = laneCalls || [];
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wazuh-')); tmps.push(tmp);
    const arch = path.join(tmp, 'archives.json'), vrl = path.join(tmp, 'win-filter.vrl'), base = path.join(tmp, 'base.yaml'), mine = path.join(tmp, 'vector-wazuh.yaml');
    fs.writeFileSync(arch, F.line(F.win({ id: 4688, message: '"history before Vector starts"' })) + '\n'); fs.writeFileSync(vrl, program);
    fs.writeFileSync(base, `data_dir: ${tmp}\n`); fs.copyFileSync(path.join(root, 'deploy/broker/vector-wazuh.yaml'), mine);
    const mark = 'scenario-' + path.basename(tmp), got = [];
    const env = { PATH: process.env.PATH, VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: 'true', ASIX_INGEST_KEY: 'asix_ik_test', ASIX_BROKER_NAME: mark, ASIX_INGEST_URL: `http://127.0.0.1:${lane.address().port}/v1/ingest/http`, ASIX_WAZUH_ARCHIVES: arch, ASIX_WIN_FILTER_VRL: vrl };
    const v = spawn(VECTOR, ['--config', base, '--config', mine], { env, stdio: 'ignore' });
    try {
      await sleep(3500);   // the file is read from its END: only what is appended now counts
      fs.appendFileSync(arch, [F.garbageLine, F.linuxLine, ...Object.values(F.events).map(F.line), ...extra].join('\n') + '\n');
      await until(() => { got.length = 0; for (const c of laneCalls.filter((x) => x.h['x-asix-collector'] === mark)) got.push(...JSON.parse(c.body)); return waitFor(got); });
      await sleep(1500); got.length = 0; const calls = laneCalls.filter((x) => x.h['x-asix-collector'] === mark); for (const c of calls) got.push(...JSON.parse(c.body));
      return { events: got, calls };
    } finally { v.kill('SIGKILL'); }
  }
  const byId = (events, id) => events.filter((e) => e.fields.win_event_id === String(id));

  it('validates alone with the base config, and with the file, HTTP and journal inputs (distinct sinks and buffers)', () => {
    const e = { PATH: process.env.PATH, VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: 'true', ASIX_INGEST_URL: 'https://x/v1/ingest/http', ASIX_INGEST_KEY: 'k', ASIX_BROKER_NAME: 'b', ASIX_SYSLOG_PORT: '514', ASIX_WIN_FILTER_VRL: path.join(root, 'deploy/broker/win-filter-identity.vrl'), ASIX_FILE_GLOB: '/tmp/*.log', ASIX_HTTP_USER: 'svc', ASIX_HTTP_PASSWORD: 's3cretpassword', ASIX_HTTP_PORT: '1' };
    const files = (...n) => n.map((f) => path.join(root, 'deploy/broker', f));
    for (const list of [['vector.yaml', 'vector-wazuh.yaml'], ['vector.yaml', 'vector-file.yaml', 'vector-http.yaml', 'vector-journald.yaml', 'vector-wazuh.yaml']]) {
      const r = spawnSync(VECTOR, ['validate', '--no-environment', ...files(...list)], { env: e, encoding: 'utf8' }); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    }
  });
  it('without the filter file Vector refuses to start (which is why bootstrap installs the keep-everything one)', () => {
    const e = { PATH: process.env.PATH, VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: 'true', ASIX_INGEST_URL: 'https://x', ASIX_INGEST_KEY: 'k', ASIX_BROKER_NAME: 'b', ASIX_SYSLOG_PORT: '514', ASIX_WIN_FILTER_VRL: '/nonexistent/win-filter.vrl' };
    const r = spawnSync(VECTOR, ['validate', '--no-environment', path.join(root, 'deploy/broker/vector.yaml'), path.join(root, 'deploy/broker/vector-wazuh.yaml')], { env: e, encoding: 'utf8' }); assert.notStrictEqual(r.status, 0);
  });

  let keep, strip;
  it('keep-everything filter: only Windows events arrive, from now on, as one JSON array per batch with the key, the broker name and the source type in headers', async () => {
    keep = await scenario({ program: wb.IDENTITY_TEXT, waitFor: (ev) => byId(ev, 1102).length >= 1 });
    const { events, calls } = keep; assert.ok(calls.length >= 1);
    for (const c of calls) { assert.strictEqual(c.h.authorization, 'Bearer asix_ik_test'); assert.match(c.h['content-type'], /^application\/json/); assert.strictEqual(c.h['x-asix-source-type'], 'windows-event'); assert.ok(Array.isArray(JSON.parse(c.body))); assert.ok(JSON.parse(c.body).length <= 500); }
    assert.deepStrictEqual(events.map((e) => e.fields.win_event_id).sort(), Object.values(F.events).map((e) => String(e.data.win.system.eventID)).sort(), 'every sample Windows event, nothing else: not the history, the Linux line or the garbage');
  });
  it('each event is "[Channel] Provider id=N text" with the message on ONE line, the event\'s own time and the computer name as host', () => {
    const e = byId(keep.events, 4625)[0];
    assert.strictEqual(e.host, 'WIN-DC01.corp.local'); assert.strictEqual(e.time, '2026-10-24T13:00:00.1234567Z');
    assert.match(e.message, /^\[Security\] Microsoft-Windows-Security-Auditing id=4625 An account failed to log on\. Subject: Security ID: S-1-0-0 Account Name: - /);
    assert.ok(!/[\r\n\t]|\s{2}|^.*"$/.test(e.message), JSON.stringify(e.message)); assert.ok(!e.message.includes('\\r'));
    assert.match(byId(keep.events, 1)[0].message, /^\[Microsoft-Windows-Sysmon\/Operational\] Microsoft-Windows-Sysmon id=1 Process Create:/);
    assert.match(byId(keep.events, 7045)[0].message, /^\[System\] Service Control Manager id=7045 /);
  });
  it('the event\'s data arrives as fields under their Windows names (first letter upper-cased again), with the Wazuh agent and the marker the rules look for', () => {
    const f = byId(keep.events, 4625)[0].fields;
    assert.deepStrictEqual([f.TargetUserName, f.IpAddress, f.LogonType, f.SubStatus, f.asix_via, f.agent_name, f.agent_id, f.agent_ip, f.win_record_id], ['admin', '10.0.0.99', '3', '0xc000006a', 'wazuh', 'WIN-DC01', '001', '10.0.0.21', '1001']);
    assert.strictEqual(byId(keep.events, 1)[0].fields.CommandLine, 'powershell -enc AAAA'); assert.strictEqual(byId(keep.events, 1)[0].fields.Image, 'C:\\Windows\\System32\\powershell.exe');
    for (const e of keep.events) for (const [k, v] of Object.entries(e.fields)) assert.strictEqual(typeof v, 'string', k);
  });
  it('the suggested starting point drops the noisy events and empties every message; the fields stay, and the rules still read them', async () => {
    strip = await scenario({ program: policyProgram(wf.presetNoisySecurity()), waitFor: (ev) => byId(ev, 1102).length >= 1 });
    assert.strictEqual(byId(strip.events, 5156).length, 0, '5156 is dropped by the policy'); assert.strictEqual(strip.events.length, Object.keys(F.events).length - 1);
    for (const e of strip.events) assert.match(e.message, /^\[[^\]]+\] \S.* id=\d+ $/, 'the text is gone: ' + JSON.stringify(e.message));
    const p = apply([defaults.rules], { source_type: 'windows-event', raw: byId(strip.events, 4625)[0].message, time: null, parsed: { ...byId(strip.events, 4625)[0].fields, format: 'json', host: 'h', message: byId(strip.events, 4625)[0].message } });
    assert.strictEqual(p.parsed.target_user, 'admin'); assert.strictEqual(p.parsed.src_ip, '10.0.0.99'); assert.strictEqual(p.matched.content_id, 'wazuh_windows_logon');
  });
  it('a policy with a regex that ends in a dollar sign or holds a dollar-brace works from the file (a file is not interpolated)', async () => {
    const tricky = F.win({ id: 4688, record: '2001', message: '"ran ${EVIL} now"', data: { SubjectUserName: 'bob', NewProcessName: 'C:\\x.exe' } });
    const keepEv = F.win({ id: 4688, record: '2002', message: '"ran fine now"', data: { SubjectUserName: 'bob2', NewProcessName: 'C:\\y.exe' } });
    const policy = { version: 1, default: 'keep', rules: [
      { id: 'anchored', action: 'drop', channel: 'Security', event_ids: [4720], match: { field: 'subjectUserName', regex: '^Administrator$' } },
      { id: 'brace', action: 'drop', channel: 'Security', event_ids: [4688], match: { field: 'message', regex: '\\$\\{EVIL\\}' } }] };
    const r = await scenario({ program: policyProgram(policy), extra: [F.line(tricky), F.line(keepEv)], waitFor: (ev) => byId(ev, 4688).length >= 2 });
    assert.strictEqual(byId(r.events, 4720).length, 0, 'the anchored regex matched the Administrator event and dropped it');
    assert.deepStrictEqual(byId(r.events, 4688).map((e) => e.fields.SubjectUserName).sort(), ['alice', 'bob2'], 'the ${EVIL} event was dropped, the others kept');
  });
});
