'use strict';
// The broker's Wazuh ALERTS input (deploy/broker/vector-wazuhalerts.yaml; bootstrap-broker.sh --wazuh-alerts, --wazuh-alerts-file, --wazuh-alerts-min-level;
// docs/endpoints.md, task E4d):
//   1. static checks that the config, broker.env.example, every script, the server lists and the portal agree (always run);
//   2. the bootstrap script's own alert checks, run in bash with nothing installed or written (always run);
//   3. the REAL asix-broker-config.sh pausing and resuming the input, and the REAL heartbeat script reporting it, with only system commands stubbed (always run);
//   4. the parsing rule `wazuh_alert` and the server's input lists (always run);
//   5. with a real Vector binary (VECTOR_BIN, or `vector` on PATH; written against 0.59.0) the config is validated and run against a real alert file and a stand-in for
//      the ASIX HTTP lane, and what arrives is parsed by the real rules. Skipped without Vector (CI has none).
const { describe, it, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { spawn, spawnSync } = require('child_process');
const A = require('./fixtures/wazuh-alerts');
const inputs = require('../src/brokers/inputs');
const paused = require('../src/brokers/paused');
const config = require('../src/brokers/config');
const { compile, apply } = require('../src/ingestion/parsing-rules');
const { jsonEvent } = require('../src/ingest/http-ingest');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const cfg = read('deploy/broker/vector-wazuhalerts.yaml');
const bootstrap = read('scripts/deploy/bootstrap-broker.sh');
const code = (text) => text.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');
const VECTOR = process.env.VECTOR_BIN || (spawnSync('vector', ['--version']).status === 0 ? 'vector' : null);

describe('broker Wazuh alerts input: the files agree', () => {
  it('reads the standard alert path from its end, sends source type "endpoint-alert" as a JSON array, buffers on disk in a buffer of its own', () => {
    assert.match(cfg, /^sources:\n {2}wazuh_alerts_in:\n {4}type: file\n/m);
    assert.match(cfg, /\$\{ASIX_WAZUH_ALERTS:-\/var\/ossec\/logs\/alerts\/alerts\.json\}/, 'the manager\'s standard path is the default');
    assert.match(cfg, /read_from: end/); assert.match(cfg, /max_line_bytes: 262144/);
    assert.match(cfg, /X-ASIX-Source-Type: endpoint-alert\b/); assert.match(cfg, /X-ASIX-Collector: \$\{ASIX_BROKER_NAME\}/);
    assert.match(cfg, /codec: json/); assert.match(cfg, /Content-Type: application\/json/); assert.match(cfg, /buffer:\n {6}type: disk/);
    assert.match(cfg, /sinks:\n {2}asix_wazuh_alerts:/, 'its own sink id, so its disk buffer is not the Windows events one');
  });
  it('the chain is parse -> event -> sink; there is no filter file in it', () => {
    assert.match(cfg, /wazuh_alerts_parse:[\s\S]*inputs: \[wazuh_alerts_in\]/); assert.match(cfg, /wazuh_alerts_to_event:[\s\S]*inputs: \[wazuh_alerts_parse\]/);
    assert.match(cfg, /asix_wazuh_alerts:[\s\S]*inputs: \[wazuh_alerts_to_event\]/);
    assert.ok(!/win-filter/.test(cfg), 'the Windows event filter does not apply to alerts, and asix-broker-config.sh must not take this file for a reader of win-filter.vrl');
  });
  it('comments hold no dollar-brace text (Vector interpolates inside comments too and would refuse to start), and every variable is a known one', () => {
    for (const l of cfg.split('\n')) if (l.trim().startsWith('#')) assert.ok(!l.includes('${'), l);
    const known = new Set(['ASIX_WAZUH_ALERTS', 'ASIX_WAZUH_ALERT_MIN_LEVEL', 'ASIX_INGEST_URL', 'ASIX_INGEST_KEY', 'ASIX_BROKER_NAME', 'ASIX_CA_FILE']);
    for (const m of code(cfg).matchAll(/\$\{([A-Z_]+)/g)) assert.ok(known.has(m[1]), m[1]);
  });
  it('the minimum level has a safe default of 0 in the config itself', () => { assert.match(cfg, /\$\{ASIX_WAZUH_ALERT_MIN_LEVEL:-0\}/); });
  it('the bootstrap script installs the file only with --wazuh-alerts, removes it on a re-run without, validates it, lists it, writes both settings', () => {
    assert.match(bootstrap, /--wazuh-alerts\) WAZUH_ALERTS=1; shift;;/); assert.match(bootstrap, /--wazuh-alerts-file\) WAZUH_ALERTS_FILE="\$2"; WAZUH_ALERTS_FILE_SET=1; shift 2;;/);
    assert.match(bootstrap, /--wazuh-alerts-min-level\) WAZUH_ALERTS_MIN="\$2"; WAZUH_ALERTS_MIN_SET=1; shift 2;;/);
    assert.match(bootstrap, /install -m 644 "\$SRC\/vector-wazuhalerts\.yaml" \/etc\/vector\/vector-wazuhalerts\.yaml/);
    assert.match(bootstrap, /rm -f \/etc\/vector\/vector-wazuhalerts\.yaml/);
    assert.match(bootstrap, /\$\{WAZUH_CFG\} \$\{WAZUH_ALERTS_CFG\} \$\{JOURNALD_CFG\} \/etc\/vector\/vector\.yaml/);
    assert.match(bootstrap, /CONFIGS="\$CONFIGS,\/etc\/vector\/vector-wazuhalerts\.yaml"/);
    assert.match(bootstrap, /echo "ASIX_WAZUH_ALERTS=\$WAZUH_ALERTS_FILE"; echo "ASIX_WAZUH_ALERT_MIN_LEVEL=\$WAZUH_ALERTS_MIN"/);
    const s = bootstrap.indexOf('if [ "$WAZUH_ALERTS" -eq 1 ]; then\n  install -m 644'); assert.ok(s > 0); assert.match(bootstrap.slice(s, s + 700), /usermod -aG wazuh vector/);
    assert.doesNotMatch(bootstrap, /--wazuh-manager\) WAZUH_MANAGER=1; WAZUH=1; WAZUH_ALERTS=1/, 'the manager does not switch alerts on by itself');
  });
  it('upgrade-broker.sh, asix-broker-config.sh and the heartbeat know the input; the env example documents it', () => {
    assert.match(read('scripts/deploy/upgrade-broker.sh'), /vector-wazuh\.yaml vector-wazuhalerts\.yaml; do/);
    const script = read('deploy/broker/asix-broker-config.sh');
    assert.match(script, /vector-wazuh\.yaml vector-wazuhalerts\.yaml; do/, 'validated with the others');
    assert.match(script, /case "\$t" in file\|http\|journald\|wazuh\|wazuhalerts\) ;;/); assert.match(script, /for t in file http journald wazuh wazuhalerts; do/);
    assert.match(read('deploy/broker/asix-broker-heartbeat.sh'), /\*vector-wazuhalerts\.yaml,\*\) INPUTS="\$INPUTS,wazuhalerts"/);
    const env = read('deploy/broker/broker.env.example'); assert.match(env, /#ASIX_WAZUH_ALERTS=\/var\/ossec\/logs\/alerts\/alerts\.json/); assert.match(env, /#ASIX_WAZUH_ALERT_MIN_LEVEL=0/);
    assert.match(env, /vector-wazuh\.yaml,\/etc\/vector\/vector-wazuhalerts\.yaml/);
  });
  it('the server and the portal know the input: reported by the heartbeat, labelled, pausable, and the pause list fits the database column', () => {
    assert.strictEqual(inputs.parseInputs('syslog:514,wazuh,wazuhalerts'), 'syslog:514,wazuh,wazuhalerts'); assert.strictEqual(inputs.parseInputs('wazuhalerts:99'), null, 'it has no port');
    assert.strictEqual(inputs.label({ kind: 'wazuhalerts', port: null }), 'Endpoint alerts');
    assert.deepStrictEqual(paused.KINDS, ['file', 'http', 'journald', 'wazuh', 'wazuhalerts']);
    const all = paused.KINDS.join(','); assert.ok(all.length <= 40 && /^[a-z,]+$/.test(all), 'the collectors columns check length <= 40 and ^[a-z,]+$ (k8s/12-schema-init.yaml)');
    const schema = read('k8s/12-schema-init.yaml'); assert.match(schema, /length\(inputs_paused\) <= 40 AND inputs_paused ~ '\^\[a-z,\]\+\$'/);
    const html = read('src/portal/index.html'); assert.match(html, /const BROKER_PAUSABLE = \['file', 'http', 'journald', 'wazuh', 'wazuhalerts'\];/); assert.match(html, /wazuhalerts: 'Endpoint alerts'/); assert.match(html, /wazuhalerts: "the alerts the Wazuh manager raised/);
  });
});

describe('bootstrap validation of --wazuh-alerts (the real block, run in bash, nothing installed)', () => {
  const start = bootstrap.indexOf('# Extra input: the alerts of a Wazuh manager.'), end = bootstrap.indexOf('# (end of the Wazuh alerts checks)');
  const block = bootstrap.slice(start, end);
  const run = (vars) => spawnSync('bash', ['-c', `set -euo pipefail\nWAZUH_ALERTS=0; WAZUH_ALERTS_FILE="/var/ossec/logs/alerts/alerts.json"; WAZUH_ALERTS_FILE_SET=0; WAZUH_ALERTS_MIN="0"; WAZUH_ALERTS_MIN_SET=0\n${vars}\n${block}\necho "CFG=[$WAZUH_ALERTS_CFG] PATH=[$WAZUH_ALERTS_FILE] MIN=[$WAZUH_ALERTS_MIN]"`], { encoding: 'utf8' });
  it('the block is found', () => { assert.ok(start > 0 && end > start); });
  it('off by default: nothing to validate and nothing refused', () => { const r = run(''); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /CFG=\[\] PATH=\[\/var\/ossec\/logs\/alerts\/alerts\.json\] MIN=\[0\]/); });
  it('--wazuh-alerts alone names the file to validate and keeps the standard path and level; the options change them', () => {
    let r = run('WAZUH_ALERTS=1'); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /CFG=\[\/etc\/vector\/vector-wazuhalerts\.yaml\] PATH=\[\/var\/ossec\/logs\/alerts\/alerts\.json\] MIN=\[0\]/);
    r = run('WAZUH_ALERTS=1; WAZUH_ALERTS_FILE=/srv/wazuh/alerts.json; WAZUH_ALERTS_FILE_SET=1; WAZUH_ALERTS_MIN=7; WAZUH_ALERTS_MIN_SET=1'); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /PATH=\[\/srv\/wazuh\/alerts\.json\] MIN=\[7\]/);
    for (const ok of ['0', '5', '15', '09']) { r = run(`WAZUH_ALERTS=1; WAZUH_ALERTS_MIN=${ok}; WAZUH_ALERTS_MIN_SET=1`); assert.strictEqual(r.status, 0, ok + r.stderr); }
  });
  it('the options without --wazuh-alerts are refused', () => {
    for (const v of ['WAZUH_ALERTS_FILE=/x/a.json; WAZUH_ALERTS_FILE_SET=1', 'WAZUH_ALERTS_MIN=5; WAZUH_ALERTS_MIN_SET=1']) { const r = run(v); assert.strictEqual(r.status, 2, v); assert.match(r.stderr, /only make sense with --wazuh-alerts/); }
  });
  it('a path that is not absolute, has spaces, `..`, a dollar sign, quotes or newlines is refused (it goes into broker.env)', () => {
    for (const bad of ['relative/a.json', '/has space/a.json', '/a/../b.json', '/a/$HOME/b', '/a/"b"', "/a/'b'", '/a;b', '/a\nb', '']) {
      const r = run(`WAZUH_ALERTS=1; WAZUH_ALERTS_FILE=$'${bad.replace(/\n/g, '\\n').replace(/'/g, "\\'")}'; WAZUH_ALERTS_FILE_SET=1`); assert.strictEqual(r.status, 2, JSON.stringify(bad)); assert.match(r.stderr, /plain characters/, JSON.stringify(bad));
    }
  });
  it('a level that is not a number from 0 to 15 is refused (it goes into broker.env and a Vector program)', () => {
    for (const bad of ['16', '99', '-1', 'abc', '1.5', '5;ls', '$(id)', '100', '']) { const r = run(`WAZUH_ALERTS=1; WAZUH_ALERTS_MIN='${bad}'; WAZUH_ALERTS_MIN_SET=1`); assert.strictEqual(r.status, 2, JSON.stringify(bad)); assert.match(r.stderr, /from 0 to 15/, JSON.stringify(bad)); }
  });
});

describe('the REAL scripts on a broker: pausing the input, validating it, reporting it', () => {
  let tmp, bin, log, envFile, stateDir, vdir;
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const state = (f, v) => fs.writeFileSync(path.join(tmp, f), v);
  const all = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);
  const calls = () => all().filter((c) => !c.startsWith('report') && !c.startsWith('fetch'));
  const reports = () => all().filter((c) => c.startsWith('report')).map((c) => JSON.parse(c.slice(c.indexOf('{'), c.lastIndexOf('}') + 1)));
  const env = () => fs.readFileSync(envFile, 'utf8');
  const answer = (o) => state('answer', JSON.stringify({ success: true, config: { syslog_port: null, tls_port: null, ...o }, interval_seconds: 300 }));
  const run = () => spawnSync('bash', [path.join(root, 'deploy/broker/asix-broker-config.sh')], { encoding: 'utf8', stdin: 'ignore',
    env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_BROKER_ENV: envFile, ASIX_VECTOR_DIR: vdir, ASIX_CONFIG_STATE_DIR: stateDir, ASIX_CONFIG_WAIT_S: '2' } });
  const list = (...names) => names.map((n) => path.join(vdir, n)).join(',');
  const FILES = ['vector.yaml', 'vector-wazuh.yaml', 'vector-wazuhalerts.yaml'];
  const BASE = () => 'ASIX_INGEST_URL=https://asix1:30443/v1/ingest/http\nASIX_INGEST_KEY=asix_ik_secretsecret\nASIX_BROKER_NAME=broker-1\nASIX_SYSLOG_PORT=514\nASIX_ACCEPT_CONFIG=true\nVECTOR_CONFIG=' + list(...FILES) + '\n';
  const vc = () => (env().match(/^VECTOR_CONFIG=(.*)$/m) || [])[1].split(',').map((p) => path.basename(p));
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bwa-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); envFile = path.join(tmp, 'broker.env'); stateDir = path.join(tmp, 'state'); vdir = path.join(tmp, 'vector');
    fs.mkdirSync(bin); fs.mkdirSync(vdir); for (const f of FILES) fs.writeFileSync(path.join(vdir, f), 'sources: {}\n');
    fs.writeFileSync(envFile, BASE(), { mode: 0o640 }); fs.chmodSync(envFile, 0o640);
    state('answer-rc', '0'); state('report-rc', '0'); state('validate', 'ok'); state('health', 'ok'); state('restart', 'ok');
    stub('id', 'echo 0');
    stub('vector', `if [ "$1" = "validate" ]; then echo "validate list=$(printf '%s,' "\${@:3}" | sed 's|${vdir}/||g;s/,$//')" >> '${log}'; [ "$(cat '${tmp}/validate')" = ok ]; exit $?; fi`);
    stub('systemctl', `echo "systemctl $*" >> '${log}'; [ "$(cat '${tmp}/restart')" = ok ]`);
    stub('curl', `case "$*" in\n  *broker-config/report*) echo "report $*" >> '${log}'; exit $(cat '${tmp}/report-rc');;\n  *broker-config*) echo "fetch $*" >> '${log}'; cat '${tmp}/answer'; exit $(cat '${tmp}/answer-rc');;\n  *health*) [ "$(cat '${tmp}/health')" = ok ]; exit $?;;\nesac`);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('pausing "wazuhalerts" takes ONLY vector-wazuhalerts.yaml out of VECTOR_CONFIG, validates the new list first, restarts, and reports it', () => {
    answer({ paused_inputs: 'wazuhalerts' }); const r = run(); assert.strictEqual(r.status, 0, r.stderr);
    assert.deepStrictEqual(vc(), ['vector.yaml', 'vector-wazuh.yaml']); assert.match(env(), /^ASIX_INPUTS_PAUSED=wazuhalerts$/m);
    const c = calls(); assert.strictEqual(c.length, 2); assert.match(c[0], /^validate list=vector\.yaml,vector-wazuh\.yaml$/); assert.match(c[1], /^systemctl restart vector/);
    assert.strictEqual(reports().at(-1).paused_inputs, 'wazuhalerts');
  });
  it('pausing "wazuh" (the Windows events) leaves the alerts input running, and the other way round', () => {
    answer({ paused_inputs: 'wazuh' }); assert.strictEqual(run().status, 0); assert.deepStrictEqual(vc(), ['vector.yaml', 'vector-wazuhalerts.yaml']);
    answer({ paused_inputs: 'wazuhalerts' }); fs.writeFileSync(log, ''); assert.strictEqual(run().status, 0); assert.deepStrictEqual(vc().sort(), ['vector-wazuh.yaml', 'vector.yaml']);
  });
  it('both paused, then resumed with an empty list: both come back, the alerts file last', () => {
    answer({ paused_inputs: 'wazuh,wazuhalerts' }); assert.strictEqual(run().status, 0); assert.deepStrictEqual(vc(), ['vector.yaml']); assert.match(env(), /^ASIX_INPUTS_PAUSED=wazuh,wazuhalerts$/m);
    fs.writeFileSync(log, ''); answer({ paused_inputs: '' }); assert.strictEqual(run().status, 0); assert.deepStrictEqual(vc().sort(), ['vector-wazuh.yaml', 'vector-wazuhalerts.yaml', 'vector.yaml']);
    assert.match(calls()[0], /^validate list=vector\.yaml,vector-wazuh\.yaml,vector-wazuhalerts\.yaml$/);
  });
  it('a list given in the wrong order is applied in the fixed order; a name nobody can pause, or a repeat, is refused with nothing changed', () => {
    answer({ paused_inputs: 'wazuhalerts,wazuh' }); assert.strictEqual(run().status, 0); assert.match(env(), /^ASIX_INPUTS_PAUSED=wazuh,wazuhalerts$/m);
    for (const bad of ['wazuh-alerts', 'wazuhalerts,wazuhalerts', 'syslog', 'wazuhalert']) {
      fs.writeFileSync(envFile, BASE()); fs.writeFileSync(log, ''); answer({ paused_inputs: bad }); const r = run(); assert.notStrictEqual(r.status, 0, bad); assert.strictEqual(env(), BASE(), bad + ': broker.env untouched'); assert.deepStrictEqual(calls(), [], bad);
    }
  });
  it('a failed validation puts everything back and the same list is not tried again', () => {
    state('validate', 'fail'); answer({ paused_inputs: 'wazuhalerts' }); assert.notStrictEqual(run().status, 0); assert.strictEqual(env(), BASE());
    assert.strictEqual(fs.readFileSync(path.join(stateDir, 'config-paused-rejected'), 'utf8').trim(), 'wazuhalerts');
    fs.writeFileSync(log, ''); state('validate', 'ok'); const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /was tried before and failed/); assert.deepStrictEqual(calls(), []);
  });
  it('a port change validates with the alerts file among the files (it is one of the optional configs the script knows)', () => {
    fs.writeFileSync(envFile, BASE().replace('ASIX_SYSLOG_PORT=514', 'ASIX_SYSLOG_PORT=514')); state('answer', JSON.stringify({ success: true, config: { syslog_port: 2514, tls_port: null }, interval_seconds: 300 }));
    const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.match(calls()[0], /^validate list=.*vector-wazuhalerts\.yaml.*vector\.yaml$/);
  });

  describe('the heartbeat script', () => {
    const SCRIPT = path.join(root, 'deploy/broker/asix-broker-heartbeat.sh');
    const hb = (extra) => {
      fs.writeFileSync(envFile, 'ASIX_INGEST_URL=https://asix1:30443/v1/ingest/http\nASIX_INGEST_KEY=asix_ik_secretsecret\nASIX_BROKER_NAME=broker-1\n' + extra); fs.writeFileSync(log, '');
      stub('vector', 'echo "vector 0.59.0 (x86_64-unknown-linux-gnu)"'); stub('curl', `case "$*" in *health*) exit 0;; *) echo "$*" >> '${log}'; exit 0;; esac`);
      const r = spawnSync('bash', [SCRIPT], { encoding: 'utf8', stdin: 'ignore', env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_BROKER_ENV: envFile } });
      const m = /--data (\{.*\})/.exec(fs.readFileSync(log, 'utf8')); return { status: r.status, inputs: m ? JSON.parse(m[1]).collector.inputs : null, stderr: r.stderr };
    };
    it('names the alerts input only when its file is in the list, after the Windows events', () => {
      let r = hb('VECTOR_CONFIG=/etc/vector/vector.yaml,/etc/vector/vector-wazuhalerts.yaml\n'); assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(r.inputs, 'syslog:514,wazuhalerts');
      assert.strictEqual(hb('VECTOR_CONFIG=/etc/vector/vector.yaml,/etc/vector/vector-wazuh.yaml,/etc/vector/vector-wazuhalerts.yaml\n').inputs, 'syslog:514,wazuh,wazuhalerts');
      assert.strictEqual(hb('VECTOR_CONFIG=/etc/vector/vector.yaml,/etc/vector/vector-wazuh.yaml\n').inputs, 'syslog:514,wazuh', 'the Windows events file is not the alerts file');
      assert.strictEqual(hb('ASIX_WAZUH_ALERTS=/var/ossec/logs/alerts/alerts.json\nVECTOR_CONFIG=/etc/vector/vector.yaml\n').inputs, 'syslog:514', 'a setting alone is not an input');
      assert.strictEqual(hb('VECTOR_CONFIG=/etc/vector/vector-wazuhalerts.yaml.bak\n').inputs, 'syslog:514', 'a similar name is not the file');
    });
    it('what it sends is something the server keeps whole', () => {
      const sent = hb('VECTOR_CONFIG=/etc/vector/vector.yaml,/etc/vector/vector-file.yaml,/etc/vector/vector-http.yaml,/etc/vector/vector-journald.yaml,/etc/vector/vector-wazuh.yaml,/etc/vector/vector-wazuhalerts.yaml\n').inputs;
      assert.strictEqual(sent, 'syslog:514,file,http:8088,journald,wazuh,wazuhalerts'); assert.strictEqual(inputs.parseInputs(sent), sent);
    });
  });
});

describe('the server side of the input: the pause list the broker reports and the pull answers', () => {
  it('a report that says wazuhalerts is paused (or was rejected) is accepted, in any position; the order is fixed', () => {
    assert.deepStrictEqual(paused.checkPaused(['wazuhalerts', 'file']), { value: ['file', 'wazuhalerts'] });
    assert.deepStrictEqual(paused.checkReportText('wazuh,wazuhalerts'), { value: 'wazuh,wazuhalerts' }); assert.deepStrictEqual(paused.checkReportText('wazuhalerts'), { value: 'wazuhalerts' });
    assert.ok(paused.checkReportText('wazuh-alerts').error, 'a hyphenated name is not a name');
    assert.strictEqual(paused.checkPaused(['wazuh-alerts']).error.includes('cannot be paused'), true);
    assert.deepStrictEqual(paused.parseText('wazuhalerts,file,nonsense'), ['file', 'wazuhalerts']);
    const rep = config.checkReport({ collector: 'broker-1', syslog_port: 514, paused_inputs: 'wazuh,wazuhalerts', rejected_paused_inputs: 'wazuhalerts' });
    assert.ok(!rep.error, JSON.stringify(rep)); assert.strictEqual(rep.paused, 'wazuh,wazuhalerts'); assert.strictEqual(rep.pausedRejected, 'wazuhalerts');
  });
  it('the whole list is at most 40 characters, which is what the shell script and the database both allow', () => { assert.ok(paused.toText(paused.KINDS).length <= 40); });
});

// ---- the parsing rule -------------------------------------------------------------------------------------------------------------------------------------------------
// The event the way the lane stores it (src/ingest/http-ingest.js jsonEvent) from what the config sends; the real-Vector section below uses what Vector REALLY sent instead.
const defaults = compile(require('../src/ingestion/default-parsing-rules'));
const parse = (rec) => apply([defaults.rules], rec);
const laneOf = (e) => { const x = jsonEvent(e, 'broker-test'); return { source_type: 'endpoint-alert', raw: x.raw, time: x.time, parsed: x.parsed }; };
const mk = (fields, message = '[Endpoint alert] rule 5763 level 10: x') => laneOf({ message, time: '2026-10-25T13:00:00.123+00:00', host: 'web1', fields: { asix_via: 'wazuh', rule_id: '5763', rule_level: '10', rule_description: 'x', ...fields } });

describe('the parsing rule for endpoint alerts', () => {
  it('lands on its own rule and gives the alert a category, a number for the level, a severity and the lifted fields', () => {
    const r = parse(mk({ data_srcip: '203.0.113.9', data_srcuser: 'admin', rule_description: 'sshd: brute force' })); assert.strictEqual(r.matched.content_id, 'wazuh_alert');
    const p = r.parsed; assert.deepStrictEqual([p.event_category, p.alert_name, p.alert_rule_id, p.alert_level, p.alert_severity, p.user, p.src_ip], ['endpoint_alert', 'sshd: brute force', '5763', 10, 'high', 'admin', '203.0.113.9']);
    assert.strictEqual(p.rule_id, '5763', 'the original fields stay'); assert.strictEqual(p.data_srcuser, 'admin'); assert.deepStrictEqual([r.matched.vendor, r.matched.product], ['asix', 'endpoint_security']);
  });
  it('severity follows the level: 0-4 low, 5-7 medium, 8-11 high, 12-15 critical', () => {
    const sev = (l) => parse(mk({ rule_level: String(l) })).parsed.alert_severity;
    assert.deepStrictEqual([0, 3, 4, 5, 7, 8, 11, 12, 15].map(sev), ['low', 'low', 'low', 'medium', 'medium', 'high', 'high', 'critical', 'critical']);
  });
  it('a Windows alert gives the target user from the event; a file alert gives the path and what happened to it', () => {
    let p = parse(mk({ data_win_eventdata_targetUserName: 'bob', data_srcuser: 'ignored' })).parsed; assert.strictEqual(p.user, 'bob');
    p = parse(mk({ syscheck_path: '/etc/passwd', syscheck_event: 'modified' })).parsed; assert.deepStrictEqual([p.file_path, p.file_event], ['/etc/passwd', 'modified']);
    assert.ok(!('tmp_win_user' in p), 'the helper field is not kept');
  });
  it('a source address that is not an address is not taken as one', () => { const p = parse(mk({ data_srcip: 'not an ip; rm -rf' })).parsed; assert.ok(p.src_ip === undefined || p.src_ip === null); });
  it('only alerts that say they came through the manager and carry a numeric rule id are claimed; the same source type from anything else is left alone', () => {
    const rec = mk({}); delete rec.parsed.asix_via; assert.notStrictEqual((parse(rec).matched || {}).content_id, 'wazuh_alert');
    assert.notStrictEqual((parse(mk({ rule_id: 'abc' })).matched || {}).content_id, 'wazuh_alert');
    const other = mk({}); other.source_type = 'windows-event'; assert.notStrictEqual((parse(other).matched || {}).content_id, 'wazuh_alert');
  });
  it('the Windows event rules are not disturbed: a Windows event from the archive file still lands on its own rule', () => {
    const W = require('./fixtures/wazuh-windows'); const s = W.events.failedLogon.data.win.system;
    const e = jsonEvent({ message: '[Security] P id=4625 ', time: s.systemTime, host: s.computer, fields: { TargetUserName: 'admin', asix_via: 'wazuh', win_event_id: '4625', IpAddress: '10.0.0.99' } }, 'b');
    assert.strictEqual(parse({ source_type: 'windows-event', raw: e.raw, time: e.time, parsed: e.parsed }).matched.content_id, 'wazuh_windows_logon');
  });
});

// ---- real Vector --------------------------------------------------------------------------------------------------------------------------------------------------------
describe('real Vector: the alerts input and what ASIX receives', { skip: VECTOR ? false : 'no Vector binary (set VECTOR_BIN or put `vector` on PATH)' }, () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const until = async (fn, ms = 25000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(150); } return false; };
  const tmps = []; let lane, laneCalls = [];
  before(async () => {
    lane = http.createServer((q, s) => { let b = ''; q.on('data', (d) => { b += d; }); q.on('end', () => { laneCalls.push({ h: q.headers, body: b }); s.writeHead(202, { 'content-type': 'application/json' }); s.end('{"success":true}'); }); });
    await new Promise((r) => lane.listen(0, '127.0.0.1', r));
  });
  after(() => { lane.close(); for (const t of tmps) fs.rmSync(t, { recursive: true, force: true }); });

  // One broker: its own folder, an alert file with a line of history, Vector started, the sample lines appended; returns what the lane got.
  async function scenario({ minLevel, extra = [], waitFor = (events) => events.length >= 1, lines }) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wazuh-alerts-')); tmps.push(tmp);
    const file = path.join(tmp, 'alerts.json'), base = path.join(tmp, 'base.yaml'), mine = path.join(tmp, 'vector-wazuhalerts.yaml');
    fs.writeFileSync(file, A.line(A.base({ rule: { level: 12, description: 'history before Vector starts', id: '1' } })) + '\n'); fs.writeFileSync(base, `data_dir: ${tmp}\n`); fs.copyFileSync(path.join(root, 'deploy/broker/vector-wazuhalerts.yaml'), mine);
    const mark = 'scenario-' + path.basename(tmp), got = [];
    const env = { PATH: process.env.PATH, VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: 'true', ASIX_INGEST_KEY: 'asix_ik_test', ASIX_BROKER_NAME: mark, ASIX_INGEST_URL: `http://127.0.0.1:${lane.address().port}/v1/ingest/http`, ASIX_WAZUH_ALERTS: file };
    if (minLevel !== undefined) env.ASIX_WAZUH_ALERT_MIN_LEVEL = minLevel;
    const v = spawn(VECTOR, ['--config', base, '--config', mine], { env, stdio: 'ignore' });
    try {
      await sleep(3500);   // the file is read from its END: only what is appended now counts
      fs.appendFileSync(file, (lines || [A.garbageLine, A.noRule, A.noRuleId, ...Object.values(A.alerts).map(A.line), ...extra]).join('\n') + '\n');
      await until(() => { got.length = 0; for (const c of laneCalls.filter((x) => x.h['x-asix-collector'] === mark)) got.push(...JSON.parse(c.body)); return waitFor(got); });
      await sleep(1500); got.length = 0; const calls = laneCalls.filter((x) => x.h['x-asix-collector'] === mark); for (const c of calls) got.push(...JSON.parse(c.body));
      return { events: got, calls };
    } finally { v.kill('SIGKILL'); }
  }
  const byRule = (events, id) => events.filter((e) => e.fields.rule_id === String(id));
  const ruleIds = (events) => events.map((e) => e.fields.rule_id).sort();
  const ALL = Object.values(A.alerts).map((a) => String(a.rule.id)).sort();

  it('validates alone with the base config, with the Windows events input, and with every other input (distinct sinks and buffers)', () => {
    const e = { PATH: process.env.PATH, VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: 'true', ASIX_INGEST_URL: 'https://x/v1/ingest/http', ASIX_INGEST_KEY: 'k', ASIX_BROKER_NAME: 'b', ASIX_SYSLOG_PORT: '514', ASIX_WIN_FILTER_VRL: path.join(root, 'deploy/broker/win-filter-identity.vrl'), ASIX_FILE_GLOB: '/tmp/*.log', ASIX_HTTP_USER: 'svc', ASIX_HTTP_PASSWORD: 's3cretpassword', ASIX_HTTP_PORT: '1' };
    const files = (...n) => n.map((f) => path.join(root, 'deploy/broker', f));
    for (const list of [['vector.yaml', 'vector-wazuhalerts.yaml'], ['vector.yaml', 'vector-wazuh.yaml', 'vector-wazuhalerts.yaml'], ['vector.yaml', 'vector-file.yaml', 'vector-http.yaml', 'vector-journald.yaml', 'vector-wazuh.yaml', 'vector-wazuhalerts.yaml']]) {
      const r = spawnSync(VECTOR, ['validate', '--no-environment', ...files(...list)], { env: e, encoding: 'utf8' }); assert.strictEqual(r.status, 0, list.join(' ') + '\n' + r.stdout + r.stderr);
    }
  });
  it('needs no filter file: it validates without win-filter.vrl present', () => {
    const e = { PATH: process.env.PATH, VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: 'true', ASIX_INGEST_URL: 'https://x', ASIX_INGEST_KEY: 'k', ASIX_BROKER_NAME: 'b', ASIX_SYSLOG_PORT: '514', ASIX_WIN_FILTER_VRL: '/nonexistent/win-filter.vrl' };
    const r = spawnSync(VECTOR, ['validate', '--no-environment', path.join(root, 'deploy/broker/vector.yaml'), path.join(root, 'deploy/broker/vector-wazuhalerts.yaml')], { env: e, encoding: 'utf8' }); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  });

  let all;
  it('every sample alert arrives once, from now on, as one JSON array per batch with the key, the broker name and the source type in headers; lines that are not alerts are skipped', async () => {
    all = await scenario({ waitFor: (ev) => byRule(ev, 5501).length >= 1 && ev.length >= ALL.length });
    const { events, calls } = all; assert.ok(calls.length >= 1);
    for (const c of calls) { assert.strictEqual(c.h.authorization, 'Bearer asix_ik_test'); assert.match(c.h['content-type'], /^application\/json/); assert.strictEqual(c.h['x-asix-source-type'], 'endpoint-alert'); assert.ok(Array.isArray(JSON.parse(c.body))); assert.ok(JSON.parse(c.body).length <= 500); }
    assert.deepStrictEqual(ruleIds(events), ALL, 'every sample alert and nothing else: not the history, the manager\'s own line, the rule without an id or the garbage');
  });
  it('each alert is "[Endpoint alert] rule N level L: description" on ONE line, with the alert\'s own time (as RFC 3339) and the agent\'s name as host', () => {
    const e = byRule(all.events, 5763)[0];
    assert.strictEqual(e.message, '[Endpoint alert] rule 5763 level 10: sshd: brute force trying to get access to the system. Authentication failed.'); assert.strictEqual(e.host, 'web1');
    assert.strictEqual(e.time, '2026-10-25T13:00:00.123+00:00'); assert.strictEqual(new Date(e.time).toISOString(), '2026-10-25T13:00:00.123Z');
    const w = byRule(all.events, 60122)[0]; assert.strictEqual(w.host, 'WIN-DC01'); assert.match(w.message, /^\[Endpoint alert\] rule 60122 level 5: Logon failure/);
    const odd = byRule(all.events, 99001)[0]; assert.strictEqual(odd.message, '[Endpoint alert] rule 99001 level 8: Multi line description with tabs'); assert.ok(!/[\r\n\t]|\s{2}/.test(odd.message));
  });
  it('the rule, the mitre ids, the agent and the decoder arrive as fields; lists become comma lists; a missing list is empty text', () => {
    const f = byRule(all.events, 5763)[0].fields;
    assert.deepStrictEqual([f.asix_via, f.rule_level, f.rule_groups, f.mitre_ids, f.mitre_tactics, f.mitre_techniques, f.agent_id, f.agent_name, f.agent_ip, f.manager_name, f.decoder_name, f.location, f.alert_id],
      ['wazuh', '10', 'syslog,sshd,authentication_failures', 'T1110', 'Credential Access', 'Brute Force', '002', 'web1', '10.0.0.30', 'wazuh-mgr', 'sshd', '/var/log/auth.log', '1761397200.1001']);
    assert.strictEqual(f.full_log, 'Oct 25 13:00:00 web1 sshd[991]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2');
    const low = byRule(all.events, 5402)[0].fields; assert.deepStrictEqual([low.mitre_ids, low.rule_groups], ['', 'syslog,sudo']);
    assert.strictEqual(byRule(all.events, 60122)[0].fields.mitre_tactics, 'Defense Evasion,Persistence,Privilege Escalation,Initial Access');
    for (const e of all.events) for (const [k, v] of Object.entries(e.fields)) assert.strictEqual(typeof v, 'string', e.fields.rule_id + ' ' + k);
  });
  it('the manager\'s data and file integrity details are flattened into data_* and syscheck_* fields; a Windows alert keeps its event data', () => {
    const f = byRule(all.events, 5763)[0].fields; assert.deepStrictEqual([f.data_srcip, f.data_srcuser], ['203.0.113.9', 'admin']);
    const w = byRule(all.events, 60122)[0].fields; assert.deepStrictEqual([w.data_win_eventdata_targetUserName, w.data_win_eventdata_ipAddress, w.data_win_system_eventID, w.data_win_system_channel], ['admin', '10.0.0.99', '4625', 'Security']);
    const s = byRule(all.events, 550)[0].fields; assert.deepStrictEqual([s.syscheck_path, s.syscheck_event, s.syscheck_md5_before, s.syscheck_md5_after, s.syscheck_size_after], ['/etc/passwd', 'modified', 'aaaa', 'bbbb', '1581']);
    assert.strictEqual(s.syscheck_changed_attributes, 'size,mtime,md5', 'a list is one comma list, not an empty value'); assert.match(s.syscheck_diff, /backdoor:x:0:0/);
  });
  it('awkward data: dots and spaces in names become underscores, lists, numbers, booleans and null become text, long values and the full log are cut', () => {
    const f = byRule(all.events, 99001)[0].fields;
    assert.deepStrictEqual([f.data_weird_key_with_dots, f.data_audit_exe, f.data_audit_a_b, f.data_vulnerability_cve, f.data_number, f.data_flag, f.data_nothing], ['v1', '/usr/bin/sudo', 'x', 'CVE-2026-0001', '42', 'true', '']);
    assert.strictEqual(f.data_vulnerability_references, 'https://a.example,https://b.example'); assert.strictEqual(f.data_long.length, 500); assert.strictEqual(f.full_log.length, 2000);
    for (const k of Object.keys(f)) assert.match(k, /^[A-Za-z0-9_]+$/, k);
  });
  it('an alert whose time nobody can read is sent with the time it was read, never dropped', () => {
    const e = byRule(all.events, 5501)[0]; assert.ok(Math.abs(Date.now() - new Date(e.time).getTime()) < 120000, e.time);
  });
  it('what ASIX stores is parsed by the real rules: every alert lands on the endpoint alert rule with a number for the level', () => {
    for (const e of all.events) {
      const r = parse({ source_type: 'endpoint-alert', ...(({ raw, time, parsed }) => ({ raw, time, parsed }))(jsonEvent(e, 'broker-test')) });
      assert.strictEqual(r.matched.content_id, 'wazuh_alert', e.fields.rule_id); assert.strictEqual(r.parsed.alert_level, Number(e.fields.rule_level)); assert.strictEqual(r.parsed.alert_rule_id, e.fields.rule_id);
    }
    const p = parse({ source_type: 'endpoint-alert', ...(({ raw, time, parsed }) => ({ raw, time, parsed }))(jsonEvent(byRule(all.events, 60122)[0], 'broker-test')) }).parsed;
    assert.deepStrictEqual([p.user, p.alert_severity], ['admin', 'medium']);
  });
  it('the minimum level keeps only alerts at that level or above', async () => {
    const r = await scenario({ minLevel: '6', waitFor: (ev) => ev.length >= 3 }); assert.deepStrictEqual(ruleIds(r.events), ['550', '5763', '99001'], 'levels 7, 10 and 8; not 5, 3 or 4');
    const edge = await scenario({ minLevel: '10', waitFor: (ev) => ev.length >= 1 }); assert.deepStrictEqual(ruleIds(edge.events), ['5763'], 'a level equal to the minimum is kept');
  });
  it('a minimum level of 0, or one nobody can read, sends everything (the bootstrap refuses a bad one, the file does not break on it)', async () => {
    const zero = await scenario({ minLevel: '0', waitFor: (ev) => ev.length >= ALL.length }); assert.deepStrictEqual(ruleIds(zero.events), ALL);
    const junk = await scenario({ minLevel: 'abc', waitFor: (ev) => ev.length >= ALL.length }); assert.deepStrictEqual(ruleIds(junk.events), ALL);
  });
  it('text that looks like a variable or like code in an alert arrives as it is (alert text is data, not configuration)', async () => {
    const tricky = A.base({ rule: { level: 9, description: 'ran ${EVIL} and $(id) now', id: '70001' }, id: '9.9', full_log: 'x ${ASIX_INGEST_KEY} y', data: { cmd: '${HOME} `id`' }, location: 'l' });
    const r = await scenario({ lines: [A.line(tricky)], waitFor: (ev) => ev.length >= 1 }); const e = byRule(r.events, 70001)[0];
    assert.strictEqual(e.message, '[Endpoint alert] rule 70001 level 9: ran ${EVIL} and $(id) now'); assert.strictEqual(e.fields.full_log, 'x ${ASIX_INGEST_KEY} y'); assert.strictEqual(e.fields.data_cmd, '${HOME} `id`');
  });
  it('a rule id that is a number (not text) and a level that is text are both handled', async () => {
    const r = await scenario({ lines: [A.line(A.base({ rule: { level: '9', description: 'numbers', id: 80001 }, id: '1' }))], waitFor: (ev) => ev.length >= 1 });
    assert.strictEqual(r.events[0].fields.rule_id, '80001'); assert.strictEqual(r.events[0].fields.rule_level, '9');
  });
});
