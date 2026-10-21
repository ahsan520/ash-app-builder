'use strict';
// "Which inputs a broker runs" (the Inputs column on the Brokers page): the text check, the broker view, the REAL heartbeat script
// (system commands stubbed on PATH: vector, curl) and the portal cell. No database; the database test is broker-inputs-report-db.test.js.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const inputs = require('../src/brokers/inputs');
const view = require('../src/brokers/broker-view');

describe('parseInputs', () => {
  it('keeps the known names and ports, in the order sent', () => {
    assert.strictEqual(inputs.parseInputs('syslog:514,syslog-tls:6514,file,http:8088'), 'syslog:514,syslog-tls:6514,file,http:8088');
    assert.strictEqual(inputs.parseInputs(['syslog:1514', 'https:8443']), 'syslog:1514,https:8443');
    assert.strictEqual(inputs.parseInputs(' Syslog:514 , FILE '), 'syslog:514,file');
    assert.strictEqual(inputs.parseInputs('syslog:514,file,http:8088,journald'), 'syslog:514,file,http:8088,journald');
    assert.strictEqual(inputs.parseInputs('syslog:514,journald:99'), 'syslog:514', 'the journal has no port');
  });
  it('drops what it does not know or cannot trust, and returns null when nothing is left', () => {
    assert.strictEqual(inputs.parseInputs('syslog:514,kafka:9092,winlog'), 'syslog:514', 'unknown names are dropped, a newer broker script must not be refused');
    assert.strictEqual(inputs.parseInputs('syslog:0,syslog:70000,syslog:5x14'), null, 'bad ports');
    assert.strictEqual(inputs.parseInputs('file:80'), null, 'file has no port');
    assert.strictEqual(inputs.parseInputs('syslog:514,syslog:515'), 'syslog:514', 'a name once');
    for (const v of [undefined, null, '', ',,', 5, {}, true, '<script>']) assert.strictEqual(inputs.parseInputs(v), null, String(v));
    assert.strictEqual(inputs.parseInputs('syslog:514\nfile'), null, 'a token with a line break in it is garbage, not two tokens');
  });
  it('is bounded: too many tokens are cut, and the stored text is never longer than the column allows', () => {
    const many = Array.from({ length: 500 }, (_, i) => 'x' + i).join(',') + ',file';
    assert.strictEqual(inputs.parseInputs(many), null, 'only the first 20 tokens are looked at');
    const all = inputs.parseInputs('syslog:65535,syslog-tls:65535,file,http:65535,https:65535,journald');
    assert.ok(all.length <= 200);
  });
});

describe('listInputs and label', () => {
  it('turns the stored text into rows, and null into null', () => {
    assert.deepStrictEqual(inputs.listInputs('syslog:514,file,http:8088'), [{ kind: 'syslog', port: 514 }, { kind: 'file', port: null }, { kind: 'http', port: 8088 }]);
    for (const v of [null, undefined, '', 'garbage:1']) assert.strictEqual(inputs.listInputs(v), null, String(v));
    assert.strictEqual(inputs.label({ kind: 'syslog-tls', port: 6514 }), 'Syslog TLS 6514');
    assert.strictEqual(inputs.label({ kind: 'file', port: null }), 'Log files');
    assert.strictEqual(inputs.label({ kind: 'journald', port: null }), 'Journal');
  });
});

describe('the broker view carries the inputs', () => {
  const row = (o = {}) => ({ id: 'i', name: 'broker-1', os: 'x', version: 'vector-0.59.0', last_ip: '10.0.0.5', first_seen: new Date(), last_seen: new Date(), events_total: '0', key_id: 'k', installer_name: 'n', key_status: 'active', ...o });
  it('reported, and never reported', () => {
    assert.deepStrictEqual(view.shape(row({ inputs: 'syslog:514,file' })).inputs, [{ kind: 'syslog', port: 514 }, { kind: 'file', port: null }]);
    assert.strictEqual(view.shape(row({ inputs: null })).inputs, null);
    assert.strictEqual(view.shape(row()).inputs, null, 'a row from a database without the column');
  });
  it('is not a problem and changes no other field', () => {
    const a = view.shape(row({ inputs: 'syslog:514' })); const b = view.shape(row({ inputs: null }));
    assert.deepStrictEqual(a.problems, b.problems); assert.strictEqual(a.status, b.status);
  });
});

describe('deploy/broker/asix-broker-heartbeat.sh: what it says about the inputs', () => {
  const SCRIPT = path.join(__dirname, '..', 'deploy', 'broker', 'asix-broker-heartbeat.sh');
  let tmp, bin, log, envFile;
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const BASE = 'ASIX_INGEST_URL=https://asix1:30443/v1/ingest/http\nASIX_INGEST_KEY=asix_ik_secretsecret\nASIX_BROKER_NAME=broker-1\n';
  const run = (extra = '') => {
    fs.writeFileSync(envFile, BASE + extra); fs.writeFileSync(log, '');
    const r = spawnSync('bash', [SCRIPT], { encoding: 'utf8', stdin: 'ignore', env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_BROKER_ENV: envFile } });
    const m = /--data (\{.*\})/.exec(fs.readFileSync(log, 'utf8'));
    return { status: r.status, body: m ? JSON.parse(m[1]) : null, stderr: r.stderr };
  };
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'binp-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); envFile = path.join(tmp, 'broker.env'); fs.mkdirSync(bin);
    stub('vector', 'echo "vector 0.59.0 (x86_64-unknown-linux-gnu)"');
    stub('curl', `case "$*" in *health*) exit 0;; *) echo "$*" >> '${log}'; exit 0;; esac`);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('syslog only: a bootstrap that wrote no extras reports syslog on the default port', () => {
    const r = run(); assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(r.body.collector.inputs, 'syslog:514'); assert.strictEqual(r.body.collector.version, 'vector-0.59.0');
  });
  it('the port comes from broker.env, so a port moved by the config pull is reported', () => {
    assert.strictEqual(run('ASIX_SYSLOG_PORT=1514\n').body.collector.inputs, 'syslog:1514');
  });
  it('every extra input the config list names, with its port', () => {
    const all = 'ASIX_SYSLOG_PORT=514\nASIX_SYSLOG_TLS_PORT=6514\nASIX_FILE_GLOB=/var/log/myapp/*.log\nASIX_HTTP_USER=svc\nASIX_HTTP_PORT=8088\nVECTOR_CONFIG=/etc/vector/vector.yaml,/etc/vector/vector-tls.yaml,/etc/vector/vector-file.yaml,/etc/vector/vector-http.yaml\n';
    const r = run(all); assert.strictEqual(r.body.collector.inputs, 'syslog:514,syslog-tls:6514,file,http:8088');
    assert.ok(!JSON.stringify(r.body).includes('/var/log'), 'the file glob is never sent');
    assert.strictEqual(run(all + 'ASIX_HTTP_TLS=true\n').body.collector.inputs, 'syslog:514,syslog-tls:6514,file,https:8088');
  });
  it('the journal is listed only when vector-journald.yaml is in the list, last after HTTP, with no port and no setting sent', () => {
    assert.strictEqual(run('VECTOR_CONFIG=/etc/vector/vector.yaml,/etc/vector/vector-journald.yaml\n').body.collector.inputs, 'syslog:514,journald');
    const r = run('ASIX_JOURNALD_MAX_PRIORITY=4\nVECTOR_CONFIG=/etc/vector/vector.yaml,/etc/vector/vector-file.yaml,/etc/vector/vector-http.yaml,/etc/vector/vector-journald.yaml\n');
    assert.strictEqual(r.body.collector.inputs, 'syslog:514,file,http:8088,journald'); assert.ok(!/priority/i.test(JSON.stringify(r.body)), 'the priority limit is not sent');
    assert.strictEqual(run('ASIX_JOURNALD_MAX_PRIORITY=4\nVECTOR_CONFIG=/etc/vector/vector.yaml\n').body.collector.inputs, 'syslog:514', 'a setting alone is not an input');
    assert.strictEqual(run('VECTOR_CONFIG=/etc/vector/vector-journald.yaml.bak\n').body.collector.inputs, 'syslog:514', 'a similar name is not the file');
  });
  it('only the files in the list count: a port variable alone is not an input', () => {
    assert.strictEqual(run('ASIX_SYSLOG_TLS_PORT=6514\nASIX_HTTP_PORT=8088\nVECTOR_CONFIG=/etc/vector/vector.yaml\n').body.collector.inputs, 'syslog:514');
    assert.strictEqual(run('VECTOR_CONFIG=/etc/vector/vector.yaml,/etc/vector/vector-file.yaml\n').body.collector.inputs, 'syslog:514,file');
    assert.strictEqual(run('VECTOR_CONFIG=/etc/vector/vector-file.yaml.bak\n').body.collector.inputs, 'syslog:514', 'a similar name is not the file');
  });
  it('the defaults apply when a listed input has no port variable, and a garbled port is left out, never sent', () => {
    assert.strictEqual(run('VECTOR_CONFIG=/etc/vector/vector.yaml,/etc/vector/vector-tls.yaml,/etc/vector/vector-http.yaml\n').body.collector.inputs, 'syslog:514,syslog-tls:6514,http:8088');
    assert.strictEqual(run('ASIX_SYSLOG_PORT=51x4\nASIX_SYSLOG_TLS_PORT=99999\nVECTOR_CONFIG=/etc/vector/vector-tls.yaml,\n').body.collector.inputs, 'syslog,syslog-tls');
  });
  it('the body is valid JSON for the server and every text it can send passes the server-side check unchanged', () => {
    for (const extra of ['', 'ASIX_SYSLOG_PORT=2514\nVECTOR_CONFIG=/etc/vector/vector-tls.yaml,/etc/vector/vector-file.yaml,/etc/vector/vector-http.yaml,/etc/vector/vector-journald.yaml\nASIX_HTTP_TLS=true\n']) {
      const sent = run(extra).body.collector.inputs; assert.strictEqual(inputs.parseInputs(sent), sent);
    }
  });
  it('still sends nothing when Vector is unhealthy', () => {
    stub('curl', `case "$*" in *health*) exit 7;; *) echo "$*" >> '${log}'; exit 0;; esac`);
    const r = run(); assert.strictEqual(r.status, 1); assert.strictEqual(r.body, null);
  });
});

describe('Brokers page: Inputs cell', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
  const cut = (name) => { const i = html.indexOf('function ' + name + '('); assert.ok(i >= 0, name + ' not found'); return html.slice(i, html.indexOf('\n}\n', i) + 3); };
  const line = (start) => { const i = html.indexOf(start); assert.ok(i >= 0, start + ' not found'); return html.slice(i, html.indexOf('\n', i) + 1); };
  const el = (tag, attrs, ...kids) => ({ tag, attrs: attrs || {}, kids: kids.flat(Infinity) });
  const pill = (text, cls) => ({ pill: text, cls });
  const { brokerInputsCell } = new Function('el', 'pill', line('const BROKER_INPUT_LABEL') + cut('brokerInputsCell') + '\nreturn { brokerInputsCell };')(el, pill);
  const pills = (n) => (n && typeof n === 'object' ? [...(n.pill ? [n.pill] : []), ...(n.kids || []).flatMap(pills)] : []);

  it('one pill per input, with the port', () => {
    assert.deepStrictEqual(pills(brokerInputsCell({ inputs: inputs.listInputs('syslog:514,syslog-tls:6514,file,https:8088,journald') })), ['Syslog 514', 'Syslog TLS 6514', 'Log files', 'HTTPS/JSON 8088', 'Journal']);
  });
  it('a broker that never said shows a dash with the reason in the tooltip, and nothing throws', () => {
    const c = brokerInputsCell({ inputs: null }); assert.deepStrictEqual(pills(c), []); assert.strictEqual(c.attrs.textContent, '-'); assert.match(c.attrs.title, /bootstrap/);
    assert.doesNotThrow(() => brokerInputsCell({})); assert.doesNotThrow(() => brokerInputsCell(null));
  });
  it('the portal labels match the server labels, and the column sits in the Brokers table', () => {
    for (const k of inputs.KINDS) assert.ok(new RegExp("'?" + k + "'?: '" + inputs.label({ kind: k, port: null }).replace('/', '\\/') + "'").test(html), k);
    assert.match(html, /\{ h: 'Inputs', f: brokerInputsCell \}/);
  });
});
