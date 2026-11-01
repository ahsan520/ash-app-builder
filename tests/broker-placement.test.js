'use strict';
// Broker capacity and placement (docs/broker-groups.md, task E8): the pure rules, the broker view, the REAL heartbeat script (vector and curl stubbed on PATH),
// the heartbeat route's field checks, the portal pieces cut out of the page, the schema columns and the parser-worker setting in the API manifest.
// No database; the database test is broker-placement-db.test.js.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const p = require('../src/brokers/placement');
const view = require('../src/brokers/broker-view');
const { listInputs } = require('../src/brokers/inputs');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

describe('rates and the recommended limit', () => {
  it('4 CPUs and 8 GB come to about 50 agents, the number in the sizing table', () => {
    assert.strictEqual(p.recommendedLimit(4, 8192, {}), 48);
    assert.strictEqual(p.recommendedLimit(4, 7800, {}), 45, 'a VM reports a little under its nominal memory');
  });
  it('the smaller of CPU and memory wins, so a big-CPU small-memory VM is held by its memory', () => {
    assert.strictEqual(p.recommendedLimit(16, 4096, {}), 24);
    assert.strictEqual(p.recommendedLimit(2, 65536, {}), 24);
  });
  it('never below 1 for a VM that exists, and null when the size is not known or not a number', () => {
    assert.strictEqual(p.recommendedLimit(1, 256, {}), 1);
    for (const [c, m] of [[null, 8192], [4, null], [0, 8192], [4, 0], ['4', 8192], [4.5, 8192], [undefined, undefined]]) assert.strictEqual(p.recommendedLimit(c, m, {}), null, String([c, m]));
  });
  it('the rates come from the environment, and a typo means the default, never an error', () => {
    assert.deepStrictEqual(p.rates({}), { per_cpu: 12, per_gb: 6, near_percent: 80 });
    assert.deepStrictEqual(p.rates({ ASIX_BROKER_AGENTS_PER_CPU: '20', ASIX_BROKER_AGENTS_PER_GB: '10' }), { per_cpu: 20, per_gb: 10, near_percent: 80 });
    for (const bad of ['0', '-3', '1.5', 'abc', '5000', ' ', '1e2']) assert.strictEqual(p.rates({ ASIX_BROKER_AGENTS_PER_CPU: bad }).per_cpu, 12, bad);
    assert.strictEqual(p.recommendedLimit(4, 8192, { ASIX_BROKER_AGENTS_PER_CPU: '20', ASIX_BROKER_AGENTS_PER_GB: '10' }), 80);
  });
});

describe('what the heartbeat may say', () => {
  it('parseHost needs both numbers, in range', () => {
    assert.deepStrictEqual(p.parseHost({ cpus: 4, mem_mb: 7800 }), { cpus: 4, mem_mb: 7800 });
    assert.deepStrictEqual(p.parseHost({ cpus: '8', mem_mb: '15900' }), { cpus: 8, mem_mb: 15900 }, 'digit strings are accepted');
    for (const bad of [null, undefined, 5, 'x', [], {}, { cpus: 4 }, { mem_mb: 8000 }, { cpus: 0, mem_mb: 8000 }, { cpus: 5000, mem_mb: 8000 }, { cpus: 4, mem_mb: 100 }, { cpus: 4, mem_mb: 99999999 }, { cpus: 4.5, mem_mb: 8000 }, { cpus: -1, mem_mb: 8000 }, { cpus: '4x', mem_mb: 8000 }, { cpus: true, mem_mb: 8000 }]) {
      assert.strictEqual(p.parseHost(bad), null, JSON.stringify(bad));
    }
  });
  it('parseAgents takes a whole number from 0 up, and a count of 0 is a real answer', () => {
    assert.strictEqual(p.parseAgents(0), 0); assert.strictEqual(p.parseAgents(42), 42); assert.strictEqual(p.parseAgents('17'), 17);
    for (const bad of [null, undefined, -1, 1.5, '1.5', 'x', '', {}, [], 1000001, true, '1e3']) assert.strictEqual(p.parseAgents(bad), null, String(bad));
  });
});

describe('what an operator may set', () => {
  it('group: a name, or empty to clear', () => {
    assert.deepStrictEqual(p.checkGroup('acme-site.1'), { value: 'acme-site.1' });
    assert.deepStrictEqual(p.checkGroup('  acme '), { value: 'acme' });
    for (const empty of [null, undefined, '']) assert.deepStrictEqual(p.checkGroup(empty), { value: null });
    for (const bad of ['-x', '.x', 'a b', 'a/b', "a'b", 'x'.repeat(41), 5, {}, [], '<b>']) assert.ok(p.checkGroup(bad).error, JSON.stringify(bad));
  });
  it('agent limit: 1 to 100000, or empty for the estimate', () => {
    assert.deepStrictEqual(p.checkLimit(60), { value: 60 }); assert.deepStrictEqual(p.checkLimit('60'), { value: 60 }); assert.deepStrictEqual(p.checkLimit(100000), { value: 100000 });
    for (const empty of [null, undefined, '']) assert.deepStrictEqual(p.checkLimit(empty), { value: null });
    for (const bad of [0, -1, 1.5, '1.5', 'x', 100001, {}, [], true, '1e3', '0']) assert.ok(p.checkLimit(bad).error, JSON.stringify(bad));
  });
});

describe('capacityOf', () => {
  const row = (o = {}) => ({ host_cpus: 4, host_mem_mb: 8192, agents_enrolled: 10, agent_limit: null, ...o });
  it('estimated limit, free slots, percent and state', () => {
    const c = p.capacityOf(row());
    assert.deepStrictEqual(c, { cpus: 4, mem_mb: 8192, enrolled: 10, recommended: 48, limit: 48, limit_source: 'estimated', free: 38, used_percent: 21, state: 'ok' });
  });
  it('the operator number wins over the estimate, and the estimate is still reported', () => {
    const c = p.capacityOf(row({ agent_limit: 30 })); assert.strictEqual(c.limit, 30); assert.strictEqual(c.limit_source, 'set'); assert.strictEqual(c.recommended, 48);
  });
  it('near at 80 percent, full at the limit and above it, ok just under 80', () => {
    assert.strictEqual(p.capacityOf(row({ agents_enrolled: 38 })).state, 'ok');   // 38/48 = 79%
    assert.strictEqual(p.capacityOf(row({ agents_enrolled: 39 })).state, 'near'); // 81%
    assert.strictEqual(p.capacityOf(row({ agents_enrolled: 47 })).state, 'near');
    assert.strictEqual(p.capacityOf(row({ agent_limit: 50, agents_enrolled: 40 })).state, 'near', 'exactly 80 percent is near');
    assert.strictEqual(p.capacityOf(row({ agent_limit: 50, agents_enrolled: 39 })).state, 'ok', '78 percent is not');
    assert.strictEqual(p.groupsOf([broker('g', { row: { agent_limit: 50, agents_enrolled: 40 } })])[0].state, 'near', 'a group is judged by the same line');
    assert.strictEqual(p.capacityOf(row({ agents_enrolled: 48 })).state, 'full');
    const over = p.capacityOf(row({ agents_enrolled: 60 })); assert.strictEqual(over.state, 'full'); assert.strictEqual(over.free, 0, 'free never goes negative');
  });
  it('unknown when the size and no limit, or the agent count, is missing', () => {
    const noSize = p.capacityOf({ agents_enrolled: 5 }); assert.strictEqual(noSize.state, 'unknown'); assert.strictEqual(noSize.limit, null); assert.strictEqual(noSize.limit_source, 'unknown');
    const noCount = p.capacityOf(row({ agents_enrolled: null })); assert.strictEqual(noCount.state, 'unknown'); assert.strictEqual(noCount.limit, 48); assert.strictEqual(noCount.free, null);
    assert.strictEqual(p.capacityOf({ agent_limit: 20, agents_enrolled: 20 }).state, 'full', 'a set limit works without a known size');
    assert.strictEqual(p.capacityOf({}).state, 'unknown');
  });
  it('database numbers that arrive as strings are numbers in the answer', () => {
    const c = p.capacityOf({ host_cpus: '4', host_mem_mb: '8192', agents_enrolled: '10', agent_limit: '30' }); assert.strictEqual(c.limit, 30); assert.strictEqual(c.enrolled, 10);
  });
});

// A broker as the placement code sees it.
const broker = (name, o = {}) => {
  const row = { host_cpus: 4, host_mem_mb: 8192, agents_enrolled: 0, agent_limit: null, ...(o.row || {}) };
  return { id: o.id || name + '-id', name, status: o.status || 'connected', group: o.group === undefined ? 'acme' : o.group, last_ip: o.last_ip || '10.0.0.5', inputs: o.inputs === undefined ? listInputs('syslog:514,wazuh,wazuhalerts') : o.inputs, capacity: p.capacityOf(row) };
};

describe('who gets the next machine', () => {
  it('the broker that is least full FOR ITS SIZE, so a bigger VM takes more machines', () => {
    const small = broker('small', { row: { host_cpus: 2, host_mem_mb: 4096, agents_enrolled: 10 } });   // limit 24, 42%
    const big = broker('big', { row: { host_cpus: 8, host_mem_mb: 16384, agents_enrolled: 30 } });      // limit 96, 31%
    assert.strictEqual(p.pickNext([small, big]).name, 'big', 'the plain count would have said small');
    const big2 = broker('big', { row: { host_cpus: 8, host_mem_mb: 16384, agents_enrolled: 60 } });     // 62%
    assert.strictEqual(p.pickNext([small, big2]).name, 'small');
  });
  it('a tie goes to the most free slots, then to the name, so the answer does not flip', () => {
    const a = broker('a', { row: { agent_limit: 10, agents_enrolled: 5 } }), b = broker('b', { row: { agent_limit: 20, agents_enrolled: 10 } });
    assert.strictEqual(p.pickNext([a, b]).name, 'b', 'same 50 percent, more free');
    const c = broker('c'), d = broker('d');
    assert.strictEqual(p.pickNext([d, c]).name, 'c'); assert.strictEqual(p.pickNext([c, d]).name, 'c');
  });
  it('skips what cannot take one, and says why', () => {
    const down = broker('down', { status: 'disconnected' });
    const full = broker('full', { row: { agents_enrolled: 48 } });
    const nomgr = broker('nomgr', { inputs: listInputs('syslog:514') });
    const old = broker('old', { inputs: null });
    const nosize = broker('nosize', { row: { host_cpus: null, host_mem_mb: null } });
    const nocount = broker('nocount', { row: { agents_enrolled: null } });
    const ok = broker('ok', { row: { agents_enrolled: 40 } });
    assert.strictEqual(p.whyNot(down), 'not connected'); assert.strictEqual(p.whyNot(full), 'full'); assert.strictEqual(p.whyNot(nomgr), 'no endpoint manager here');
    assert.match(p.whyNot(old), /older script/); assert.match(p.whyNot(nosize), /size is not known/); assert.match(p.whyNot(nocount), /how many agents/); assert.strictEqual(p.whyNot(ok), null);
    assert.strictEqual(p.pickNext([down, full, nomgr, old, nosize, nocount, ok]).name, 'ok');
    assert.strictEqual(p.pickNext([down, full, nomgr, old, nosize, nocount]), null);
    assert.strictEqual(p.pickNext([]), null);
  });
  it('a broker that reads only the manager alerts still runs a manager', () => {
    assert.strictEqual(p.runsManager(broker('x', { inputs: listInputs('syslog:514,wazuhalerts') })), true);
    assert.strictEqual(p.runsManager(broker('x', { inputs: listInputs('syslog:514,file') })), false);
  });
});

describe('groups', () => {
  it('totals, state, next broker and members, with a broker outside any group last', () => {
    const g = p.groupsOf([
      broker('a2', { row: { agents_enrolled: 30 } }), broker('a1', { row: { agents_enrolled: 10 } }), broker('lone', { group: null, row: { agents_enrolled: 1 } }), broker('z', { group: 'zeta', row: { agents_enrolled: 0 } }),
    ]);
    assert.deepStrictEqual(g.map((x) => x.name), ['acme', 'zeta', null]);
    const acme = g[0];
    assert.strictEqual(acme.brokers, 2); assert.strictEqual(acme.connected, 2); assert.strictEqual(acme.enrolled, 40); assert.strictEqual(acme.limit, 96); assert.strictEqual(acme.free, 56); assert.strictEqual(acme.used_percent, 42); assert.strictEqual(acme.state, 'ok');
    assert.strictEqual(acme.next.name, 'a1'); assert.strictEqual(acme.next.free, 38);
    assert.deepStrictEqual(acme.members.map((m) => [m.name, m.can_take_next]), [['a2', true], ['a1', true]]);
  });
  it('a total counts only brokers that know their limit and count, and says how many did not', () => {
    const g = p.groupsOf([broker('known', { row: { agents_enrolled: 10 } }), broker('blind', { row: { host_cpus: null, host_mem_mb: null } })])[0];
    assert.strictEqual(g.unknown_brokers, 1); assert.strictEqual(g.limit, 48); assert.strictEqual(g.enrolled, 10);
    const none = p.groupsOf([broker('blind', { row: { host_cpus: null, host_mem_mb: null } })])[0];
    assert.strictEqual(none.state, 'unknown'); assert.strictEqual(none.used_percent, null); assert.strictEqual(none.next, null);
  });
  it('a group with every broker full is full and has no next broker', () => {
    const g = p.groupsOf([broker('a', { row: { agents_enrolled: 48 } }), broker('b', { row: { agents_enrolled: 50 } })])[0];
    assert.strictEqual(g.state, 'full'); assert.strictEqual(g.next, null); assert.strictEqual(g.free, 0);
  });
  it('no brokers, no groups', () => assert.deepStrictEqual(p.groupsOf([]), []));
});

describe('plan: how many brokers a client needs', () => {
  it('rounds up and adds a spare', () => {
    assert.deepStrictEqual(p.plan(3000, 48), { endpoints: 3000, per_broker: 48, brokers_for_load: 63, spare: 1, brokers_total: 64 });
    assert.strictEqual(p.plan(48, 48).brokers_for_load, 1); assert.strictEqual(p.plan(49, 48).brokers_for_load, 2); assert.strictEqual(p.plan('100', 50).brokers_for_load, 2);
  });
  it('refuses a bad count or no known size', () => {
    for (const bad of [0, -5, 1.5, 'x', '', null, undefined, 1000001]) assert.ok(p.plan(bad, 48).error, String(bad));
    assert.ok(p.plan(100, null).error); assert.ok(p.plan(100, 0).error);
  });
  it('the typical limit is the median of the connected brokers that know theirs', () => {
    const l = (name, lim, o = {}) => broker(name, { ...o, row: { agent_limit: lim } });
    assert.strictEqual(p.typicalLimit([l('a', 10), l('b', 50), l('c', 20)]), 20);
    assert.strictEqual(p.typicalLimit([l('a', 10), l('b', 50)]), 30);
    assert.strictEqual(p.typicalLimit([l('a', 10), l('b', 999, { status: 'disconnected' })]), 10, 'a broker that is down does not size the plan');
    assert.strictEqual(p.typicalLimit([]), null); assert.strictEqual(p.typicalLimit([broker('x', { row: { host_cpus: null, host_mem_mb: null } })]), null);
  });
  it('the address is what the heartbeat came from, with an IPv4-mapped prefix removed', () => {
    assert.strictEqual(p.addressOf({ last_ip: '::ffff:192.168.68.54' }), '192.168.68.54'); assert.strictEqual(p.addressOf({ last_ip: '10.1.2.3' }), '10.1.2.3'); assert.strictEqual(p.addressOf(null), '');
  });
});

describe('the broker view carries capacity and group', () => {
  const row = (o = {}) => ({ id: 'i', name: 'broker-1', os: 'x', version: 'vector-0.59.0', last_ip: '10.0.0.5', first_seen: new Date(), last_seen: new Date(), events_total: '0', key_id: 'k', installer_name: 'n', key_status: 'active', ...o });
  it('capacity and group are on every broker, and a full broker is not a "problem"', () => {
    const b = view.shape(row({ host_cpus: 4, host_mem_mb: 8192, agents_enrolled: 48, broker_group: 'acme' }));
    assert.strictEqual(b.group, 'acme'); assert.strictEqual(b.capacity.state, 'full'); assert.deepStrictEqual(b.problems, []);
    const o = view.shape(row({})); assert.strictEqual(o.group, null); assert.strictEqual(o.capacity.state, 'unknown');
  });
  it('the summary counts agents and brokers near or at their limit', () => {
    const s = view.summarize([view.shape(row({ host_cpus: 4, host_mem_mb: 8192, agents_enrolled: 48 })), view.shape(row({ host_cpus: 4, host_mem_mb: 8192, agents_enrolled: 40 })), view.shape(row({ host_cpus: 4, host_mem_mb: 8192, agents_enrolled: 5 })), view.shape(row({}))]);
    assert.strictEqual(s.agents_enrolled, 93); assert.strictEqual(s.capacity_full, 1); assert.strictEqual(s.capacity_near, 1);
  });
  it('status, problems and every other field are the same with and without the new columns', () => {
    const a = view.shape(row({ host_cpus: 4, host_mem_mb: 8192, agents_enrolled: 10, broker_group: 'g' })), b = view.shape(row({}));
    assert.deepStrictEqual(a.problems, b.problems); assert.strictEqual(a.status, b.status); assert.deepStrictEqual(a.inputs_paused, b.inputs_paused);
  });
});

describe('deploy/broker/asix-broker-heartbeat.sh: the size and the agent count', () => {
  const SCRIPT = path.join(root, 'deploy', 'broker', 'asix-broker-heartbeat.sh');
  let tmp, bin, log, envFile;
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
  const BASE = 'ASIX_INGEST_URL=https://asix1:30443/v1/ingest/http\nASIX_INGEST_KEY=asix_ik_secretsecret\nASIX_BROKER_NAME=broker-1\n';
  const run = (extra = '', env = {}) => {
    fs.writeFileSync(envFile, BASE + extra); fs.writeFileSync(log, '');
    const r = spawnSync('bash', [SCRIPT], { encoding: 'utf8', stdin: 'ignore', env: { PATH: bin + ':' + process.env.PATH, HOME: tmp, ASIX_BROKER_ENV: envFile, ASIX_WAZUH_KEYS: path.join(tmp, 'no-such-file'), ...env } });
    const m = /--data (\{.*\})/.exec(fs.readFileSync(log, 'utf8'));
    return { status: r.status, body: m ? JSON.parse(m[1]) : null, stderr: r.stderr };
  };
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bplc-')); bin = path.join(tmp, 'bin'); log = path.join(tmp, 'calls.log'); envFile = path.join(tmp, 'broker.env'); fs.mkdirSync(bin);
    stub('vector', 'echo "vector 0.59.0 (x86_64-unknown-linux-gnu)"');
    stub('curl', `case "$*" in *health*) exit 0;; *) echo "$*" >> '${log}'; exit 0;; esac`);
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const keys = (lines) => { const f = path.join(tmp, 'client.keys'); fs.writeFileSync(f, lines); return { ASIX_WAZUH_KEYS: f }; };

  it('sends this machine\'s CPUs and memory, as whole numbers the server accepts', () => {
    const r = run(); assert.strictEqual(r.status, 0, r.stderr);
    const h = r.body.collector.host; assert.ok(h, 'host is sent');
    assert.strictEqual(h.cpus, os.cpus().length); assert.ok(Number.isInteger(h.mem_mb) && h.mem_mb >= 256);
    assert.deepStrictEqual(p.parseHost(h), h, 'the server-side check keeps it unchanged');
  });
  it('counts the enrolled agents (one line each in client.keys), ignoring blank and odd lines', () => {
    const r = run('', keys('001 pc-1 any aaaa\n002 pc-2 any bbbb\n\n   \n003 srv-3 10.0.0.9 cccc\n# comment\nnot a key line\n'));
    assert.strictEqual(r.body.collector.agents, 3);
    assert.strictEqual(p.parseAgents(r.body.collector.agents), 3);
  });
  it('an empty client.keys is zero agents (a real answer), a missing or unreadable file sends no count at all', () => {
    assert.strictEqual(run('', keys('')).body.collector.agents, 0);
    const none = run(); assert.ok(!('agents' in none.body.collector), 'a broker with no manager sends no count');
    const f = path.join(tmp, 'locked.keys'); fs.writeFileSync(f, '001 a any k\n'); fs.chmodSync(f, 0o000);
    if (process.getuid && process.getuid() !== 0) assert.ok(!('agents' in run('', { ASIX_WAZUH_KEYS: f }).body.collector), 'unreadable: no count');
  });
  it('the inputs, name and version are exactly what they were before', () => {
    const r = run('ASIX_SYSLOG_PORT=1514\n', keys('001 a any k\n')); assert.strictEqual(r.body.collector.inputs, 'syslog:1514'); assert.strictEqual(r.body.collector.version, 'vector-0.59.0'); assert.strictEqual(r.body.collector.name, 'broker-1');
  });
  it('still sends nothing when Vector is unhealthy', () => {
    stub('curl', `case "$*" in *health*) exit 7;; *) echo "$*" >> '${log}'; exit 0;; esac`);
    const r = run('', keys('001 a any k\n')); assert.notStrictEqual(r.status, 0); assert.strictEqual(r.body, null);
  });
});

describe('the heartbeat route stores them without changing anything else', () => {
  const src = read('src/ingest/heartbeat.js');
  it('the three values go in the insert and are kept when a heartbeat does not carry them (COALESCE)', () => {
    assert.match(src, /host_cpus, host_mem_mb, agents_enrolled\)/);
    assert.match(src, /host_cpus = COALESCE\(EXCLUDED\.host_cpus, collectors\.host_cpus\)/);
    assert.match(src, /host_mem_mb = COALESCE\(EXCLUDED\.host_mem_mb, collectors\.host_mem_mb\)/);
    assert.match(src, /agents_enrolled = COALESCE\(EXCLUDED\.agents_enrolled, collectors\.agents_enrolled\)/);
  });
  it('they are checked by the placement code before they reach the database', () => { assert.match(src, /parseHost\(req\.body && req\.body\.collector \? req\.body\.collector\.host : null\)/); assert.match(src, /parseAgents\(/); });
});

describe('schema, route mounting and the manifest', () => {
  it('the five columns exist, each with a check that matches the code', () => {
    const y = read('k8s/12-schema-init.yaml');
    for (const c of ['host_cpus', 'host_mem_mb', 'agents_enrolled', 'broker_group', 'agent_limit']) assert.match(y, new RegExp('ALTER TABLE collectors ADD COLUMN IF NOT EXISTS ' + c + ' '), c);
    assert.match(y, /host_cpus BETWEEN 1 AND 4096/); assert.match(y, /host_mem_mb BETWEEN 256 AND 16777216/); assert.match(y, /agent_limit BETWEEN 1 AND 100000/);
    assert.match(y, /broker_group ~ '\^\[A-Za-z0-9\]\[A-Za-z0-9\._-\]\{0,39\}\$'/);
  });
  it('the routes are mounted before the readiness route, and the route file puts nothing on the router object', () => {
    const idx = read('src/gateway/index.js');
    assert.ok(idx.indexOf("require('./routes/broker-placement')") > 0 && idx.indexOf("require('./routes/broker-placement')") < idx.indexOf('/v1/health/ready'));
    const f = read('src/gateway/routes/broker-placement.js');
    assert.ok(!/router\.(handle|stack|route)\s*=/.test(f), 'the E6f hang: nothing may overwrite a router method');
    assert.match(f, /module\.exports = router;/);
  });
  it('the broker list reads the new columns', () => assert.match(read('src/gateway/routes/brokers.js'), /c\.host_cpus, c\.host_mem_mb, c\.agents_enrolled, c\.broker_group, c\.agent_limit/));
  it('parser workers are on (2) with room for them: 768Mi and a CPU limit of 1000m', () => {
    const y = read('k8s/30-asix-api.yaml');
    assert.match(y, /- name: ASIX_PARSER_WORKERS\n\s+value: "2"/);
    assert.match(y, /limits:\n\s+cpu: "1000m"\n\s+memory: "768Mi"/);
    assert.match(y, /requests:\n\s+cpu: "250m"\n\s+memory: "384Mi"/);
    assert.match(y, /- name: ASIX_PARSER_TIMEOUT_MS\n\s+value: "5000"/);
  });
});

describe('Brokers page: capacity column, dialog and card', () => {
  const html = read('src/portal/index.html');
  const cut = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
  const line = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); return html.slice(i, html.indexOf('\n', i)); };
  const el = (tag, attrs, ...kids) => Object.assign({ tag, attrs: attrs || {}, kids: kids.flat(Infinity) }, attrs || {});
  const pill = (text, cls) => ({ pill: text, cls });
  const walk = (n, f) => { if (n && typeof n === 'object') { f(n); (n.kids || []).forEach((k) => walk(k, f)); } };
  const texts = (n) => { const out = []; walk(n, (x) => { if (x.pill) out.push(x.pill); if (typeof x.textContent === 'string' && x.textContent) out.push(x.textContent); }); return out; };
  const make = (io = {}) => new Function('el', 'pill', 'card', 'table', 'api', 'openModal', 'route',
    line('const BROKER_CAP_PILL') + '\n' + cut('function brokerCapacityText(') + cut('function brokerCapacityCell(') + cut('function brokerPlacementEdit(') + cut('function brokerPlacementCard(') + '\nreturn { brokerCapacityText, brokerCapacityCell, brokerPlacementEdit, brokerPlacementCard };')(
    el, pill, (title, ...kids) => el('card', { title }, ...kids), (cols, rows) => ({ cols, rows }), io.api || (async () => ({})), io.openModal || (() => ({ box: { append() {} }, close() {} })), io.route || (() => {}));
  const cap = (o) => p.capacityOf({ host_cpus: 4, host_mem_mb: 8192, agents_enrolled: 10, ...o });

  it('the cell: used and limit with a colour for the state, the group, and the size in the tooltip', () => {
    const { brokerCapacityCell } = make();
    const c = brokerCapacityCell({ capacity: cap({}), group: 'acme' });
    assert.deepStrictEqual(texts(c), ['10 / 48 (21%)', 'acme']); assert.match(c.attrs.title, /4 CPUs, 8\.0 GB/); assert.match(c.attrs.title, /estimated from its size/);
    assert.strictEqual(c.kids[0].cls, 'ok');
    assert.strictEqual(brokerCapacityCell({ capacity: cap({ agents_enrolled: 40 }) }).kids[0].cls, 'bad', 'near');
    assert.strictEqual(brokerCapacityCell({ capacity: cap({ agents_enrolled: 48 }) }).kids[0].cls, 'bad', 'full');
    assert.match(brokerCapacityCell({ capacity: cap({ agents_enrolled: 48 }) }).attrs.title, /Full/);
    assert.match(brokerCapacityCell({ capacity: cap({ agent_limit: 30 }) }).attrs.title, /set by you/);
  });
  it('a broker that said nothing shows a dash and says what to do; the cell never throws', () => {
    const { brokerCapacityCell, brokerCapacityText } = make();
    const c = brokerCapacityCell({ capacity: p.capacityOf({}) }); assert.strictEqual(c.attrs.textContent, '-'); assert.match(c.attrs.title, /heartbeat/);
    assert.doesNotThrow(() => brokerCapacityCell({})); assert.doesNotThrow(() => brokerCapacityCell(null));
    assert.strictEqual(brokerCapacityText(p.capacityOf({ agents_enrolled: 3 })), '3 enrolled'); assert.strictEqual(brokerCapacityText(p.capacityOf({ agent_limit: 9 })), 'limit 9');
  });
  it('a group name from the server is shown as text, never as markup', () => {
    const { brokerCapacityCell } = make(); const c = brokerCapacityCell({ capacity: cap({}), group: '<img src=x onerror=alert(1)>' });
    walk(c, (n) => { assert.ok(!('innerHTML' in (n.attrs || {})), 'no innerHTML'); }); assert.ok(texts(c).includes('<img src=x onerror=alert(1)>'));
  });
  it('the dialog saves the group and the limit, empty meaning clear, and shows the error when the server refuses', async () => {
    const calls = []; let fail = false; let routed = 0;
    const m = { box: { kids: [], append(...k) { this.kids.push(...k); } }, close() { m.closed = true; } };
    const { brokerPlacementEdit } = make({ api: async (u, o) => { calls.push([u, o]); if (fail) throw new Error('Agent limit: a whole number'); return {}; }, openModal: (...k) => { m.content = k; return m; }, route: () => { routed++; } });
    brokerPlacementEdit({ id: 'b1', name: 'broker-1', group: null, capacity: cap({}) });
    const find = (pred) => { let r = null; for (const k of m.content) walk(k, (n) => { if (!r && pred(n)) r = n; }); return r; };
    const [group, limit] = [find((n) => n.tag === 'input' && /acme/.test(n.attrs.placeholder)), find((n) => n.tag === 'input' && /estimate: 48/.test(n.attrs.placeholder))];
    assert.ok(group && limit, 'the two inputs are there, the limit showing the estimate');
    const save = m.box.kids.flat(Infinity).flatMap((k) => k.kids || []).find((n) => n.attrs && n.attrs.textContent === 'Save');
    group.value = '  acme-site '; limit.value = '';
    await save.onclick(); assert.deepStrictEqual(calls[0], ['/v1/brokers/b1/placement', { method: 'PUT', body: { group: 'acme-site', agent_limit: null } }]); assert.ok(m.closed); assert.strictEqual(routed, 1);
    group.value = ''; limit.value = ' 60 '; await save.onclick(); assert.deepStrictEqual(calls[1][1].body, { group: null, agent_limit: '60' });
    fail = true; m.closed = false; await save.onclick(); assert.ok(!m.closed, 'a refused save leaves the dialog open'); assert.ok(texts(m.content[m.content.length - 1]).includes('Agent limit: a whole number') || m.content.some((k) => texts(k).includes('Agent limit: a whole number')));
  });
  it('the card lists the groups with the next broker, and says why when none can take a machine', () => {
    const { brokerPlacementCard } = make();
    const a = broker('a1', { row: { agents_enrolled: 10 } }), full = broker('f1', { group: 'solo', row: { agents_enrolled: 48 } });
    const c = brokerPlacementCard({ brokers: [a, full], groups: p.groupsOf([a, full]) });
    const t = c.kids.find((k) => k && k.rows); const cell = (col, g) => { const v = t.cols.find((x) => x.h === col).f(g); return texts(typeof v === 'string' ? { textContent: v } : v).join(' '); };
    assert.strictEqual(cell('Group', t.rows[0]), 'acme'); assert.strictEqual(cell('Brokers', t.rows[0]), '1 of 1 connected'); assert.strictEqual(cell('Agents', t.rows[0]), '10 / 48 (21%)'); assert.strictEqual(cell('State', t.rows[0]), 'Room'); assert.strictEqual(cell('Next machine goes to', t.rows[0]), 'a1 (38 free)');
    assert.strictEqual(cell('State', t.rows[1]), 'Full'); assert.match(cell('Next machine goes to', t.rows[1]), /none: f1 full/);
    assert.strictEqual(make().brokerPlacementCard(null), ''); assert.strictEqual(make().brokerPlacementCard({ brokers: [], groups: [] }), '');
  });
  it('the planner asks the server and shows the answer or its error', async () => {
    const asked = []; const { brokerPlacementCard } = make({ api: async (u) => { asked.push(u); if (/endpoints=0/.test(u)) throw new Error('endpoints: a whole number from 1 to 1000000'); return { plan: { endpoints: 3000, per_broker: 48, brokers_for_load: 63, spare: 1, brokers_total: 64, brokers_now: 2, more_brokers: 62 } }; } });
    const a = broker('a1'); const c = brokerPlacementCard({ brokers: [a], groups: p.groupsOf([a]) });
    let input = null, btn = null, out = null; walk(c, (n) => { if (n.tag === 'input' && n.attrs.type === 'number') input = n; if (n.attrs && n.attrs.textContent === 'Calculate') btn = n; if (n.tag === 'div' && n.attrs.style === 'margin-top:8px') out = n; });
    input.value = '3000'; await btn.onclick(); assert.strictEqual(asked[0], '/v1/brokers/placement?endpoints=3000'); assert.match(out.textContent, /3,000 machines at about 48 per broker need 63 brokers plus 1 spare = 64\. You have 2, so add 62\./);
    input.value = '0'; await btn.onclick(); assert.match(out.textContent, /whole number/);
  });
  it('the Brokers table has the Agents column and a Capacity button, and the page still loads when the placement read fails', () => {
    assert.match(html, /\{ h: 'Agents', f: brokerCapacityCell \}/); assert.match(html, /textContent: 'Capacity'[^\n]*onclick: \(\) => brokerPlacementEdit\(b\)/);
    assert.match(html, /let place = null; try \{ place = await api\('\/v1\/brokers\/placement'\); \} catch \(e\) \{ place = null; \}/); assert.match(html, /brokerPlacementCard\(place\),/);
  });
});
