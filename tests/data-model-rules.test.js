'use strict';
const assert = require('assert');
const { compile, apply, applyModel, RuleError } = require('../src/ingestion/parsing-rules');
const P = compile(require('../src/ingestion/default-parsing-rules'), 'ingest');
const M = compile(require('../src/ingestion/default-model-rules'), 'model');
const FILE_RE = /^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s:[\]]+)(?:\[(\d+)\])?:\s*(.*)$/;

// full pipeline: line -> parsing rules -> model rules
function run(line, userModel) {
  const m = line.match(FILE_RE);
  const parsed = { host: m[2], app_name: m[3], proc_id: m[4] || null, message: m[5], collector_id: 'web01-col' };
  const o = apply([P.rules], { source_type: 'syslog', raw: line, time: null, parsed });
  const sets = userModel ? [M.rules, compile(userModel, 'model').rules] : [M.rules];
  return applyModel(sets, { source_type: o.source_type, raw: line, time: o.time, parsed: o.parsed });
}

let r = run('Oct  1 10:00:01 web01 sshd[2201]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2');
assert.strictEqual(r.xdm.event.type, 'authentication');
assert.strictEqual(r.xdm.event.outcome, 'FAILED');
assert.strictEqual(r.xdm.target.user.username, 'admin');
assert.strictEqual(r.xdm.source.ipv4, '203.0.113.9');
assert.strictEqual(r.xdm.source.port, 51234);
assert.ok(!('ipv6' in r.xdm.source));
assert.strictEqual(r.xdm.source.process.pid, 2201);            // base pipeline + specific pipeline both applied
assert.strictEqual(r.xdm.observer.name, 'web01-col');
assert.strictEqual(r.xdm.target.host.hostname, 'web01');

r = run('Oct  1 10:00:09 web01 sshd[9]: Accepted publickey for deploy from 2001:db8::5 port 22 ssh2');
assert.strictEqual(r.xdm.event.outcome, 'SUCCESS'); assert.strictEqual(r.xdm.source.ipv6, '2001:db8::5'); assert.ok(!('ipv4' in r.xdm.source));

r = run('Oct  1 10:01:44 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow');
assert.deepStrictEqual([r.xdm.event.type, r.xdm.source.user.username, r.xdm.target.user.username, r.xdm.target.process.command_line], ['privilege_use', 'alice', 'root', '/bin/cat /etc/shadow']);

r = run('Oct  1 10:02:05 web01 kernel: eth0: link up');       // unmatched by parsing: still gets the base mapping
assert.strictEqual(r.xdm.event.description, 'eth0: link up'); assert.ok(!r.xdm.event.type);

// user mapping overrides defaults; temp variables, XDM_CONST, arraycreate, other datasets ignored
r = run('Oct  1 10:00:01 web01 sshd[1]: Failed password for bob from 1.2.3.4 port 5 ssh2',
  `[MODEL: dataset=syslog]
filter _content_id = "linux_sshd"
| alter _t = uppercase(user), xdm.target.user.username = _t, xdm.event.tags = arraycreate("ssh", "auth"), xdm.event.outcome = XDM_CONST.OUTCOME_UNKNOWN;
[MODEL: dataset=other] alter xdm.event.type = "nope";`);
assert.strictEqual(r.xdm.target.user.username, 'BOB'); assert.deepStrictEqual(r.xdm.event.tags, ['ssh', 'auth']); assert.strictEqual(r.xdm.event.outcome, 'UNKNOWN'); assert.strictEqual(r.xdm.event.type, 'authentication');

// validation
const bad = (src, re) => assert.throws(() => compile(src, 'model'), (e) => e instanceof RuleError && re.test(e.message) && e.line >= 1);
bad('[MODEL: dataset=syslog] alter xdm.source.ipv44 = host;', /Unknown XDM field/);
bad('[MODEL: dataset=syslog] alter user = host;', /only assign xdm/);
bad('[MODEL: dataset=syslog] alter xdm.event.outcome = XDM_CONST.NOPE;', /Unknown constant/);
bad('[MODEL: dataset=syslog] filter host = "a" | fields -x;', /not used/);
bad('[MODEL: x=1] alter xdm.event.type = "a";', /Unknown header option/);
bad('[MODEL: dataset=syslog] alter xdm.event.type = "a"', /;/);
console.log('data-model-rules: all tests passed');
