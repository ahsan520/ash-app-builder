'use strict';
const assert = require('assert');
const { compile, apply, RuleError } = require('../src/ingestion/parsing-rules');
const DEFAULTS = require('../src/ingestion/default-parsing-rules');

const defaults = compile(DEFAULTS);
const run = (sets, app, message, st = 'syslog') => apply(sets, { source_type: st, raw: message, time: null, parsed: { app_name: app, message, host: 'h1' } });

// sshd
let r = run([defaults.rules], 'sshd', 'Failed password for invalid user bob from 203.0.113.9 port 51234 ssh2');
assert.strictEqual(r.matched.content_id, 'linux_sshd');
assert.deepStrictEqual([r.parsed.user, r.parsed.src_ip, r.parsed.src_port, r.parsed.event_outcome, r.parsed.auth_method], ['bob', '203.0.113.9', 51234, 'failure', 'password']);
r = run([defaults.rules], 'sshd', 'Accepted publickey for root from 10.0.0.5 port 22 ssh2: RSA SHA256:abc');
assert.deepStrictEqual([r.parsed.user, r.parsed.event_outcome, r.parsed.auth_method], ['root', 'success', 'publickey']);

// sudo (two pipelines in one rule)
r = run([defaults.rules], 'sudo', 'alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow');
assert.deepStrictEqual([r.parsed.user, r.parsed.run_as, r.parsed.command, r.parsed.event_outcome], ['alice', 'root', '/bin/cat /etc/shadow', 'success']);
r = run([defaults.rules], 'sudo', 'alice : 3 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=/bin/ls');
assert.strictEqual(r.parsed.event_outcome, 'failure');

// accounts + cron
assert.strictEqual(run([defaults.rules], 'useradd', "new user: name=eve, UID=1002").parsed.target_user, 'eve');
r = run([defaults.rules], 'CRON', '(root) CMD (/usr/local/bin/backup.sh)');
assert.deepStrictEqual([r.parsed.user, r.parsed.command], ['root', '/usr/local/bin/backup.sh']);

// no match leaves the event untouched and kept
r = run([defaults.rules], 'kernel', 'eth0: link up');
assert.strictEqual(r.matched, null); assert.strictEqual(r.dropped, false); assert.strictEqual(r.parsed.message, 'eth0: link up');

// user rules win over defaults; target_dataset, time, fields -pattern, no_hit=drop
const user = compile(`[INGEST:vendor="acme", product="app", target_dataset="acme_raw", source_type="syslog", no_hit=keep, content_id="acme"]
filter app_name = "sshd"
| alter tmp_x = "1", _time = parse_timestamp("%FT%H:%M:%E*SZ", "2024-09-24T16:41:59.698Z"), tag = concat("a-", uppercase(host))
| fields -tmp_*;`);
r = run([user.rules, defaults.rules], 'sshd', 'Failed password for x from 1.2.3.4 port 1 ssh2');
assert.strictEqual(r.matched.content_id, 'acme'); assert.strictEqual(r.source_type, 'acme_raw');
assert.strictEqual(r.time, '2024-09-24T16:41:59.698Z'); assert.strictEqual(r.parsed.tag, 'a-H1'); assert.ok(!('tmp_x' in r.parsed));
const drop = compile(`[INGEST:content_id="noise", source_type="syslog", no_hit=drop] filter app_name = "chatty" | alter x = "1";`);
assert.strictEqual(run([drop.rules], 'other', 'hi').dropped, true);
assert.strictEqual(run([drop.rules], 'chatty', 'hi').dropped, false);

// errors carry a position; read-only and ReDoS-prone input is rejected
const bad = (src, re) => assert.throws(() => compile(src), (e) => e instanceof RuleError && re.test(e.message) && e.line >= 1);
bad('[INGEST:content_id="a"] filter x = ;', /Unexpected/);
bad('[INGEST:content_id="a"] alter _raw = "x";', /read-only/);
bad('[INGEST:content_id="a"] filter x ~= "(a+)+$";', /nested quantifier/);
bad('[INGEST:content_id="a"] filter nope(1) = 2;', /Unknown function/);
bad('[INGEST:vendor="a"] filter x = "1";', /content_id/);
bad('[INGEST:content_id="a"] filter x = "1"', /;/);
console.log('parsing-rules: all tests passed');
