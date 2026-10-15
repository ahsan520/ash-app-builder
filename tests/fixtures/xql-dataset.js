'use strict';
// The events every engine is tested against (tests/event-search-conformance.js). Times are minutes after T0;
// all received_at values are distinct so ordering is deterministic. buildDataset() gives every call new random
// ids (an event is identified by (id, received_at) across ALL tenants, so fixed ids would collide with rows a
// crashed earlier run left behind) and `n` numbers the events so tests can refer to them.
const T0 = Date.parse('2026-10-01T00:00:00.000Z');
const iso = (m) => new Date(T0 + m * 60000).toISOString();
const crypto = require('crypto');

const SPEC = [
  { n: 1, st: 'syslog', col: 'c1', raw: 'Failed password for invalid user admin from 203.0.113.9', parsed: { host: 'web01', app_name: 'sshd', bytes: 100, xdm: { source: { ipv4: '203.0.113.9' }, event: { outcome: 'FAILED' } } } },
  { n: 2, st: 'syslog', col: 'c1', raw: 'Accepted publickey for ash', parsed: { host: 'web01', app_name: 'sshd', bytes: '2500', xdm: { source: { ipv4: '10.0.0.5' }, event: { outcome: 'SUCCESS' } } } },
  { n: 3, st: 'syslog', col: 'c2', raw: 'sudo: bob : COMMAND=/bin/ls', parsed: { host: 'web02', app_name: 'sudo', bytes: 12.5 } },
  { n: 4, st: 'syslog', col: null, raw: 'no host here', parsed: {} },
  { n: 5, st: 'mac', col: 'c3', raw: 'XProtect FAILED scan', parsed: { host: 'mbp', app_name: 'xprotect', tags: ['a', 'b'], ok: true, bytes: 'abc' } },
  { n: 6, st: 'mac', col: 'c3', raw: 'UPPER and lower CaSe', parsed: { host: 'MBP', nested: { list: [{ k: 'v0' }, { k: 'v1' }] }, none: null, bytes: -3 } },
  { n: 7, st: 'router', col: 'c4', raw: 'dhcp 100%_done\\ back\\slash', parsed: { host: 'rtr', app_name: 'dnsmasq', bytes: 0 } },
  { n: 8, st: 'syslog', col: 'c1', raw: 'unicode \u00fcn\u00efc\u00f6d\u00e9 \u65e5\u672c\u8a9e', parsed: { host: 'web01', app_name: 'cron', bytes: 1000 } },
  { n: 9, st: 'syslog', col: 'c1', raw: 'no event time', et: null, parsed: { host: 'web03', app_name: 'cron', bytes: '7' } },
  { n: 10, st: 'syslog', col: 'c1', raw: 'dup host', parsed: { host: 'web01', app_name: 'sshd', bytes: 5 } },
];

function buildDataset() {
  const nOf = new Map();                      // event id -> n
  const events = SPEC.map((e) => {
    const id = crypto.randomUUID(); nOf.set(id, e.n);
    return { id, received_at: iso(e.n * 10), event_time: e.et === null ? null : iso(e.n * 10 - 3), source_type: e.st, collector_id: e.col, raw: e.raw, parsed: e.parsed };
  });
  const other = { id: crypto.randomUUID(), received_at: iso(55), event_time: iso(52), source_type: 'syslog', collector_id: 'cx', raw: 'other tenant web01', parsed: { host: 'web01', app_name: 'sshd', bytes: 1 } };
  nOf.set(other.id, 99);
  return { events, other, nOf };
}

module.exports = { buildDataset, T0, iso };
