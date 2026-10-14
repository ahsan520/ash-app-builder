'use strict';
// Unit tests (no database, no Vector binary): heartbeat field handling and the broker config contract.
const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { describeBeat } = require('../src/ingest/heartbeat');
const { parseLine } = require('../src/ingest/http-ingest');

test('describeBeat: headers, body and fallbacks', () => {
  let d = describeBeat({ 'x-asix-collector': 'broker-1', 'x-asix-platform': 'Linux' }, undefined, 'key-name', 'generic');
  assert.deepStrictEqual(d, { name: 'broker-1', platform: 'linux', os: null, version: null });
  d = describeBeat({}, { collector: { name: 'b2', platform: 'macos', os: 'Vector broker VM (Ubuntu)', version: 'vector-0.49.0' } }, 'k', 'linux');
  assert.deepStrictEqual(d, { name: 'b2', platform: 'macos', os: 'Vector broker VM (Ubuntu)', version: 'vector-0.49.0' });
  d = describeBeat({}, {}, 'key-name', 'windows');           // falls back to the key's name and platform
  assert.strictEqual(d.name, 'key-name'); assert.strictEqual(d.platform, 'windows');
  d = describeBeat({ 'x-asix-platform': 'plan9' }, null, 'key-name', 'linux');
  assert.strictEqual(d.platform, 'linux');                    // unknown platform ignored
});

test('describeBeat: bad names and oversize values', () => {
  assert.ok(describeBeat({}, { collector: { name: 'bad name!' } }, 'k', null).error);
  assert.ok(describeBeat({}, {}, '', null).error);
  assert.ok(describeBeat({}, { collector: { name: 'x'.repeat(101) } }, 'k', null).error);
  const d = describeBeat({}, { collector: { name: 'ok', os: 'o'.repeat(500), version: 'v'.repeat(500) } }, 'k', null);
  assert.strictEqual(d.os.length, 100); assert.strictEqual(d.version.length, 50);
});

// The line Vector writes (deploy/broker/vector.yaml, checked by `vector test`) must parse in the HTTP lane.
test('Vector output line is parsed by the HTTP ingest lane', () => {
  const line = '2026-10-13T10:00:01+00:00 web01 sshd[2201]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2';
  const it = parseLine(line, 'broker-1');
  assert.strictEqual(it.parsed.format, 'syslog-file');
  assert.strictEqual(it.parsed.host, 'web01');
  assert.strictEqual(it.parsed.app_name, 'sshd');
  assert.strictEqual(it.parsed.proc_id, '2201');
  assert.strictEqual(it.time, '2026-10-13T10:00:01.000Z');
  const noPid = parseLine('2026-10-13T10:00:02+00:00 my_host my_app_x: line one line two', 'broker-1');
  assert.strictEqual(noPid.parsed.app_name, 'my_app_x'); assert.strictEqual(noPid.parsed.proc_id, null);
});

test('vector.yaml stays inside the ingest lane limits and sends the headers the lane reads', () => {
  const y = fs.readFileSync(path.join(__dirname, '..', 'deploy', 'broker', 'vector.yaml'), 'utf8');
  const maxEvents = Number(/max_events:\s*(\d+)/.exec(y)[1]);
  const maxBytes = Number(/max_bytes:\s*(\d+)/.exec(y)[1]);
  assert.ok(maxEvents <= 1000, 'ingest accepts at most 1000 events per request');
  assert.ok(maxBytes < 1024 * 1024, 'ingest accepts at most 1 MB per request');
  for (const h of ['Authorization: "Bearer ${ASIX_INGEST_KEY}"', 'X-ASIX-Collector:', 'X-ASIX-Source-Type: syslog', 'Content-Type: text/plain']) {
    assert.ok(y.includes(h), 'missing ' + h);
  }
  assert.ok(/framing:\s*\n\s*method:\s*newline_delimited/.test(y));
  assert.ok(/type:\s*disk/.test(y), 'the sink buffer must be on disk');
  assert.ok(!/verify_certificate:\s*false/.test(y), 'TLS verification must stay on');
});
