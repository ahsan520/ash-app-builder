'use strict';
// The HTTP ingest lane with parsing inline (default) or on the parser workers, end to end on a real Postgres.
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node --test tests/parse-ingest-db.test.js
//   ASIX_PARSER_WORKERS=2 ASIX_TEST_DB=1 ... node --test tests/parse-ingest-db.test.js     (same checks, on 2 workers)
// Skips itself without ASIX_TEST_DB, so `npm test` and CI's unit job are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const test = require('node:test');
const assert = require('assert');
const path = require('path');
const express = require('express');
const db = require('../src/db');
const { router: httpIngest, generateKey, hashKey } = require('../src/ingest/http-ingest');
const rulesStore = require('../src/ingestion/rules-store');
const { ParserPool, getParserPool, setParserPool, closeParserPool } = require('../src/ingestion/parser-pool');
const { parseItems } = require('../src/ingestion/parse-batch');
const { buildSets } = require('../src/ingestion/rule-sets');

const FAKE = path.join(__dirname, 'fixtures', 'fake-parser-worker.js');
const SSH = '2026-10-13T10:00:01+00:00 web01 sshd[2201]: Failed password for invalid user bob from 203.0.113.9 port 51234 ssh2';
const SUDO = '2026-10-13T10:00:02+00:00 web01 sudo[77]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow';
const PLAIN = 'something that no rule claims';

let T, key, srv, base;
const stamp = Date.now();
const send = async (body, headers = {}) => {
  const r = await fetch(base + '/v1/ingest/http', { method: 'POST', headers: { authorization: 'Bearer ' + key, 'content-type': 'text/plain', ...headers }, body });
  return { status: r.status, headers: r.headers, json: await r.json() };
};
const rows = async (src) => (await db.withTenant(T, (c) => c.query('SELECT * FROM events WHERE source_type = $1 ORDER BY raw', [src]))).rows;

test.before(async () => {
  T = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['parse-ingest-' + stamp])).rows[0].id;
  key = generateKey();
  await db.withTenant(T, (c) => c.query(
    "INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,'k1','linux',$2,$3)", [T, key.slice(0, 12), hashKey(key)]));
  const app = express(); app.use(httpIngest);
  srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
});

test.after(async () => {
  srv.close();
  await closeParserPool();
  await db.withTenant(T, (c) => c.query('DELETE FROM events')).catch(() => {});
  await db.withTenant(T, (c) => c.query('DELETE FROM parsing_rules')).catch(() => {});
  await db.withTenant(T, (c) => c.query('DELETE FROM data_model_rules')).catch(() => {});
  for (const t of ['audit_events', 'collectors', 'ingestion_keys']) await db.query(`DELETE FROM ${t} WHERE tenant_id = $1`, [T]).catch(() => {});
  await db.query('DELETE FROM tenants WHERE id = $1', [T]).catch(() => {});
  await db.close();
});

test(`built-in rules: stored events carry the parsed fields and xdm (mode: ${process.env.ASIX_PARSER_WORKERS ? process.env.ASIX_PARSER_WORKERS + ' workers' : 'inline'})`, async () => {
  // source type syslog (the default): the built-in data model rules are written for that dataset
  const r = await send([SSH, SUDO, PLAIN].join('\n'), { 'x-asix-collector': 'c-default' });
  assert.strictEqual(r.status, 202); assert.strictEqual(r.json.accepted, 3); assert.strictEqual(r.json.dropped, 0);
  const e = await rows('syslog');
  assert.strictEqual(e.length, 3);
  const ssh = e.find((x) => /Failed password/.test(x.raw));
  assert.strictEqual(ssh.parsed._content_id, 'linux_sshd'); assert.strictEqual(ssh.parsed.user, 'bob'); assert.strictEqual(ssh.parsed.src_ip, '203.0.113.9');
  assert.ok(ssh.parsed.xdm && ssh.parsed.xdm.event, 'data model pass ran');
  assert.strictEqual(e.find((x) => /COMMAND=/.test(x.raw)).parsed._content_id, 'linux_sudo');
  assert.strictEqual(e.find((x) => x.raw === PLAIN).parsed._content_id, undefined);
  assert.ok(e.every((x) => !x.parsed._parse_error));
  // Same as running the parse step directly: whichever path the lane took, the result is the same.
  const items = [SSH, SUDO, PLAIN].map((l) => { const m = l.match(/^(\S+)\s+(\S+)\s+([^\s:[\]]+)(?:\[(\d+)\])?:\s*(.*)$/); return m ? { raw: l, time: new Date(m[1]).toISOString(), parsed: { format: 'syslog-file', host: m[2], app_name: m[3], proc_id: m[4] || null, message: m[5], transport: 'http', remote_address: ssh.parsed.remote_address, collector_id: 'c-default' } } : { raw: l, time: null, parsed: { format: 'plain', host: 'c-default', message: l, transport: 'http', remote_address: ssh.parsed.remote_address, collector_id: 'c-default' } }; });
  const s = buildSets({}); const want = parseItems(s.parsingSets, s.modelSets, 'syslog', items).kept;
  for (const w of want) assert.deepStrictEqual(e.find((x) => x.raw === w.raw).parsed, w.parsed, w.raw);
});

test('the tenant\'s own parsing and model rules are applied, and a saved change takes effect at once', async () => {
  const rule = (tag) => `[INGEST:vendor="acme", product="app", target_dataset="pi_acme", source_type="pi-user", no_hit=keep, content_id="acme"]
filter app_name = "sshd" | alter tag = "${tag}";`;
  await rulesStore.saveUser(T, 'parsing', rule('one'), null);
  await rulesStore.saveUser(T, 'model', '[MODEL: dataset=pi_acme]\nalter xdm.event.description = tag;', null);
  let r = await send(SSH, { 'x-asix-source-type': 'pi-user', 'x-asix-collector': 'c-user' });
  assert.strictEqual(r.status, 202);
  let e = await rows('pi_acme');                       // the rule moved it to another dataset
  assert.strictEqual(e.length, 1); assert.strictEqual(e[0].parsed.tag, 'one'); assert.strictEqual(e[0].parsed.xdm.event.description, 'one');
  assert.strictEqual((await rows('pi-user')).length, 0);
  await rulesStore.saveUser(T, 'parsing', rule('two'), null);
  r = await send(SSH.replace('web01', 'web02'), { 'x-asix-source-type': 'pi-user', 'x-asix-collector': 'c-user' });
  assert.strictEqual(r.status, 202);
  e = await rows('pi_acme');
  assert.deepStrictEqual(e.map((x) => x.parsed.tag).sort(), ['one', 'two']);
});

test('a rule that drops events: they are counted in the answer and not stored', async () => {
  await rulesStore.saveUser(T, 'parsing', '[INGEST:content_id="noise", source_type="pi-drop", no_hit=drop] filter app_name = "chatty" | alter x = "1";', null);
  const r = await send('2026-10-13T10:00:03+00:00 h chatty[1]: hello\n2026-10-13T10:00:04+00:00 h other[1]: hi', { 'x-asix-source-type': 'pi-drop', 'x-asix-collector': 'c-drop' });
  assert.strictEqual(r.status, 202);
  assert.strictEqual(r.json.accepted + r.json.dropped, 2);
  assert.strictEqual((await rows('pi-drop')).length, r.json.accepted);
});

test('workers that time out or crash lose nothing: events are stored unparsed and marked (fake worker)', async () => {
  const log = console.error; console.error = () => {};
  const before = getParserPool();
  const pool = new ParserPool({ size: 1, workerPath: FAKE, timeoutMs: 300 });
  setParserPool(pool);
  try {
    for (const [raw, why] of [['hang', 'PARSE_TIMEOUT'], ['crash', 'PARSE_WORKER_CRASH']]) {
      const src = 'pi-' + why.toLowerCase();
      const r = await send(raw, { 'x-asix-source-type': src, 'x-asix-collector': 'c-bad' });
      assert.strictEqual(r.status, 202, why); assert.strictEqual(r.json.accepted, 1);
      const e = await rows(src);
      assert.strictEqual(e.length, 1); assert.strictEqual(e[0].parsed._parse_error, why); assert.strictEqual(e[0].raw, raw);
    }
    const ok = await send('fine', { 'x-asix-source-type': 'pi-after', 'x-asix-collector': 'c-bad' });   // the pool recovered
    assert.strictEqual(ok.status, 202); assert.strictEqual((await rows('pi-after'))[0].parsed._parse_error, undefined);
  } finally { console.error = log; setParserPool(before); await pool.close(); }
});

test('a full parser queue is a 503 with Retry-After, nothing is stored, and the collector bookkeeping is untouched (fake worker)', async () => {
  const log = console.error; console.error = () => {};
  const before = getParserPool();
  const pool = new ParserPool({ size: 1, workerPath: FAKE, timeoutMs: 500, maxQueue: 0 });
  setParserPool(pool);
  try {
    const first = send('hang', { 'x-asix-source-type': 'pi-busy1', 'x-asix-collector': 'c-busy' });   // holds the only worker
    await new Promise((r) => setTimeout(r, 100));
    const r = await send('fine', { 'x-asix-source-type': 'pi-busy2', 'x-asix-collector': 'c-busy' });
    assert.strictEqual(r.status, 503); assert.strictEqual(r.json.error.code, 'INGEST_BUSY'); assert.strictEqual(r.headers.get('retry-after'), '2');
    assert.strictEqual((await rows('pi-busy2')).length, 0);
    assert.strictEqual((await first).status, 202);
    const col = (await db.withTenant(T, (c) => c.query("SELECT events_total FROM collectors WHERE name = 'c-busy'"))).rows[0];
    assert.strictEqual(Number(col.events_total), 1, 'only the batch that was accepted is counted');
  } finally { console.error = log; setParserPool(before); await pool.close(); }
});
