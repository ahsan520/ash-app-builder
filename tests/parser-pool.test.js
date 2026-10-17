'use strict';
// The parser worker pool (src/ingestion/parser-pool.js): real worker threads running the real parser, and a fake worker
// (tests/fixtures/fake-parser-worker.js) that hangs, crashes or runs out of memory on request. No database.
const test = require('node:test');
const assert = require('assert');
const path = require('path');
const { ParserPool } = require('../src/ingestion/parser-pool');
const { parseItems } = require('../src/ingestion/parse-batch');
const { buildSets } = require('../src/ingestion/rule-sets');

const FAKE = path.join(__dirname, 'fixtures', 'fake-parser-worker.js');
const ev = (app, message) => ({ raw: message, time: null, parsed: { format: 'syslog-file', host: 'h1', app_name: app, message } });
const SSH = 'Failed password for invalid user bob from 203.0.113.9 port 51234 ssh2';
const batch = (n) => Array.from({ length: n }, (_, i) => (i % 3 === 0 ? ev('sshd', SSH) : i % 3 === 1 ? ev('sudo', 'alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls') : ev('kernel', 'eth0: link up ' + i)));
const job = (items, extra = {}) => ({ scope: 't1', rulesKey: 'default', rules: { parsing: '', model: '' }, sourceType: 'syslog', items, ...extra });
const inline = (rules, items) => { const s = buildSets(rules); return parseItems(s.parsingSets, s.modelSets, 'syslog', structuredClone(items)); };
const code = (p) => p.then(() => 'resolved', (e) => e.code);
const quiet = () => { const l = console.error; console.error = () => {}; return () => { console.error = l; }; };

test('workers give exactly what parsing inline gives, also for many batches at once', async () => {
  const pool = new ParserPool({ size: 2 });
  try {
    const items = batch(60);
    const want = inline({ parsing: '', model: '' }, items);
    const got = await Promise.all(Array.from({ length: 12 }, () => pool.parse(job(structuredClone(items)))));
    for (const g of got) { assert.deepStrictEqual(g.kept, want.kept); assert.strictEqual(g.dropped, want.dropped); }
    assert.strictEqual(want.kept[0].parsed._content_id, 'linux_sshd');
    assert.strictEqual(pool.stats().completed, 12); assert.strictEqual(pool.stats().busy, 0);
  } finally { await pool.close(); }
});

test('a tenant\'s own rules reach the worker as text and are used; two rule sets alternate correctly', async () => {
  const userA = '[INGEST:content_id="acme", target_dataset="acme_raw", source_type="syslog", no_hit=keep] filter app_name = "kernel" | alter tag = "A";';
  const userB = '[INGEST:content_id="acme", target_dataset="acme_raw", source_type="syslog", no_hit=keep] filter app_name = "kernel" | alter tag = "B";';
  const items = batch(6);
  const pool = new ParserPool({ size: 1 });
  try {
    for (const [key, src] of [['a', userA], ['b', userB], ['a', userA], ['default', '']]) {
      const rules = { parsing: src, model: '' };
      const got = await pool.parse(job(structuredClone(items), { rulesKey: key, rules }));
      assert.deepStrictEqual(got.kept, inline(rules, items).kept, 'rules ' + key);
    }
    assert.strictEqual((await pool.parse(job(structuredClone(items), { rulesKey: 'a', rules: { parsing: userA, model: '' } }))).kept.find((k) => k.source_type === 'acme_raw').parsed.tag, 'A');
  } finally { await pool.close(); }
});

test('a worker that forgot the rules (cache of one) asks again and the batch still succeeds', async () => {
  const userA = '[INGEST:content_id="x", source_type="syslog", no_hit=keep] filter app_name = "kernel" | alter tag = "A";';
  const userB = userA.replace('"A"', '"B"');
  const pool = new ParserPool({ size: 1, workerData: { maxCachedRulesets: 1 } });
  try {
    const items = batch(3);
    for (const [key, src] of [['a', userA], ['b', userB], ['a', userA], ['b', userB]]) {
      const rules = { parsing: src, model: '' };
      assert.deepStrictEqual((await pool.parse(job(structuredClone(items), { rulesKey: key, rules }))).kept, inline(rules, items).kept);
    }
    // The pool still believes the worker has 'a' after 'b' pushed it out: it sent no rules and the worker said so.
    assert.ok(pool.stats().rules_resent >= 1, 'need_rules handshake used: ' + JSON.stringify(pool.stats()));
  } finally { await pool.close(); }
});

test('a batch that never finishes is cut off at the time limit, the worker is replaced, the next batch works', async () => {
  const restore = quiet();
  const pool = new ParserPool({ size: 1, workerPath: FAKE, timeoutMs: 300 });
  try {
    const t0 = Date.now();
    assert.strictEqual(await code(pool.parse(job([ev('x', 'hang')]))), 'PARSE_TIMEOUT');
    assert.ok(Date.now() - t0 < 3000);
    const ok = await pool.parse(job([ev('x', 'fine')]));
    assert.strictEqual(ok.kept.length, 1);
    assert.strictEqual(pool.stats().timeouts, 1);
  } finally { restore(); await pool.close(); }
});

test('a worker that crashes fails its own batch only and is replaced', async () => {
  const restore = quiet();
  const pool = new ParserPool({ size: 2, workerPath: FAKE, timeoutMs: 2000 });
  try {
    const [crash, fine] = await Promise.all([code(pool.parse(job([ev('x', 'crash')]))), pool.parse(job([ev('x', 'fine')]))]);
    assert.strictEqual(crash, 'PARSE_WORKER_CRASH'); assert.strictEqual(fine.kept.length, 1);
    assert.strictEqual((await pool.parse(job([ev('x', 'fine')]))).kept.length, 1);
    assert.strictEqual(pool.stats().crashes, 1);
  } finally { restore(); await pool.close(); }
});

test('a worker that runs out of memory dies alone, at its cap, not the process', async () => {
  const restore = quiet();
  const pool = new ParserPool({ size: 1, workerPath: FAKE, timeoutMs: 20000, maxOldGenerationSizeMb: 64 });
  try {
    assert.strictEqual(await code(pool.parse(job([ev('x', 'oom')]))), 'PARSE_WORKER_CRASH');
    assert.strictEqual((await pool.parse(job([ev('x', 'fine')]))).kept.length, 1);
  } finally { restore(); await pool.close(); }
});

test('a full queue refuses new batches (PARSER_BUSY) and the queued ones still run', async () => {
  const restore = quiet();
  const pool = new ParserPool({ size: 1, workerPath: FAKE, timeoutMs: 400, maxQueue: 1 });
  try {
    const running = code(pool.parse(job([ev('x', 'hang')])));   // takes the only worker
    const queued = pool.parse(job([ev('x', 'fine')]));          // waits
    assert.strictEqual(await code(pool.parse(job([ev('x', 'fine')]))), 'PARSER_BUSY');
    assert.strictEqual(await running, 'PARSE_TIMEOUT');
    assert.strictEqual((await queued).kept.length, 1);
    assert.strictEqual(pool.stats().rejected, 1);
  } finally { restore(); await pool.close(); }
});

test('maxQueue 0 means never wait, not never run: an idle worker still takes the batch', async () => {
  const restore = quiet();
  const pool = new ParserPool({ size: 2, workerPath: FAKE, timeoutMs: 300, maxQueue: 0 });
  try {
    const a = code(pool.parse(job([ev('x', 'hang')])));
    const b = code(pool.parse(job([ev('x', 'hang')])));
    assert.strictEqual(await code(pool.parse(job([ev('x', 'fine')]))), 'PARSER_BUSY');   // both busy, nobody may wait
    assert.deepStrictEqual([await a, await b], ['PARSE_TIMEOUT', 'PARSE_TIMEOUT']);
    assert.strictEqual((await pool.parse(job([ev('x', 'fine')]))).kept.length, 1);
  } finally { restore(); await pool.close(); }
});

test('after repeated timeouts a tenant is skipped for a while; other tenants and a later success are unaffected', async () => {
  const restore = quiet();
  const pool = new ParserPool({ size: 1, workerPath: FAKE, timeoutMs: 150, quarantineAfter: 3, quarantineMs: 400 });
  try {
    for (let i = 0; i < 3; i++) assert.strictEqual(await code(pool.parse(job([ev('x', 'hang')]))), 'PARSE_TIMEOUT');
    const t0 = Date.now();
    assert.strictEqual(await code(pool.parse(job([ev('x', 'fine')]))), 'PARSE_QUARANTINED');   // answered at once, no waiting
    assert.ok(Date.now() - t0 < 100);
    assert.strictEqual((await pool.parse(job([ev('x', 'fine')], { scope: 't2' }))).kept.length, 1);  // another tenant
    await new Promise((r) => setTimeout(r, 450));
    assert.strictEqual((await pool.parse(job([ev('x', 'fine')]))).kept.length, 1);              // quarantine over
    assert.strictEqual(pool.stats().quarantined, 1);
  } finally { restore(); await pool.close(); }
});

test('a success in between resets the count of timeouts in a row', async () => {
  const restore = quiet();
  const pool = new ParserPool({ size: 1, workerPath: FAKE, timeoutMs: 150, quarantineAfter: 3, quarantineMs: 5000 });
  try {
    for (let i = 0; i < 2; i++) await code(pool.parse(job([ev('x', 'hang')])));
    await pool.parse(job([ev('x', 'fine')]));
    for (let i = 0; i < 2; i++) assert.strictEqual(await code(pool.parse(job([ev('x', 'hang')]))), 'PARSE_TIMEOUT');
    assert.strictEqual((await pool.parse(job([ev('x', 'fine')]))).kept.length, 1);
  } finally { restore(); await pool.close(); }
});

test('close() rejects batches still waiting, stops the workers, and refuses new ones', async () => {
  const restore = quiet();
  const pool = new ParserPool({ size: 1, workerPath: FAKE, timeoutMs: 5000 });
  const running = code(pool.parse(job([ev('x', 'hang')])));
  const queued = code(pool.parse(job([ev('x', 'fine')])));
  await pool.close();
  assert.strictEqual(await running, 'PARSER_CLOSED'); assert.strictEqual(await queued, 'PARSER_CLOSED');
  assert.strictEqual(await code(pool.parse(job([ev('x', 'fine')]))), 'PARSER_CLOSED');
  restore();
});
