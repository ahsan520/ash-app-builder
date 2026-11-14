'use strict';
// SR3, src/engine/start.js: where ASIX may call, and the call itself, against a small local server that plays the engine. Loopback is only reachable here through the
// `loopback` argument that exists for this test; the environment cannot turn it on.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const http = require('http');
const start = require('../src/engine/start');

const URLS = (u) => String(u);
const msgOf = (fn) => { try { fn(); return null; } catch (e) { return e; } };

describe('engine start: where ASIX may call', () => {
  let saved;
  beforeEach(() => { saved = process.env.ASIX_ENGINE_ALLOW_PRIVATE; delete process.env.ASIX_ENGINE_ALLOW_PRIVATE; });
  afterEach(() => { if (saved === undefined) delete process.env.ASIX_ENGINE_ALLOW_PRIVATE; else process.env.ASIX_ENGINE_ALLOW_PRIVATE = saved; });

  it('https to a public name or address is fine', () => {
    assert.strictEqual(start.checkTarget('https://engine.example.test/api/webhooks/wf/abc').hostname, 'engine.example.test');
    assert.strictEqual(start.checkTarget('https://93.184.216.34/x').hostname, '93.184.216.34');
  });

  it('http is refused, private networks are refused, loopback and cloud metadata are refused, and credentials in the address are refused', () => {
    for (const u of ['http://engine.example.test/x', 'ftp://engine.example.test/x', 'not a url', 'https://u:p@engine.example.test/x']) assert.strictEqual(msgOf(() => start.checkTarget(u)).code, 'EBADURL', u);
    for (const u of ['https://10.1.2.3/x', 'https://192.168.68.58/x', 'https://172.16.0.9/x', 'https://127.0.0.1/x', 'https://localhost/x', 'https://169.254.169.254/latest', 'https://[::1]/x', 'https://0.0.0.0/x', 'https://[fd00::1]/x']) assert.strictEqual(msgOf(() => start.checkTarget(u)).code, 'EBLOCKED', u);
  });

  it('ASIX_ENGINE_ALLOW_PRIVATE=true lets a private engine in (https or http), but loopback and cloud metadata stay refused', () => {
    process.env.ASIX_ENGINE_ALLOW_PRIVATE = 'true';
    assert.strictEqual(start.checkTarget('https://192.168.68.58/x').hostname, '192.168.68.58'); assert.strictEqual(start.checkTarget('http://10.0.0.5:8080/x').port, '8080');
    for (const u of ['https://127.0.0.1/x', 'http://localhost/x', 'https://169.254.169.254/latest', 'https://[::1]/x']) assert.strictEqual(msgOf(() => start.checkTarget(u)).code, 'EBLOCKED', u);
    assert.strictEqual(msgOf(() => start.checkTarget('ftp://10.0.0.5/x')).code, 'EBADURL');
  });

  it('the notification switch does not open this door', () => {
    process.env.NOTIFY_ALLOW_PRIVATE_TARGETS = 'true';
    try { assert.strictEqual(msgOf(() => start.checkTarget('https://192.168.68.58/x')).code, 'EBLOCKED'); } finally { delete process.env.NOTIFY_ALLOW_PRIVATE_TARGETS; }
  });

  it('an error message never repeats the address (it carries a secret)', () => {
    for (const u of ['https://u:pw@engine.example.test/SECRET-PART', 'http://engine.example.test/SECRET-PART', 'https://10.9.9.9/SECRET-PART']) assert.ok(!msgOf(() => start.checkTarget(u)).message.includes('SECRET-PART'), u);
  });

  it('the connect-time lookup refuses a name that resolves to a blocked address (DNS rebinding)', async () => {
    const lookup = start.lookupFor(false);
    const err = await new Promise((res) => lookup('localhost', {}, (e) => res(e)));
    assert.ok(err && err.code === 'EBLOCKED');
    const ok = await new Promise((res) => start.lookupFor(true)('localhost', {}, (e, addr) => res(e ? { e } : { addr })));
    assert.ok(ok.addr, 'the test-only loopback argument lets localhost through');
  });
});

describe('engine start: the call', () => {
  let srv; let seen; let answer;
  beforeEach(async () => {
    seen = []; answer = { status: 200, body: JSON.stringify({ message: 'Workflow execution started', wf_exec_id: 'wf_1/exec_2' }) };
    srv = http.createServer((req, res) => { let t = ''; req.on('data', (c) => (t += c)); req.on('end', () => { seen.push({ method: req.method, url: req.url, type: req.headers['content-type'], body: t }); res.writeHead(answer.status, { 'Content-Type': 'application/json' }); res.end(answer.body); }); });
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  });
  afterEach(async () => { await new Promise((r) => srv.close(r)); });
  const url = (p) => `http://127.0.0.1:${srv.address().port}${p || '/api/webhooks/wf/SECRET-PART'}`;

  it('POSTs the JSON body to the webhook and reads the engine\'s reference', async () => {
    const r = await start.postHook(url(), { run_id: 'r1', token: 'aet_x' }, { loopback: true });
    assert.deepStrictEqual([r.ok, r.status, r.engineRef, r.error], [true, 200, 'wf_1/exec_2', null]);
    assert.deepStrictEqual([seen[0].method, seen[0].url, seen[0].type], ['POST', '/api/webhooks/wf/SECRET-PART', 'application/json']); assert.deepStrictEqual(JSON.parse(seen[0].body), { run_id: 'r1', token: 'aet_x' });
  });

  it('an answer that is not JSON is still a success (no reference), a non-2xx answer is a failure that says only the status, and an oversized answer is cut', async () => {
    answer = { status: 202, body: 'accepted' }; let r = await start.postHook(url(), {}, { loopback: true }); assert.deepStrictEqual([r.ok, r.engineRef], [true, null]);
    answer = { status: 500, body: JSON.stringify({ detail: 'SECRET-PART stack trace' }) }; r = await start.postHook(url(), {}, { loopback: true });
    assert.deepStrictEqual([r.ok, r.status, r.error], [false, 500, 'The engine answered HTTP 500']); assert.ok(!JSON.stringify(r).includes('SECRET'));
    answer = { status: 200, body: JSON.stringify({ wf_exec_id: 'x'.repeat(10000) }) }; r = await start.postHook(url(), {}, { loopback: true }); assert.strictEqual(r.engineRef, null, 'a cut answer is not parsed');
  });

  it('a refused address is not called at all, and nothing reaches the server', async () => {
    const r = await start.postHook(url(), {}); assert.strictEqual(r.ok, false); assert.match(r.error, /blocked network|must start with https/); assert.strictEqual(seen.length, 0);
  });

  it('a server that is not there is a failure with a short phrase, never the address', async () => {
    const dead = http.createServer(); await new Promise((r) => dead.listen(0, '127.0.0.1', r)); const p = dead.address().port; await new Promise((r) => dead.close(r));
    const r = await start.postHook(`http://127.0.0.1:${p}/SECRET-PART`, {}, { loopback: true });
    assert.strictEqual(r.ok, false); assert.match(r.error, /^The engine could not be reached \(ECONNREFUSED\)$/); assert.ok(!r.error.includes('SECRET'));
  });

  it('never throws or rejects, even for nonsense', async () => {
    for (const u of [undefined, null, '', 'x', 5, {}]) { const r = await start.postHook(u, {}); assert.strictEqual(r.ok, false); }
    assert.ok(URLS('ok'));
  });
});
