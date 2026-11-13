'use strict';
// SOAR spike stand-in (deploy/soar-spike/stand-in.js, task SR0): a real HTTP server on a free port. What matters is the verdict: it must pass for a correct run of the
// scenario and fail, naming the reason, for each way an engine can get it wrong.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const http = require('http');
const { createStandIn } = require('../deploy/soar-spike/stand-in');

describe('SOAR spike stand-in', () => {
  let s, base;
  const basic = (k = 'spike-key', sec = 'spike-secret') => 'Basic ' + Buffer.from(k + ':' + sec).toString('base64');
  const call = (method, path, body, headers = {}) => new Promise((resolve, reject) => {
    const data = body === undefined ? null : (typeof body === 'string' ? body : JSON.stringify(body));
    const req = http.request(base + path, { method, headers: { ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}), ...headers } }, (res) => {
      let t = ''; res.on('data', (c) => (t += c)); res.on('end', () => { let j = null; try { j = JSON.parse(t); } catch (_) { /* text */ } resolve({ status: res.statusCode, text: t, json: j, type: res.headers['content-type'] }); });
    });
    req.on('error', reject); if (data) req.write(data); req.end();
  });
  const failed = async () => (await call('GET', '/_spike/report')).json.checks.filter((c) => !c.ok).map((c) => c.id);
  const ask = async (address) => (await call('POST', '/asix/approvals', { address })).json.id;
  const block = (address, h) => call('POST', '/api/firewall/alias_util/add/asix_block', { address }, { Authorization: basic(), ...h });

  beforeEach(async () => { s = createStandIn(); await new Promise((r) => s.server.listen(0, '127.0.0.1', r)); base = 'http://127.0.0.1:' + s.server.address().port; });
  afterEach(async () => { await new Promise((r) => s.server.close(r)); });

  it('serves the feed as plain text, including a private address a block list must never take', async () => {
    const r = await call('GET', '/feed.txt'); assert.strictEqual(r.status, 200); assert.match(r.type, /text\/plain/); assert.match(r.text, /203\.0\.113\.10/); assert.match(r.text, /10\.0\.0\.5/);
  });

  it('passes for the right order: fetch, ask, a person grants, block, and an unapproved address stays out', async () => {
    await call('GET', '/feed.txt');
    const id = await ask('203.0.113.10'); const other = await ask('203.0.113.11');
    assert.strictEqual((await call('GET', '/asix/approvals/' + id)).json.status, 'waiting');
    assert.strictEqual((await call('POST', `/asix/approvals/${id}/grant`)).json.status, 'granted');
    assert.strictEqual((await call('POST', `/asix/approvals/${other}/reject`)).json.status, 'rejected');
    assert.strictEqual((await block('203.0.113.10')).status, 200);
    const rep = (await call('GET', '/_spike/report')).json;
    assert.strictEqual(rep.verdict, 'pass', JSON.stringify(rep.checks.filter((c) => !c.ok)));
    assert.deepStrictEqual(rep.blocked, ['203.0.113.10']);
    const list = await call('GET', '/api/firewall/alias_util/list/asix_block', undefined, { Authorization: basic() });
    assert.deepStrictEqual(list.json.rows, [{ ip: '203.0.113.10' }]);
  });

  it('refuses a block with no granted approval, and the verdict names it (waiting, rejected and never asked are all unapproved)', async () => {
    await call('GET', '/feed.txt'); const w = await ask('203.0.113.10'); const rj = await ask('203.0.113.11'); await call('POST', `/asix/approvals/${rj}/reject`);
    for (const a of ['203.0.113.10', '203.0.113.11', '198.51.100.7']) { const r = await block(a); assert.strictEqual(r.status, 403); assert.strictEqual(r.json.status, 'refused'); }
    assert.ok(w);
    const bad = await failed(); assert.ok(bad.includes('no_unapproved')); assert.ok(bad.includes('blocked_one')); assert.strictEqual((await call('GET', '/_spike/report')).json.verdict, 'fail');
    assert.deepStrictEqual((await call('GET', '/_spike/report')).json.blocked, []);
  });

  it('fails an engine that never asked, never fetched, or sent a private address', async () => {
    assert.ok((await failed()).includes('fetched')); assert.ok((await failed()).includes('asked'));
    const id = await ask('10.0.0.5'); await call('POST', `/asix/approvals/${id}/grant`); await block('10.0.0.5');   // approved by mistake: the engine still must not send it
    assert.ok((await failed()).includes('no_private'));
  });

  it('wrong credentials: 401, nothing changes, and the verdict fails', async () => {
    const id = await ask('203.0.113.10'); await call('POST', `/asix/approvals/${id}/grant`);
    const r = await call('POST', '/api/firewall/alias_util/add/asix_block', { address: '203.0.113.10' }, { Authorization: basic('spike-key', 'wrong') });
    assert.strictEqual(r.status, 401); assert.strictEqual((await call('POST', '/api/firewall/alias_util/add/asix_block', { address: '203.0.113.10' })).status, 401);
    assert.deepStrictEqual((await call('GET', '/_spike/report')).json.blocked, []); assert.ok((await failed()).includes('credentials'));
  });

  it('every approval answer carries the address it is about, so a later step needs no lookup (as a real ASIX approval carries its action)', async () => {
    const created = await call('POST', '/asix/approvals', { address: '203.0.113.10' }); assert.strictEqual(created.json.address, '203.0.113.10');
    const id = created.json.id; assert.strictEqual((await call('GET', '/asix/approvals/' + id)).json.address, '203.0.113.10');
    const granted = await call('POST', `/asix/approvals/${id}/grant`); assert.deepStrictEqual(granted.json, { id, address: '203.0.113.10', status: 'granted' });
  });

  it('an approval can be decided once; unknown ones are 404', async () => {
    const id = await ask('203.0.113.10'); assert.strictEqual((await call('POST', `/asix/approvals/${id}/grant`)).status, 200);
    assert.strictEqual((await call('POST', `/asix/approvals/${id}/reject`)).status, 409); assert.strictEqual((await call('GET', '/asix/approvals/ap999')).status, 404);
    assert.strictEqual((await call('POST', '/asix/approvals/ap999/grant')).status, 404);
  });

  it('removes an address on del, and says not_found for one that was not there', async () => {
    const id = await ask('203.0.113.10'); await call('POST', `/asix/approvals/${id}/grant`); await block('203.0.113.10');
    const del = (a) => call('POST', '/api/firewall/alias_util/del/asix_block', { address: a }, { Authorization: basic() });
    assert.strictEqual((await del('203.0.113.10')).json.status, 'done'); assert.strictEqual((await del('203.0.113.10')).json.status, 'not_found');
    assert.deepStrictEqual((await call('GET', '/_spike/report')).json.blocked, []);
  });

  it('rejects what is not an IPv4 address, a bad body, an unknown alias, an oversized body, and reset clears everything', async () => {
    assert.strictEqual((await call('POST', '/asix/approvals', { address: '999.1.1.1' })).status, 400); assert.strictEqual((await call('POST', '/asix/approvals', { address: 'evil.com' })).status, 400);
    assert.strictEqual((await call('POST', '/asix/approvals', '{not json')).status, 400);
    assert.strictEqual((await block('1.2.3.4x')).status, 400);
    assert.strictEqual((await call('POST', '/api/firewall/alias_util/add/other', { address: '1.2.3.4' }, { Authorization: basic() })).status, 404);
    assert.strictEqual((await call('GET', '/nothing')).status, 404);
    await ask('203.0.113.10'); await call('POST', '/_spike/reset'); assert.deepStrictEqual((await call('GET', '/_spike/report')).json.approvals, []);
    const big = await call('POST', '/asix/approvals', JSON.stringify({ address: '1.2.3.4', pad: 'x'.repeat(40000) }), {}).catch(() => ({ status: 0 }));
    assert.ok([0, 400].includes(big.status), 'an oversized body must not be accepted (status ' + big.status + ')');
  });

  it('listens on loopback by default when run as a program', () => {
    const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'deploy', 'soar-spike', 'stand-in.js'), 'utf8');
    assert.match(src, /get\('host', '127\.0\.0\.1'\)/);
  });
});
