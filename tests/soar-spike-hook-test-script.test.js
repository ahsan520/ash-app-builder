'use strict';
// scripts/deploy/soar-spike-hook-test.sh (task SR0): curl and node are the real ones. The stand-in is the real one (deploy/soar-spike/stand-in.js). The ENGINE is played by a small fake
// webhook in this file: it answers a POST and then does what the probe workflow does (two calls to the stand-in), optionally after checking a key header. The script runs asynchronously
// (not spawnSync), because the fake webhook lives in this same process.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const http = require('http');
const path = require('path');
const { execFile } = require('child_process');
const { createStandIn } = require('../deploy/soar-spike/stand-in');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'deploy', 'soar-spike-hook-test.sh');

describe('soar-spike-hook-test.sh', () => {
  let stand, standBase, hook, hookBase, hookOpts;
  const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const run = (args, env = {}) => new Promise((resolve) => {
    execFile('bash', [SCRIPT, ...args], { env: { PATH: process.env.PATH, HOME: '/tmp', ...env }, timeout: 60000 }, (err, stdout, stderr) => resolve({ status: err ? (typeof err.code === 'number' ? err.code : 99) : 0, stdout, stderr }));
  });
  const post = (url, path_, body, headers = {}) => new Promise((resolve, reject) => {
    const d = body === undefined ? null : JSON.stringify(body);
    const req = http.request(url + path_, { method: 'POST', headers: { ...(d ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(d) } : {}), ...headers } }, (res) => { let t = ''; res.on('data', (c) => (t += c)); res.on('end', () => resolve({ status: res.statusCode, text: t })); });
    req.on('error', reject); if (d) req.write(d); req.end();
  });
  const basic = (k, s) => 'Basic ' + Buffer.from(k + ':' + s).toString('base64');
  const common = () => ['--stand-in', standBase, '--wait', '6'];

  beforeEach(async () => {
    stand = createStandIn(); await listen(stand.server); standBase = 'http://127.0.0.1:' + stand.server.address().port;
    hookOpts = { needKey: null, ping: true };
    hook = http.createServer((req, res) => {
      let t = ''; req.on('data', (c) => (t += c)); req.on('end', async () => {
        if (req.url !== '/api/hooks/wf-1/s3cr3t-value') { res.writeHead(404); return res.end('{"detail":"not found"}'); }
        if (hookOpts.needKey && req.headers['x-api-key'] !== hookOpts.needKey) { res.writeHead(401); return res.end('{"detail":"missing or wrong key"}'); }
        res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"wf_exec_id":"exec-1"}');
        if (!hookOpts.ping) return;
        let body = {}; try { body = t ? JSON.parse(t) : {}; } catch (_) { /* none */ }
        await post(standBase, '/asix/ping', { note: 'webhook-probe' });
        await post(standBase, '/asix/ping', { tenant: body.tenant || null, note: body.note || null });
      });
    });
    await listen(hook); hookBase = 'http://127.0.0.1:' + hook.address().port;
  });
  afterEach(async () => { await new Promise((r) => hook.close(r)); await new Promise((r) => stand.server.close(r)); });

  const URL_OK = () => hookBase + '/api/hooks/wf-1/s3cr3t-value';

  it('webhook: a run started and the JSON body reached it; the URL is printed with its secret part hidden', async () => {
    const r = await run(['webhook', '--url', URL_OK(), ...common()]);
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /HTTP status: 200/); assert.match(r.stdout, /run started: YES/); assert.match(r.stdout, /JSON body reached the run: YES/);
    assert.ok(!r.stdout.includes('s3cr3t-value') && !r.stderr.includes('s3cr3t-value'), 'the secret part of the URL must not be printed');
    assert.match(r.stdout, /calling http:\/\/127\.0\.0\.1:\d+\/api\/hooks\/wf-1\/<hidden>/);
  });

  it('webhook: reads the URL from SOAR_HOOK_URL, and --no-body sends a bare POST (what `curl -X POST <url>` does) so only "a run started" is judged', async () => {
    const r = await run(['webhook', '--no-body', ...common()], { SOAR_HOOK_URL: URL_OK() });
    assert.strictEqual(r.status, 0, r.stdout + r.stderr); assert.match(r.stdout, /run started: YES/); assert.match(r.stdout, /not tested \(--no-body\)/);
  });

  it('webhook: a webhook that wants a key answers 401, the script says it NEEDS A KEY and exits 1; with the key from --header-env it passes, and the key value is never printed', async () => {
    hookOpts.needKey = 'k-12345';
    let r = await run(['webhook', '--url', URL_OK(), ...common(), '--wait', '0']);
    assert.strictEqual(r.status, 1); assert.match(r.stdout, /HTTP status: 401/); assert.match(r.stdout, /run started: NO/); assert.match(r.stdout, /NEEDS A KEY/);
    r = await run(['webhook', '--url', URL_OK(), ...common(), '--header-env', 'HOOK_KEY'], { HOOK_KEY: 'X-API-Key: k-12345' });
    assert.strictEqual(r.status, 0, r.stdout + r.stderr); assert.match(r.stdout, /run started: YES/); assert.ok(!r.stdout.includes('k-12345'));
  });

  it('webhook: accepted but no run showed (the workflow failed or points elsewhere) is exit 1 and says to open the run in Tracecat; a wrong URL says not found', async () => {
    hookOpts.ping = false;
    let r = await run(['webhook', '--url', URL_OK(), ...common(), '--wait', '2']);
    assert.strictEqual(r.status, 1); assert.match(r.stdout, /run started: NO/); assert.match(r.stdout, /accepted the call but nothing arrived/);
    r = await run(['webhook', '--url', hookBase + '/api/hooks/other/xyz', ...common(), '--wait', '0']);
    assert.strictEqual(r.status, 1); assert.match(r.stdout, /HTTP status: 404/); assert.match(r.stdout, /Webhook switch/);
  });

  it('webhook: refuses bad input with exit 2 (no URL, a URL that is not http, a bad --wait, a header variable that is empty or not a header line, a stand-in that is not there)', async () => {
    assert.strictEqual((await run(['webhook', ...common()])).status, 2);
    assert.match((await run(['webhook', '--url', 'ftp://x/y', ...common()])).stderr, /must start with http/);
    assert.strictEqual((await run(['webhook', '--url', URL_OK(), '--wait', 'abc'])).status, 2);
    assert.match((await run(['webhook', '--url', URL_OK(), ...common(), '--header-env', 'NOPE'])).stderr, /empty/);
    assert.match((await run(['webhook', '--url', URL_OK(), ...common(), '--header-env', 'H'], { H: 'no colon here' })).stderr, /Name: value/);
    const dead = await run(['webhook', '--url', URL_OK(), '--stand-in', 'http://127.0.0.1:9', '--wait', '0']);
    assert.strictEqual(dead.status, 2); assert.match(dead.stderr, /does not answer/);
    assert.strictEqual((await run(['nonsense'])).status, 2); assert.strictEqual((await run([])).status, 2); assert.strictEqual((await run(['verdict', '--bogus'])).status, 2);
  });

  it('verdict: a WRONG secret in the second environment fails the credentials check and says a wrong credential reached the firewall; after reset the right one passes', async () => {
    const id = (await post(standBase, '/asix/approvals', { address: '203.0.113.10' })); const apId = JSON.parse(id.text).id;
    await post(standBase, `/asix/approvals/${apId}/grant`);
    await post(standBase, '/api/firewall/alias_util/add/asix_block', { address: '203.0.113.10' }, { Authorization: basic('spike-key', 'deliberately-wrong') });
    let r = await run(['verdict', '--stand-in', standBase]);
    assert.strictEqual(r.status, 1, r.stdout); assert.match(r.stdout, /verdict: FAIL/); assert.match(r.stdout, /credentials: no request reached the firewall with wrong credentials/);
    assert.match(r.stdout, /WRONG {2}x1/); assert.match(r.stdout, /a WRONG credential reached the firewall/); assert.ok(!r.stdout.includes('deliberately-wrong'));
    // the next run, pointed back at the right environment (the stand-in is cleared first, as the doc says)
    r = await run(['verdict', '--stand-in', standBase, '--reset']); assert.match(r.stdout, /stand-in cleared/);
    await post(standBase, '/_spike/reset'); await new Promise((res) => http.get(standBase + '/feed.txt', (x) => { x.resume(); x.on('end', res); }));
    const ap2 = JSON.parse((await post(standBase, '/asix/approvals', { address: '203.0.113.10' })).text).id; await post(standBase, `/asix/approvals/${ap2}/grant`);
    await post(standBase, '/api/firewall/alias_util/add/asix_block', { address: '203.0.113.10' }, { Authorization: basic('spike-key', 'spike-secret') });
    r = await run(['verdict', '--stand-in', standBase]);
    assert.strictEqual(r.status, 0, r.stdout); assert.match(r.stdout, /verdict: PASS/); assert.match(r.stdout, /RIGHT {2}x1/); assert.match(r.stdout, /only the right credentials reached the firewall/); assert.ok(!/WRONG/.test(r.stdout));
  });

  it('verdict --decide grants the approvals that are waiting (so a run need not sit), and reset clears the stand-in', async () => {
    const ap = JSON.parse((await post(standBase, '/asix/approvals', { address: '203.0.113.11' })).text).id;
    const r = await run(['verdict', '--stand-in', standBase, '--decide', '1']);
    assert.match(r.stdout, new RegExp('granted ' + ap)); assert.strictEqual(stand.report().approvals.find((a) => a.id === ap).status, 'granted');
    assert.match((await run(['reset', '--stand-in', standBase])).stdout, /stand-in cleared/); assert.deepStrictEqual(stand.report().approvals, []);
  });

  it('is a bash script with a usage block at the top and no `set -e` surprises', () => {
    const src = require('fs').readFileSync(SCRIPT, 'utf8'); assert.match(src, /^#!\/bin\/bash/); assert.match(src, /set -uo pipefail/); assert.ok(!/set -e\b/.test(src));
    assert.ok(!/echo .*\$URL[^_]/.test(src.replace(/mask_url "\$URL"/g, '')), 'the URL must only be echoed through mask_url');
  });
});
