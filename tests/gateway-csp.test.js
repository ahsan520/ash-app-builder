'use strict';
// S3 of docs/product-plan.md: the portal's headers, the /app/* headers, and what is served from /portal/modules (docs/portal-shell.md).
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const { PORTAL_CSP, APP_CSP, portalHeaders, appHeaders, moduleFiles, MODULE_FILE } = require('../src/gateway/portal-headers');

function request(port, p, method = 'GET') {
  return new Promise((resolve, reject) => {
    const q = http.request({ port, path: p, method, timeout: 3000 }, (r) => {
      let body = ''; r.setEncoding('utf8'); r.on('data', (c) => { body += c; });
      r.on('end', () => resolve({ status: r.statusCode, headers: r.headers, body }));
    });
    q.on('timeout', () => { q.destroy(); reject(new Error('timeout on ' + p)); });
    q.on('error', reject);
    q.end();
  });
}

const directive = (csp, name) => (csp.split(';').map((x) => x.trim()).find((x) => x.startsWith(name + ' ')) || '');

describe('policies as written', () => {
  it('the portal may frame only its own origin and nobody may frame the portal', () => {
    assert.strictEqual(directive(PORTAL_CSP, 'frame-src'), "frame-src 'self'");
    assert.strictEqual(directive(PORTAL_CSP, 'frame-ancestors'), "frame-ancestors 'none'");
  });
  it('the portal still loads scripts only from itself (module pages are same-origin files)', () => {
    assert.strictEqual(directive(PORTAL_CSP, 'script-src'), "script-src 'self' 'unsafe-inline'");
    assert.strictEqual(directive(PORTAL_CSP, 'default-src'), "default-src 'self'");
    assert.ok(!/\*/.test(PORTAL_CSP), 'no wildcard sources');
  });
  it('/app/* may be framed by the portal only, and sets nothing else that would break a tool', () => {
    assert.strictEqual(APP_CSP, "frame-ancestors 'self'");
    assert.ok(!/default-src|script-src|style-src/.test(APP_CSP));
  });
});

describe('the real gateway', () => {
  let server; let port;
  before(() => { server = require('../src/gateway').listen(0); port = server.address().port; });
  after(() => { server.close(); });

  it('/portal/ is the shell with the portal policy, nosniff and no caching', async () => {
    const r = await request(port, '/portal/');
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.headers['content-security-policy'], PORTAL_CSP);
    assert.strictEqual(r.headers['x-content-type-options'], 'nosniff');
    assert.strictEqual(r.headers['cache-control'], 'no-store');
    assert.match(r.body, /<html/i);
  });
  it('an unknown /app path is a 404 that nothing can frame (Express\'s own 404 sets a strict policy of its own)', async () => {
    const r = await request(port, '/app/no-such-tool/');
    assert.strictEqual(r.status, 404);
    assert.strictEqual(r.headers['content-security-policy'], "default-src 'none'");
    assert.notStrictEqual(r.headers['content-security-policy'], PORTAL_CSP);
  });
  it('appHeaders and portalHeaders are mounted on the real app, before any route that could answer /app or /portal', () => {
    const layers = (require('../src/gateway').router).stack;
    const at = (fn) => layers.findIndex((l) => l.handle === fn);
    const firstRoute = layers.findIndex((l) => l.route);
    assert.ok(at(portalHeaders) >= 0, 'portalHeaders is not mounted');
    assert.ok(at(appHeaders) >= 0, 'appHeaders is not mounted');
    assert.ok(firstRoute === -1 || at(appHeaders) < firstRoute, 'appHeaders must come before routes');
  });
  it('/portal answers never carry the /app framing policy', async () => {
    const r = await request(port, '/portal/modules/no-such/page.js');
    assert.strictEqual(r.status, 404);
    assert.strictEqual(r.headers['content-security-policy'], PORTAL_CSP);
    assert.ok(!('x-frame-options' in r.headers));
  });
  it('/portal/modules with nothing after it, and a folder, are 404, never a listing', async () => {
    assert.strictEqual((await request(port, '/portal/modules')).status, 404);
    assert.strictEqual((await request(port, '/portal/modules/')).status, 404);
    assert.strictEqual((await request(port, '/portal/modules/no-such/')).status, 404);
  });
  it('a request that is not GET or HEAD is refused with Allow', async () => {
    const r = await request(port, '/portal/modules/no-such/page.js', 'POST');
    assert.strictEqual(r.status, 405);
    assert.strictEqual(r.headers.allow, 'GET, HEAD');
  });
  it('data routes behind the Bearer token are untouched (still 401, headers unchanged)', async () => {
    const r = await request(port, '/v1/modules');
    assert.strictEqual(r.status, 401);
  });
});

describe('/app/* headers on a response a tool route would send (S4 mounts routes after appHeaders)', () => {
  let server; let port;
  before(() => {
    const app = express();
    app.use('/app', appHeaders);
    app.get('/app/demo/', (req, res) => res.status(200).send('<p>tool</p>'));
    server = app.listen(0); port = server.address().port;
  });
  after(() => { server.close(); });
  it('may be framed by the portal only, with nosniff and no caching, and without the portal policy', async () => {
    const r = await request(port, '/app/demo/');
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.headers['content-security-policy'], APP_CSP);
    assert.strictEqual(r.headers['x-frame-options'], 'SAMEORIGIN');
    assert.strictEqual(r.headers['x-content-type-options'], 'nosniff');
    assert.strictEqual(r.headers['cache-control'], 'no-store');
  });
});

describe('module page files (a temporary folder standing in for src/portal/modules)', () => {
  let tmp; let server; let port; let outside;
  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-modfiles-'));
    fs.mkdirSync(path.join(tmp, 'market'));
    fs.mkdirSync(path.join(tmp, 'market', 'deep'));
    fs.writeFileSync(path.join(tmp, 'market', 'marketplace.js'), 'export async function mount() {}\n');
    fs.writeFileSync(path.join(tmp, 'market', 'market.css'), '.mod-market{color:red}\n');
    fs.writeFileSync(path.join(tmp, 'market', 'marketplace.js.map'), '{}');
    fs.writeFileSync(path.join(tmp, 'market', 'README.md'), '# notes');
    fs.writeFileSync(path.join(tmp, 'market', 'page.html'), '<script>alert(1)</script>');
    fs.writeFileSync(path.join(tmp, 'market', '.secret.js'), 'x');
    fs.writeFileSync(path.join(tmp, 'market', 'deep', 'inner.js'), 'x');
    outside = path.join(path.dirname(tmp), 'asix-outside-' + path.basename(tmp) + '.js');
    fs.writeFileSync(outside, 'SECRET OUTSIDE');
    const app = express();
    app.use('/portal', portalHeaders);
    app.use('/portal/modules', moduleFiles(tmp));
    app.use('/portal', (req, res) => res.status(200).send('general portal static folder'));   // must never be reached for /portal/modules/*
    server = app.listen(0); port = server.address().port;
  });
  after(() => { server.close(); fs.rmSync(tmp, { recursive: true, force: true }); fs.rmSync(outside, { force: true }); });

  it('serves a page file as JavaScript with the portal headers', async () => {
    const r = await request(port, '/portal/modules/market/marketplace.js');
    assert.strictEqual(r.status, 200);
    assert.match(r.headers['content-type'], /^(text|application)\/javascript/);
    assert.strictEqual(r.headers['x-content-type-options'], 'nosniff');
    assert.strictEqual(r.headers['content-security-policy'], PORTAL_CSP);
    assert.match(r.body, /export async function mount/);
  });
  it('serves a module stylesheet as CSS', async () => {
    const r = await request(port, '/portal/modules/market/market.css');
    assert.strictEqual(r.status, 200);
    assert.match(r.headers['content-type'], /^text\/css/);
  });
  it('answers HEAD without a body', async () => {
    const r = await request(port, '/portal/modules/market/marketplace.js', 'HEAD');
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body, '');
  });
  it('refuses everything else in the folder: maps, notes, html, hidden files, nested files', async () => {
    for (const p of ['marketplace.js.map', 'README.md', 'page.html', '.secret.js', 'deep/inner.js', 'deep/', 'MARKETPLACE.JS']) {
      const r = await request(port, '/portal/modules/market/' + p);
      assert.strictEqual(r.status, 404, p + ' must not be served');
      assert.ok(!/general portal static/.test(r.body), p + ' must not fall through to the general portal folder');
    }
  });
  it('cannot climb out of the folder, however the dots and slashes are written', async () => {
    const name = path.basename(outside);
    for (const p of ['market/../../' + name, '..%2f' + name, 'market/%2e%2e/%2e%2e/' + name, 'market%2f..%2f..%2f' + name, '%2e%2e/' + name, 'market/..\\' + name]) {
      const r = await request(port, '/portal/modules/' + p);
      assert.notStrictEqual(r.status, 200, p + ' must not be served');
      assert.ok(!/SECRET OUTSIDE/.test(r.body), p + ' leaked a file outside the folder');
    }
  });
  it('a missing file with a well-formed name is a plain 404', async () => {
    const r = await request(port, '/portal/modules/market/nothing.js');
    assert.strictEqual(r.status, 404);
  });
});

describe('the file-name rule on its own', () => {
  it('accepts only /<module id>/<name>.js|css', () => {
    for (const ok of ['/market/marketplace.js', '/a1/b-2.css', '/market/x.js']) assert.ok(MODULE_FILE.test(ok), ok);
    for (const bad of ['/', '/market', '/market/', '/market/a/b.js', '/Market/a.js', '/market/A.js', '/market/.a.js', '/market/a.json', '/market/a.js.map', '/1x/a.js', '/market/a b.js', '/market/%2e%2e.js', '//x.js']) assert.ok(!MODULE_FILE.test(bad), bad);
  });
});
