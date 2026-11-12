'use strict';
// IOC feeds: the fetcher (src/feeds/fetcher.js) against real local servers. The safety rules (no internal addresses, checked at connect time, redirects
// re-checked, token not forwarded, size and time limits, no query string in errors) are the point.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('assert');
const http = require('http');
const dns = require('dns');
const fetcher = require('../src/feeds/fetcher');

let a; let b; let portA; let portB; const seen = [];
const SEC = { max: 0 };
before(async () => {
  a = http.createServer((req, res) => {
    seen.push({ server: 'a', url: req.url, auth: req.headers.authorization || null, ua: req.headers['user-agent'] });
    if (req.url.startsWith('/ok')) { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('1.2.3.4\n'); }
    if (req.url.startsWith('/redir-b')) { res.writeHead(302, { Location: `http://127.0.0.1:${portB}/landing` }); return res.end(); }
    if (req.url.startsWith('/redir-self')) { res.writeHead(302, { Location: '/ok-after' }); return res.end(); }
    if (req.url.startsWith('/loop')) { res.writeHead(302, { Location: '/loop' }); return res.end(); }
    if (req.url.startsWith('/to-meta')) { delete process.env.ASIX_FEED_ALLOW_PRIVATE; res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' }); return res.end(); }
    if (req.url.startsWith('/big')) { res.writeHead(200); return res.end('x'.repeat(2 * 1024 * 1024)); }
    if (req.url.startsWith('/big-stream')) { res.writeHead(200); const t = setInterval(() => res.write('x'.repeat(65536)), 1); res.on('close', () => clearInterval(t)); return; }
    if (req.url.startsWith('/slow')) return;   // never answers
    if (req.url.startsWith('/500')) { res.writeHead(500); return res.end('oops'); }
    res.writeHead(404); res.end();
  });
  b = http.createServer((req, res) => { seen.push({ server: 'b', url: req.url, auth: req.headers.authorization || null }); res.writeHead(200); res.end('9.9.9.9\n'); });
  await new Promise((r) => a.listen(0, '127.0.0.1', r)); await new Promise((r) => b.listen(0, '127.0.0.1', r));
  portA = a.address().port; portB = b.address().port;
});
after(() => { a.closeAllConnections(); b.closeAllConnections(); a.close(); b.close(); });
beforeEach(() => { seen.length = 0; delete process.env.ASIX_FEED_ALLOW_PRIVATE; });
const U = (p) => `http://127.0.0.1:${portA}${p}`;
const rejects = (p, code) => assert.rejects(p, (e) => { assert.strictEqual(e.code, code, e.message); return true; });

describe('addresses that are refused', () => {
  it('internal and reserved addresses, both families, including IPv4 written as IPv6', () => {
    for (const ip of ['127.0.0.1', '10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', '::', 'fe80::1', 'fd12::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a00:1', 'nonsense']) assert.ok(fetcher.isBlockedAddress(ip), ip);
    for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111', '172.32.0.1', '11.0.0.1']) assert.ok(!fetcher.isBlockedAddress(ip), ip);
  });
  it('a request to a loopback address is refused before anything is sent', async () => {
    await rejects(fetcher.fetchFeed(U('/ok')), 'BLOCKED_ADDRESS'); assert.strictEqual(seen.length, 0);
    await rejects(fetcher.fetchFeed('http://[::1]:1/'), 'BLOCKED_ADDRESS');
    await rejects(fetcher.fetchFeed('http://169.254.169.254/latest/meta-data/'), 'BLOCKED_ADDRESS');
  });
  it('a NAME that resolves to an internal address is refused, and so is a name with one bad answer among good ones', async () => {
    await rejects(fetcher.fetchFeed(`http://localhost:${portA}/ok`), 'BLOCKED_ADDRESS'); assert.strictEqual(seen.length, 0);
    const real = dns.lookup;
    dns.lookup = (host, opts, cb) => cb(null, [{ address: '93.184.216.34', family: 4 }, { address: '10.0.0.5', family: 4 }]);
    try { await rejects(fetcher.fetchFeed('http://feed.example.test/list.txt'), 'BLOCKED_ADDRESS'); } finally { dns.lookup = real; }
  });
  it('the connection goes to the address that was checked (no second lookup)', async () => {
    process.env.ASIX_FEED_ALLOW_PRIVATE = '1';
    const real = dns.lookup; let calls = 0;
    dns.lookup = (host, opts, cb) => { calls++; cb(null, [{ address: '127.0.0.1', family: 4 }]); };
    try { const r = await fetcher.fetchFeed(`http://feed.example.test:${portA}/ok`); assert.strictEqual(r.body, '1.2.3.4\n'); assert.strictEqual(calls, 1); } finally { dns.lookup = real; }
  });
  it('can be allowed for a feed server inside the network, on purpose', async () => {
    process.env.ASIX_FEED_ALLOW_PRIVATE = '1';
    const r = await fetcher.fetchFeed(U('/ok?apikey=SECRETKEY'), { token: 't0ken' });
    assert.deepStrictEqual([r.body, r.bytes], ['1.2.3.4\n', 8]);
    assert.strictEqual(seen[0].auth, 'Bearer t0ken'); assert.match(seen[0].ua, /^ASIX-feed-import/);
  });
});

describe('addresses that are not feeds', () => {
  it('only http and https, no user name or password, nothing malformed', async () => {
    for (const u of ['file:///etc/passwd', 'ftp://a.example/x', 'gopher://a.example/', 'javascript:alert(1)', 'http://user:pw@a.example/x', 'not a url', '']) await rejects(fetcher.fetchFeed(u), 'BAD_URL');
  });
});

describe('redirects', () => {
  beforeEach(() => { process.env.ASIX_FEED_ALLOW_PRIVATE = '1'; });
  it('are followed within the same host, and the token goes along', async () => {
    const r = await fetcher.fetchFeed(U('/redir-self'), { token: 'tok' });
    assert.strictEqual(r.body, '1.2.3.4\n');
    assert.deepStrictEqual(seen.map((x) => [x.url, x.auth]), [['/redir-self', 'Bearer tok'], ['/ok-after', 'Bearer tok']]);
  });
  it('the token is never sent to another host', async () => {
    const r = await fetcher.fetchFeed(U('/redir-b'), { token: 'tok-ORIGIN-ONLY' });
    assert.strictEqual(r.body, '9.9.9.9\n');
    assert.strictEqual(seen.find((s) => s.server === 'a').auth, 'Bearer tok-ORIGIN-ONLY'); assert.strictEqual(seen.find((s) => s.server === 'b').auth, null);
  });
  it('every redirect is checked again: a first hop that is allowed cannot lead to the metadata address', async () => {
    // the first hop is allowed (the switch is on); the server turns the switch off just before it redirects to 169.254.169.254, so the second hop is judged on its own
    await rejects(fetcher.fetchFeed(U('/to-meta')), 'BLOCKED_ADDRESS');
    assert.strictEqual(seen.length, 1, 'nothing was sent to the second address');
  });
  it('are limited in number', async () => { await rejects(fetcher.fetchFeed(U('/loop')), 'TOO_MANY_REDIRECTS'); });
});

describe('limits', () => {
  beforeEach(() => { process.env.ASIX_FEED_ALLOW_PRIVATE = '1'; });
  it('a declared size over the limit is refused without reading it', async () => { await rejects(fetcher.fetchFeed(U('/big'), { maxBytes: 1024 }), 'TOO_LARGE'); });
  it('an endless body is cut off at the limit', async () => { await rejects(fetcher.fetchFeed(U('/big-stream'), { maxBytes: 200000 }), 'TOO_LARGE'); });
  it('an answer that never comes is cut off', async () => { const t = Date.now(); await rejects(fetcher.fetchFeed(U('/slow'), { timeoutMs: 300 }), 'TIMEOUT'); assert.ok(Date.now() - t < 3000); });
  it('a status other than 200 is a failure', async () => { await rejects(fetcher.fetchFeed(U('/500')), 'HTTP_STATUS'); await rejects(fetcher.fetchFeed(U('/nothing')), 'HTTP_STATUS'); });
  it('a closed port is a plain refusal', async () => { await rejects(fetcher.fetchFeed('http://127.0.0.1:1/x'), 'CONNECTION_REFUSED'); });
});

describe('errors never carry the query string', () => {
  beforeEach(() => { process.env.ASIX_FEED_ALLOW_PRIVATE = '1'; });
  it('the key in the address stays out of every message', async () => {
    for (const p of ['/500?apikey=SECRETKEY', '/slow?apikey=SECRETKEY']) {
      await assert.rejects(fetcher.fetchFeed(U(p), { timeoutMs: 300 }), (e) => { assert.ok(!e.message.includes('SECRETKEY'), e.message); return true; });
    }
    await assert.rejects(fetcher.fetchFeed('http://127.0.0.1:1/x?apikey=SECRETKEY'), (e) => { assert.ok(!e.message.includes('SECRETKEY'), e.message); return true; });
    delete process.env.ASIX_FEED_ALLOW_PRIVATE;
    await assert.rejects(fetcher.fetchFeed(`http://localhost:${portA}/x?apikey=SECRETKEY`), (e) => { assert.ok(!e.message.includes('SECRETKEY'), e.message); return true; });
  });
});
