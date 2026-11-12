#!/usr/bin/env node
'use strict';
// SOAR engine spike (task SR0, docs/soar-spike.md): ONE small server that plays the three things the spike scenario talks to, so two engines can be
// compared on the same scenario without a real firewall, a real feed or the real ASIX approval gate:
//   1. an indicator feed          GET  /feed.txt
//   2. ASIX's approval gate       POST /asix/approvals, GET /asix/approvals/:id, POST /asix/approvals/:id/grant|reject   (the person's decision)
//   3. a firewall alias API       POST /api/firewall/alias_util/add|del/:alias, GET /api/firewall/alias_util/list/:alias   (basic auth)
// plus   GET /_spike/report (the verdict: did the engine do the scenario in the right order and nothing else)   and   POST /_spike/reset.
// The firewall paths follow OPNsense's alias_util API as we remember it (NOT checked against a real OPNsense): the answers are only as exact as that memory.
// No dependency. Listens on 127.0.0.1 unless --host says otherwise: it has no login of its own on /asix and /_spike, so never expose it beyond the lab.
//   node deploy/soar-spike/stand-in.js [--port 8099] [--host 127.0.0.1] [--key K --secret S] [--alias asix_block]
const http = require('http');
const crypto = require('crypto');

const DEFAULT_FEED = ['# stand-in feed (documentation addresses, RFC 5737)', '203.0.113.10', '203.0.113.11 ; seen scanning', '198.51.100.7', '10.0.0.5   # private: a block list must never take this', ''].join('\n');
const PRIVATE = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
const IPV4 = /^(\d{1,3})(\.\d{1,3}){3}$/;
const MAX_BODY = 16 * 1024;

function createStandIn(opts = {}) {
  const cfg = { feed: opts.feed || DEFAULT_FEED, key: opts.key || 'spike-key', secret: opts.secret || 'spike-secret', alias: opts.alias || 'asix_block' };
  let st;
  const reset = () => { st = { events: [], approvals: new Map(), blocked: new Set(), seq: 0 }; };
  reset();
  const log = (type, extra = {}) => { st.events.push({ n: st.events.length + 1, t: new Date().toISOString(), type, ...extra }); };

  const readJson = (req) => new Promise((resolve) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > MAX_BODY) { req.destroy(); resolve(null); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (_) { resolve(null); } });
    req.on('error', () => resolve(null));
  });
  const send = (res, code, body, type) => { const s = typeof body === 'string' ? body : JSON.stringify(body); res.writeHead(code, { 'Content-Type': type || 'application/json', 'Content-Length': Buffer.byteLength(s) }); res.end(s); };
  const ipOk = (a) => typeof a === 'string' && IPV4.test(a) && a.split('.').every((o) => Number(o) <= 255);
  const authOk = (req) => {
    const m = /^Basic (.+)$/.exec(req.headers.authorization || ''); if (!m) return false;
    const got = Buffer.from(Buffer.from(m[1], 'base64').toString('utf8')); const want = Buffer.from(cfg.key + ':' + cfg.secret);
    return got.length === want.length && crypto.timingSafeEqual(got, want);
  };
  const grantedFor = (address) => [...st.approvals.values()].some((a) => a.address === address && a.status === 'granted');

  // What the spike is judged on. Each check is one sentence a person can read; `ok` is a plain boolean.
  function report() {
    const ev = st.events; const first = (t, f) => ev.findIndex((e) => e.type === t && (!f || f(e)));
    const blocks = ev.filter((e) => e.type === 'block');
    const checks = [];
    const add = (id, text, ok) => checks.push({ id, text, ok: !!ok });
    add('fetched', 'the engine fetched the feed', first('feed_fetched') >= 0);
    const approvals = [...st.approvals.values()];
    add('asked', 'the engine asked for approval before blocking (at least one request)', approvals.length > 0);
    add('waited', 'every block came AFTER the approval for that address was granted', blocks.length > 0 && blocks.every((b) => {
      const g = first('approval_granted', (e) => e.address === b.address); return g >= 0 && g < ev.indexOf(b);
    }));
    add('no_unapproved', 'no block was tried without a granted approval', !ev.some((e) => e.type === 'block_refused_no_approval'));
    add('no_private', 'no private address was sent to the firewall', !ev.some((e) => (e.type === 'block' || e.type === 'block_refused_no_approval') && PRIVATE.test(e.address || '')));
    add('only_approved', 'the firewall alias holds only addresses that were approved', [...st.blocked].every(grantedFor));
    add('rejected_stays_out', 'an address whose approval was rejected is not in the alias', approvals.filter((a) => a.status === 'rejected').every((a) => !st.blocked.has(a.address)));
    add('credentials', 'no request reached the firewall with wrong credentials', !ev.some((e) => e.type === 'bad_credentials'));
    add('blocked_one', 'at least one address ended up blocked', st.blocked.size > 0);
    return { verdict: checks.every((c) => c.ok) ? 'pass' : 'fail', checks, blocked: [...st.blocked].sort(), approvals: approvals.map((a) => ({ id: a.id, address: a.address, status: a.status })), events: ev };
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x'); const p = url.pathname; const m = req.method;
    try {
      if (m === 'GET' && p === '/feed.txt') { log('feed_fetched'); return send(res, 200, cfg.feed, 'text/plain; charset=utf-8'); }
      if (m === 'GET' && p === '/_spike/report') return send(res, 200, report());
      if (m === 'POST' && p === '/_spike/reset') { reset(); return send(res, 200, { reset: true }); }

      if (m === 'POST' && p === '/asix/approvals') {
        const b = await readJson(req); if (!b || !ipOk(b.address)) return send(res, 400, { error: 'address must be an IPv4 address' });
        const id = 'ap' + (++st.seq); st.approvals.set(id, { id, address: b.address, status: 'waiting' }); log('approval_requested', { id, address: b.address });
        return send(res, 201, { id, status: 'waiting' });
      }
      let r = /^\/asix\/approvals\/(ap\d+)(?:\/(grant|reject))?$/.exec(p);
      if (r) {
        const a = st.approvals.get(r[1]); if (!a) return send(res, 404, { error: 'unknown approval' });
        if (m === 'GET' && !r[2]) return send(res, 200, { id: a.id, status: a.status });
        if (m === 'POST' && r[2]) {
          if (a.status !== 'waiting') return send(res, 409, { error: 'already ' + a.status });
          a.status = r[2] === 'grant' ? 'granted' : 'rejected'; log(a.status === 'granted' ? 'approval_granted' : 'approval_rejected', { id: a.id, address: a.address });
          return send(res, 200, { id: a.id, status: a.status });
        }
      }

      r = /^\/api\/firewall\/alias_util\/(add|del|list)\/([A-Za-z0-9_]{1,32})$/.exec(p);
      if (r) {
        if (!authOk(req)) { log('bad_credentials', { path: p }); return send(res, 401, { status: 'unauthorized' }); }
        if (r[2] !== cfg.alias) return send(res, 404, { status: 'unknown alias' });
        if (r[1] === 'list' && m === 'GET') return send(res, 200, { total: st.blocked.size, rowCount: st.blocked.size, rows: [...st.blocked].sort().map((ip) => ({ ip })) });
        if (m === 'POST' && (r[1] === 'add' || r[1] === 'del')) {
          const b = await readJson(req); if (!b || !ipOk(b.address)) return send(res, 400, { status: 'failed', error: 'address must be an IPv4 address' });
          if (r[1] === 'add') {
            if (!grantedFor(b.address)) { log('block_refused_no_approval', { address: b.address }); return send(res, 403, { status: 'refused', error: 'no granted approval for this address' }); }
            st.blocked.add(b.address); log('block', { address: b.address }); return send(res, 200, { status: 'done' });
          }
          const had = st.blocked.delete(b.address); log('unblock', { address: b.address, had }); return send(res, 200, { status: had ? 'done' : 'not_found' });
        }
      }
      return send(res, 404, { error: 'not found' });
    } catch (e) { return send(res, 500, { error: 'stand-in error' }); }
  });
  return { server, config: cfg, reset, report };
}

module.exports = { createStandIn, DEFAULT_FEED };

if (require.main === module) {
  const a = process.argv.slice(2); const get = (n, d) => { const i = a.indexOf('--' + n); return i >= 0 && a[i + 1] ? a[i + 1] : d; };
  const port = Number(get('port', 8099)); const host = get('host', '127.0.0.1');
  if (!Number.isInteger(port) || port < 1 || port > 65535) { console.error('--port must be 1 to 65535'); process.exit(2); }
  const s = createStandIn({ key: get('key'), secret: get('secret'), alias: get('alias') });
  s.server.listen(port, host, () => console.log(`SOAR spike stand-in on http://${host}:${port}  (feed /feed.txt, approvals /asix/approvals, firewall /api/firewall/alias_util, verdict /_spike/report)`));
}
