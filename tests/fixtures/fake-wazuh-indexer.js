'use strict';
// A stand-in for the central Wazuh indexer over HTTPS with its own self-signed certificate, written from the documented shape of the Wazuh 4.8+ vulnerability state index and the
// OpenSearch search API (NOT captured from a real indexer). It speaks only what ASIX sends: basic authentication, GET /<index>/_count and POST /<index>/_search with the filters
// (`term`, a `bool.should` of case-insensitive `wildcard`s), sort, from/size and the aggregations built in src/endpoints/wazuh-indexer.js. It records every request so a test can say
// exactly what was asked, and has switches for the awkward cases. Documents carry extra fields a real index holds that the proxy must NOT pass on.
const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { makeCert } = require('./fake-wazuh-api');

const doc = (agentId, agentName, pkg, ver, cve, severity, score, detected, extra = {}) => ({
  agent: { id: agentId, name: agentName, type: 'wazuh', version: 'v4.14.9', groups: ['default'], host: { ip: ['10.0.0.9'] } },
  host: { os: { name: 'Ubuntu', full: 'Ubuntu 24.04.1 LTS', version: '24.04', kernel: 'secret-kernel-build' } },
  package: { name: pkg, version: ver, type: 'deb', architecture: 'amd64', size: 1234, installed: '2026-09-01T00:00:00Z', path: '/secret/install/path' },
  vulnerability: { id: cve, severity, score: { base: score, version: '3.1' }, description: 'Description of ' + cve, reference: 'https://nvd.nist.gov/vuln/detail/' + cve, published_at: '2026-08-01T00:00:00Z', detected_at: detected,
    category: 'Packages', classification: 'CVSS', enumeration: 'CVE', scanner: { reference: 'https://cti.wazuh.com/vulnerabilities/cves/' + cve }, under_evaluation: false, ...(extra.vulnerability || {}) },
  wazuh: { cluster: { name: 'wazuh', node: 'node01' }, schema: { version: '1.0.0' } },
});
const DOCS_A = [
  doc('001', 'WIN-DC01', 'openssl', '3.0.13', 'CVE-2026-1001', 'Critical', 9.8, '2026-10-30T10:00:00Z'),
  doc('001', 'WIN-DC01', 'openssl', '3.0.13', 'CVE-2026-1002', 'High', 7.5, '2026-10-30T10:00:01Z'),
  doc('001', 'WIN-DC01', 'curl', '8.5.0', 'CVE-2026-2001', 'Medium', 5.3, '2026-10-29T10:00:00Z'),
  doc('002', 'web1', 'openssl', '3.0.13', 'CVE-2026-1001', 'Critical', 9.8, '2026-10-30T11:00:00Z'),
  doc('002', 'web1', 'bash', '5.2.21', 'CVE-2026-3001', 'Low', 3.1, '2026-10-28T10:00:00Z'),
  doc('002', 'web1', 'libxml2', '2.9.14', 'CVE-2026-4001', 'High', 7.1, '2026-10-27T10:00:00Z', { vulnerability: { reference: ['https://example.org/advisory', 'javascript:alert(1)', 'ftp://x/y'], description: 'x'.repeat(3000) } }),
];
const DOCS_B = [doc('001', 'b-host', 'zlib', '1.2.13', 'CVE-2026-9001', 'High', 8.1, '2026-10-30T12:00:00Z')];

// OpenSearch wildcard syntax: * any run, ? one character, a backslash makes the next character literal.
function wildcard(v, ci) {
  let re = '';
  for (let i = 0; i < v.length; i++) {
    const ch = v[i];
    if (ch === '\\' && i + 1 < v.length) { re += v[++i].replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
    else if (ch === '*') re += '.*'; else if (ch === '?') re += '.'; else re += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp('^' + re + '$', ci ? 'i' : '');
}
const get = (o, p) => p.split('.').reduce((x, k) => (x === undefined || x === null ? undefined : x[k]), o);

async function start({ user = 'asix-vuln-a', password = 'Idx-Passw0rd!x', cn = 'wazuh-indexer-test', indexes = { 'wazuh-states-vulnerabilities-mgr-a': DOCS_A }, tag = 'A', dir } = {}) {
  dir = dir || fs.mkdtempSync(path.join(os.tmpdir(), 'fakeindexer-'));
  const c = makeCert(dir, { cn, ca: true });
  const state = { requests: [], mode: null, delayMs: 0, indexes, allowed: null };   // allowed: the indexes this user's role may read (null = all of them)
  const srv = https.createServer({ key: c.key, cert: c.cert }, (req, res) => {
    const u = new URL(req.url, 'https://x');
    let raw = ''; req.on('data', (d) => { raw += d; });
    req.on('end', () => {
      let body = null; try { body = raw ? JSON.parse(raw) : null; } catch { /* kept null */ }
      state.requests.push({ method: req.method, path: req.url, auth: req.headers.authorization ? req.headers.authorization.split(' ')[0] : null, headers: req.headers, body, raw });
      const send = (status, b, type = 'application/json') => { const t = typeof b === 'string' ? b : JSON.stringify(b); setTimeout(() => { res.writeHead(status, { 'content-type': type }); res.end(t); }, state.delayMs); };
      if (state.mode === 'redirect') { res.writeHead(302, { location: 'https://127.0.0.1:1/elsewhere' }); return res.end(); }
      if (state.mode === 'huge') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{"data":"' + 'x'.repeat(5 * 1024 * 1024) + '"}'); }
      if (state.mode === 'html') return send(200, '<html>not the indexer</html>', 'text/html');
      const m = /^Basic (.+)$/.exec(req.headers.authorization || '');
      const [bu, ...bp] = m ? Buffer.from(m[1], 'base64').toString('utf8').split(':') : [];
      if (!m || bu !== user || bp.join(':') !== password) return send(401, { error: 'Unauthorized', status: 401 });
      const mm = /^\/([^/?]+)\/(_count|_search)$/.exec(u.pathname);
      if (!mm) return send(404, { error: 'no handler found for uri', status: 404 });
      const index = mm[1];
      if (state.allowed && !state.allowed.includes(index)) return send(403, { error: { type: 'security_exception', reason: 'no permissions for [indices:data/read/search] and User [name=' + user + ']' }, status: 403 });
      const docs = state.indexes[index];
      if (!docs) return send(404, { error: { root_cause: [{ type: 'index_not_found_exception', reason: 'no such index [' + index + ']' }], type: 'index_not_found_exception' }, status: 404 });
      if (mm[2] === '_count') { if (req.method !== 'GET') return send(405, { error: 'method' }); return send(200, { count: docs.length, _shards: { total: 1, successful: 1, failed: 0 } }); }
      if (req.method !== 'POST' || !body) return send(400, { error: 'a search body is needed' });
      // filters
      let hits = docs.slice();
      for (const f of ((body.query && body.query.bool && body.query.bool.filter) || [])) {
        if (f.term) { const [k, v] = Object.entries(f.term)[0]; hits = hits.filter((d) => String(get(d, k)) === String(v)); }
        else if (f.bool && f.bool.should) {
          const ws = f.bool.should.map((s) => { const [k, o] = Object.entries(s.wildcard)[0]; return { k, re: wildcard(o.value, o.case_insensitive) }; });
          hits = hits.filter((d) => ws.some((w) => w.re.test(String(get(d, w.k) ?? ''))));
        } else return send(400, { error: 'unsupported filter in the stand-in' });
      }
      const out = { took: 1, timed_out: false, hits: { total: { value: hits.length, relation: 'eq' }, hits: [] } };
      if (body.sort && body.sort.length) {
        hits.sort((a, b) => { for (const s of body.sort) { const [k, o] = Object.entries(s)[0], x = get(a, k), y = get(b, k); const r = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y)); if (r) return o.order === 'desc' ? -r : r; } return 0; });
      }
      const from = body.from || 0, size = body.size === undefined ? 10 : body.size;
      out.hits.hits = hits.slice(from, from + size).map((d, i) => ({ _index: index, _id: '00' + i, _source: d }));
      if (body.aggs) {
        out.aggregations = {};
        const terms = (docsX, spec) => { const n = new Map(); for (const d of docsX) { const k = get(d, spec.field); if (k !== undefined) n.set(k, (n.get(k) || []).concat(d)); } return [...n].sort((a, b) => b[1].length - a[1].length).slice(0, spec.size || 10); };
        for (const [name, a] of Object.entries(body.aggs)) {
          if (a.terms) out.aggregations[name] = { buckets: terms(hits, a.terms).map(([key, ds]) => ({ key, doc_count: ds.length, ...(a.aggs ? Object.fromEntries(Object.entries(a.aggs).map(([n2, a2]) => [n2, { buckets: terms(ds, a2.terms).map(([k2, d2]) => ({ key: k2, doc_count: d2.length })) }])) : {}) })) };
          else if (a.cardinality) out.aggregations[name] = { value: new Set(hits.map((d) => get(d, a.cardinality.field))).size };
        }
      }
      return send(200, out);
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { url: 'https://127.0.0.1:' + srv.address().port, port: srv.address().port, user, password, cert: c.cert, certFile: c.certFile, state, tag, dir, index: Object.keys(indexes)[0],
    stop: () => new Promise((r) => { srv.closeAllConnections && srv.closeAllConnections(); srv.close(r); }) };
}

module.exports = { start, DOCS_A, DOCS_B };
