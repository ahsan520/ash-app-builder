'use strict';
// The read-only proxy client for the central Wazuh indexer (src/endpoints/wazuh-indexer.js, docs/endpoints.md task E6e) against a stand-in indexer over real HTTPS with its own
// self-signed certificate (tests/fixtures/fake-wazuh-indexer.js; written from the documented Wazuh 4.8+ shape, NOT a real indexer). Checks what the proxy asks for, what it passes on,
// and the ways it refuses: a certificate other than the registered one, a redirect, a huge answer, a slow answer, forbidden addresses, a body or index the caller chose, too many calls.
process.env.ASIX_WAZUH_INDEXER_TIMEOUT_MS = '600';
process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true';       // the stand-in listens on 127.0.0.1; one test switches this off
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('assert');
const fake = require('./fixtures/fake-wazuh-indexer');
const ix = require('../src/endpoints/wazuh-indexer');

const mk = (srv, extra = {}) => ({ tenant_id: 'T-' + srv.port, index_url: srv.url, index_user: srv.user, index_password: srv.password, ca_pem: srv.cert, cert_sha256: 'x', index_name: srv.index, ...extra });
const rejects = async (p, code) => { try { await p; } catch (e) { assert.ok(e instanceof ix.WazuhIndexerError, 'a WazuhIndexerError, got ' + e); assert.strictEqual(e.code, code, e.message); return e; } assert.fail('expected ' + code); };
const q = (o) => { const r = ix.parseQuery(o); assert.ok(!r.error, JSON.stringify(o) + ' -> ' + r.error); return r; };

describe('parseQuery: only validated parameters are used', () => {
  it('no parameters: the defaults (50 rows, highest score first)', () => {
    const r = q({}); assert.deepStrictEqual([r.limit, r.offset, r.severity, r.agent, r.q, r.cve], [50, 0, null, null, null, null]); assert.deepStrictEqual(r.sort, { field: 'vulnerability.score.base', order: 'desc' });
  });
  it('every allowed parameter is understood; severity is matched case-insensitively and stored as the index spells it', () => {
    const r = q({ limit: '25', offset: '50', severity: 'CRITICAL', agent: '001', q: ' openssl ', cve: 'CVE-2026-1001', sort: 'agent' });
    assert.deepStrictEqual([r.limit, r.offset, r.severity, r.agent, r.q, r.cve, r.sort.field, r.sort.order], [25, 50, 'Critical', '001', 'openssl', 'CVE-2026-1001', 'agent.name', 'asc']);
    assert.strictEqual(q({ sort: '-package' }).sort.order, 'desc'); assert.strictEqual(q({ sort: '+score' }).sort.order, 'asc'); assert.strictEqual(q({ sort: 'detected' }).sort.order, 'desc');
  });
  it('anything else is refused by name, so a caller cannot ask the indexer for another feature', () => {
    for (const k of ['index', 'query', 'aggs', 'script', 'size', 'from', 'fields', '_source', 'pretty', 'scroll', 'agent.name']) assert.match(ix.parseQuery({ [k]: '1' }).error, /Unknown parameter/, k);
    assert.match(ix.parseQuery({ limit: '5' }, { list: false }).error, /Unknown parameter/, 'the summary takes filters only');
  });
  it('limits, ids and text are checked; the result window of the indexer is respected', () => {
    for (const o of [{ limit: '0' }, { limit: '101' }, { limit: '-1' }, { limit: '1.5' }, { limit: 'abc' }, { offset: '-1' }, { offset: '10000' }, { offset: '9990', limit: '50' }]) assert.ok(ix.parseQuery(o).error, JSON.stringify(o));
    for (const o of [{ severity: 'urgent' }, { agent: '1' }, { agent: '001a' }, { agent: '../x' }, { cve: 'a b' }, { cve: 'x'.repeat(61) }, { q: 'x'.repeat(101) }, { q: 'a\nb' }, { sort: 'password' }, { sort: 'score;id' }, { sort: '--score' }]) assert.ok(ix.parseQuery(o).error, JSON.stringify(o));
    assert.ok(ix.parseQuery({ severity: ['high', 'low'] }).error, 'a repeated parameter'); assert.strictEqual(q({ limit: '100', offset: '9900' }).offset, 9900);
    assert.strictEqual(q({ q: '   ' }).q, null, 'blank text is no filter');
  });
});

describe('the search body is built here, never taken from the request', () => {
  it('exact filters are terms; the text is a case-insensitive wildcard over three keyword fields, with wildcard characters escaped', () => {
    const f = ix.buildFilter(q({ severity: 'high', agent: '002', cve: 'CVE-2026-1001', q: 'a*b?c\\d' })).bool.filter;
    assert.deepStrictEqual(f.slice(0, 3), [{ term: { 'vulnerability.severity': 'High' } }, { term: { 'agent.id': '002' } }, { term: { 'vulnerability.id': 'CVE-2026-1001' } }]);
    const w = f[3].bool; assert.strictEqual(w.minimum_should_match, 1);
    assert.deepStrictEqual(w.should.map((s) => Object.keys(s.wildcard)[0]), ['package.name', 'vulnerability.id', 'agent.name']);
    for (const s of w.should) { const o = Object.values(s.wildcard)[0]; assert.strictEqual(o.value, '*a\\*b\\?c\\\\d*'); assert.strictEqual(o.case_insensitive, true); }
    assert.deepStrictEqual(ix.buildFilter(q({})), { bool: { filter: [] } });
  });
  it('the list body has fixed size, source fields and sort; the summary body has fixed aggregations and no hits', () => {
    const b = ix.listBody(q({ limit: '10', offset: '20' })); assert.deepStrictEqual([b.size, b.from, b.track_total_hits], [10, 20, true]);
    assert.ok(Array.isArray(b._source) && !b._source.includes('agent.groups') && b._source.includes('vulnerability.id'));
    assert.deepStrictEqual(Object.keys(b).sort(), ['_source', 'from', 'query', 'size', 'sort', 'track_total_hits']);
    const s = ix.summaryBody(q({})); assert.strictEqual(s.size, 0); assert.deepStrictEqual(Object.keys(s.aggs).sort(), ['agents', 'cves', 'distinct_cves', 'machines', 'packages', 'severity']);
  });
  it('index names have one shape: wazuh-states-vulnerabilities-<name>, lower case, no wildcard, no path', () => {
    for (const n of ['wazuh-states-vulnerabilities-mgr-a', 'wazuh-states-vulnerabilities-a.b_c-1']) assert.ok(!ix.checkIndexName(n).error, n);
    for (const n of ['wazuh-states-vulnerabilities-*', 'wazuh-states-vulnerabilities-', 'wazuh-states-vulnerabilities-A', 'wazuh-alerts-4.x-2026', '*', '_all', 'wazuh-states-vulnerabilities-a/../b', 'wazuh-states-vulnerabilities-a,b', 'wazuh-states-vulnerabilities-a?x=1', '', undefined, 5]) assert.ok(ix.checkIndexName(n).error, String(n));
  });
});

describe('checkUrl', () => {
  it('only https://host:port is accepted, and the messages speak of the indexer', () => {
    assert.deepStrictEqual(ix.checkUrl('https://wazuh-indexer.internal:9200'), { origin: 'https://wazuh-indexer.internal:9200', host: 'wazuh-indexer.internal', port: 9200 });
    for (const bad of ['http://10.1.2.3:9200', 'https://u:p@10.1.2.3:9200', 'https://10.1.2.3:9200/_search', 'https://10.1.2.3:9200/?x=1', 'ftp://x', 'nope', '', undefined]) { const r = ix.checkUrl(bad); assert.ok(r.error, String(bad)); assert.ok(!/manager/i.test(r.error), r.error); }
  });
  it('loopback, link-local (cloud metadata) and reserved addresses are refused; private ones are fine', () => {
    delete process.env.ASIX_WAZUH_ALLOW_LOOPBACK;
    try {
      for (const h of ['127.0.0.1', '[::1]', '169.254.169.254', '0.0.0.0', '224.0.0.1', 'localhost']) assert.ok(ix.checkUrl('https://' + h + ':9200').error, h);
      for (const h of ['10.0.0.5', '172.16.4.4', '192.168.1.9', 'wazuh-indexer.corp.example']) assert.ok(!ix.checkUrl('https://' + h + ':9200').error, h);
    } finally { process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true'; }
  });
});

describe('against a stand-in indexer', () => {
  let A, B;
  before(async () => { A = await fake.start({ tag: 'A' }); B = await fake.start({ tag: 'B', cn: 'other-indexer', user: 'asix-vuln-b', password: 'Idx-B-Passw0rd!', indexes: { 'wazuh-states-vulnerabilities-mgr-b': fake.DOCS_B } }); });
  after(async () => { await A.stop(); await B.stop(); });
  beforeEach(() => { A.state.requests.length = 0; B.state.requests.length = 0; A.state.mode = null; A.state.delayMs = 0; A.state.allowed = null; });

  it('count: the number of findings, by a GET on the index\'s _count', async () => {
    assert.deepStrictEqual(await ix.count(mk(A)), { count: 6 });
    assert.deepStrictEqual(A.state.requests.map((r) => [r.method, r.path, r.auth]), [['GET', '/wazuh-states-vulnerabilities-mgr-a/_count', 'Basic']]);
  });
  it('the list is rebuilt from known fields only (no groups, host address, install path, kernel, scanner link, cluster), highest score first', async () => {
    const r = await ix.listFindings(mk(A), q({}));
    assert.deepStrictEqual([r.total, r.limit, r.offset, r.findings.length], [6, 50, 0, 6]);
    assert.deepStrictEqual(r.findings.map((f) => f.score), [9.8, 9.8, 7.5, 7.1, 5.3, 3.1]);
    const f = r.findings.find((x) => x.cve === 'CVE-2026-1002');
    assert.deepStrictEqual(f, { cve: 'CVE-2026-1002', severity: 'high', score: 7.5, score_version: '3.1', agent_id: '001', agent_name: 'WIN-DC01', package: 'openssl', version: '3.0.13', package_type: 'deb', architecture: 'amd64', os: 'Ubuntu 24.04.1 LTS',
      description: 'Description of CVE-2026-1002', references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-1002'], published_at: '2026-08-01T00:00:00Z', detected_at: '2026-10-30T10:00:01Z', under_evaluation: false });
    const text = JSON.stringify(r); for (const s of ['secret-kernel-build', '/secret/install/path', '10.0.0.9', 'cti.wazuh.com', 'node01', 'groups']) assert.ok(!text.includes(s), s + ' leaked');
  });
  it('a reference string with several links joined by a comma is split (the real Wazuh 4.14 shape)', () => {
    const f = ix.shapeFinding({ _source: { vulnerability: { id: 'CVE-2026-98161', reference: 'https://ubuntu.com/security/CVE-2026-98161, https://www.cve.org/CVERecord?id=CVE-2026-98161' } } });
    assert.deepStrictEqual(f.references, ['https://ubuntu.com/security/CVE-2026-98161', 'https://www.cve.org/CVERecord?id=CVE-2026-98161']);
  });
  it('only http(s) references become links and long text is cut', async () => {
    const f = (await ix.listFindings(mk(A), q({ cve: 'CVE-2026-4001' }))).findings[0];
    assert.deepStrictEqual(f.references, ['https://example.org/advisory']); assert.strictEqual(f.description.length, 1500);
  });
  it('filters reach the index as built: severity, machine, vulnerability id and text; sorting and paging', async () => {
    assert.deepStrictEqual((await ix.listFindings(mk(A), q({ severity: 'critical' }))).findings.map((f) => f.agent_id), ['001', '002']);
    assert.strictEqual((await ix.listFindings(mk(A), q({ agent: '002' }))).total, 3);
    assert.strictEqual((await ix.listFindings(mk(A), q({ cve: 'CVE-2026-1001' }))).total, 2);
    assert.deepStrictEqual((await ix.listFindings(mk(A), q({ q: 'OPENSSL' }))).findings.map((f) => f.cve).sort(), ['CVE-2026-1001', 'CVE-2026-1001', 'CVE-2026-1002']);
    assert.strictEqual((await ix.listFindings(mk(A), q({ q: 'web' }))).total, 3, 'text matches the machine name too');
    assert.strictEqual((await ix.listFindings(mk(A), q({ q: '*' }))).total, 0, 'a typed * is a literal star, not "everything"');
    const p2 = await ix.listFindings(mk(A), q({ limit: '2', offset: '2', sort: 'cve' })); assert.deepStrictEqual([p2.total, p2.findings.map((f) => f.cve)], [6, ['CVE-2026-1002', 'CVE-2026-2001']]);
  });
  it('the summary: totals, severity counts and top lists from the aggregations', async () => {
    const s = await ix.summary(mk(A), q({}));
    assert.deepStrictEqual([s.total, s.machines, s.distinct_cves], [6, 2, 5]); assert.deepStrictEqual(s.severity, { critical: 2, high: 2, medium: 1, low: 1, unknown: 0 });
    assert.deepStrictEqual(s.top_packages[0], { key: 'openssl', count: 3 }); assert.deepStrictEqual(s.top_cves[0], { key: 'CVE-2026-1001', count: 2 });
    assert.deepStrictEqual(s.top_agents.map((a) => [a.agent_id, a.name, a.count]), [['001', 'WIN-DC01', 3], ['002', 'web1', 3]]);
    const f = await ix.summary(mk(A), q({ agent: '002' })); assert.deepStrictEqual([f.total, f.machines], [3, 1]);
  });
  it('the paths are only ever <index>/_search (POST) and <index>/_count (GET); the body is the built one and nothing from the caller but validated values', async () => {
    await ix.listFindings(mk(A), q({ q: 'x"}, "script": {', severity: 'high' })); await ix.summary(mk(A), q({})); await ix.count(mk(A));
    for (const r of A.state.requests) assert.match(r.method + ' ' + r.path, /^(POST \/wazuh-states-vulnerabilities-mgr-a\/_search\?ignore_unavailable=false&allow_no_indices=false|GET \/wazuh-states-vulnerabilities-mgr-a\/_count)$/);
    const sent = A.state.requests[0].body; assert.deepStrictEqual(Object.keys(sent).sort(), ['_source', 'from', 'query', 'size', 'sort', 'track_total_hits']); assert.ok(!('script' in sent) && !JSON.stringify(sent).includes('"script"'), 'text stays a string value');
  });
  it('a tenant\'s call reaches only the index in its own row, whatever the other index holds', async () => {
    const r = await ix.listFindings(mk(B), q({})); assert.deepStrictEqual(r.findings.map((f) => f.cve), ['CVE-2026-9001']);
    assert.ok(B.state.requests.every((x) => x.path.startsWith('/wazuh-states-vulnerabilities-mgr-b/')), 'B saw only its own index'); assert.strictEqual(A.state.requests.length, 0);
  });
  it('a row with another or a tampered index name is refused before any request is made', async () => {
    for (const n of ['*', 'wazuh-states-vulnerabilities-*', '_all', 'wazuh-alerts-4.x-2026', 'wazuh-states-vulnerabilities-a/../../_cat']) await rejects(ix.count(mk(A, { index_name: n })), 'BAD_INDEX');
    assert.strictEqual(A.state.requests.length, 0);
  });
  it('an index that does not exist yet is NO_INDEX with a plain message', async () => {
    const e = await rejects(ix.count(mk(A, { index_name: 'wazuh-states-vulnerabilities-nothing-yet' })), 'NO_INDEX'); assert.match(e.message, /has not sent any finding/);
  });
  it('a wrong password is AUTH_FAILED; a role that may not read the index is AUTH_FAILED with its own message', async () => {
    const e1 = await rejects(ix.count(mk(A, { index_password: 'wrong-password' })), 'AUTH_FAILED'); assert.match(e1.message, /refused the registered user/);
    A.state.allowed = ['wazuh-states-vulnerabilities-mgr-other']; const e2 = await rejects(ix.count(mk(A)), 'AUTH_FAILED'); assert.strictEqual(e2.status, 403); assert.match(e2.message, /may not read this index/);
  });
  it('a certificate other than the registered one is refused before the password is sent (TLS)', async () => {
    A.state.requests.length = 0; const e = await rejects(ix.count(mk(A, { ca_pem: B.cert })), 'TLS'); assert.match(e.message, /not the one registered/); assert.strictEqual(A.state.requests.length, 0, 'no request reached the server');
  });
  it('a redirect is not followed; HTML instead of JSON; a huge answer; a slow answer', async () => {
    A.state.mode = 'redirect'; await rejects(ix.count(mk(A)), 'BAD_RESPONSE');
    A.state.mode = 'html'; await rejects(ix.count(mk(A)), 'BAD_RESPONSE');
    A.state.mode = 'huge'; await rejects(ix.count(mk(A)), 'TOO_LARGE');
    A.state.mode = null; A.state.delayMs = 1500; await rejects(ix.count(mk(A)), 'TIMEOUT');
  });
  it('a body of the wrong shape is BAD_RESPONSE, not a crash', async () => {
    const orig = A.state.indexes['wazuh-states-vulnerabilities-mgr-a']; A.state.indexes['wazuh-states-vulnerabilities-weird'] = [{ not: 'a finding' }, { vulnerability: { id: 'CVE-1-1' } }, { vulnerability: { id: 'CVE-2026-0001', severity: 'weird', score: { base: 'abc' } } }];
    try {
      const r = await ix.listFindings(mk(A, { index_name: 'wazuh-states-vulnerabilities-weird' }), q({ sort: 'cve' }));
      assert.deepStrictEqual(r.findings.map((f) => [f.cve, f.severity, f.score, f.agent_id, f.package]), [['CVE-1-1', null, null, null, null], ['CVE-2026-0001', 'unknown', null, null, null]], 'a missing field is null, a strange severity is unknown');
    } finally { delete A.state.indexes['wazuh-states-vulnerabilities-weird']; assert.ok(orig); }
  });
  it('a forbidden address is refused when connecting, and too many calls at once are BUSY', async () => {
    delete process.env.ASIX_WAZUH_ALLOW_LOOPBACK;
    try { await rejects(ix.count(mk(A)), 'BAD_ADDRESS'); } finally { process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true'; }
    A.state.delayMs = 300; const m = mk(A, { tenant_id: 'busy-tenant' });
    const results = await Promise.allSettled([1, 2, 3, 4, 5].map(() => ix.count(m)));
    assert.ok(results.some((r) => r.status === 'rejected' && r.reason.code === 'BUSY'), 'the fourth and fifth call at once are refused'); assert.strictEqual(results.filter((r) => r.status === 'fulfilled').length, 3);
  });
});
