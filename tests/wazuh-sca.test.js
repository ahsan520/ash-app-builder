'use strict';
// Configuration checks of ONE machine from the manager (src/endpoints/wazuh-api.js scaPolicies / scaChecks / parseScaQuery, src/gateway/routes/endpoint-checks.js;
// docs/endpoints.md task E6f) against the stand-in manager API over real HTTPS (tests/fixtures/fake-wazuh-api.js, written from the documented Wazuh 4.x shape, NOT a real manager).
process.env.ASIX_WAZUH_API_TIMEOUT_MS = '600';
process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true';
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const fake = require('./fixtures/fake-wazuh-api');
const api = require('../src/endpoints/wazuh-api');

const mk = (srv, extra = {}) => ({ tenant_id: 'T-' + srv.port, api_url: srv.url, api_user: srv.user, api_password: srv.password, ca_pem: srv.cert, cert_sha256: 'x', api_secret_enc_hash: 'h', ...extra });
const rejects = async (p, code) => { try { await p; } catch (e) { assert.ok(e instanceof api.WazuhApiError, 'a WazuhApiError, got ' + e); assert.strictEqual(e.code, code, e.message); return e; } assert.fail('expected ' + code); };
const scaCalls = (srv) => srv.state.requests.filter((r) => r.path.startsWith('/sca/'));

describe('parseScaQuery: only validated parameters reach the manager', () => {
  it('no parameters: the defaults, in a fixed order', () => { assert.deepStrictEqual(api.parseScaQuery({}), { query: 'limit=50&offset=0', limit: 50, offset: 0 }); assert.strictEqual(api.parseScaQuery(undefined).query, 'limit=50&offset=0'); });
  it('every allowed parameter is passed in its own form; the result uses the manager\'s own word', () => {
    const p = api.parseScaQuery({ limit: '25', offset: '50', result: 'not_applicable', search: 'password length', sort: '-title' });
    assert.strictEqual(p.query, 'limit=25&offset=50&result=not+applicable&search=password+length&sort=-title');
    assert.strictEqual(api.parseScaQuery({ result: 'failed' }).query, 'limit=50&offset=0&result=failed');
    assert.strictEqual(api.parseScaQuery({ sort: 'id' }).query, 'limit=50&offset=0&sort=%2Bid');
    assert.strictEqual(api.parseScaQuery({ limit: '500' }).limit, 500);
  });
  it('anything else is refused, by name, so a caller cannot use another Wazuh API feature', () => {
    for (const k of ['q', 'select', 'command', 'file', 'registry', 'title', 'rationale', 'agents_list', 'policy_id', 'wait_for_complete', 'pretty', 'raw']) assert.match(api.parseScaQuery({ [k]: '1' }).error, /Unknown parameter/, k);
  });
  it('limits, results, text and sort are checked', () => {
    for (const q of [{ limit: '0' }, { limit: '501' }, { limit: '-1' }, { limit: '1.5' }, { limit: 'abc' }, { limit: '99999999999' }, { offset: '-1' }, { offset: '1000001' }]) assert.ok(api.parseScaQuery(q).error, JSON.stringify(q));
    for (const q of [{ result: 'Failed' }, { result: 'not applicable' }, { result: 'fail' }, { result: 'passed,failed' }, { result: '__proto__' }, { result: 'toString' }, { search: 'x'.repeat(101) }, { search: 'a\nb' }, { search: 'a\u0000b' },
      { sort: 'command' }, { sort: 'title;id' }, { sort: '--id' }, { sort: 'id desc' }]) assert.ok(api.parseScaQuery(q).error, JSON.stringify(q));
    for (const k of ['limit', 'offset', 'result', 'search', 'sort']) assert.ok(api.parseScaQuery({ [k]: ['1', '2'] }).error, 'a repeated ' + k);
  });
  it('ids: an agent id is digits only and a policy id a short fixed alphabet', () => {
    for (const ok of ['cis_win11', 'cis_ubuntu22-04', 'sca_distro_independent_linux', 'a.b-c_d', 'X']) assert.ok(api.POLICY_ID_RE.test(ok), ok);
    for (const bad of ['', '../agents', 'a b', 'a/b', 'a?b=1', 'a%2fb', '-x', '.x', 'a;b', 'x'.repeat(101)]) assert.ok(!api.POLICY_ID_RE.test(bad), bad);
  });
});

describe('the client against a stand-in manager', () => {
  let srv, m;
  before(async () => { srv = await fake.start(); m = mk(srv); });
  after(() => srv.stop());

  it('policies: one GET on the fixed path, the answer rebuilt from allowed fields (no hash, no references, no checks)', async () => {
    srv.state.requests.length = 0;
    const out = await api.scaPolicies(m, '001');
    assert.deepStrictEqual(scaCalls(srv).map((r) => r.method + ' ' + r.path), ['GET /sca/001?limit=50&sort=%2Bname']);
    assert.strictEqual(out.length, 2);
    assert.deepStrictEqual(out[0], { policy_id: 'cis_win11', name: 'CIS Microsoft Windows 11 Enterprise Benchmark', description: 'Guidance for secure configuration.', passed: 2, failed: 2, not_applicable: 1, total: 5, score: 50,
      start_scan: '2026-10-30T10:00:00Z', end_scan: '2026-10-30T10:02:00Z' });
    assert.ok(!JSON.stringify(out).includes('deadbeef') && !JSON.stringify(out).includes('cisecurity'));
  });
  it('a machine with no results, or one the manager does not know, is an empty list (not an error); a bad id is refused before any call', async () => {
    srv.state.requests.length = 0;
    assert.deepStrictEqual(await api.scaPolicies(m, '002'), []);
    assert.deepStrictEqual(await api.scaPolicies(m, '999'), []);
    const before = srv.state.requests.length;
    for (const id of ['1', '12', '123456789', 'abc', '001/../..', '001;x', '', undefined]) await rejects(api.scaPolicies(m, id), 'BAD_ID');
    assert.strictEqual(srv.state.requests.length, before, 'nothing was sent for a bad id');
  });
  it('checks: every field is allowed through by name; what the manager adds (rules, policy_id) is not passed on', async () => {
    srv.state.requests.length = 0;
    const out = await api.scaChecks(m, '001', 'cis_win11', api.parseScaQuery({}));
    assert.deepStrictEqual(scaCalls(srv).map((r) => r.method + ' ' + r.path), ['GET /sca/001/checks/cis_win11?limit=50&offset=0']);
    assert.strictEqual(out.total, 5); assert.strictEqual(out.limit, 50); assert.strictEqual(out.offset, 0); assert.strictEqual(out.checks.length, 5);
    const c = out.checks[0];
    assert.deepStrictEqual(Object.keys(c).sort(), ['command', 'compliance', 'condition', 'description', 'directory', 'file', 'id', 'process', 'rationale', 'reason', 'references', 'registry', 'remediation', 'result', 'title']);
    assert.strictEqual(c.id, '26000'); assert.strictEqual(c.result, 'failed'); assert.strictEqual(c.remediation, 'Set it in Group Policy.');
    assert.deepStrictEqual(c.compliance, [{ key: 'cis', value: '1.1.26000' }, { key: 'pci_dss', value: '2.2' }]); assert.strictEqual(c.references, 'https://www.cisecurity.org/cis-benchmarks');
    assert.ok(!JSON.stringify(out).includes('HKLM\\\\SOFTWARE\\\\X'), 'the rules are not passed on');
  });
  it('the result, search, sort and paging are passed to the manager and applied there', async () => {
    srv.state.requests.length = 0;
    let out = await api.scaChecks(m, '001', 'cis_win11', api.parseScaQuery({ result: 'failed' }));
    assert.deepStrictEqual(out.checks.map((c) => c.id), ['26000', '26002']); assert.strictEqual(out.total, 2);
    out = await api.scaChecks(m, '001', 'cis_win11', api.parseScaQuery({ result: 'not_applicable' }));
    assert.deepStrictEqual(out.checks.map((c) => [c.id, c.result, c.reason]), [['26004', 'not applicable', 'Not a laptop']]);
    assert.ok(scaCalls(srv).some((r) => r.path.includes('result=not+applicable')), 'the manager is asked with its own word');
    out = await api.scaChecks(m, '001', 'cis_win11', api.parseScaQuery({ search: 'bitlocker' })); assert.deepStrictEqual(out.checks.map((c) => c.id), ['26004']);
    out = await api.scaChecks(m, '001', 'cis_win11', api.parseScaQuery({ sort: '-id', limit: '2', offset: '1' })); assert.deepStrictEqual(out.checks.map((c) => c.id), ['26003', '26002']); assert.strictEqual(out.total, 5);
  });
  it('an unknown policy is an empty list; a policy id that is not allowed is refused before any call, one with a slash cannot change the path', async () => {
    srv.state.requests.length = 0;
    const out = await api.scaChecks(m, '001', 'nope', api.parseScaQuery({})); assert.deepStrictEqual([out.total, out.checks], [0, []]);
    const n = srv.state.requests.length;
    for (const p of ['', '../agents', 'a b', 'a/b', 'a?x=1', undefined]) await rejects(api.scaChecks(m, '001', p, api.parseScaQuery({})), 'BAD_POLICY');
    await rejects(api.scaChecks(m, 'abc', 'cis_win11', api.parseScaQuery({})), 'BAD_ID');
    assert.strictEqual(srv.state.requests.length, n);
  });
  it('shaping: long texts are cut, the compliance list is capped, an unknown result is null, a check with no id is dropped', () => {
    const long = 'x'.repeat(5000);
    const c = api.shapeCheck({ id: 7, title: long, result: 'WEIRD', remediation: long, compliance: Array.from({ length: 50 }, (_, i) => ({ key: 'k' + i, value: long })), references: Array.from({ length: 30 }, () => long) });
    assert.strictEqual(c.title.length, 300); assert.strictEqual(c.remediation.length, 1000); assert.strictEqual(c.result, null); assert.strictEqual(c.compliance.length, 20); assert.ok(c.compliance.every((x) => x.value.length === 200));
    assert.ok(c.references.length <= 10 * 300 + 18, 'ten references at most, each cut');
    assert.strictEqual(api.shapeCheck({ title: 'no id' }), null); assert.strictEqual(api.shapeCheck(null), null); assert.strictEqual(api.shapeCheck('x'), null);
    assert.strictEqual(api.shapeCheck({ id: 1, result: ' Passed ' }).result, 'passed');
    const p = api.shapePolicy({ policy_id: 'p', pass: -3, fail: 'x', invalid: 1.5, total_checks: 4, score: 140 });
    assert.deepStrictEqual([p.passed, p.failed, p.not_applicable, p.total, p.score], [null, null, null, 4, null], 'a count that is not a whole number and a score outside 0 to 100 are null');
    assert.strictEqual(api.shapePolicy({ name: 'no id' }), null);
  });
  it('only GET goes to the manager after sign-in, and a reply that is not the API is a BAD_RESPONSE', async () => {
    assert.ok(srv.state.requests.every((r) => r.method === 'GET' || r.path.startsWith('/security/user/authenticate')), 'no write call');
    const s2 = await fake.start({ cn: 'w2' }); try {
      const m2 = mk(s2); s2.state.mode = 'html';
      await rejects(api.scaPolicies(m2, '001'), 'BAD_RESPONSE'); await rejects(api.scaChecks(m2, '001', 'cis_win11', api.parseScaQuery({})), 'BAD_RESPONSE');
    } finally { await s2.stop(); }
  });
});

describe('routes GET /v1/endpoints/agents/:id/sca and .../sca/:policy/checks', () => {
  const express = require('express');
  const sharedPath = require.resolve('../src/gateway/shared'), storePath = require.resolve('../src/endpoints/wazuh-manager-store');
  const routeFiles = ['wazuh-manager', 'endpoint-checks'].map((n) => require.resolve('../src/gateway/routes/' + n));
  const perms = []; let srv, row, server, base;
  const put = (p, exports) => { require.cache[p] = { id: p, filename: p, loaded: true, exports }; };
  before(async () => {
    srv = await fake.start({ cn: 'route' });
    row = { tenant_id: 'T1' };
    put(sharedPath, { db: { withTenant: async (t, fn) => fn({}) }, apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }),
      guarded: (perm) => { perms.push(perm); return [(req, res, next) => { req.tenant_id = 'T1'; next(); }]; } });
    put(storePath, { readRow: async () => row, credentials: () => mk(srv, { tenant_id: 'T1' }), isMissingTable: () => false, view: () => ({}) });
    for (const f of routeFiles) delete require.cache[f];
    const app = express(); app.use(require('../src/gateway/routes/endpoint-checks'));
    await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); }); base = 'http://127.0.0.1:' + server.address().port;
  });
  after(async () => { server.close(); await srv.stop(); for (const p of [...routeFiles, sharedPath, storePath]) delete require.cache[p]; });
  const get = async (p) => { const r = await fetch(base + p); return { status: r.status, body: await r.json() }; };

  it('both are GET only and ask for search:events:read (the permission of the Configuration checks tab), not capacity:read', () => {
    assert.ok(perms.length >= 2); assert.ok(perms.slice(-2).every((p) => p === 'search:events:read'), perms.join());   // the two new ones; the six before them belong to wazuh-manager.js (capacity:read), loaded for its helper
    assert.ok(perms.slice(0, -2).every((p) => p === 'capacity:read'), 'the older routes keep capacity:read');
    const src = fs.readFileSync(path.join(__dirname, '..', 'src/gateway/routes/endpoint-checks.js'), 'utf8');
    assert.ok(!/router\.(post|put|patch|delete|all|use)\(/.test(src)); assert.strictEqual((src.match(/router\.get\(/g) || []).length, 2);
    assert.match(fs.readFileSync(path.join(__dirname, '..', 'src/gateway/index.js'), 'utf8'), /app\.use\(require\('\.\/routes\/endpoint-checks'\)\)/);
  });
  it('policies of an agent', async () => {
    const r = await get('/v1/endpoints/agents/001/sca'); assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    assert.strictEqual(r.body.agent, '001'); assert.deepStrictEqual(r.body.policies.map((p) => p.policy_id), ['cis_win11', 'sca_distro_independent_linux']);
    const none = await get('/v1/endpoints/agents/002/sca'); assert.deepStrictEqual([none.status, none.body.policies], [200, []]);
  });
  it('checks of a policy, filtered and paged; the answer says which agent and policy', async () => {
    const r = await get('/v1/endpoints/agents/001/sca/cis_win11/checks?result=failed&limit=1&offset=1'); assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    assert.deepStrictEqual([r.body.agent, r.body.policy, r.body.total, r.body.limit, r.body.offset, r.body.checks.map((c) => c.id)], ['001', 'cis_win11', 2, 1, 1, ['26002']]);
  });
  it('bad ids and bad queries are a 400 with nothing sent to the manager', async () => {
    const n = srv.state.requests.length;
    for (const [p, code] of [['/v1/endpoints/agents/ab/sca', 'INVALID_AGENT_ID'], ['/v1/endpoints/agents/12/sca/x/checks', 'INVALID_AGENT_ID'], ['/v1/endpoints/agents/001/sca/a%20b/checks', 'INVALID_POLICY_ID'],
      ['/v1/endpoints/agents/001/sca/-x/checks', 'INVALID_POLICY_ID'], ['/v1/endpoints/agents/001/sca/cis_win11/checks?q=1', 'INVALID_SCA_QUERY'], ['/v1/endpoints/agents/001/sca/cis_win11/checks?result=bogus', 'INVALID_SCA_QUERY'],
      ['/v1/endpoints/agents/001/sca/cis_win11/checks?limit=501', 'INVALID_SCA_QUERY'], ['/v1/endpoints/agents/001/sca/cis_win11/checks?result=a&result=b', 'INVALID_SCA_QUERY']]) {
      const r = await get(p); assert.strictEqual(r.status, 400, p); assert.strictEqual(r.body.error.code, code, p);
    }
    assert.strictEqual(srv.state.requests.length, n);
  });
  it('no manager is a 404; a manager that cannot be reached is a 502 with the proxy\'s own code', async () => {
    row = null; let r = await get('/v1/endpoints/agents/001/sca'); assert.deepStrictEqual([r.status, r.body.error.code], [404, 'WAZUH_NO_MANAGER']); row = { tenant_id: 'T1' };
    api.forget('T1'); srv.state.failAuth = true; try { r = await get('/v1/endpoints/agents/001/sca'); assert.deepStrictEqual([r.status, r.body.error.code], [502, 'WAZUH_AUTH_FAILED']); } finally { srv.state.failAuth = false; }
  });
});
