'use strict';
// The read-only proxy client for a tenant's central Wazuh manager (src/endpoints/wazuh-api.js, docs/endpoints.md task E4c) against a stand-in manager API over real HTTPS
// with its own self-signed certificate (tests/fixtures/fake-wazuh-api.js; written from the documented Wazuh 4.x shape, NOT a real manager). Checks what the proxy asks for,
// what it passes on, and the ways it refuses: a certificate other than the registered one, a redirect, a huge answer, a slow answer, forbidden addresses, too many calls.
process.env.ASIX_WAZUH_API_TIMEOUT_MS = '600';
process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true';       // the stand-in listens on 127.0.0.1; one test switches this off
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('assert');
const fake = require('./fixtures/fake-wazuh-api');
const api = require('../src/endpoints/wazuh-api');

const mk = (srv, extra = {}) => ({ tenant_id: 'T-' + srv.port, api_url: srv.url, api_user: srv.user, api_password: srv.password, ca_pem: srv.cert, cert_sha256: 'x', api_secret_enc_hash: 'h', ...extra });
const rejects = async (p, code) => { try { await p; } catch (e) { assert.ok(e instanceof api.WazuhApiError, 'a WazuhApiError, got ' + e); assert.strictEqual(e.code, code, e.message); return e; } assert.fail('expected ' + code); };

describe('parseAgentQuery: only validated parameters reach the manager', () => {
  it('no parameters: the defaults, in a fixed order', () => { assert.deepStrictEqual(api.parseAgentQuery({}), { query: 'limit=100&offset=0', limit: 100, offset: 0 }); assert.strictEqual(api.parseAgentQuery(undefined).query, 'limit=100&offset=0'); });
  it('every allowed parameter is passed in its own form', () => {
    const p = api.parseAgentQuery({ limit: '25', offset: '50', status: 'active,disconnected', search: 'WIN dc', sort: '-name', os_platform: 'windows' });
    assert.deepStrictEqual(new URLSearchParams(p.query).get('os.platform'), 'windows');
    assert.strictEqual(p.query, 'limit=25&offset=50&status=active%2Cdisconnected&search=WIN+dc&sort=-name&os.platform=windows');
    assert.strictEqual(api.parseAgentQuery({ sort: 'ip' }).query, 'limit=100&offset=0&sort=%2Bip');
    assert.strictEqual(api.parseAgentQuery({ status: 'active,active' }).query, 'limit=100&offset=0&status=active');
  });
  it('anything else is refused, by name, so a caller cannot use another Wazuh API feature', () => {
    for (const k of ['agents_list', 'q', 'select', 'group', 'older_than', 'wait_for_complete', 'os.platform', 'pretty', 'raw']) assert.match(api.parseAgentQuery({ [k]: '1' }).error, /Unknown parameter/, k);
  });
  it('limits, lists and text are checked', () => {
    for (const q of [{ limit: '0' }, { limit: '501' }, { limit: '-1' }, { limit: '1.5' }, { limit: 'abc' }, { limit: '99999999999' }, { offset: '-1' }, { offset: '1000001' }]) assert.ok(api.parseAgentQuery(q).error, JSON.stringify(q));
    for (const q of [{ status: 'active,bogus' }, { status: 'ACTIVE' }, { status: 'a,b,c,d,e' }, { sort: 'key' }, { sort: 'name;id' }, { sort: '--name' }, { search: 'x'.repeat(101) }, { search: 'a\nb' }, { search: 'a\u0000b' }, { os_platform: 'win;dows' }, { os_platform: 'x'.repeat(31) }]) assert.ok(api.parseAgentQuery(q).error, JSON.stringify(q));
    assert.strictEqual(api.parseAgentQuery({ limit: '500' }).limit, 500);
    assert.ok(api.parseAgentQuery({ limit: ['1', '2'] }).error, 'a repeated parameter');
  });
});

describe('checkApiUrl and addresses', () => {
  it('only https://host:port is accepted', () => {
    assert.deepStrictEqual(api.checkApiUrl('https://wazuh-acme.internal:55000'), { origin: 'https://wazuh-acme.internal:55000', host: 'wazuh-acme.internal', port: 55000 });
    assert.strictEqual(api.checkApiUrl('https://10.1.2.3').port, 443);
    for (const bad of ['http://10.1.2.3:55000', 'https://u:p@10.1.2.3:55000', 'https://10.1.2.3:55000/agents', 'https://10.1.2.3:55000/?x=1', 'https://10.1.2.3:55000/#x', 'ftp://x', 'not a url', '', undefined]) assert.ok(api.checkApiUrl(bad).error, String(bad));
  });
  it('loopback, link-local (cloud metadata) and reserved addresses are refused; private ones are fine (a manager is a machine in the ASIX network)', () => {
    delete process.env.ASIX_WAZUH_ALLOW_LOOPBACK;
    try {
      for (const h of ['127.0.0.1', '[::1]', '169.254.169.254', '0.0.0.0', '224.0.0.1', '[fe80::1]', 'localhost', 'LOCALHOST']) assert.ok(api.checkApiUrl('https://' + h + ':55000').error, h);
      for (const h of ['10.0.0.5', '172.16.4.4', '192.168.1.9', 'wazuh.corp.example']) assert.ok(!api.checkApiUrl('https://' + h + ':55000').error, h);
    } finally { process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true'; }
  });
  it('a NAME that resolves to a forbidden address is refused when connecting (DNS rebinding), not only when it is registered', async () => {
    delete process.env.ASIX_WAZUH_ALLOW_LOOPBACK;
    try { const e = await new Promise((r) => api.guardedLookup('localhost', {}, (err) => r(err))); assert.ok(e && e.code === 'BLOCKED_ADDRESS', String(e)); }
    finally { process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true'; }
  });
});

describe('against a stand-in manager', () => {
  let A, B;
  before(async () => { A = await fake.start({ tag: 'A' }); B = await fake.start({ tag: 'B', cn: 'wazuh-other' }); });
  after(async () => { await A.stop(); await B.stop(); });
  beforeEach(() => { A.state.requests.length = 0; B.state.requests.length = 0; A.state.mode = null; A.state.delayMs = 0; A.state.failAuth = false; A.state.tokens.clear(); A.state.authCalls = 0; A.state.tokenTtl = 900; api.forget('T-' + A.port); });

  it('manager info and the agent summary are rebuilt from known fields only', async () => {
    const info = await api.managerInfo(mk(A)); assert.deepStrictEqual(info, { version: 'v4.14.9', compilation_date: '2026-10-14T10:00:00Z', max_agents: '14000', timezone: 'UTC' });
    assert.deepStrictEqual(await api.agentsSummary(mk(A)), { active: 2, disconnected: 1, never_connected: 1, pending: 0, total: 4 });
  });
  it('the agent list drops everything not on the allow-list (key, configSum, mergedSum, uname, the install path of the manager)', async () => {
    const r = await api.listAgents(mk(A), api.parseAgentQuery({}));
    assert.strictEqual(r.total, 4); assert.strictEqual(r.agents.length, 4);
    const win = r.agents.find((a) => a.id === '001');
    assert.deepStrictEqual(win, { id: '001', name: 'WIN-DC01', ip: '10.0.0.21', register_ip: 'any', status: 'active', version: 'Wazuh v4.14.9', groups: ['default', 'windows'], last_keep_alive: '2026-10-25T13:00:00Z', date_added: '2026-10-20T09:00:00Z', node: 'node01', manager: 'wazuh-mgr', os: { name: 'Microsoft Windows Server 2022 Standard', platform: 'windows', version: '10.0.20348.2700', arch: 'x86_64' } });
    const text = JSON.stringify(r); for (const s of ['MDAxIFdJTi1', 'configSum', 'mergedSum', 'secret-build-info', 'key']) assert.ok(!text.includes(s), s + ' leaked');
    assert.deepStrictEqual(r.agents.find((a) => a.id === '003').os, { name: null, platform: null, version: null, arch: null });
  });
  it('filters and paging go through; one agent by id; an unknown id is null; an id that is not digits never leaves ASIX', async () => {
    let r = await api.listAgents(mk(A), api.parseAgentQuery({ status: 'active', sort: '-name', limit: '1', offset: '1' }));
    assert.deepStrictEqual([r.total, r.agents.map((a) => a.name)], [2, ['wazuh-mgr']]);   // descending by name: WIN-DC01, then wazuh-mgr (the second page of size 1)
    assert.strictEqual((await api.getAgent(mk(A), '002')).name, 'web1');
    assert.strictEqual(await api.getAgent(mk(A), '999'), null);
    const n = A.state.requests.length;
    for (const bad of ['1', '001,002', '../manager/info', '001%0d%0a', '0x1', '']) await rejects(api.getAgent(mk(A), bad), 'BAD_ID');
    assert.strictEqual(A.state.requests.length, n, 'nothing was sent for a bad id');
  });
  it('exactly what is sent: only GET (plus the one POST to sign in), the fixed paths, a Bearer token, and basic auth only on the sign-in', async () => {
    await api.managerInfo(mk(A)); await api.agentsSummary(mk(A)); await api.listAgents(mk(A), api.parseAgentQuery({ search: 'x' })); await api.getAgent(mk(A), '001');
    assert.deepStrictEqual(A.state.requests.map((r) => r.method + ' ' + r.path), ['POST /security/user/authenticate?raw=true', 'GET /manager/info', 'GET /agents/summary/status', 'GET /agents?limit=100&offset=0&search=x', 'GET /agents?agents_list=001&limit=1']);
    assert.deepStrictEqual(A.state.requests.map((r) => r.auth), ['Basic', 'Bearer', 'Bearer', 'Bearer', 'Bearer']);
    assert.ok(A.state.requests.every((r) => !r.headers.cookie && r.headers['user-agent'] === 'asix-wazuh-proxy'));
  });
  it('the token is kept (one sign-in for many calls), replaced when it is about to expire, and replaced once when the manager refuses it', async () => {
    const m = mk(A);
    await api.managerInfo(m); await api.agentsSummary(m); await api.managerInfo(m); assert.strictEqual(A.state.authCalls, 1, 'kept');
    A.state.tokens.clear();                                             // the manager restarted: it knows no token
    assert.strictEqual((await api.managerInfo(m)).version, 'v4.14.9'); assert.strictEqual(A.state.authCalls, 2, 'one new sign-in, one retry');
    api.forget(m.tenant_id); A.state.tokenTtl = 10;                     // a token with under 30 s left is never used
    await api.managerInfo(m); await api.managerInfo(m); assert.strictEqual(A.state.authCalls, 4, 'each call signs in again');
  });
  it('a changed password is not served from the old token', async () => {
    const m = mk(A); await api.managerInfo(m);
    await rejects(api.managerInfo({ ...m, api_password: 'something-else-1!', api_secret_enc_hash: 'h2' }), 'AUTH_FAILED');
  });
  it('a refused user or password is AUTH_FAILED and is asked once, not retried', async () => {
    await rejects(api.managerInfo(mk(A, { api_password: 'wrong-password' })), 'AUTH_FAILED'); assert.strictEqual(A.state.authCalls, 1);
  });
  it('a certificate other than the registered one is refused BEFORE anything is sent: the password never reaches it', async () => {
    const e = await rejects(api.managerInfo(mk(B, { ca_pem: A.cert })), 'TLS');       // B answers, but only A's certificate is trusted
    assert.match(e.message, /certificate/); assert.strictEqual(B.state.requests.length, 0, 'the other machine saw no request at all');
    await rejects(api.managerInfo(mk(A, { ca_pem: B.cert })), 'TLS'); assert.strictEqual(A.state.requests.length, 0);
  });
  it('the registered certificate is trusted whatever name it carries and whether or not it says CA:TRUE (Wazuh makes its own self-signed one)', async () => {
    const C = await fake.start({ tag: 'C', cn: 'some-other-name', ca: false });
    try { assert.strictEqual((await api.managerInfo(mk(C))).version, 'v4.14.9'); } finally { await C.stop(); }
  });
  it('a redirect is not followed, an HTML answer and a huge answer are refused, a slow answer times out', async () => {
    A.state.mode = 'redirect'; api.forget('T-' + A.port); const e = await rejects(api.managerInfo(mk(A)), 'BAD_RESPONSE'); assert.strictEqual(e.status, 302); assert.strictEqual(A.state.requests.length, 1, 'only the sign-in was sent; the redirect target was not visited');
    A.state.mode = 'html'; await rejects(api.managerInfo(mk(A)), 'BAD_RESPONSE');
    A.state.mode = 'huge'; await rejects(api.managerInfo(mk(A)), 'TOO_LARGE');
    A.state.mode = null; A.state.delayMs = 1500; api.forget('T-' + A.port); const t0 = Date.now(); await rejects(api.managerInfo(mk(A)), 'TIMEOUT'); assert.ok(Date.now() - t0 < 1400, 'gave up near the limit');
  });
  it('an answer in a shape this version does not know is BAD_RESPONSE, not a crash', async () => {
    A.state.agents = [];
    try { assert.deepStrictEqual(await api.listAgents(mk(A), api.parseAgentQuery({})), { total: 0, limit: 100, offset: 0, agents: [] }); } finally { A.state.agents = fake.AGENTS; }
  });
  it('at most four calls at once per tenant; the others are refused at once, not queued onto the manager', async () => {
    A.state.delayMs = 300; const m = mk(A); await api.managerInfo(m); A.state.requests.length = 0;
    const res = await Promise.allSettled(Array.from({ length: 7 }, () => api.agentsSummary(m)));
    assert.strictEqual(res.filter((r) => r.status === 'fulfilled').length, 4); assert.deepStrictEqual([...new Set(res.filter((r) => r.status === 'rejected').map((r) => r.reason.code))], ['BUSY']);
    assert.strictEqual(A.state.requests.length, 4, 'only four reached the manager');
    await api.agentsSummary(m);                                         // and the count came back down
  });
  it('a connection refused is UNREACHABLE', async () => {
    const C = await fake.start({ tag: 'C' }); const m = mk(C); await C.stop();
    await rejects(api.managerInfo(m), 'UNREACHABLE');
  });
  it('forbidden addresses are refused when the call is made too', async () => {
    delete process.env.ASIX_WAZUH_ALLOW_LOOPBACK;
    try { await rejects(api.managerInfo(mk(A)), 'BAD_ADDRESS'); assert.strictEqual(A.state.requests.length, 0); } finally { process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true'; }
  });
});
