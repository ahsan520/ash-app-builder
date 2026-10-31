'use strict';
// A stand-in for the Wazuh manager API over HTTPS with its own self-signed certificate, written from the documented shape of Wazuh 4.x (NOT captured from a real manager):
//   POST /security/user/authenticate?raw=true   basic auth -> the JWT as plain text
//   GET  /manager/info, /agents/summary/status, /agents (agents_list, status, search, sort, limit, offset, os.platform)   Authorization: Bearer <jwt>
//   GET  /sca/<agent>, /sca/<agent>/checks/<policy> (limit, offset, sort, search, result)   (E6f; the documented 4.x shape, with extra fields a real manager sends that must NOT be passed on)
// It records every request so a test can say exactly what the proxy asked for, and has switches for the awkward cases.
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

function makeCert(dir, { cn = 'wazuh-test', days = 30, ca = true } = {}) {
  const key = path.join(dir, cn + '.key'), crt = path.join(dir, cn + '.crt');
  const args = ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', crt, '-days', String(days), '-subj', '/CN=' + cn,
    '-addext', ca ? 'basicConstraints=critical,CA:TRUE' : 'basicConstraints=critical,CA:FALSE'];
  const r = spawnSync('openssl', args, { encoding: 'utf8' });
  if (r.status !== 0) throw new Error('openssl failed: ' + r.stderr);
  return { key: fs.readFileSync(key, 'utf8'), cert: fs.readFileSync(crt, 'utf8'), keyFile: key, certFile: crt };
}
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (ttlS, sub) => b64({ alg: 'HS256', typ: 'JWT' }) + '.' + b64({ iss: 'wazuh', sub, exp: Math.floor(Date.now() / 1000) + ttlS }) + '.' + crypto.randomBytes(24).toString('base64url');

const AGENTS = [
  { id: '000', name: 'wazuh-mgr', ip: '127.0.0.1', status: 'active', version: 'Wazuh v4.14.9', node_name: 'node01', manager: 'wazuh-mgr' },
  { id: '001', name: 'WIN-DC01', ip: '10.0.0.21', registerIP: 'any', status: 'active', status_code: 0, version: 'Wazuh v4.14.9', group: ['default', 'windows'], lastKeepAlive: '2026-10-25T13:00:00Z', dateAdd: '2026-10-20T09:00:00Z',
    node_name: 'node01', manager: 'wazuh-mgr', configSum: 'abc', mergedSum: 'def', os: { name: 'Microsoft Windows Server 2022 Standard', platform: 'windows', version: '10.0.20348.2700', arch: 'x86_64', major: '10', uname: 'secret-build-info' }, key: 'MDAxIFdJTi1EQzAxIDEwLjAuMC4yMSBzdXBlcnNlY3JldA==' },
  { id: '002', name: 'web1', ip: '10.0.0.30', registerIP: 'any', status: 'disconnected', version: 'Wazuh v4.14.8', group: ['default'], lastKeepAlive: '2026-10-24T08:00:00Z', dateAdd: '2026-10-21T09:00:00Z', node_name: 'node01', manager: 'wazuh-mgr', os: { name: 'Ubuntu', platform: 'ubuntu', version: '24.04', arch: 'x86_64' } },
  { id: '003', name: 'WS-0042', ip: '10.0.1.42', status: 'never_connected', version: null, group: ['default'], dateAdd: '2026-10-22T09:00:00Z', node_name: 'unknown', manager: 'wazuh-mgr' },
];

// E6f: what the manager has for configuration checks, per agent id. `hash_file` and the references on a policy, and `rules`, are fields a real manager sends that the proxy leaves out.
const check = (id, title, result, extra = {}) => ({ id, policy_id: 'cis_win11', title, description: 'About ' + title, rationale: 'Because ' + title, remediation: 'Fix ' + title, command: null, reason: null,
  file: null, directory: null, process: null, registry: null, references: ['https://www.cisecurity.org/cis-benchmarks'], condition: 'all', result, compliance: [{ key: 'cis', value: '1.1.' + id }, { key: 'pci_dss', value: '2.2' }],
  rules: [{ type: 'registry', rule: 'r:HKLM\\SOFTWARE\\X' }], ...extra });
const SCA = {
  '001': [
    { policy_id: 'cis_win11', name: 'CIS Microsoft Windows 11 Enterprise Benchmark', description: 'Guidance for secure configuration.', references: ['https://www.cisecurity.org/'], pass: 2, fail: 2, invalid: 1, total_checks: 5, score: 50,
      start_scan: '2026-10-30T10:00:00Z', end_scan: '2026-10-30T10:02:00Z', hash_file: 'deadbeef', checks: [
        check(26000, 'Ensure Password history is set to 24 or more', 'failed', { remediation: 'Set it in Group Policy.' }), check(26001, 'Ensure Minimum password length is 14 or more', 'passed'),
        check(26002, 'Ensure Account lockout duration is 15 or more', 'failed', { reason: 'Could not read the registry', registry: 'HKLM\\SOFTWARE\\Policies' }), check(26003, 'Ensure Guest account is disabled', 'passed'),
        check(26004, 'Ensure BitLocker is enabled', 'not applicable', { reason: 'Not a laptop' })] },
    { policy_id: 'sca_distro_independent_linux', name: 'Generic Linux checks', description: 'Checks for any Linux.', pass: 1, fail: 0, invalid: 0, total_checks: 1, score: 100, start_scan: '2026-10-30T10:03:00Z', end_scan: '2026-10-30T10:03:30Z', hash_file: 'f00', checks: [check(100, 'Ensure SSH root login is disabled', 'passed', { policy_id: 'sca_distro_independent_linux' })] },
  ],
  '002': [],
};

async function start({ user = 'asix-readonly', password = 'Str0ng-pw!', cn = 'wazuh-test', ca = true, tokenTtl = 900, dir, agents = AGENTS, tag = 'A', security = false, sca = SCA } = {}) {
  dir = dir || fs.mkdtempSync(path.join(os.tmpdir(), 'fakewazuh-'));
  const c = makeCert(dir, { cn, ca });
  const state = { requests: [], tokens: new Set(), authCalls: 0, failAuth: false, delayMs: 0, mode: null, rejectTokens: false, tokenTtl, agents, tokenUser: new Map(), refuse: new Set(), nextId: 100, sca };
  // security mode: a fresh manager as Wazuh ships it, with the two well-known users and the default roles. Passwords are checked as given, the policy of the real API
  // (8 to 64 characters with an upper case letter, a lower case letter, a digit and a symbol) is applied to every new password, and `readonly` may read but not touch /security.
  state.users = security ? new Map([['wazuh', { id: 1, password: 'wazuh', roles: [1] }], ['wazuh-wui', { id: 2, password: 'wazuh-wui', roles: [1] }]]) : new Map([[user, { id: 3, password, roles: [2] }]]);
  state.roles = [{ id: 1, name: 'administrator' }, { id: 2, name: 'readonly' }];
  const strong = (p) => typeof p === 'string' && p.length >= 8 && p.length <= 64 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p);
  const srv = https.createServer({ key: c.key, cert: c.cert }, (req, res) => {
    const u = new URL(req.url, 'https://x');
    state.requests.push({ method: req.method, path: req.url, auth: req.headers.authorization ? req.headers.authorization.split(' ')[0] : null, headers: req.headers });
    const send = (status, body, type = 'application/json') => { const t = typeof body === 'string' ? body : JSON.stringify(body); setTimeout(() => { res.writeHead(status, { 'content-type': type }); res.end(t); }, state.delayMs); };
    if (state.mode === 'redirect') { res.writeHead(302, { location: 'https://127.0.0.1:1/elsewhere' }); return res.end(); }
    if (state.mode === 'huge') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{"data":"' + 'x'.repeat(3 * 1024 * 1024) + '"}'); }
    if (state.mode === 'html') return send(200, '<html>not the API</html>', 'text/html');
    if (req.method === 'POST' && u.pathname === '/security/user/authenticate') {
      state.authCalls++;
      const m = /^Basic (.+)$/.exec(req.headers.authorization || '');
      const [bu, ...bp] = m ? Buffer.from(m[1], 'base64').toString('utf8').split(':') : [];
      const rec = state.users.get(bu);
      if (state.failAuth || !rec || rec.password !== bp.join(':')) return send(401, { title: 'Unauthorized', detail: 'Invalid credentials' });
      const t = jwt(state.tokenTtl, bu); state.tokens.add(t); state.tokenUser.set(t, bu);
      return send(200, t, 'text/plain');
    }
    const bearer = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    if (!bearer || !state.tokens.has(bearer[1]) || state.rejectTokens) return send(401, { title: 'Unauthorized', detail: 'Invalid token' });
    const who = state.users.get(state.tokenUser.get(bearer[1])) || { roles: [] }, isAdmin = who.roles.includes(1), canRead = isAdmin || who.roles.includes(2);
    const items = (a) => ({ data: { affected_items: a, total_affected_items: a.length, total_failed_items: 0, failed_items: [] }, message: 'ok', error: 0 });
    if (u.pathname.startsWith('/security/')) {
      if (!isAdmin) return send(403, { title: 'Permission Denied' });
      if (req.method === 'GET' && u.pathname === '/security/users') return send(200, items([...state.users].map(([n, r]) => ({ id: r.id, username: n, allow_run_as: false, roles: r.roles }))));
      if (req.method === 'GET' && u.pathname === '/security/roles') return send(200, items(state.roles));
      let body = ''; req.on('data', (c) => { body += c; });
      return req.on('end', () => {
        let j = {}; try { j = JSON.parse(body || '{}'); } catch { return send(400, { title: 'Bad request' }); }
        if (state.refuse.has(req.method + ' ' + u.pathname)) return send(500, { title: 'refused on purpose' });
        let m;
        if (req.method === 'POST' && u.pathname === '/security/users') {
          if (!strong(j.password)) return send(400, { title: 'Bad Request', detail: 'Invalid password' });
          if (state.users.has(j.username)) return send(400, { title: 'Bad Request', detail: 'exists' });
          state.users.set(j.username, { id: state.nextId++, password: j.password, roles: [] }); return send(200, items([{ username: j.username }]));
        }
        if (req.method === 'PUT' && (m = /^\/security\/users\/(\d+)$/.exec(u.pathname))) {
          const e = [...state.users].find(([, r]) => r.id === Number(m[1])); if (!e) return send(404, { title: 'Not found' });
          if (!strong(j.password)) return send(400, { title: 'Bad Request', detail: 'Invalid password' });
          e[1].password = j.password; return send(200, items([{ id: e[1].id }]));
        }
        if (req.method === 'POST' && (m = /^\/security\/users\/(\d+)\/roles$/.exec(u.pathname))) {
          const e = [...state.users].find(([, r]) => r.id === Number(m[1])); if (!e) return send(404, { title: 'Not found' });
          for (const rid of String(u.searchParams.get('role_ids') || '').split(',')) if (rid && !e[1].roles.includes(Number(rid))) e[1].roles.push(Number(rid));
          return send(200, items([{ id: e[1].id }]));
        }
        send(404, { title: 'Not found' });
      });
    }
    if (!canRead) return send(403, { title: 'Permission Denied' });
    if (req.method !== 'GET') return send(405, { title: 'Method not allowed' });
    if (u.pathname === '/manager/info') return send(200, { data: { affected_items: [{ version: 'v4.14.9', compilation_date: '2026-10-14T10:00:00Z', type: 'server', max_agents: '14000', openssl_support: 'yes', tz_offset: '+0000', tz_name: 'UTC', path: '/var/ossec' }], total_affected_items: 1, total_failed_items: 0, failed_items: [] }, message: 'ok', error: 0 });
    if (u.pathname === '/agents/summary/status') { const n = (s) => state.agents.filter((a) => a.status === s).length; return send(200, { data: { connection: { active: n('active'), disconnected: n('disconnected'), never_connected: n('never_connected'), pending: n('pending'), total: state.agents.length }, configuration: { synced: 1 } }, error: 0 }); }
    let sm;
    if ((sm = /^\/sca\/(\d+)$/.exec(u.pathname))) {
      const pols = state.sca[sm[1]];
      if (!pols) return send(200, { data: { affected_items: [], total_affected_items: 0, total_failed_items: 1, failed_items: [{ error: { code: 1701, message: 'Agent does not exist' }, id: [sm[1]] }] }, message: 'no', error: 1 });
      const out = pols.map(({ checks, ...p }) => p), lim = Number(u.searchParams.get('limit') || 500);
      return send(200, { data: { affected_items: out.slice(0, lim), total_affected_items: out.length, total_failed_items: 0, failed_items: [] }, message: 'ok', error: 0 });
    }
    if ((sm = /^\/sca\/(\d+)\/checks\/([^/]+)$/.exec(u.pathname))) {
      const pol = (state.sca[sm[1]] || []).find((p) => p.policy_id === decodeURIComponent(sm[2]));
      if (!pol) return send(200, { data: { affected_items: [], total_affected_items: 0, total_failed_items: 1, failed_items: [{ error: { code: 1802, message: 'Policy not found' } }] }, message: 'no', error: 1 });
      let list = pol.checks.slice(); const q = u.searchParams;
      if (q.get('result')) list = list.filter((c) => c.result === q.get('result'));
      if (q.get('search')) list = list.filter((c) => JSON.stringify(c).toLowerCase().includes(q.get('search').toLowerCase()));
      if (q.get('sort')) { const s = q.get('sort'), desc = s.startsWith('-'), f = s.replace(/^[+-]/, ''); list.sort((a, b) => String(a[f]).localeCompare(String(b[f]), undefined, { numeric: true }) * (desc ? -1 : 1)); }
      const total = list.length, off = Number(q.get('offset') || 0), lim = Number(q.get('limit') || 500);
      return send(200, { data: { affected_items: list.slice(off, off + lim), total_affected_items: total, total_failed_items: 0, failed_items: [] }, message: 'ok', error: 0 });
    }
    if (u.pathname === '/agents') {
      let list = state.agents.slice(); const q = u.searchParams;
      if (q.get('agents_list')) { const ids = q.get('agents_list').split(','); list = list.filter((a) => ids.includes(a.id)); }
      if (q.get('status')) { const st = q.get('status').split(','); list = list.filter((a) => st.includes(a.status)); }
      if (q.get('search')) list = list.filter((a) => JSON.stringify(a).toLowerCase().includes(q.get('search').toLowerCase()));
      if (q.get('os.platform')) list = list.filter((a) => a.os && a.os.platform === q.get('os.platform'));
      if (q.get('sort')) { const s = q.get('sort'), desc = s.startsWith('-'), f = s.replace(/^[+-]/, ''); list.sort((a, b) => String(a[f]).localeCompare(String(b[f])) * (desc ? -1 : 1)); }
      const total = list.length, off = Number(q.get('offset') || 0), lim = Number(q.get('limit') || 500);
      return send(200, { data: { affected_items: list.slice(off, off + lim), total_affected_items: total, total_failed_items: 0, failed_items: [] }, message: 'ok', error: 0 });
    }
    send(404, { title: 'Not found' });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { url: 'https://127.0.0.1:' + srv.address().port, port: srv.address().port, user, password, cert: c.cert, certFile: c.certFile, state, tag, dir,
    stop: () => new Promise((r) => { srv.closeAllConnections && srv.closeAllConnections(); srv.close(r); }) };
}
module.exports = { start, makeCert, AGENTS, SCA };
