'use strict';
// The read-only proxy to a tenant's central Wazuh manager API (docs/endpoints.md, task E4c).
//
// WHAT "TENANT FILTER" MEANS HERE. Every tenant that has a central manager has its OWN manager (one dedicated manager per tenant, decided 2026-10-23), so the filter is not a
// query condition: it is that a call can only ever reach the manager registered to the caller's own tenant (the row is read under row security, see wazuh-manager-store.js),
// and that nothing the caller sends decides where the call goes or what it asks for:
//   - the address, user, password and certificate come from the registry row, never from a request;
//   - the method is always GET and the path comes from the four fixed paths below; an agent id is digits only;
//   - the query string is built from a short list of validated parameters and anything else is refused (parseAgentQuery), so a caller cannot ask for `q=`, another
//     `select`, a group or any other Wazuh API feature;
//   - the answer is rebuilt from an allow-list of fields, so what the manager adds in a later version (and fields such as configSum and mergedSum) is never passed on;
//   - the connection trusts ONLY the manager's own certificate that was stored at registration (self-signed, so the usual public CA check would fail; pinning it is stricter),
//     follows no redirects, has a timeout and a size cap, and never goes to a loopback, link-local or metadata address.
// A shared manager with one agent group per tenant (the option for tiny clients, "later, if ever") would add a forced `group` here; it is not built.
//
// The Wazuh API is used as documented for 4.x: POST /security/user/authenticate?raw=true with basic auth answers a JWT (default lifetime 15 minutes), then
// GET /manager/info, GET /agents/summary/status, GET /agents (with agents_list, status, search, sort, limit, offset ...) with `Authorization: Bearer <jwt>`.
// NOT checked against a real manager (none was available): see docs/endpoints.md, "E4c as built".
const https = require('https');
const dns = require('dns');
const net = require('net');
const netGuard = require('../notifications/net-guard');

const TIMEOUT_MS = Number(process.env.ASIX_WAZUH_API_TIMEOUT_MS || 8000);
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_IN_FLIGHT = 4;                          // calls at once per tenant: the manager is a busy machine, a page of the portal must not be able to pile calls onto it
const TOKEN_MARGIN_S = 30;                        // a token with less life than this is replaced before use
const DEFAULT_TOKEN_S = 600;                      // when the token carries no readable expiry
const LIMIT_DEFAULT = 100, LIMIT_MAX = 500;
const STATUSES = ['active', 'disconnected', 'never_connected', 'pending'];
const SORT_FIELDS = ['id', 'name', 'ip', 'status', 'version', 'lastKeepAlive', 'dateAdd'];

class WazuhApiError extends Error {
  constructor(code, message, status) { super(message); this.name = 'WazuhApiError'; this.code = code; this.status = status || 0; }
}

// --- where it may connect ------------------------------------------------------------------------------------------------------------------
// A manager lives on a private address (a VM in the ASIX network), so private ranges are allowed here, unlike the notification senders. Loopback, link-local (including the
// cloud metadata address), unspecified, multicast and reserved addresses are not. ASIX_WAZUH_ALLOW_LOOPBACK=true lifts the loopback rule for a lab where the manager is on
// the same machine as the API (and for the tests); nothing else is lifted.
const allowLoopback = () => process.env.ASIX_WAZUH_ALLOW_LOOPBACK === 'true';
function addressOk(ip) {
  if (allowLoopback() && (ip === '::1' || /^127\./.test(ip))) return true;
  return netGuard.classify(ip) !== 'blocked';
}
const blocked = (host) => new WazuhApiError('BLOCKED_ADDRESS', host + ' is not an address the manager proxy may connect to (loopback, link-local, metadata and reserved addresses are refused)');
function guardedLookup(hostname, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err);
    if (!addrs.length || addrs.some((a) => !addressOk(a.address))) return cb(blocked(hostname));
    return options && options.all ? cb(null, addrs) : cb(null, addrs[0].address, addrs[0].family);
  });
}
// Static check of a registered URL (no DNS), shared with the registration: https, a host and a port, nothing else.
function checkApiUrl(raw) {
  let u;
  try { u = new URL(String(raw)); } catch { return { error: 'The manager API address is not a valid URL' }; }
  if (u.protocol !== 'https:') return { error: 'The manager API address must start with https://' };
  if (u.username || u.password) return { error: 'The manager API address must not contain a user name or password' };
  if ((u.pathname && u.pathname !== '/') || u.search || u.hash) return { error: 'The manager API address must be just https://host:port' };
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (!host) return { error: 'The manager API address has no host' };
  if (/^localhost$/i.test(host) && !allowLoopback()) return { error: 'localhost is not an address the manager proxy may connect to' };
  if (net.isIP(host) && !addressOk(host)) return { error: host + ' is not an address the manager proxy may connect to (loopback, link-local, metadata and reserved addresses are refused)' };
  return { origin: 'https://' + u.host, host, port: Number(u.port || 443) };
}

// --- one HTTPS exchange ---------------------------------------------------------------------------------------------------------------------
// ca = the manager's own certificate: it is the ONLY trust anchor, so the handshake fails (before anything is sent, the password included) for any other certificate.
// The host name is not compared (the certificate Wazuh makes for itself names whatever its installer put there); pinning the exact certificate is the stronger check.
function exchange(m, { method = 'GET', path, headers = {} }) {
  return new Promise((resolve, reject) => {
    const u = checkApiUrl(m.api_url);
    if (u.error) return reject(new WazuhApiError('BAD_ADDRESS', u.error));
    let done = false; const finish = (fn, v) => { if (!done) { done = true; fn(v); } };
    const req = https.request({
      host: u.host, port: u.port, path, method, agent: false, timeout: TIMEOUT_MS, lookup: guardedLookup,
      ca: m.ca_pem, rejectUnauthorized: true, checkServerIdentity: () => undefined, minVersion: 'TLSv1.2',
      headers: { Accept: 'application/json', 'User-Agent': 'asix-wazuh-proxy', ...headers },
    }, (res) => {
      const chunks = []; let n = 0;
      res.on('data', (c) => {
        n += c.length;
        if (n > MAX_BYTES) { res.destroy(); finish(reject, new WazuhApiError('TOO_LARGE', 'The manager answered with more than ' + (MAX_BYTES / 1048576) + ' MB')); } else chunks.push(c);
      });
      res.on('end', () => finish(resolve, { status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', (e) => finish(reject, mapNetError(e)));
    });
    req.on('timeout', () => { req.destroy(); finish(reject, new WazuhApiError('TIMEOUT', 'The manager did not answer within ' + Math.round(TIMEOUT_MS / 1000) + ' seconds')); });
    req.on('error', (e) => finish(reject, mapNetError(e)));
    req.end();
  });
}
function mapNetError(e) {
  if (e instanceof WazuhApiError) return e;
  if (e && e.code === 'BLOCKED_ADDRESS') return e;
  const c = e && e.code ? String(e.code) : '';
  if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS|ERR_SSL|HOSTNAME_MISMATCH/.test(c) || /certificate|self.signed|handshake|wrong version number/i.test(e && e.message)) return new WazuhApiError('TLS', 'The manager\'s certificate is not the one registered (it was replaced, or something else answers at that address)');
  if (/ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|ENETUNREACH|ECONNRESET|EAI_AGAIN|EPIPE/.test(c)) return new WazuhApiError('UNREACHABLE', 'The manager cannot be reached (' + c + ')');
  return new WazuhApiError('UNREACHABLE', 'The manager cannot be reached' + (c ? ' (' + c + ')' : ''));
}

// --- the token ------------------------------------------------------------------------------------------------------------------------------
const tokens = new Map();                         // tenant_id -> { key, token, exp (ms) }; per API process, forgotten on restart
const inFlight = new Map();
const credKey = (m) => [m.api_url, m.api_user, m.cert_sha256 || '', m.api_secret_enc_hash || ''].join('|');

function jwtExpiry(t) {
  try { const p = JSON.parse(Buffer.from(String(t).split('.')[1], 'base64url').toString('utf8')); if (Number.isFinite(p.exp)) return p.exp * 1000; } catch { /* not a readable token */ }
  return Date.now() + DEFAULT_TOKEN_S * 1000;
}
async function token(m, force) {
  const have = tokens.get(m.tenant_id);
  if (!force && have && have.key === credKey(m) && have.exp - Date.now() > TOKEN_MARGIN_S * 1000) return have.token;
  const basic = Buffer.from(m.api_user + ':' + m.api_password, 'utf8').toString('base64');
  const r = await exchange(m, { method: 'POST', path: '/security/user/authenticate?raw=true', headers: { Authorization: 'Basic ' + basic } });
  if (r.status === 401 || r.status === 403) { tokens.delete(m.tenant_id); throw new WazuhApiError('AUTH_FAILED', 'The manager refused the registered API user and password', r.status); }
  const t = r.text.trim();
  if (r.status !== 200 || !/^[A-Za-z0-9._-]{20,4096}$/.test(t)) throw new WazuhApiError('BAD_RESPONSE', 'The manager answered the sign-in with an unexpected reply (HTTP ' + r.status + ')', r.status);
  tokens.set(m.tenant_id, { key: credKey(m), token: t, exp: jwtExpiry(t) });
  return t;
}
const forget = (tenantId) => tokens.delete(tenantId);

// A GET on one of the fixed paths. One retry with a new token when the manager says 401 (it was restarted, or the token expired early).
async function get(m, path) {
  const n = inFlight.get(m.tenant_id) || 0;
  if (n >= MAX_IN_FLIGHT) throw new WazuhApiError('BUSY', 'Too many calls to this manager at once, try again in a moment');
  inFlight.set(m.tenant_id, n + 1);
  try {
    for (let attempt = 0; ; attempt++) {
      const t = await token(m, attempt > 0);
      const r = await exchange(m, { path, headers: { Authorization: 'Bearer ' + t } });
      if (r.status === 401 && attempt === 0) { forget(m.tenant_id); continue; }
      if (r.status === 401 || r.status === 403) throw new WazuhApiError('AUTH_FAILED', r.status === 403 ? 'The registered API user may not read this (its role needs read access to agents and the manager)' : 'The manager refused the registered API user and password', r.status);
      let json = null; try { json = JSON.parse(r.text); } catch { /* checked below */ }
      if (r.status !== 200 || !json || typeof json !== 'object') throw new WazuhApiError('BAD_RESPONSE', 'The manager answered with an unexpected reply (HTTP ' + r.status + ')', r.status);
      return json;
    }
  } finally {
    const left = (inFlight.get(m.tenant_id) || 1) - 1; if (left > 0) inFlight.set(m.tenant_id, left); else inFlight.delete(m.tenant_id);
  }
}

// --- what a caller may ask ------------------------------------------------------------------------------------------------------------------
const AGENT_ID_RE = /^[0-9]{3,8}$/;
const PARAMS = ['limit', 'offset', 'status', 'search', 'sort', 'os_platform'];
// Query of GET /v1/endpoints/agents -> the query string for the manager. Returns { error } or { query: 'limit=100&offset=0...', limit, offset }.
function parseAgentQuery(q) {
  q = q && typeof q === 'object' ? q : {};
  for (const k of Object.keys(q)) if (!PARAMS.includes(k)) return { error: 'Unknown parameter "' + String(k).slice(0, 40) + '". Allowed: ' + PARAMS.join(', ') };
  const one = (k) => (Array.isArray(q[k]) ? undefined : q[k]);
  for (const k of PARAMS) if (q[k] !== undefined && one(k) === undefined) return { error: k + ' can be given once' };
  const int = (k, def, min, max) => {
    if (q[k] === undefined || q[k] === '') return def;
    if (!/^[0-9]{1,9}$/.test(String(q[k]))) return NaN;
    const v = Number(q[k]); return v < min || v > max ? NaN : v;
  };
  const limit = int('limit', LIMIT_DEFAULT, 1, LIMIT_MAX), offset = int('offset', 0, 0, 1000000);
  if (Number.isNaN(limit)) return { error: 'limit must be a whole number from 1 to ' + LIMIT_MAX };
  if (Number.isNaN(offset)) return { error: 'offset must be a whole number from 0 to 1000000' };
  const p = new URLSearchParams(); p.set('limit', String(limit)); p.set('offset', String(offset));
  if (q.status !== undefined && q.status !== '') {
    const list = String(q.status).split(',');
    if (list.length > STATUSES.length || list.some((s) => !STATUSES.includes(s))) return { error: 'status must be one or more of ' + STATUSES.join(', ') + ' (comma separated)' };
    p.set('status', [...new Set(list)].join(','));
  }
  if (q.search !== undefined && q.search !== '') {
    const s = String(q.search);
    if (s.length > 100 || /[\u0000-\u001f\u007f]/.test(s)) return { error: 'search must be text of at most 100 characters' };
    p.set('search', s);
  }
  if (q.sort !== undefined && q.sort !== '') {
    const m = /^([+-]?)([A-Za-z]+)$/.exec(String(q.sort));
    if (!m || !SORT_FIELDS.includes(m[2])) return { error: 'sort must be one of ' + SORT_FIELDS.join(', ') + ', optionally with a leading - for descending' };
    p.set('sort', (m[1] === '-' ? '-' : '+') + m[2]);
  }
  if (q.os_platform !== undefined && q.os_platform !== '') {
    if (!/^[A-Za-z0-9._ -]{1,30}$/.test(String(q.os_platform))) return { error: 'os_platform must be 1 to 30 letters, digits, dots, dashes or spaces' };
    p.set('os.platform', String(q.os_platform));
  }
  return { query: p.toString(), limit, offset };
}

// --- what is passed on ----------------------------------------------------------------------------------------------------------------------
const txt = (v, n = 200) => (typeof v === 'string' || typeof v === 'number' ? String(v).slice(0, n) : null);
function shapeAgent(a) {
  if (!a || typeof a !== 'object') return null;
  const os = a.os && typeof a.os === 'object' ? a.os : {};
  return {
    id: txt(a.id, 20), name: txt(a.name), ip: txt(a.ip, 64), register_ip: txt(a.registerIP, 64), status: txt(a.status, 30), version: txt(a.version, 60),
    groups: Array.isArray(a.group) ? a.group.slice(0, 20).map((g) => txt(g, 100)).filter(Boolean) : [],
    last_keep_alive: txt(a.lastKeepAlive, 40), date_added: txt(a.dateAdd, 40), node: txt(a.node_name, 100), manager: txt(a.manager, 100),
    os: { name: txt(os.name), platform: txt(os.platform, 40), version: txt(os.version, 60), arch: txt(os.arch, 30) },
  };
}
const items = (j) => (j && j.data && Array.isArray(j.data.affected_items) ? j.data.affected_items : null);
const bad = () => new WazuhApiError('BAD_RESPONSE', 'The manager answered with a shape this version of ASIX does not know');
const count = (v) => (Number.isInteger(v) && v >= 0 ? v : null);

async function managerInfo(m) {
  const j = await get(m, '/manager/info'), it = items(j);
  if (!it || !it[0] || typeof it[0] !== 'object') throw bad();
  const i = it[0];
  return { version: txt(i.version, 40), compilation_date: txt(i.compilation_date, 40), max_agents: txt(i.max_agents, 20), timezone: txt(i.tz_name, 60) };
}
async function agentsSummary(m) {
  const j = await get(m, '/agents/summary/status'), d = j && j.data;
  const c = d && (d.connection || d); if (!c || typeof c !== 'object') throw bad();
  const out = {}; for (const k of ['active', 'disconnected', 'never_connected', 'pending', 'total']) out[k] = count(c[k]) ?? 0;
  return out;
}
async function listAgents(m, parsed) {
  const j = await get(m, '/agents?' + parsed.query), it = items(j);
  if (!it) throw bad();
  return { total: count(j.data.total_affected_items) ?? it.length, limit: parsed.limit, offset: parsed.offset, agents: it.map(shapeAgent).filter(Boolean) };
}
// null when the manager has no such agent
async function getAgent(m, id) {
  if (!AGENT_ID_RE.test(String(id))) throw new WazuhApiError('BAD_ID', 'An agent id is 3 to 8 digits');
  const j = await get(m, '/agents?agents_list=' + String(id) + '&limit=1'), it = items(j);
  if (!it) throw bad();
  const a = it.find((x) => x && String(x.id) === String(id));
  return a ? shapeAgent(a) : null;
}

module.exports = { WazuhApiError, checkApiUrl, addressOk, guardedLookup, parseAgentQuery, managerInfo, agentsSummary, listAgents, getAgent, forget, AGENT_ID_RE, LIMIT_MAX, STATUSES, SORT_FIELDS, shapeAgent, _tokens: tokens };
