'use strict';
// The read-only proxy to a tenant's central Wazuh indexer, for the Vulnerabilities tab (docs/endpoints.md, task E6e; sizing and set-up in docs/wazuh-indexer.md).
//
// WHY THERE IS AN INDEXER AT ALL. From Wazuh 4.8 the manager keeps the vulnerabilities it detects ONLY in the Wazuh indexer (index `wazuh-states-vulnerabilities-<manager name>`); the
// manager API no longer lists them. The indexer is NOT on the broker VM: ONE central indexer, run by ASIX staff on its own VM, receives the findings of every manager over TLS. ASIX
// events stay in ClickHouse or PostgreSQL; this indexer holds the findings and nothing else (no alerts, no archives).
//
// WHAT "TENANT FILTER" MEANS HERE (the same rule as src/endpoints/wazuh-api.js). A tenant has its OWN manager and therefore its OWN index, so the filter is not a query condition: it is
// that a call can only ever read the ONE index registered for the caller's tenant (the row is read under row security, see wazuh-indexer-store.js), as the indexer user registered for it
// (a role that may read that index and nothing else, docs/wazuh-indexer.md; this is a second wall, behind ASIX's own). Nothing the caller sends decides where the call goes or what it asks:
//   - the address, user, password, certificate and INDEX NAME come from the registry row, never from a request; the index name is exact (no wildcard), checked against a fixed shape;
//   - the paths are two fixed shapes: POST /<index>/_search and GET /<index>/_count; the search body is BUILT here from validated parameters, never taken from the request, so a caller
//     cannot send a script, another index, an aggregation of their own or a size above the limits;
//   - the answer is rebuilt from an allow-list of fields with every text cut to a length;
//   - the connection trusts ONLY the certificate stored at registration (the indexer's root CA from the Wazuh certificate tool, or its own certificate), follows no redirects, has a timeout and
//     a size cap, and never goes to a loopback, link-local or metadata address.
//
// Written from the documented Wazuh 4.8+ shape of the vulnerability state index (ECS-like fields: agent.id, agent.name, package.name, package.version, vulnerability.id,
// vulnerability.severity, vulnerability.score.base, vulnerability.detected_at ...) and the OpenSearch search API. NOT checked against a real Wazuh indexer (none was available):
// docs/endpoints.md, "E6e as built". A field that is missing from a document is shown as a dash, never an error.
const https = require('https');
const wazuhApi = require('./wazuh-api');

const TIMEOUT_MS = Number(process.env.ASIX_WAZUH_INDEXER_TIMEOUT_MS || 10000);
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_IN_FLIGHT = 3;                            // calls at once per tenant: the indexer is shared by every tenant
const LIMIT_DEFAULT = 50, LIMIT_MAX = 100;
const WINDOW_MAX = 10000;                           // OpenSearch's default index.max_result_window: from + size may not pass it
const INDEX_RE = /^wazuh-states-vulnerabilities-[a-z0-9][a-z0-9._-]{0,100}$/;
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SORTS = { score: 'vulnerability.score.base', detected: 'vulnerability.detected_at', package: 'package.name', agent: 'agent.name', cve: 'vulnerability.id', severity: 'vulnerability.severity' };
const AGENT_ID_RE = /^[0-9]{3,8}$/;
const CVE_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,59}$/;

class WazuhIndexerError extends Error {
  constructor(code, message, status) { super(message); this.name = 'WazuhIndexerError'; this.code = code; this.status = status || 0; }
}

// --- where it may connect ------------------------------------------------------------------------------------------------------------------
// Same rules as the manager proxy: https://host:port only, private ranges allowed (the indexer is a machine in the ASIX network), loopback, link-local (cloud metadata), unspecified,
// multicast and reserved refused (ASIX_WAZUH_ALLOW_LOOPBACK=true lifts only the loopback rule, for a lab and the tests).
function checkUrl(raw) {
  const r = wazuhApi.checkApiUrl(raw);
  if (r.error) return { error: r.error.replace(/manager API address/g, 'indexer address').replace(/the manager proxy/g, 'the indexer proxy') };
  return r;
}
function checkIndexName(name) {
  if (typeof name !== 'string' || !INDEX_RE.test(name)) return { error: 'index must be the exact name of the vulnerability index of this tenant\'s manager: wazuh-states-vulnerabilities-<manager name> in lower case, with no wildcard' };
  return { index: name };
}

// --- one HTTPS exchange ---------------------------------------------------------------------------------------------------------------------
function mapNetError(e) {
  if (e instanceof WazuhIndexerError) return e;
  if (e && e.code === 'BLOCKED_ADDRESS') return new WazuhIndexerError('BLOCKED_ADDRESS', String(e.message).replace(/the manager proxy/g, 'the indexer proxy'));
  const c = e && e.code ? String(e.code) : '';
  if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS|ERR_SSL|HOSTNAME_MISMATCH/.test(c) || /certificate|self.signed|handshake|wrong version number/i.test(e && e.message)) return new WazuhIndexerError('TLS', 'The indexer\'s certificate is not the one registered (it was replaced, or something else answers at that address)');
  return new WazuhIndexerError('UNREACHABLE', 'The indexer cannot be reached' + (c ? ' (' + c + ')' : ''));
}
function exchange(m, { method, path, body }) {
  return new Promise((resolve, reject) => {
    const u = checkUrl(m.index_url);
    if (u.error) return reject(new WazuhIndexerError('BAD_ADDRESS', u.error));
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body), 'utf8');
    const basic = Buffer.from(m.index_user + ':' + m.index_password, 'utf8').toString('base64');
    let done = false; const finish = (fn, v) => { if (!done) { done = true; fn(v); } };
    const req = https.request({
      host: u.host, port: u.port, path, method, agent: false, timeout: TIMEOUT_MS, lookup: wazuhApi.guardedLookup,
      ca: m.ca_pem, rejectUnauthorized: true, checkServerIdentity: () => undefined, minVersion: 'TLSv1.2',
      headers: { Accept: 'application/json', 'User-Agent': 'asix-wazuh-indexer-proxy', Authorization: 'Basic ' + basic, ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}) },
    }, (res) => {
      const chunks = []; let n = 0;
      res.on('data', (c) => {
        n += c.length;
        if (n > MAX_BYTES) { res.destroy(); finish(reject, new WazuhIndexerError('TOO_LARGE', 'The indexer answered with more than ' + (MAX_BYTES / 1048576) + ' MB')); } else chunks.push(c);
      });
      res.on('end', () => finish(resolve, { status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', (e) => finish(reject, mapNetError(e)));
    });
    req.on('timeout', () => { req.destroy(); finish(reject, new WazuhIndexerError('TIMEOUT', 'The indexer did not answer within ' + Math.round(TIMEOUT_MS / 1000) + ' seconds')); });
    req.on('error', (e) => finish(reject, mapNetError(e)));
    if (payload) req.write(payload);
    req.end();
  });
}

const inFlight = new Map();
// One of the two fixed calls. The index name is checked here as well as at registration, so a tampered row cannot make a different path.
async function call(m, kind, body) {
  const ix = checkIndexName(m.index_name); if (ix.error) throw new WazuhIndexerError('BAD_INDEX', 'The registered vulnerability index name is not valid: register the indexer again');
  const n = inFlight.get(m.tenant_id) || 0;
  if (n >= MAX_IN_FLIGHT) throw new WazuhIndexerError('BUSY', 'Too many calls to the indexer at once, try again in a moment');
  inFlight.set(m.tenant_id, n + 1);
  try {
    const r = kind === 'count' ? await exchange(m, { method: 'GET', path: '/' + ix.index + '/_count' }) : await exchange(m, { method: 'POST', path: '/' + ix.index + '/_search?ignore_unavailable=false&allow_no_indices=false', body });
    let json = null; try { json = JSON.parse(r.text); } catch { /* checked below */ }
    if (r.status === 401) throw new WazuhIndexerError('AUTH_FAILED', 'The indexer refused the registered user and password', 401);
    if (r.status === 403) throw new WazuhIndexerError('AUTH_FAILED', 'The registered indexer user may not read this index (its role needs read access to it)', 403);
    if (r.status === 404 && json && json.error && /index_not_found/.test(JSON.stringify(json.error).slice(0, 400))) throw new WazuhIndexerError('NO_INDEX', 'The indexer has no vulnerability index of that name yet: the manager has not sent any finding (vulnerability detection is off on it, or no machine has been scanned)', 404);
    if (r.status !== 200 || !json || typeof json !== 'object') throw new WazuhIndexerError('BAD_RESPONSE', 'The indexer answered with an unexpected reply (HTTP ' + r.status + ')', r.status);
    return json;
  } finally {
    const left = (inFlight.get(m.tenant_id) || 1) - 1; if (left > 0) inFlight.set(m.tenant_id, left); else inFlight.delete(m.tenant_id);
  }
}

// --- what a caller may ask ------------------------------------------------------------------------------------------------------------------
const FIELDS = ['limit', 'offset', 'severity', 'agent', 'q', 'cve', 'sort'];
const likeEscape = (s) => s.replace(/[\\*?]/g, (c) => '\\' + c);
// Query of GET /v1/endpoints/vulnerabilities -> { error } or { filters, q, cve, agent, severity, limit, offset, sort: { field, order } }. Used by the list AND the summary (which takes
// the filters only).
function parseQuery(q, { list = true } = {}) {
  q = q && typeof q === 'object' ? q : {};
  const allowed = list ? FIELDS : ['severity', 'agent', 'q', 'cve'];
  for (const k of Object.keys(q)) if (!allowed.includes(k)) return { error: 'Unknown parameter "' + String(k).slice(0, 40) + '". Allowed: ' + allowed.join(', ') };
  for (const k of allowed) if (Array.isArray(q[k])) return { error: k + ' can be given once' };
  const has = (k) => q[k] !== undefined && q[k] !== '';
  const int = (k, def, min, max) => {
    if (!has(k)) return def;
    if (!/^[0-9]{1,9}$/.test(String(q[k]))) return NaN;
    const v = Number(q[k]); return v < min || v > max ? NaN : v;
  };
  const out = { severity: null, agent: null, q: null, cve: null, limit: LIMIT_DEFAULT, offset: 0, sort: { field: SORTS.score, order: 'desc' } };
  if (list) {
    out.limit = int('limit', LIMIT_DEFAULT, 1, LIMIT_MAX); out.offset = int('offset', 0, 0, WINDOW_MAX - 1);
    if (Number.isNaN(out.limit)) return { error: 'limit must be a whole number from 1 to ' + LIMIT_MAX };
    if (Number.isNaN(out.offset)) return { error: 'offset must be a whole number from 0 to ' + (WINDOW_MAX - 1) };
    if (out.offset + out.limit > WINDOW_MAX) return { error: 'offset plus limit cannot pass ' + WINDOW_MAX + ': narrow the search with a filter instead' };
    if (has('sort')) {
      const m = /^([+-]?)([a-z]+)$/.exec(String(q.sort));
      if (!m || !Object.prototype.hasOwnProperty.call(SORTS, m[2])) return { error: 'sort must be one of ' + Object.keys(SORTS).join(', ') + ', optionally with a leading - for descending' };
      out.sort = { field: SORTS[m[2]], order: m[1] === '-' ? 'desc' : m[1] === '+' ? 'asc' : (m[2] === 'score' || m[2] === 'detected' ? 'desc' : 'asc') };
    }
  }
  if (has('severity')) {
    const s = String(q.severity).toLowerCase();
    if (!SEVERITIES.includes(s)) return { error: 'severity must be one of ' + SEVERITIES.join(', ') };
    out.severity = s[0].toUpperCase() + s.slice(1);
  }
  if (has('agent')) { if (!AGENT_ID_RE.test(String(q.agent))) return { error: 'agent must be an agent id of 3 to 8 digits' }; out.agent = String(q.agent); }
  if (has('cve')) { if (!CVE_RE.test(String(q.cve))) return { error: 'cve must be a vulnerability id such as CVE-2024-12345' }; out.cve = String(q.cve); }
  if (has('q')) {
    const s = String(q.q).trim();
    if (s.length > 100 || /[\u0000-\u001f\u007f]/.test(s)) return { error: 'q must be text of at most 100 characters' };
    if (s) out.q = s;
  }
  return out;
}
// The query part of the body: exact filters, and the text search as a case-insensitive wildcard over three keyword fields (wildcard characters in the text are escaped).
function buildFilter(p) {
  const filter = [];
  if (p.severity) filter.push({ term: { 'vulnerability.severity': p.severity } });
  if (p.agent) filter.push({ term: { 'agent.id': p.agent } });
  if (p.cve) filter.push({ term: { 'vulnerability.id': p.cve } });
  if (p.q) {
    const v = '*' + likeEscape(p.q) + '*';
    filter.push({ bool: { minimum_should_match: 1, should: ['package.name', 'vulnerability.id', 'agent.name'].map((f) => ({ wildcard: { [f]: { value: v, case_insensitive: true } } })) } });
  }
  return { bool: { filter } };
}
const SOURCE = ['agent.id', 'agent.name', 'host.os.name', 'host.os.full', 'host.os.version', 'package.name', 'package.version', 'package.type', 'package.architecture',
  'vulnerability.id', 'vulnerability.severity', 'vulnerability.score.base', 'vulnerability.score.version', 'vulnerability.description', 'vulnerability.reference',
  'vulnerability.published_at', 'vulnerability.detected_at', 'vulnerability.under_evaluation'];
function listBody(p) {
  return { size: p.limit, from: p.offset, track_total_hits: true, _source: SOURCE, query: buildFilter(p), sort: [{ [p.sort.field]: { order: p.sort.order, unmapped_type: 'keyword' } }, { 'vulnerability.id': { order: 'asc', unmapped_type: 'keyword' } }, { 'agent.id': { order: 'asc', unmapped_type: 'keyword' } }] };
}
function summaryBody(p) {
  const top = (field, size = 10) => ({ terms: { field, size, order: { _count: 'desc' } } });
  return { size: 0, track_total_hits: true, query: buildFilter(p), aggs: {
    severity: top('vulnerability.severity', 10), packages: top('package.name'), agents: { terms: { field: 'agent.id', size: 10, order: { _count: 'desc' } }, aggs: { name: { terms: { field: 'agent.name', size: 1 } } } },
    cves: top('vulnerability.id'), machines: { cardinality: { field: 'agent.id' } }, distinct_cves: { cardinality: { field: 'vulnerability.id' } } } };
}

// --- what is passed on ----------------------------------------------------------------------------------------------------------------------
const txt = (v, n = 200) => (typeof v === 'string' || typeof v === 'number' ? String(v).slice(0, n) : null);
const at = (o, p) => p.split('.').reduce((x, k) => (x && typeof x === 'object' ? x[k] : undefined), o);
// A document may hold the field as nested JSON or as a flat dotted key; both are read.
const pick = (src, path) => { const v = at(src, path); return v !== undefined ? v : src ? src[path] : undefined; };
const score = (v) => (Number.isFinite(Number(v)) && v !== null && v !== '' && Number(v) >= 0 && Number(v) <= 10 ? Number(v) : null);
const sev = (v) => { const t = typeof v === 'string' ? v.trim().toLowerCase() : ''; return SEVERITIES.includes(t) ? t : (t ? 'unknown' : null); };
function refs(v) {
  // A real 4.14 index holds ONE string with the links joined by ", " (checked 2026-11-01); a list is also accepted.
  const l = Array.isArray(v) ? v : (typeof v === 'string' && v ? v.split(/,\s+(?=https?:\/\/)/i) : []);
  return l.slice(0, 10).map((x) => txt(x, 300)).filter((x) => x && /^https?:\/\//i.test(x));   // links only: the portal never turns anything else into a link
}
function shapeFinding(hit) {
  const s = hit && typeof hit === 'object' ? hit._source : null; if (!s || typeof s !== 'object') return null;
  const id = txt(pick(s, 'vulnerability.id'), 60); if (!id) return null;
  return {
    cve: id, severity: sev(pick(s, 'vulnerability.severity')), score: score(pick(s, 'vulnerability.score.base')), score_version: txt(pick(s, 'vulnerability.score.version'), 10),
    agent_id: txt(pick(s, 'agent.id'), 20), agent_name: txt(pick(s, 'agent.name'), 100),
    package: txt(pick(s, 'package.name'), 200), version: txt(pick(s, 'package.version'), 100), package_type: txt(pick(s, 'package.type'), 40), architecture: txt(pick(s, 'package.architecture'), 30),
    os: txt(pick(s, 'host.os.full') || pick(s, 'host.os.name'), 120),
    description: txt(pick(s, 'vulnerability.description'), 1500), references: refs(pick(s, 'vulnerability.reference')),
    published_at: txt(pick(s, 'vulnerability.published_at'), 40), detected_at: txt(pick(s, 'vulnerability.detected_at'), 40), under_evaluation: pick(s, 'vulnerability.under_evaluation') === true,
  };
}
const num = (v) => (Number.isInteger(v) && v >= 0 ? v : null);
const total = (j) => { const t = j && j.hits && j.hits.total; return num(typeof t === 'number' ? t : t && t.value); };
const bad = () => new WazuhIndexerError('BAD_RESPONSE', 'The indexer answered with a shape this version of ASIX does not know');
const buckets = (a) => (a && Array.isArray(a.buckets) ? a.buckets : []);

// { total, limit, offset, findings }
async function listFindings(m, p) {
  const j = await call(m, 'search', listBody(p));
  if (!j.hits || !Array.isArray(j.hits.hits)) throw bad();
  const findings = j.hits.hits.map(shapeFinding).filter(Boolean);
  return { total: total(j) ?? findings.length, limit: p.limit, offset: p.offset, findings };
}
// Totals and top lists for the cards.
async function summary(m, p) {
  const j = await call(m, 'search', summaryBody(p)), a = j.aggregations;
  if (!a || typeof a !== 'object') throw bad();
  const bySev = {}; for (const b of buckets(a.severity)) { const k = sev(b.key); if (k) bySev[k] = (bySev[k] || 0) + (num(b.doc_count) || 0); }
  const top = (agg) => buckets(agg).slice(0, 10).map((b) => ({ key: txt(b.key, 200), count: num(b.doc_count) || 0 })).filter((b) => b.key);
  return {
    total: total(j) ?? 0, machines: num(a.machines && a.machines.value) ?? 0, distinct_cves: num(a.distinct_cves && a.distinct_cves.value) ?? 0,
    severity: { critical: bySev.critical || 0, high: bySev.high || 0, medium: bySev.medium || 0, low: bySev.low || 0, unknown: bySev.unknown || 0 },
    top_packages: top(a.packages), top_cves: top(a.cves),
    top_agents: buckets(a.agents).slice(0, 10).map((b) => ({ agent_id: txt(b.key, 20), name: txt(buckets(b.name)[0] && buckets(b.name)[0].key, 100), count: num(b.doc_count) || 0 })).filter((b) => b.agent_id),
  };
}
// E6k: how many findings were first detected at or after `sinceIso`, by severity. A fixed body (a range on the detection time and one terms aggregation); the time is checked
// here as a strict ISO-8601 UTC text, so nothing a caller sends reaches the query. { total, critical, high, medium, low, unknown }
const SINCE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
function detectedSinceBody(sinceIso) {
  if (typeof sinceIso !== 'string' || !SINCE_RE.test(sinceIso) || Number.isNaN(Date.parse(sinceIso))) throw new WazuhIndexerError('BAD_REQUEST', 'since must be an ISO-8601 UTC time such as 2026-11-03T03:00:00Z');
  return { size: 0, track_total_hits: true, query: { bool: { filter: [{ range: { 'vulnerability.detected_at': { gte: sinceIso } } }] } }, aggs: { severity: { terms: { field: 'vulnerability.severity', size: 10 } } } };
}
async function detectedSince(m, sinceIso) {
  const j = await call(m, 'search', detectedSinceBody(sinceIso)), a = j.aggregations;
  if (!a || typeof a !== 'object') throw bad();
  const by = {}; for (const b of buckets(a.severity)) { const k = sev(b.key); if (k) by[k] = (by[k] || 0) + (num(b.doc_count) || 0); }
  return { total: total(j) ?? 0, critical: by.critical || 0, high: by.high || 0, medium: by.medium || 0, low: by.low || 0, unknown: by.unknown || 0 };
}
// E6l: findings per machine and severity, the machines with the most findings first (at most `limit`, default 200). A fixed body: one terms aggregation on the machine id with
// the name and the severities under it. [{ agent_id, name, total, critical, high, medium, low, unknown }]
async function machineSeverities(m, limit = 200) {
  const size = Number.isInteger(limit) && limit >= 1 && limit <= 500 ? limit : 200;
  const j = await call(m, 'search', { size: 0, aggs: { agents: { terms: { field: 'agent.id', size, order: { _count: 'desc' } }, aggs: { name: { terms: { field: 'agent.name', size: 1 } }, severity: { terms: { field: 'vulnerability.severity', size: 10 } } } } } });
  if (!j.aggregations || typeof j.aggregations !== 'object') throw bad();
  return buckets(j.aggregations.agents).map((b) => {
    const by = {}; for (const x of buckets(b.severity)) { const k = sev(x.key); if (k) by[k] = (by[k] || 0) + (num(x.doc_count) || 0); }
    return { agent_id: txt(b.key, 20), name: txt(buckets(b.name)[0] && buckets(b.name)[0].key, 100), total: num(b.doc_count) || 0, critical: by.critical || 0, high: by.high || 0, medium: by.medium || 0, low: by.low || 0, unknown: by.unknown || 0 };
  }).filter((x) => x.agent_id);
}
// How many findings the index holds (the reachability check and the registration check): { count }
async function count(m) {
  const j = await call(m, 'count');
  const c = num(j.count); if (c === null) throw bad();
  return { count: c };
}

module.exports = { WazuhIndexerError, checkUrl, checkIndexName, parseQuery, buildFilter, listBody, summaryBody, shapeFinding, listFindings, summary, count, detectedSince, machineSeverities, detectedSinceBody, SEVERITIES, SORTS, LIMIT_MAX, LIMIT_DEFAULT, WINDOW_MAX, INDEX_RE, AGENT_ID_RE };
