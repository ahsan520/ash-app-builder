const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const store = require('../../endpoints/wazuh-indexer-store');
const indexer = require('../../endpoints/wazuh-indexer');

// ---- The tenant's vulnerability findings, read-only (src/endpoints/wazuh-indexer.js, docs/endpoints.md task E6e) ---------------------------------------
// Three GET routes, all `capacity:read` (the same permission as the other Endpoints routes: no role changes). Which index is read is decided by the caller's tenant alone (the registry
// row is read under row security and holds the address, the user and the exact index name); nothing in the request chooses an address, an index, a path or a credential, the search body is
// built on the server from validated parameters, and the answer is rebuilt from an allow-list of fields. No route registers, changes or removes the indexer: an operator uses
// src/endpoints/wazuh-indexer-cli.js (see wazuh-indexer-store.js for why).

const STATUS = { AUTH_FAILED: 502, TLS: 502, UNREACHABLE: 502, TIMEOUT: 504, BAD_RESPONSE: 502, TOO_LARGE: 502, BUSY: 503, BLOCKED_ADDRESS: 502, BAD_ADDRESS: 502, BAD_INDEX: 502, NO_INDEX: 404 };
const apiProblem = (res, e) => apiError(res, STATUS[e.code] || 502, 'VULN_' + e.code, e.message);

// The tenant's indexer entry with its password opened: { m } or { sent: true } after the answer was written.
async function load(req, res) {
  let row;
  try { row = await db.withTenant(req.tenant_id, (client) => store.readRow(client, req.tenant_id)); }
  catch (e) {
    if (store.isMissingTable(e)) { apiError(res, 503, 'VULN_NOT_READY', 'The database has no wazuh_indexers table yet: run the schema job (a normal deploy does)'); return { sent: true }; }
    console.error('Wazuh indexer lookup failed:', e.message);
    apiError(res, 500, 'VULN_ERROR', 'Failed to look up the vulnerability source'); return { sent: true };
  }
  if (!row) { apiError(res, 404, 'VULN_NO_INDEXER', 'No vulnerability source (central indexer) is registered for this tenant'); return { sent: true }; }
  try { return { m: store.credentials(row) }; }
  catch (e) {
    if (e && e.code === 'NO_KEY') apiError(res, 503, 'VULN_NO_KEY', 'NOTIFY_ENCRYPTION_KEY is not configured, so the stored indexer password cannot be opened');
    else apiError(res, 500, 'VULN_SECRET', 'The stored indexer password cannot be opened (the encryption key may have changed): register the indexer again');
    return { sent: true };
  }
}
const handle = (fn) => async (req, res) => {
  const l = await load(req, res); if (l.sent) return;
  try { await fn(l.m, req, res); }
  catch (e) {
    if (e instanceof indexer.WazuhIndexerError) return apiProblem(res, e);
    console.error('Wazuh indexer call failed:', e.message);
    apiError(res, 500, 'VULN_ERROR', 'The call to the vulnerability source failed');
  }
};
const parse = (list) => (req, res, next) => {
  const p = indexer.parseQuery(req.query, { list });
  if (p.error) return apiError(res, 400, 'INVALID_VULN_QUERY', p.error);
  req.vulnQuery = p; next();
};

// Is a source registered, and does it answer (with the number of findings)? Always 200 when the registry can be read: an unreachable indexer is a state, not a failed request.
router.get('/v1/endpoints/vulnerabilities/status', ...guarded('capacity:read'), async (req, res) => {
  let row;
  try { row = await db.withTenant(req.tenant_id, (client) => store.readRow(client, req.tenant_id)); }
  catch (e) {
    if (store.isMissingTable(e)) return res.status(200).json({ success: true, source: store.view(null, false) });
    console.error('Wazuh indexer lookup failed:', e.message);
    return apiError(res, 500, 'VULN_ERROR', 'Failed to look up the vulnerability source');
  }
  const source = store.view(row);
  if (!row) return res.status(200).json({ success: true, source });
  let m;
  try { m = store.credentials(row); }
  catch (e) { source.status = { reachable: false, code: e && e.code === 'NO_KEY' ? 'NO_KEY' : 'SECRET', message: e && e.code === 'NO_KEY' ? 'NOTIFY_ENCRYPTION_KEY is not configured' : 'The stored password cannot be opened: register the indexer again' }; return res.status(200).json({ success: true, source }); }
  try { source.status = { reachable: true, ...(await indexer.count(m)) }; }
  catch (e) {
    if (!(e instanceof indexer.WazuhIndexerError)) console.error('Wazuh indexer call failed:', e.message);
    source.status = { reachable: false, code: e instanceof indexer.WazuhIndexerError ? e.code : 'ERROR', message: e instanceof indexer.WazuhIndexerError ? e.message : 'The call to the vulnerability source failed' };
  }
  res.status(200).json({ success: true, source });
});

router.get('/v1/endpoints/vulnerabilities/summary', ...guarded('capacity:read'), parse(false), handle(async (m, req, res) => {
  res.status(200).json({ success: true, summary: await indexer.summary(m, req.vulnQuery) });
}));

router.get('/v1/endpoints/vulnerabilities', ...guarded('capacity:read'), parse(true), handle(async (m, req, res) => {
  res.status(200).json({ success: true, ...(await indexer.listFindings(m, req.vulnQuery)) });
}));

module.exports = router;
