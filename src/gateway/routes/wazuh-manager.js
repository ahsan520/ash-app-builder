const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const store = require('../../endpoints/wazuh-manager-store');
const api = require('../../endpoints/wazuh-api');
const installer = require('../../endpoints/agent-installer');

// ---- The tenant's central Wazuh manager, read-only (src/endpoints/wazuh-api.js, docs/endpoints.md task E4c) ----------------------------------------
// Four GET routes, all `capacity:read` (the same permission as the Windows filter page: no role changes). Which manager is called is decided by the caller's tenant alone
// (the registry row is read under row security); nothing in the request chooses an address, a path or a credential, and the query string is validated parameter by parameter.
// There is no route that registers, changes or removes a manager: an operator does that with src/endpoints/wazuh-manager-cli.js (see wazuh-manager-store.js for why).

const STATUS = { AUTH_FAILED: 502, TLS: 502, UNREACHABLE: 502, TIMEOUT: 504, BAD_RESPONSE: 502, TOO_LARGE: 502, BUSY: 503, BLOCKED_ADDRESS: 502, BAD_ADDRESS: 502, BAD_ID: 400, BAD_POLICY: 400 };
const apiProblem = (res, e) => apiError(res, STATUS[e.code] || 502, 'WAZUH_' + e.code, e.message);

// The tenant's manager with its password opened: { m } or { sent: true } after the answer was written.
async function load(req, res) {
  let row;
  try { row = await db.withTenant(req.tenant_id, (client) => store.readRow(client, req.tenant_id)); }
  catch (e) {
    if (store.isMissingTable(e)) { apiError(res, 503, 'WAZUH_NOT_READY', 'The database has no wazuh_managers table yet: run the schema job (a normal deploy does)'); return { sent: true }; }
    console.error('Wazuh manager lookup failed:', e.message);
    apiError(res, 500, 'WAZUH_ERROR', 'Failed to look up the Wazuh manager'); return { sent: true };
  }
  if (!row) { apiError(res, 404, 'WAZUH_NO_MANAGER', 'No central Wazuh manager is registered for this tenant'); return { sent: true }; }
  try { return { m: store.credentials(row) }; }
  catch (e) {
    if (e && e.code === 'NO_KEY') apiError(res, 503, 'WAZUH_NO_KEY', 'NOTIFY_ENCRYPTION_KEY is not configured, so the stored manager password cannot be opened');
    else apiError(res, 500, 'WAZUH_SECRET', 'The stored manager password cannot be opened (the encryption key may have changed): register the manager again');
    return { sent: true };
  }
}
const handle = (fn) => async (req, res) => {
  const l = await load(req, res); if (l.sent) return;
  try { await fn(l.m, req, res); }
  catch (e) {
    if (e instanceof api.WazuhApiError) return apiProblem(res, e);
    console.error('Wazuh manager call failed:', e.message);
    apiError(res, 500, 'WAZUH_ERROR', 'The call to the Wazuh manager failed');
  }
};

// Is a manager registered, and does it answer (with its version)? Always 200 when the registry can be read: an unreachable manager is a state, not a failed request.
router.get('/v1/endpoints/manager', ...guarded('capacity:read'), async (req, res) => {
  let row;
  try { row = await db.withTenant(req.tenant_id, (client) => store.readRow(client, req.tenant_id)); }
  catch (e) {
    if (store.isMissingTable(e)) return res.status(200).json({ success: true, manager: store.view(null, false) });
    console.error('Wazuh manager lookup failed:', e.message);
    return apiError(res, 500, 'WAZUH_ERROR', 'Failed to look up the Wazuh manager');
  }
  const manager = store.view(row);
  if (!row) return res.status(200).json({ success: true, manager });
  let m;
  try { m = store.credentials(row); }
  catch (e) { manager.status = { reachable: false, code: e && e.code === 'NO_KEY' ? 'NO_KEY' : 'SECRET', message: e && e.code === 'NO_KEY' ? 'NOTIFY_ENCRYPTION_KEY is not configured' : 'The stored password cannot be opened: register the manager again' }; return res.status(200).json({ success: true, manager }); }
  try { manager.status = { reachable: true, ...(await api.managerInfo(m)) }; }
  catch (e) {
    if (!(e instanceof api.WazuhApiError)) console.error('Wazuh manager call failed:', e.message);
    manager.status = { reachable: false, code: e instanceof api.WazuhApiError ? e.code : 'ERROR', message: e instanceof api.WazuhApiError ? e.message : 'The call to the Wazuh manager failed' };
  }
  res.status(200).json({ success: true, manager });
});

router.get('/v1/endpoints/agents/summary', ...guarded('capacity:read'), handle(async (m, req, res) => {
  res.status(200).json({ success: true, summary: await api.agentsSummary(m) });
}));

router.get('/v1/endpoints/agents', ...guarded('capacity:read'), (req, res, next) => {
  const p = api.parseAgentQuery(req.query);
  if (p.error) return apiError(res, 400, 'INVALID_AGENT_QUERY', p.error);
  req.agentQuery = p; next();
}, handle(async (m, req, res) => {
  res.status(200).json({ success: true, ...(await api.listAgents(m, req.agentQuery)) });
}));

router.get('/v1/endpoints/agents/:id', ...guarded('capacity:read'), (req, res, next) => {
  if (!api.AGENT_ID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_AGENT_ID', 'An agent id is 3 to 8 digits');
  next();
}, handle(async (m, req, res) => {
  const agent = await api.getAgent(m, req.params.id);
  if (!agent) return apiError(res, 404, 'WAZUH_NO_AGENT', 'The manager has no agent with that id');
  res.status(200).json({ success: true, agent });
}));

// The agent installers for this tenant's manager (docs/endpoints.md, task E5; Linux and Windows). A GET that reads the registry and asks the manager for its version, and fills a script template:
// the address comes from the registered manager, never from the request; the only parameter, `group`, is validated to a strict alphabet. The enrolment password is not known to ASIX
// and is not in the answer: the portal puts it into the script in the browser, or the script asks for it on the machine.
for (const [platform, make] of [['linux', installer.render], ['windows', installer.renderWindows]]) {
  router.get('/v1/endpoints/installer/' + platform, ...guarded('capacity:read'), handle(async (m, req, res) => {
    let managerVersion = null;
    try { managerVersion = (await api.managerInfo(m)).version; } catch (e) { /* the manager does not answer: the default version is used and the answer says so */ }
    let out;
    try { out = make({ host: new URL(m.api_url).hostname, group: req.query.group, managerVersion }); }
    catch (e) { if (e instanceof installer.InstallerError) return apiError(res, 400, 'INSTALLER_' + e.code, e.message); throw e; }
    res.status(200).json({ success: true, installer: { platform, ...out, password_token: installer.PASSWORD_TOKEN } });
  }));
}

module.exports = router;
module.exports.handle = handle;     // the checks routes (endpoint-checks.js) reuse the registry lookup and the error mapping
