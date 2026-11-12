const express = require('express');
const router = express.Router();
const { db, guarded, UUID_RE, apiError } = require('../shared');

// ---- Integrations (task SR1, docs/integrations.md): a tenant's accounts for other products -------------------------------------------------------
// Two new permissions: `soar:integrations:read` and `soar:integrations:write`; scripts/deploy/bootstrap-portal.sh gives both to the portal-admin role.
// Credentials go in (PUT .../credentials) and never come out: no route returns one, not even to the person who typed it.
const catalog = require('../../integrations/catalog');
const model = require('../../integrations/model');
const service = require('../../integrations/service');
const secrets = require('../../secrets/provider');
const modules = require('../../modules');

async function requireModule(req, res, next) {
  try {
    if (await modules.isEnabled('integrations')) return next();
    return apiError(res, 403, 'MODULE_DISABLED', 'The Integrations module is not enabled on this deployment');
  } catch (e) {
    console.error('Module check failed:', e.message);
    return apiError(res, 500, 'MODULES_ERROR', 'Failed to resolve modules');
  }
}
// Never put e.message of a credential request in a log line that could hold a value: these messages come from our own code and the database, not from the body.
const fail = (res, e, what, code) => { console.error(`${what} failed:`, e.message); apiError(res, 500, code, `Failed to ${what}`); };
const idOk = (req, res) => (UUID_RE.test(req.params.id) ? true : (apiError(res, 400, 'INVALID_ID', 'Invalid integration id'), false));
const STATUS = { NOT_FOUND: 404, NAME_TAKEN: 409, TOO_MANY: 409, SECRET_UNREADABLE: 409, UNKNOWN_DEFINITION: 400, INVALID_BODY: 400, SECRETS_NOT_CONFIGURED: 503 };
const refused = (res, out) => apiError(res, STATUS[out.code] || 400, out.code, out.message || (out.code === 'NOT_FOUND' ? 'Integration not found' : 'Request refused'));

const publicDefinition = (d) => ({ id: d.id, name: d.name, publisher: d.publisher, category: d.category, kind: d.kind, description: d.description,
  config: d.config.map((f) => ({ name: f.name, label: f.label, type: f.type, required: !!f.required, ...(f.values ? { values: f.values } : {}) })),
  credentials: d.credentials.map((f) => ({ name: f.name, label: f.label, required: !!f.required })) });

router.get('/v1/integrations/definitions', ...guarded('soar:integrations:read'), requireModule, (req, res) => {
  res.status(200).json({ success: true, definitions: catalog.list().map(publicDefinition), categories: catalog.CATEGORIES, secrets_configured: secrets.configured() });
});

router.get('/v1/integrations', ...guarded('soar:integrations:read'), requireModule, async (req, res) => {
  try {
    const integrations = await db.withTenant(req.tenant_id, (client) => service.listAll(client, req.tenant_id));
    res.status(200).json({ success: true, integrations, secrets_configured: secrets.configured() });
  } catch (e) { fail(res, e, 'list the integrations', 'INTEGRATIONS_LIST_ERROR'); }
});

router.post('/v1/integrations', ...guarded('soar:integrations:write'), requireModule, async (req, res) => {
  const body = req.body;
  const def = body && typeof body === 'object' && typeof body.definition_id === 'string' ? catalog.get(body.definition_id) : null;
  if (!def) return apiError(res, 400, 'UNKNOWN_DEFINITION', 'definition_id must name one of the integrations ASIX describes (GET /v1/integrations/definitions)');
  const p = model.parseCreate(def, body);
  if (p.error) return apiError(res, 400, p.error.code, p.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.create(client, req.tenant_id, req.user_id, def, p.value));
    if (out.code) return refused(res, out);
    res.status(201).json({ success: true, integration: out.integration });
  } catch (e) { fail(res, e, 'create the integration', 'INTEGRATION_CREATE_ERROR'); }
});

router.get('/v1/integrations/:id', ...guarded('soar:integrations:read'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const integration = await db.withTenant(req.tenant_id, (client) => service.get(client, req.tenant_id, req.params.id));
    if (!integration) return refused(res, { code: 'NOT_FOUND' });
    res.status(200).json({ success: true, integration });
  } catch (e) { fail(res, e, 'read the integration', 'INTEGRATION_READ_ERROR'); }
});

// body: { name?, config?: { setting: value | null }, enabled? }
router.put('/v1/integrations/:id', ...guarded('soar:integrations:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.update(client, req.tenant_id, req.user_id, req.params.id, (def) => model.parsePatch(def, req.body)));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, integration: out.integration });
  } catch (e) { fail(res, e, 'change the integration', 'INTEGRATION_UPDATE_ERROR'); }
});

router.delete('/v1/integrations/:id', ...guarded('soar:integrations:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.remove(client, req.tenant_id, req.user_id, req.params.id));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true });
  } catch (e) { fail(res, e, 'delete the integration', 'INTEGRATION_DELETE_ERROR'); }
});

// body: { values: { api_key: "…" }, clear?: ["api_secret"] }. The answer says which credentials are set, never what they are.
router.put('/v1/integrations/:id/credentials', ...guarded('soar:integrations:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const inst = await service.get(client, req.tenant_id, req.params.id);
      if (!inst) return { code: 'NOT_FOUND' };
      const def = catalog.get(inst.definition_id);
      if (!def) return { code: 'UNKNOWN_DEFINITION', message: 'ASIX no longer has a definition for this integration' };
      const p = model.parseCredentials(def, req.body);
      if (p.error) return { code: p.error.code, message: p.error.message };
      return service.setCredentials(client, req.tenant_id, req.user_id, req.params.id, p.value);
    });
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, integration: out.integration });
  } catch (e) { fail(res, e, 'save the credentials', 'INTEGRATION_CREDENTIALS_ERROR'); }
});

router.delete('/v1/integrations/:id/credentials', ...guarded('soar:integrations:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.clearCredentials(client, req.tenant_id, req.user_id, req.params.id));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, integration: out.integration });
  } catch (e) { fail(res, e, 'clear the credentials', 'INTEGRATION_CREDENTIALS_CLEAR_ERROR'); }
});

module.exports = router;
