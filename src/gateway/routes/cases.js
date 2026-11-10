const express = require('express');
const router = express.Router();
const { db, guarded, UUID_RE, apiError } = require('../shared');

// ---- Cases (task CS1, docs/cases.md): a case groups alerts under an owner, a status and a timeline ----------------------------------
// Uses the existing alerts:read / alerts:write permissions, so no role changes are needed (the same choice as alert triage and content packs).
// Rules and wording live in src/cases/model.js; the SQL in src/cases/service.js.
const model = require('../../cases/model');
const service = require('../../cases/service');
const modules = require('../../modules');

async function requireModule(req, res, next) {
  try {
    if (await modules.isEnabled('cases')) return next();
    return apiError(res, 403, 'MODULE_DISABLED', 'The Cases module is not enabled on this deployment');
  } catch (e) {
    console.error('Module check failed:', e.message);
    return apiError(res, 500, 'MODULES_ERROR', 'Failed to resolve modules');
  }
}

// What a refused service call becomes. Anything else is a 500 from the route's own catch.
function refused(res, out) {
  switch (out.code) {
    case 'NOT_FOUND': return apiError(res, 404, 'NOT_FOUND', 'Case not found');
    case 'CASE_CLOSED': return apiError(res, 409, 'CASE_CLOSED', 'This case is closed. Reopen it (set the status) before changing anything else.');
    case 'OWNER_NOT_FOUND': return apiError(res, 404, 'USER_NOT_FOUND', 'User not found in this tenant');
    case 'ALERTS_NOT_FOUND': return apiError(res, 404, 'ALERTS_NOT_FOUND', `These alerts were not found: ${out.ids.join(', ')}`);
    case 'ALERTS_TAKEN': return apiError(res, 409, 'ALERTS_TAKEN', `An alert belongs to one case only. Already in a case: ${out.taken.map((t) => `${t.alert_id} (case #${t.case_number})`).join(', ')}`);
    case 'NOT_ATTACHED': return apiError(res, 404, 'NOT_ATTACHED', 'That alert is not in this case');
    default: return null;
  }
}
// The unique key on case_alerts.alert_id refusing a row means two requests raced for the same alert: the database refused the second. Any other database error is a 500.
const raced = (res, e) => (e && e.code === '23505' && e.constraint === 'case_alerts_one_case' ? apiError(res, 409, 'ALERTS_TAKEN', 'An alert belongs to one case only, and one of these alerts was just added to a case') : null);
const idOk = (req, res) => (UUID_RE.test(req.params.id) ? true : (apiError(res, 400, 'INVALID_ID', 'Invalid case id'), false));
const fail = (res, e, what, code) => { if (!raced(res, e)) { console.error(`${what} failed:`, e.message); apiError(res, 500, code, `Failed to ${what}`); } };

router.get('/v1/cases', ...guarded('alerts:read'), requireModule, async (req, res) => {
  const q = model.parseListQuery(req.query, req.user_id);
  if (q.error) return apiError(res, 400, q.error.code, q.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.list(client, req.tenant_id, q.value));
    res.status(200).json({ success: true, ...out, limit: q.value.limit, offset: q.value.offset });
  } catch (e) { fail(res, e, 'list cases', 'CASES_LIST_ERROR'); }
});

// Before /v1/cases/:id, which would otherwise take "candidates" for an id.
router.get('/v1/cases/candidates', ...guarded('alerts:read'), requireModule, async (req, res) => {
  try {
    const alerts = await db.withTenant(req.tenant_id, (client) => service.candidates(client, req.tenant_id, 50));
    res.status(200).json({ success: true, alerts });
  } catch (e) { fail(res, e, 'list alerts that can be added', 'CASES_CANDIDATES_ERROR'); }
});

router.get('/v1/alerts/:id/case', ...guarded('alerts:read'), requireModule, async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid alert id');
  try {
    const c = await db.withTenant(req.tenant_id, (client) => service.ofAlert(client, req.tenant_id, req.params.id));
    res.status(200).json({ success: true, case: c });
  } catch (e) { fail(res, e, 'look up the case of an alert', 'CASE_OF_ALERT_ERROR'); }
});

router.get('/v1/cases/:id', ...guarded('alerts:read'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.get(client, req.tenant_id, req.params.id));
    if (!out) return refused(res, { code: 'NOT_FOUND' });
    res.status(200).json({ success: true, ...out });
  } catch (e) { fail(res, e, 'read the case', 'CASE_READ_ERROR'); }
});

// body: { title, description?, severity? (default: the worst of the alerts, else medium), owner_id?, alert_ids? (up to 50) }
router.post('/v1/cases', ...guarded('alerts:write'), requireModule, async (req, res) => {
  const p = model.parseCreate(req.body);
  if (p.error) return apiError(res, 400, p.error.code, p.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const made = await service.create(client, req.tenant_id, req.user_id, p.value);
      return made.code ? made : { id: made.id, view: await service.get(client, req.tenant_id, made.id) };
    });
    if (out.code) return refused(res, out);
    res.status(201).json({ success: true, ...out.view });
  } catch (e) { fail(res, e, 'create the case', 'CASE_CREATE_ERROR'); }
});

// body: any of { title, description, severity, status, owner_id (null = nobody) }. A closed case may only be reopened.
router.patch('/v1/cases/:id', ...guarded('alerts:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  const p = model.parsePatch(req.body);
  if (p.error) return apiError(res, 400, p.error.code, p.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const r = await service.update(client, req.tenant_id, req.user_id, req.params.id, p.value);
      return r.code ? r : { view: await service.get(client, req.tenant_id, req.params.id) };
    });
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, ...out.view });
  } catch (e) { fail(res, e, 'update the case', 'CASE_UPDATE_ERROR'); }
});

// body: { alert_ids: [1 to 50] }. Alerts already in this case are skipped; an alert in another case refuses the whole request.
router.post('/v1/cases/:id/alerts', ...guarded('alerts:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  const p = model.parseAlertIds(req.body);
  if (p.error) return apiError(res, 400, p.error.code, p.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const r = await service.attachAlerts(client, req.tenant_id, req.user_id, req.params.id, p.value);
      return r.code ? r : { ...r, view: await service.get(client, req.tenant_id, req.params.id) };
    });
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, added: out.added, already: out.already, ...out.view });
  } catch (e) { fail(res, e, 'add alerts to the case', 'CASE_ALERTS_ERROR'); }
});

router.delete('/v1/cases/:id/alerts/:alertId', ...guarded('alerts:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  if (!UUID_RE.test(req.params.alertId)) return apiError(res, 400, 'INVALID_ID', 'Invalid alert id');
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const r = await service.detachAlert(client, req.tenant_id, req.user_id, req.params.id, req.params.alertId);
      return r.code ? r : { view: await service.get(client, req.tenant_id, req.params.id) };
    });
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, ...out.view });
  } catch (e) { fail(res, e, 'remove the alert from the case', 'CASE_ALERTS_ERROR'); }
});

// body: { body: "text" } (1 to 2000 characters). Allowed on a closed case too.
router.post('/v1/cases/:id/notes', ...guarded('alerts:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  const p = model.parseNote(req.body);
  if (p.error) return apiError(res, 400, p.error.code, p.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const r = await service.addNote(client, req.tenant_id, req.user_id, req.params.id, p.value);
      return r.code ? r : { view: await service.get(client, req.tenant_id, req.params.id) };
    });
    if (out.code) return refused(res, out);
    res.status(201).json({ success: true, ...out.view });
  } catch (e) { fail(res, e, 'add the note', 'CASE_NOTE_ERROR'); }
});

module.exports = router;
