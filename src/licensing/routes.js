'use strict';
const crypto = require('crypto');
const express = require('express');
const router = express.Router();
const { guarded, apiError } = require('../gateway/shared');
const db = require('../db');
const modules = require('../modules');
const license = require('./license');
const store = require('./license-store');
const installation = require('./installation');
const buildChannel = require('./build-channel');
const bundles = require('./bundles');

// ---- The License page (docs/licensing.md) --------------------------------------------------------------------------------------------------------------------
// Licenses are stored in the database: many can be "available", one "active". Uploading checks the license (signature, this installation) before it is kept and does NOT activate it;
// activating, deactivating, removing and the enforcement switch are separate steps. Every call is audited by the standard chain. Reading needs license:read, changing needs license:write
// (bootstrap-portal.sh gives both to the portal admin of the Default Tenant only). The platform-wide state lives here, not per tenant. The routes are never gated by a license.
const MAX_TOKEN = 8192;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const sha = (t) => crypto.createHash('sha256').update(t, 'utf8').digest('hex');
const problem = (res, e) => { console.error('License call failed:', e && e.message); return apiError(res, 500, 'LICENSE_ERROR', 'The license could not be read or changed'); };
const bodyOk = (req, res, allowed) => {
  const b = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : null;
  if (!b) { apiError(res, 400, 'LICENSE_BAD_BODY', 'The body must be a JSON object'); return null; }
  const extra = Object.keys(b).filter((k) => !allowed.includes(k)); if (extra.length) { apiError(res, 400, 'LICENSE_BAD_BODY', 'Unknown field "' + String(extra[0]).slice(0, 30) + '"'); return null; }
  return b;
};
const NOT_USABLE = { expired: 'It has expired and its grace period is over', wrong_install: 'It was made for a different installation', invalid: 'It is not a valid license', clock_error: 'The server clock is behind the last time the platform ran', none: 'It is not a license', unreadable: 'It is not readable' };

// Checks a pasted license against this installation. { ok, info } or { ok: false, message }.
async function check(token) {
  const inst = await installation.read(db);
  const r = await license.load({}, new Date(), { token, iid: inst.id, clockBack: inst.clock_back });
  if (r.status !== 'valid' && r.status !== 'grace') return { ok: false, message: (NOT_USABLE[r.status] || 'It cannot be used') + (r.reason && r.status === 'invalid' ? ' (' + r.reason + ')' : '') + '.' };
  return { ok: true, info: r };
}

router.get('/v1/license', ...guarded('license:read'), async (req, res) => {
  try {
    modules.resetCache(); const snap = await modules.snapshot();
    const files = (await store.list(db)).map((f) => ({ id: f.id, label: f.label, customer: f.customer, kind: f.kind, expires_at: f.expires_at, uploaded_at: f.uploaded_at, active: f.active }));
    res.status(200).json({ success: true, license: snap.license, build: snap.build, files, can_switch_enforcement: snap.build.channel === 'dev',
      features: { residential: bundles.RESIDENTIAL, enterprise: bundles.ENTERPRISE_ONLY } });
  } catch (e) { problem(res, e); }
});

router.post('/v1/license', ...guarded('license:write'), async (req, res) => {
  const b = bodyOk(req, res, ['license', 'label']); if (!b) return;
  const token = typeof b.license === 'string' ? b.license.replace(/\s+/g, '') : '';
  if (!token || token.length > MAX_TOKEN || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) return apiError(res, 400, 'LICENSE_BAD_FORMAT', 'That does not look like a license (three parts separated by dots)');
  const label = typeof b.label === 'string' ? b.label.trim().slice(0, 80) : '';
  try {
    const c = await check(token); if (!c.ok) return apiError(res, 422, 'LICENSE_REFUSED', c.message);
    const added = await store.add(db, { label: label || (c.info.customer || 'License'), token, sha256: sha(token), customer: c.info.customer, kind: c.info.kind, expires_at: c.info.expires_at, uploaded_by: req.user_id ? String(req.user_id) : null });
    if (!added.ok) return apiError(res, 409, 'LICENSE_' + added.code, added.message);
    res.status(201).json({ success: true, id: added.id, active: false, message: 'Stored. It is not active until you activate it.' });
  } catch (e) { problem(res, e); }
});

router.post('/v1/license/deactivate', ...guarded('license:write'), async (req, res) => {
  if (!bodyOk(req, res, [])) return;
  try { await store.deactivate(db); modules.resetCache(); res.status(200).json({ success: true }); } catch (e) { problem(res, e); }
});

router.post('/v1/license/:id/activate', ...guarded('license:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'LICENSE_BAD_ID', 'Not a license id');
  if (!bodyOk(req, res, [])) return;
  try {
    const f = (await db.query('SELECT token FROM license_files WHERE id = $1::uuid', [req.params.id])).rows[0];
    if (!f) return apiError(res, 404, 'LICENSE_NOT_FOUND', 'No such stored license');
    const c = await check(f.token); if (!c.ok) return apiError(res, 422, 'LICENSE_REFUSED', c.message);
    if (!(await store.activate(db, req.params.id))) return apiError(res, 404, 'LICENSE_NOT_FOUND', 'No such stored license');
    modules.resetCache(); res.status(200).json({ success: true });
  } catch (e) { problem(res, e); }
});

router.delete('/v1/license/:id', ...guarded('license:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'LICENSE_BAD_ID', 'Not a license id');
  try {
    if (!(await store.remove(db, req.params.id))) return apiError(res, 409, 'LICENSE_NOT_REMOVED', 'The license is not stored, or it is the active one (deactivate it first)');
    res.status(200).json({ success: true });
  } catch (e) { problem(res, e); }
});

// The enforcement switch exists on a development build only. On a release build it is refused: licensing is always enforced there.
router.put('/v1/license/enforcement', ...guarded('license:write'), async (req, res) => {
  const b = bodyOk(req, res, ['enforce']); if (!b) return;
  if (typeof b.enforce !== 'boolean') return apiError(res, 400, 'LICENSE_BAD_BODY', 'enforce must be true or false');
  if (buildChannel.get().channel !== 'dev') return apiError(res, 409, 'LICENSE_ALWAYS_ENFORCED', 'This is a release build: licensing is always enforced');
  try { await store.setEnforce(db, b.enforce); modules.resetCache(); res.status(200).json({ success: true, enforce: b.enforce }); } catch (e) { problem(res, e); }
});

module.exports = router;
