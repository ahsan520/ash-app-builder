const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');

// ---- Content packs: installable bundles of detection rules (residential packs first) ---------
// Reuses the detections permissions: reading needs detections:rules:read, installing or removing
// needs detections:rules:write, so no role changes are needed. See docs/product-plan.md.
const packs = require('../../packs');
const service = require('../../packs/service');
const modules = require('../../modules');

async function requireModule(req, res, next) {
  try {
    if (await modules.isEnabled('content-packs')) return next();
    return apiError(res, 403, 'MODULE_DISABLED', 'The Content packs module is not enabled on this deployment');
  } catch (e) {
    console.error('Module check failed:', e.message);
    return apiError(res, 500, 'MODULES_ERROR', 'Failed to resolve modules');
  }
}

const view = (p, st) => {
  const s = st[p.id];
  return {
    id: p.id, name: p.name, description: p.description, version: p.version, audience: p.audience, sources: p.sources,
    rule_count: p.rules.length,
    rules: p.rules.map((r) => ({ key: r.key, name: r.name, description: r.description, severity: r.severity, kind: r.kind, category: r.category, mitre: r.mitre })),
    installed_rules: s ? s.installed : 0, enabled_rules: s ? s.enabled : 0, open_alerts: s ? s.open_alerts : 0,
    state: !s ? 'available' : s.installed >= p.rules.length ? 'installed' : 'partial',
  };
};

router.get('/v1/packs', ...guarded('detections:rules:read'), requireModule, async (req, res) => {
  try {
    const st = await db.withTenant(req.tenant_id, (client) => service.status(client, req.tenant_id));
    res.status(200).json({ success: true, packs: packs.all().map((p) => view(p, st)) });
  } catch (error) {
    console.error('Pack listing failed:', error.message);
    apiError(res, 500, 'PACKS_LIST_ERROR', 'Failed to list content packs');
  }
});

// body: { enabled?: boolean (default true), overwrite?: boolean (restore shipped definitions) }
router.post('/v1/packs/:id/install', ...guarded('detections:rules:write'), requireModule, async (req, res) => {
  const pack = packs.get(req.params.id);
  if (!pack) return apiError(res, 404, 'NOT_FOUND', 'Unknown content pack');
  const b = req.body || {};
  try {
    const out = await db.withTenant(req.tenant_id, (client) =>
      service.install(client, req.tenant_id, pack, { enabled: b.enabled !== false, overwrite: b.overwrite === true }));
    res.status(200).json({ success: true, pack: pack.id, version: pack.version, ...out });
  } catch (error) {
    console.error('Pack install failed:', error.message);
    apiError(res, 500, 'PACK_INSTALL_ERROR', 'Failed to install content pack');
  }
});

// ?delete_alerts=true is required when the pack's rules have raised alerts: they are deleted with the rules.
router.delete('/v1/packs/:id', ...guarded('detections:rules:write'), requireModule, async (req, res) => {
  const pack = packs.get(req.params.id);
  if (!pack) return apiError(res, 404, 'NOT_FOUND', 'Unknown content pack');
  try {
    const out = await db.withTenant(req.tenant_id, (client) =>
      service.uninstall(client, req.tenant_id, pack.id, { deleteAlerts: req.query.delete_alerts === 'true' }));
    if (out.notInstalled) return apiError(res, 404, 'NOT_INSTALLED', 'This pack is not installed');
    if (out.blocked) return apiError(res, 409, 'HAS_ALERTS', `These rules have raised ${out.alerts} alert(s). Removing the pack deletes them too; repeat with delete_alerts=true to confirm.`);
    res.status(200).json({ success: true, pack: pack.id, removed_rules: out.removed, removed_alerts: out.alerts });
  } catch (error) {
    console.error('Pack removal failed:', error.message);
    apiError(res, 500, 'PACK_REMOVE_ERROR', 'Failed to remove content pack');
  }
});

module.exports = router;
