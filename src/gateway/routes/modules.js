const express = require('express');
const router = express.Router();
const { guarded, apiError } = require('../shared');

// ---- Modules, deployment profile and license entitlements (read-only) -------------------------------
// Which modules are enabled comes from ASIX_PROFILE plus the signed license file, never from the
// request. See src/modules and docs/product-plan.md.
const modules = require('../../modules');
const limits = require('../../modules/limits');
const db = require('../../db');

router.get('/v1/modules', ...guarded('modules:read'), async (req, res) => {
  try {
    const snap = await modules.snapshot();
    // usage next to the limits; a failed count must not break the page
    let usage = null;
    try { usage = { tenants: (await db.query('SELECT count(*)::int AS n FROM tenants')).rows[0].n }; } catch { /* leave null */ }
    res.status(200).json({ success: true, ...snap, usage, over_limit: limits.usageReport(snap.limits, usage) });
  }
  catch (e) { console.error('Module snapshot failed:', e.message); apiError(res, 500, 'MODULES_ERROR', 'Failed to resolve modules'); }
});

module.exports = router;
