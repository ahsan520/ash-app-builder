const express = require('express');
const router = express.Router();
const { guarded, apiError } = require('../shared');

// ---- Modules, deployment profile and license entitlements (read-only) -------------------------------
// Which modules are enabled comes from ASIX_PROFILE plus the signed license file, never from the
// request. See src/modules and docs/product-plan.md.
const modules = require('../../modules');

router.get('/v1/modules', ...guarded('modules:read'), async (req, res) => {
  try { res.status(200).json({ success: true, ...(await modules.snapshot()) }); }
  catch (e) { console.error('Module snapshot failed:', e.message); apiError(res, 500, 'MODULES_ERROR', 'Failed to resolve modules'); }
});

module.exports = router;
