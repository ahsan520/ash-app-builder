const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const watchAll = require('../../collectors/watch-all');
const { checkMinutes, MIN_MINUTES, MAX_MINUTES } = require('../../collectors/silence');

// "Watch everything": the tenant-wide switch for the collector alerts (src/collectors/watch-all.js holds the rules).
// It only adds to the per-collector settings and never touches them. Uses collectors:read / collectors:write; no role change.
const view = (s, c) => ({
  disconnect: s.disconnect, silent_min: s.silent_min,
  max_age_days: watchAll.maxAgeDays(), collectors: c.total, left_out_as_retired: c.retired,
  silent_limits: { min: MIN_MINUTES, max: MAX_MINUTES },
});

router.get('/v1/collector-watch-defaults', ...guarded('collectors:read'), async (req, res) => {
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => ({
      s: await watchAll.read(client, req.tenant_id), c: await watchAll.retiredCount(client, req.tenant_id) }));
    res.status(200).json({ success: true, defaults: view(out.s, out.c) });
  } catch (error) {
    console.error('Collector watch defaults read failed:', error.message);
    apiError(res, 500, 'WATCH_DEFAULTS_ERROR', 'Failed to read the watch settings');
  }
});

// Body: { disconnect?: true|false, silent_min?: 5..4320|null }. At least one. What is left out stays as it was.
// Turning one off closes the alerts that only it was covering, on the next watchdog cycle (they are no longer watched).
router.put('/v1/collector-watch-defaults', ...guarded('collectors:write'), async (req, res) => {
  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  const has = (k) => Object.prototype.hasOwnProperty.call(body, k);
  if (!has('disconnect') && !has('silent_min')) return apiError(res, 400, 'INVALID_BODY', 'Send disconnect (true or false), silent_min (5 to 4320, or null), or both');
  const patch = {};
  if (has('disconnect')) {
    if (typeof body.disconnect !== 'boolean') return apiError(res, 400, 'INVALID_BODY', 'disconnect must be true or false');
    patch.disconnect = body.disconnect;
  }
  if (has('silent_min')) {
    const m = checkMinutes(body.silent_min);
    if (m.error) return apiError(res, 400, 'INVALID_SILENT_MINUTES', m.error);
    patch.silent_min = m.value;
  }
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const s = await watchAll.write(client, req.tenant_id, patch, req.user_id);
      return { s, c: await watchAll.retiredCount(client, req.tenant_id) };
    });
    res.status(200).json({ success: true, defaults: view(out.s, out.c) });
  } catch (error) {
    console.error('Collector watch defaults update failed:', error.message);
    apiError(res, 500, 'WATCH_DEFAULTS_ERROR', 'Failed to save the watch settings');
  }
});

module.exports = router;
