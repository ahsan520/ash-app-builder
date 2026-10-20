const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const parseAlert = require('../../ingestion/parse-alert');
const parseWatch = require('../../ingestion/parse-watch');

// ---- Unparsed-events alert limit (src/ingestion/parse-alert.js) ------------------------------------
// Read: capacity:read (same as the Parser pool page). Change: parsing:rules:write (the parsing settings permission). No role changes.
// A saved limit wins over the server settings for this tenant; { follow_server: true } deletes it. The alert picks it up on the
// watchdog's next cycle (within about a minute). Nothing is pushed anywhere and no event is touched.
router.get('/v1/parser/alert', ...guarded('capacity:read'), async (req, res) => {
  const server = parseWatch.config();
  try {
    const row = await db.withTenant(req.tenant_id, (client) => parseAlert.readRow(client, req.tenant_id));
    res.status(200).json({ success: true, settings: parseAlert.view(row, server) });
  } catch (e) {
    // The schema job has not created the table yet: say so instead of failing, the page shows a notice.
    if (parseAlert.isMissingTable(e)) return res.status(200).json({ success: true, settings: parseAlert.view(null, server, true) });
    console.error('Parser alert read failed:', e.message);
    apiError(res, 500, 'PARSER_ALERT_ERROR', 'Failed to read the unparsed-events alert setting');
  }
});

// Body: { min_events: 0..1000000, window_min?: 5..1440 } (0 = off for this tenant; a window left out keeps the current one), or { follow_server: true }.
router.put('/v1/parser/alert', ...guarded('parsing:rules:write'), async (req, res) => {
  const b = parseAlert.parseBody(req.body);
  if (b.error) return apiError(res, 400, 'INVALID_PARSER_ALERT', b.error);
  const server = parseWatch.config();
  try {
    const row = await db.withTenant(req.tenant_id, async (client) => {
      if (b.follow) { await parseAlert.clearRow(client, req.tenant_id); return null; }
      const current = await parseAlert.readRow(client, req.tenant_id);
      const window = b.window_min != null ? b.window_min : (current ? current.window_min : server.windowMin);
      await parseAlert.writeRow(client, req.tenant_id, b.min_events, window, req.user_id);
      return parseAlert.readRow(client, req.tenant_id);
    });
    res.status(200).json({ success: true, settings: parseAlert.view(row, server) });
  } catch (e) {
    if (parseAlert.isMissingTable(e)) return apiError(res, 503, 'PARSER_ALERT_NOT_READY', 'The database has no parse_alert_settings table yet: run the schema job (a normal deploy does)');
    console.error('Parser alert update failed:', e.message);
    apiError(res, 500, 'PARSER_ALERT_ERROR', 'Failed to save the unparsed-events alert setting');
  }
});

module.exports = router;
