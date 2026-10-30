const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const agentAlert = require('../../endpoints/agent-alert');
const agentWatch = require('../../endpoints/agent-watch');

// ---- "Endpoint agent disconnected" alert: limit and machines not watched (src/endpoints/agent-alert.js, docs/endpoints.md task E4m) ----------------------------------
// Read: capacity:read (the same as the rest of the Endpoints section). Change: parsing:rules:write (the same permission as the Windows filter and the unparsed-events
// alert limit). No role changes. A saved limit wins over ASIX_AGENT_WATCH_MIN for this tenant; { follow_server: true } goes back to it. The alert picks a change up on the
// watchdog's next cycle (about a minute). Nothing is sent to the manager or to an agent: this only decides which alerts ASIX raises.
router.get('/v1/endpoints/agent-alert', ...guarded('capacity:read'), async (req, res) => {
  const server = agentWatch.config();
  try {
    const row = await db.withTenant(req.tenant_id, (client) => agentAlert.readRow(client, req.tenant_id));
    res.status(200).json({ success: true, settings: agentAlert.view(row, server) });
  } catch (e) {
    if (agentAlert.isMissingTable(e)) return res.status(200).json({ success: true, settings: agentAlert.view(null, server, true) });
    console.error('Agent alert setting read failed:', e.message);
    apiError(res, 500, 'AGENT_ALERT_ERROR', 'Failed to read the endpoint agent alert setting');
  }
});

// Body: { minutes: 0 or 5..10080 } | { follow_server: true } | { skip_agent: "002", skip: true|false }
router.put('/v1/endpoints/agent-alert', ...guarded('parsing:rules:write'), async (req, res) => {
  const b = agentAlert.parseBody(req.body);
  if (b.error) return apiError(res, 400, 'INVALID_AGENT_ALERT', b.error);
  const server = agentWatch.config();
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      if (b.follow) await agentAlert.clearMinutes(client, req.tenant_id, req.user_id);
      else if (b.minutes !== undefined) await agentAlert.writeMinutes(client, req.tenant_id, b.minutes, req.user_id);
      else {
        const r = await agentAlert.setSkip(client, req.tenant_id, b.agent, b.skip, req.user_id);
        if (r.full) return { full: true };
      }
      return { row: await agentAlert.readRow(client, req.tenant_id) };
    });
    if (out.full) return apiError(res, 400, 'AGENT_ALERT_LIST_FULL', `At most ${agentAlert.LIMITS.MAX_SKIP} machines can be left out of this alert`);
    res.status(200).json({ success: true, settings: agentAlert.view(out.row, server) });
  } catch (e) {
    if (agentAlert.isMissingTable(e)) return apiError(res, 503, 'AGENT_ALERT_NOT_READY', 'The database has no agent_watch_settings table yet: run the schema job (a normal deploy does)');
    console.error('Agent alert setting update failed:', e.message);
    apiError(res, 500, 'AGENT_ALERT_ERROR', 'Failed to save the endpoint agent alert setting');
  }
});

module.exports = router;
