'use strict';
// Broker capacity and placement (docs/broker-groups.md, task E8). Plain routes on a plain router: nothing is attached to the router object itself.
//   GET /v1/brokers/placement[?endpoints=N]                    collectors:read   the brokers' capacity, the groups, which broker takes the next machine, and (with endpoints) how many brokers a client of that size needs
//   PUT /v1/brokers/:id/placement  { group?, agent_limit? }    collectors:write  set or clear a broker's group and its agent limit (null clears; a key that is not sent is left alone)
//   GET /v1/brokers/placement/installer/:platform              capacity:read     the agent installer pointed at ONE broker's endpoint manager: ?broker=<id> or ?broker=auto&broker_group=<name>, optional ?group=<agent group>, ?force=1
// No schema beyond the five columns on collectors, no new permission, nothing is sent to a broker: the limit is applied when ASIX chooses which address goes into an installer.
const express = require('express');
const router = express.Router();
const { db, guarded, apiError, UUID_RE } = require('../shared');
const placement = require('../../brokers/placement');
const { statusOf } = require('../../collectors/status');
const { listInputs } = require('../../brokers/inputs');
const view = require('../../brokers/broker-view');
const installer = require('../../endpoints/agent-installer');

const COLUMNS = 'c.id, c.name, c.last_ip, c.last_seen, c.connected_within_min, c.inputs, c.host_cpus, c.host_mem_mb, c.agents_enrolled, c.broker_group, c.agent_limit';

// One row -> what the placement code works with (no settings read, no other table).
const shapeRow = (row, now = Date.now()) => ({
  id: row.id, name: row.name, last_ip: row.last_ip || null, address: placement.addressOf(row),
  status: statusOf(row.last_seen, row.connected_within_min, now), inputs: listInputs(row.inputs),
  group: row.broker_group || null, capacity: placement.capacityOf(row),
});

const readAll = (client, tenantId) => client.query(
  `SELECT ${COLUMNS} FROM collectors c WHERE c.tenant_id = $1 AND c.version ILIKE $2 ORDER BY c.name`, [tenantId, view.BROKER_VERSION_SQL]);

router.get('/v1/brokers/placement', ...guarded('collectors:read'), async (req, res) => {
  try {
    const now = Date.now();
    const r = await db.withTenant(req.tenant_id, (client) => readAll(client, req.tenant_id));
    const brokers = r.rows.map((row) => shapeRow(row, now));
    const out = {
      success: true, generated_at: new Date(now).toISOString(), settings: placement.rates(), brokers: brokers.map(({ address, ...b }) => ({ ...b, address })),
      groups: placement.groupsOf(brokers), typical_limit: placement.typicalLimit(brokers), plan: null,
    };
    if (req.query.endpoints !== undefined) {
      const typical = out.typical_limit;
      const p = placement.plan(String(req.query.endpoints), typical);
      if (p.error) return apiError(res, 400, 'INVALID_ENDPOINTS', p.error);
      const have = out.groups.reduce((n, g) => n + g.limit, 0);
      out.plan = { ...p, brokers_now: brokers.length, room_now: have, more_brokers: Math.max(0, p.brokers_total - brokers.length) };
    }
    res.status(200).json(out);
  } catch (e) {
    console.error('Broker placement read failed:', e.message);
    apiError(res, 500, 'BROKER_PLACEMENT_ERROR', 'Failed to read broker capacity');
  }
});

router.put('/v1/brokers/:id/placement', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid broker id');
  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  const sets = []; const vals = [req.params.id, req.tenant_id, view.BROKER_VERSION_SQL];
  if ('group' in body) { const g = placement.checkGroup(body.group); if (g.error) return apiError(res, 400, 'INVALID_GROUP', g.error); vals.push(g.value); sets.push('broker_group = $' + vals.length); }
  if ('agent_limit' in body) { const l = placement.checkLimit(body.agent_limit); if (l.error) return apiError(res, 400, 'INVALID_LIMIT', l.error); vals.push(l.value); sets.push('agent_limit = $' + vals.length); }
  if (!sets.length) return apiError(res, 400, 'INVALID_BODY', 'Send group, agent_limit or both (null clears one)');
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      `UPDATE collectors SET ${sets.join(', ')} WHERE id = $1 AND tenant_id = $2 AND version ILIKE $3
       RETURNING id, name, last_ip, last_seen, connected_within_min, inputs, host_cpus, host_mem_mb, agents_enrolled, broker_group, agent_limit`, vals));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Broker not found');
    const b = shapeRow(r.rows[0]);
    res.status(200).json({ success: true, broker: { id: b.id, name: b.name, group: b.group, agent_limit: r.rows[0].agent_limit, capacity: b.capacity } });
  } catch (e) {
    console.error('Broker placement save failed:', e.message);
    apiError(res, 500, 'BROKER_PLACEMENT_ERROR', 'Failed to save the broker setting');
  }
});

// The installer for the next machine, pointed at a broker's manager. The address is the one ASIX saw the broker's heartbeat come from, never taken from the request;
// the agent group is validated by the installer's own strict alphabet. The agent package version is the tested default: a site manager is not reachable by ASIX, so its version is not read.
for (const [platform, make] of [['linux', installer.render], ['windows', installer.renderWindows]]) {
  router.get('/v1/brokers/placement/installer/' + platform, ...guarded('capacity:read'), async (req, res) => {
    const want = String(req.query.broker || '');
    if (!want) return apiError(res, 400, 'INVALID_BROKER', 'broker is required: a broker id, or auto together with broker_group');
    if (want !== 'auto' && !UUID_RE.test(want)) return apiError(res, 400, 'INVALID_BROKER', 'broker must be a broker id or auto');
    let groupName = null;
    if (want === 'auto') {
      const g = placement.checkGroup(req.query.broker_group);
      if (g.error || g.value === null) return apiError(res, 400, 'INVALID_GROUP', 'auto needs broker_group: the name of a group of brokers');
      groupName = g.value;
    }
    try {
      const now = Date.now();
      const r = await db.withTenant(req.tenant_id, (client) => readAll(client, req.tenant_id));
      const all = r.rows.map((row) => shapeRow(row, now));
      let chosen;
      if (want === 'auto') {
        const members = all.filter((b) => b.group === groupName);
        if (!members.length) return apiError(res, 404, 'NOT_FOUND', 'No broker is in that group');
        chosen = placement.pickNext(members);
        if (!chosen) return apiError(res, 409, 'NO_BROKER_AVAILABLE', 'No broker in that group can take another machine: ' + members.map((m) => m.name + ' (' + placement.whyNot(m) + ')').join('; '));
      } else {
        chosen = all.find((b) => b.id === want);
        if (!chosen) return apiError(res, 404, 'NOT_FOUND', 'Broker not found');
        const why = placement.whyNot(chosen);
        if (why && !(why === 'full' && req.query.force === '1')) return apiError(res, 409, why === 'full' ? 'BROKER_FULL' : 'BROKER_NOT_AVAILABLE', chosen.name + ' cannot take another machine: ' + why + (why === 'full' ? '. Add ?force=1 to go over its limit.' : '.'));
      }
      let out;
      try { out = make({ host: chosen.address, group: req.query.group, managerVersion: null }); }
      catch (e) { if (e instanceof installer.InstallerError) return apiError(res, 400, 'INSTALLER_' + e.code, e.message); throw e; }
      res.status(200).json({ success: true, installer: { platform, ...out, password_token: installer.PASSWORD_TOKEN },
        broker: { id: chosen.id, name: chosen.name, address: chosen.address, group: chosen.group, free_before: chosen.capacity.free, over_limit: chosen.capacity.free === 0 },
        note: 'The address is where ASIX sees this broker connect from. If your machines reach it by another address or a name, edit the script before using it.' });
    } catch (e) {
      console.error('Broker placement installer failed:', e.message);
      apiError(res, 500, 'BROKER_PLACEMENT_ERROR', 'Failed to make the installer');
    }
  });
}

module.exports = router;
