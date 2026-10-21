const express = require('express');
const router = express.Router();
const { db, guarded, apiError, UUID_RE } = require('../shared');
const { generateKey, hashKey, PLATFORMS: KEY_PLATFORMS } = require('../../ingest/http-ingest');
const { getEventStore } = require('../../events');
const view = require('../../brokers/broker-view');
const upgrade = require('../../brokers/upgrade');
const config = require('../../brokers/config');
const signing = require('../../brokers/config-signing');
const watchAll = require('../../collectors/watch-all');

// ---- Brokers (read-only) --------------------------------------------------------------------------
// The broker VMs that report to this install, recognised by their heartbeat (see src/brokers/broker-view.js), with their
// status, event counts, installer key state and what is wrong. Uses collectors:read; no schema or role change.
router.get('/v1/brokers', ...guarded('collectors:read'), async (req, res) => {
  try {
    const reg = await db.withTenant(req.tenant_id, (client) => client.query(
      `SELECT c.id, c.name, c.alias, c.os, c.version, c.last_ip, c.first_seen, c.last_seen, c.events_total::bigint AS events_total,
              c.connected_within_min, c.watch_disconnect, c.watch_exclude, c.config_syslog_port, c.config_rejected_port, c.config_reported_at, c.config_signature, c.config_tls_port, c.config_rejected_tls_port, c.syslog_port_override, c.syslog_port_exclude, c.tls_port_override, c.inputs, c.key_id, k.name AS installer_name, k.status AS key_status, k.key_prefix, k.last_used_at AS key_last_used_at
       FROM collectors c LEFT JOIN ingestion_keys k ON k.id = c.key_id
       WHERE c.tenant_id = $1 AND c.version ILIKE $2 ORDER BY c.name`, [req.tenant_id, view.BROKER_VERSION_SQL]));
    let day = []; let countsError = null;
    try { day = await getEventStore().groupCounts(req.tenant_id, { by: 'collector_id', since: new Date(Date.now() - 86400000).toISOString() }); }
    catch (e) { countsError = 'Event counts are unavailable right now.'; console.error('Broker counts failed:', e.message); }
    const d = new Map(day.map((g) => [g.key, g.events]));
    let target = null;   // the page still loads if the setting cannot be read (a database that has not had the new schema yet)
    try { target = await db.withTenant(req.tenant_id, (client) => upgrade.readTarget(client, req.tenant_id)); }
    catch (e) { console.error('Broker target version read failed:', e.message); }
    let syslogPort = null;   // same: the page still loads without it (the new columns or table not created yet)
    try { syslogPort = await db.withTenant(req.tenant_id, (client) => config.readSyslogPort(client, req.tenant_id)); }
    catch (e) { console.error('Broker syslog port read failed:', e.message); }
    let tlsPort = null;   // the tenant-wide syslog-over-TLS port; its own read, so the page still loads without it (column not created yet)
    try { tlsPort = await db.withTenant(req.tenant_id, (client) => config.readTlsPort(client, req.tenant_id)); }
    catch (e) { console.error('Broker TLS port read failed:', e.message); }
    let signingOn = false;   // whether ASIX signs its answers (never throws: an unusable key just reads as off)
    try { signingOn = signing.status().enabled === true; } catch (e) { console.error('Broker signing status failed:', e.message); }
    let watchDefaults = watchAll.OFF;   // the Watch everything switch; the page still loads without it (table not created yet) and then shows only each broker's own setting
    try { watchDefaults = await db.withTenant(req.tenant_id, (client) => watchAll.read(client, req.tenant_id)); }
    catch (e) { console.error('Broker watch defaults read failed:', e.message); }
    const now = Date.now();
    const brokers = reg.rows.filter(view.isBroker).map((r) => view.shape(r, { now, events24h: d.get(r.name) || 0, target, syslogPort, signingOn, tlsPort, watchDefaults }));
    res.status(200).json({ success: true, generated_at: new Date(now).toISOString(), summary: view.summarize(brokers), brokers,
      vector_target: target, upgrade_command: upgrade.upgradeCommand(target), syslog_port: syslogPort, tls_port: tlsPort,
      install_command: view.installCommand(), counts_error: countsError });
  } catch (e) {
    console.error('Broker listing failed:', e.message);
    apiError(res, 500, 'BROKER_LIST_ERROR', 'Failed to list brokers');
  }
});

// ---- Rotate a broker's installer key --------------------------------------------------------------
// Makes a NEW installer key for this broker and returns it once, with the bootstrap command filled in. The old key is NOT
// revoked here, so the broker keeps working until you re-run the bootstrap script with the new key; the heartbeat then
// moves the broker to the new key (collectors.key_id), and the old key can be revoked on the Installers page (or by the
// portal's "Revoke old key" button) with nothing left on it. Uses collectors:write; no schema or role change.
router.post('/v1/brokers/:id/rotate-key', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid broker id');
  try {
    const cur = (await db.withTenant(req.tenant_id, (client) => client.query(
      `SELECT c.id, c.name, c.version, c.key_id, k.platform AS key_platform
       FROM collectors c LEFT JOIN ingestion_keys k ON k.id = c.key_id WHERE c.id = $1 AND c.tenant_id = $2`, [req.params.id, req.tenant_id]))).rows[0];
    if (!cur || !view.isBroker(cur)) return apiError(res, 404, 'NOT_FOUND', 'Broker not found');
    const platform = KEY_PLATFORMS.includes(cur.key_platform) ? cur.key_platform : 'linux';
    const name = view.rotatedName(cur.name);
    const key = generateKey();
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      `INSERT INTO ingestion_keys (tenant_id, name, description, platform, key_prefix, key_hash, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, platform, key_prefix, created_at`,
      [req.tenant_id, name, `Replacement key for broker ${cur.name}`.slice(0, 500), platform, key.slice(0, 12), hashKey(key), req.user_id || null]));
    res.status(201).json({ success: true, key, installer: r.rows[0], broker: { id: cur.id, name: cur.name },
      old_installer_id: cur.key_id || null, command: view.rotateCommand(cur.name, key) });
  } catch (e) {
    if (e.code === '23505') return apiError(res, 409, 'NAME_IN_USE', 'A key for this broker was just created; wait a minute and try again');
    console.error('Broker key rotation failed:', e.message);
    apiError(res, 500, 'BROKER_ROTATE_ERROR', 'Failed to create a new key');
  }
});

module.exports = router;
