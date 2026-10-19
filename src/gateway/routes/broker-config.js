const express = require('express');
const router = express.Router();
const { db, guarded, apiError } = require('../shared');
const config = require('../../brokers/config');
const signing = require('../../brokers/config-signing');

// Broker config for the portal: the syslog port (and the syslog-over-TLS port) brokers that opted in (bootstrap-broker.sh --accept-config) should listen on.
// Nothing is pushed: brokers ask for it (src/ingest/broker-config.js). Uses collectors:read / collectors:write; no role change.
router.get('/v1/broker-config', ...guarded('collectors:read'), async (req, res) => {
  try {
    const port = await db.withTenant(req.tenant_id, (client) => config.readSyslogPort(client, req.tenant_id));
    let tls = null;   // its own read: with the schema job not yet run the syslog port still shows
    try { tls = await db.withTenant(req.tenant_id, (client) => config.readTlsPort(client, req.tenant_id)); } catch (e) { console.error('Broker TLS port read failed:', e.message); }
    res.status(200).json({ success: true, config: { ...config.view(port), tls_port: tls, signing: signing.status() } });   // signing: whether answers are signed, the key id and the PUBLIC key
  } catch (e) {
    console.error('Broker config read failed:', e.message);
    apiError(res, 500, 'BROKER_CONFIG_ERROR', 'Failed to read the broker config');
  }
});

// Body: { syslog_port?: 1514 | null, tls_port?: 6514 | null }, at least one of the two. A key that is left out is not touched; null (or an empty
// string) clears that one: brokers keep whatever they have. The TLS port only means something to brokers that already have a TLS listener.
router.put('/v1/broker-config', ...guarded('collectors:write'), async (req, res) => {
  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  const has = (k) => Object.prototype.hasOwnProperty.call(body, k);
  if (!has('syslog_port') && !has('tls_port')) return apiError(res, 400, 'INVALID_BODY', 'Send syslog_port and/or tls_port (for example 1514, or null to clear it)');
  const sp = has('syslog_port') ? config.checkSyslogPort(body.syslog_port) : null;
  if (sp && sp.error) return apiError(res, 400, 'INVALID_SYSLOG_PORT', sp.error);
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const curSyslog = sp ? sp.value : await config.readSyslogPort(client, req.tenant_id);
      let curTls = null;
      if (has('tls_port') || sp) { try { curTls = await config.readTlsPort(client, req.tenant_id); } catch (e) { if (has('tls_port')) throw e; } }   // a syslog-only save works before the schema job has added the column
      const tp = has('tls_port') ? config.checkTlsPort(body.tls_port, curSyslog) : null;
      if (tp && tp.error) return { status: 400, code: 'INVALID_TLS_PORT', message: tp.error };
      if (!tp && sp && sp.value !== null && curTls !== null && sp.value === curTls) return { status: 400, code: 'INVALID_SYSLOG_PORT', message: `Syslog port ${sp.value} is the syslog-over-TLS port; choose a different one` };
      if (sp) await config.writeSyslogPort(client, req.tenant_id, sp.value, req.user_id);
      if (tp) await config.writeTlsPort(client, req.tenant_id, tp.value, req.user_id);
      return { status: 200, port: curSyslog, tls: tp ? tp.value : curTls };
    });
    if (out.status !== 200) return apiError(res, out.status, out.code, out.message);
    res.status(200).json({ success: true, config: { ...config.view(out.port), tls_port: out.tls } });
  } catch (e) {
    console.error('Broker config update failed:', e.message);
    apiError(res, 500, 'BROKER_CONFIG_ERROR', 'Failed to save the broker config');
  }
});

module.exports = router;
