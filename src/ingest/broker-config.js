'use strict';
// The lane a broker uses to ask what it should be configured with (broker config pull, src/brokers/config.js).
//   GET /v1/ingest/broker-config     Authorization: Bearer asix_ik_...   (the broker's own ingestion key, same as the heartbeat)
//   -> { success: true, config: { syslog_port: 1514 | null }, interval_seconds: 300 }
//   POST /v1/ingest/broker-config/report   { collector: "broker-1", syslog_port: 1514, rejected_port: null }   (same key)
//   -> { success: true, recorded: true }   The broker says which port it listens on and which it rejected, so the Brokers page can show
//   Applied / Pending / Rejected. It is information only: it changes no setting, writes no audit row, and lands on the collector row that
//   belongs to the sending key (same name, same key), so one key cannot write another broker's row. recorded:false = no such broker row yet.
// The GET is read only: it changes nothing and writes no audit row. null means "no opinion, leave the broker as it is". A broker that was not set
// up with --accept-config never calls it, and one that does still checks the value itself before touching anything.

const express = require('express');
const db = require('../db');
const { authKey } = require('./heartbeat');
const config = require('../brokers/config');

const INTERVAL_S = 300;
const router = express.Router();

router.get('/v1/ingest/broker-config', authKey, async (req, res) => {
  try {
    const port = await db.withTenant(req.ingestKey.tenant_id, (client) => config.readSyslogPort(client, req.ingestKey.tenant_id));
    res.set('Cache-Control', 'no-store');
    res.status(200).json({ success: true, config: { syslog_port: port }, interval_seconds: INTERVAL_S });
  } catch (e) {
    console.error('Broker config pull failed:', e.message);
    res.status(500).json({ success: false, error: { code: 'BROKER_CONFIG_ERROR', message: 'Broker config is temporarily unavailable' } });
  }
});

router.post('/v1/ingest/broker-config/report', authKey, express.json({ limit: '4kb' }), async (req, res) => {
  const rep = config.checkReport(req.body);
  if (rep.error) return res.status(400).json({ success: false, error: { code: 'BROKER_REPORT_INVALID', message: rep.error } });
  try {
    const recorded = await db.withTenant(req.ingestKey.tenant_id, (client) => config.recordReport(client, req.ingestKey.tenant_id, req.ingestKey.id, rep));
    res.set('Cache-Control', 'no-store');
    res.status(200).json({ success: true, recorded });
  } catch (e) {
    console.error('Broker config report failed:', e.message);
    res.status(500).json({ success: false, error: { code: 'BROKER_CONFIG_ERROR', message: 'Broker config is temporarily unavailable' } });
  }
});

router.use('/v1/ingest/broker-config', (e, req, res, next) => {
  if (e && e.status) return res.status(e.status).json({ success: false, error: { code: 'BROKER_REPORT_BAD_BODY', message: 'Malformed or oversized request body' } });
  next(e);
});

module.exports = { router, INTERVAL_S };
