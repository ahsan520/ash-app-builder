'use strict';
// The lane a broker uses to ask what it should be configured with (broker config pull, src/brokers/config.js).
//   GET /v1/ingest/broker-config     Authorization: Bearer asix_ik_...   (the broker's own ingestion key, same as the heartbeat)
//   -> { success: true, config: { syslog_port: 1514 | null }, interval_seconds: 300 }
// Read only: it changes nothing and writes no audit row. null means "no opinion, leave the broker as it is". A broker that was not set
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

module.exports = { router, INTERVAL_S };
