'use strict';
// The lane a broker uses to ask what it should be configured with (broker config pull, src/brokers/config.js).
//   GET /v1/ingest/broker-config     Authorization: Bearer asix_ik_...   (the broker's own ingestion key, same as the heartbeat)
//   -> { success: true, config: { syslog_port: 1514 | null, tls_port: 6514 | null[, paused_inputs: "file,journald" | ""] }, interval_seconds: 300 }
//   paused_inputs: optional inputs (file, http, journald) this broker should not run; "" = run them all again. Present only when something is asked or must be resumed.
//   tls_port: the tenant-wide syslog-over-TLS port; only a broker that already has a TLS listener acts on it. A broker left out gets null for both.
//   Optional ?collector=broker-1: the broker's own port and its own TLS port (set on the Brokers page) win over the tenant-wide ones; found by this key AND that name.
//   A broker that was left out of the tenant-wide port (and has no own port) is answered null: no opinion, it keeps what it has. The same for its TLS port.
//   With ASIX_CONFIG_SIGNING_KEY set the answer also has `signed: { v, alg, key_id, payload, signature }` (src/brokers/config-signing.js): a broker
//   that has the public key acts on the signed payload alone and ignores `config`.
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
const signing = require('../brokers/config-signing');
const pausedInputs = require('../brokers/paused');

const INTERVAL_S = 300;
const router = express.Router();

router.get('/v1/ingest/broker-config', authKey, async (req, res) => {
  try {
    const tenantId = req.ingestKey.tenant_id;
    const name = config.nameOrNull(req.query.collector);   // sent by brokers with the per-broker script; without it the tenant-wide value is the answer
    const tenantPort = await db.withTenant(tenantId, (client) => config.readSyslogPort(client, tenantId));
    let own = null;   // its own transaction: if the column is missing (schema job not run) the tenant-wide value still answers
    if (name) { try { own = await db.withTenant(tenantId, (client) => config.readOverride(client, tenantId, req.ingestKey.id, name)); } catch (e) { console.error('Broker port override read failed:', e.message); } }
    let tenantTls = null;   // the tenant-wide syslog-over-TLS port; its own transaction too: a missing column (schema job not run) means no opinion
    try { tenantTls = await db.withTenant(tenantId, (client) => config.readTlsPort(client, tenantId)); } catch (e) { console.error('Broker TLS port read failed:', e.message); }
    let left = false;   // left out of the tenant-wide settings: only asked when it matters (a tenant-wide port set, and either no own port or a TLS port to hold back); a missing column means not left out
    if (name && (tenantTls !== null || (own === null && tenantPort !== null))) { try { left = await db.withTenant(tenantId, (client) => config.readExclude(client, tenantId, req.ingestKey.id, name)); } catch (e) { console.error('Broker port exclusion read failed:', e.message); } }
    let ownTls = null;   // the broker's own TLS port, in its own transaction too: a missing column (schema job not run) means none
    if (name) { try { ownTls = await db.withTenant(tenantId, (client) => config.readTlsOverride(client, tenantId, req.ingestKey.id, name)); } catch (e) { console.error('Broker TLS port override read failed:', e.message); } }
    const port = config.effectivePort(tenantPort, own, left);
    const tlsPort = config.effectiveTlsPort(tenantTls, ownTls, left);   // its own, else the tenant-wide one; a broker left out is told no tenant-wide port and keeps what it has
    // Optional inputs to pause on this broker ('file,journald'; '' = resume everything). Only said when it matters: something is asked, or the broker reported something paused that must now be resumed. Its own
    // transaction: a database without the new columns, or a broker script that sends no name, simply gets no such field.
    let paused;
    if (name) { try { paused = await db.withTenant(tenantId, (client) => pausedInputs.readForPull(client, tenantId, req.ingestKey.id, name)); } catch (e) { console.error('Broker paused inputs read failed:', e.message); } }
    const answer = { success: true, config: { syslog_port: port, tls_port: tlsPort }, interval_seconds: INTERVAL_S };
    if (paused !== undefined) answer.config.paused_inputs = paused;
    // With a signing key set, a signed copy of the same setting is added; brokers given the public key act on that copy only. If signing fails
    // the answer goes out unsigned (a broker that requires signatures refuses it) rather than not at all.
    try { const sk = signing.current(); if (sk && sk.privateKey) answer.signed = signing.signedDocument(sk, name, port, Date.now(), tlsPort, paused); } catch (e) { console.error('Broker config signing failed:', e.message); }
    res.set('Cache-Control', 'no-store');
    res.status(200).json(answer);
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
    if (recorded && rep.paused !== undefined) {   // its own transaction: a database without the pause columns still keeps the port report above
      try { await db.withTenant(req.ingestKey.tenant_id, (client) => pausedInputs.recordReport(client, req.ingestKey.tenant_id, req.ingestKey.id, rep.name, rep.paused, rep.pausedRejected)); }
      catch (e) { console.error('Broker paused inputs report failed:', e.message); }
    }
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
