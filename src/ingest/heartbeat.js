'use strict';
// Collector heartbeat lanes. A sender that is up but idle (a broker VM with nothing to forward, the
// built-in syslog collector on a quiet network) must not read as "Disconnected", so it pings here
// and the ping refreshes `collectors.last_seen`. No schema change: the same row the event lanes use.
//
//   POST /v1/ingest/heartbeat          Authorization: Bearer asix_ik_...   (per-installer ingestion key)
//     JSON (optional) { collector: {name, platform, os, version} }   or headers X-ASIX-Collector / -Platform / -Os / -Version
//   POST /v1/ingest/heartbeat/broker   Authorization: Bearer <BROKER_INGEST_TOKEN>  (in-cluster syslog collector)
//     JSON { tenant_id | tenant_name, collector_id, version? }
//
// A heartbeat never inserts events and never writes an audit row (one per minute per sender would be
// noise). Both lanes are rate limited per sender; both return the interval the sender should use.

const express = require('express');
const db = require('../db');
const { hashKey, KEY_PREFIX, PLATFORMS } = require('./http-ingest');
const { brokerAuthMiddleware } = require('../gateway/middleware');

const NAME_RE = /^[A-Za-z0-9._:-]{1,100}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const INTERVAL_S = 60;
const RATE_PER_MIN = Math.max(1, Number(process.env.HEARTBEAT_RATE_PER_MIN || 30));

// Sliding-window limiter (per API replica), same idea as the ingest lane.
const hits = new Map();
function limited(id, limit) {
  const now = Date.now();
  const arr = (hits.get(id) || []).filter((t) => now - t < 60000);
  const over = arr.length >= limit;
  if (!over) arr.push(now);
  hits.set(id, arr);
  return over;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, a] of hits) { const f = a.filter((t) => now - t < 60000); f.length ? hits.set(k, f) : hits.delete(k); }
}, 60000).unref();

const err = (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } });
const clientIp = (req) => String(req.headers['x-real-ip'] || req.socket.remoteAddress || '').slice(0, 64);
const clip = (v, n) => (v === undefined || v === null || v === '' ? null : String(v).slice(0, n));

// Pure: turn headers + body into the fields we store. Returns {error} instead of throwing.
function describeBeat(headers, body, fallbackName, fallbackPlatform) {
  const b = body && typeof body === 'object' ? body : {};
  const c = b.collector && typeof b.collector === 'object' ? b.collector : {};
  const h = (n) => (headers[n] ? String(headers[n]) : null);
  const name = String(c.name || h('x-asix-collector') || fallbackName || '');
  if (!NAME_RE.test(name)) return { error: 'Collector name: 1-100 chars of letters, digits . _ : -' };
  const p = String(c.platform || h('x-asix-platform') || '').toLowerCase();
  return {
    name,
    platform: PLATFORMS.includes(p) ? p : fallbackPlatform || null,
    os: clip(c.os || h('x-asix-os'), 100),
    version: clip(c.version || h('x-asix-version'), 50),
  };
}

async function authKey(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  const fail = () => (limited('hbfail:' + clientIp(req), 30)
    ? err(res, 429, 'HEARTBEAT_RATE_LIMITED', 'Too many failed attempts')
    : err(res, 401, 'HEARTBEAT_AUTH_INVALID', 'Invalid, revoked or missing ingestion key'));
  if (!token.startsWith(KEY_PREFIX)) return fail();
  try {
    const r = await db.query("SELECT id, tenant_id, name, platform FROM ingestion_keys WHERE key_hash = $1 AND status = 'active'", [hashKey(token)]);
    if (!r.rows.length) return fail();
    req.ingestKey = r.rows[0];
  } catch (e) {
    console.error('Heartbeat key lookup failed:', e.message);
    return err(res, 500, 'HEARTBEAT_ERROR', 'Heartbeat is temporarily unavailable');
  }
  if (limited('hb:' + req.ingestKey.id, RATE_PER_MIN)) {
    res.set('Retry-After', '30');
    return err(res, 429, 'HEARTBEAT_RATE_LIMITED', `Rate limit: ${RATE_PER_MIN} heartbeats per minute per key`);
  }
  next();
}

const router = express.Router();
const small = express.json({ limit: '16kb' });

router.post('/v1/ingest/heartbeat', authKey, small, async (req, res) => {
  const key = req.ingestKey;
  const d = describeBeat(req.headers, req.body, key.name, key.platform);
  if (d.error) return err(res, 400, 'HEARTBEAT_INVALID_COLLECTOR', d.error);
  try {
    await db.withTenant(key.tenant_id, async (client) => {
      await client.query(
        `INSERT INTO collectors (tenant_id, key_id, name, platform, os, version, last_ip, events_total)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 0)
         ON CONFLICT (tenant_id, name) DO UPDATE SET
           key_id = EXCLUDED.key_id, platform = COALESCE(EXCLUDED.platform, collectors.platform),
           os = COALESCE(EXCLUDED.os, collectors.os), version = COALESCE(EXCLUDED.version, collectors.version),
           last_ip = EXCLUDED.last_ip, last_seen = localtimestamp`,
        [key.tenant_id, key.id, d.name, d.platform, d.os, d.version, clientIp(req)]);
      await client.query('UPDATE ingestion_keys SET last_used_at = localtimestamp WHERE id = $1', [key.id]);
    });
    res.status(200).json({ success: true, interval_seconds: INTERVAL_S });
  } catch (e) {
    console.error('Heartbeat failed:', e.message);
    err(res, 500, 'HEARTBEAT_ERROR', 'Failed to record heartbeat');
  }
});

// Built-in lane: the in-cluster syslog collector has no ingestion key, only the shared broker token.
// Its row is created key-less (key_id NULL), which the Collectors page shows as "built-in".
router.post('/v1/ingest/heartbeat/broker', brokerAuthMiddleware, small, async (req, res) => {
  const b = req.body || {};
  const name = String(b.collector_id || '');
  if (!NAME_RE.test(name)) return err(res, 400, 'HEARTBEAT_INVALID_COLLECTOR', 'collector_id: 1-100 chars of letters, digits . _ : -');
  if (limited('hbb:' + name, RATE_PER_MIN)) { res.set('Retry-After', '30'); return err(res, 429, 'HEARTBEAT_RATE_LIMITED', 'Too many heartbeats'); }
  try {
    let tenantId = b.tenant_id;
    if (tenantId !== undefined && !UUID_RE.test(String(tenantId))) return err(res, 400, 'HEARTBEAT_INVALID_TENANT', 'tenant_id must be a UUID');
    if (!tenantId) {
      if (!b.tenant_name) return err(res, 400, 'HEARTBEAT_NO_TENANT', 'tenant_id or tenant_name is required');
      const t = await db.query('SELECT id FROM tenants WHERE name = $1 LIMIT 1', [String(b.tenant_name)]);
      if (!t.rows.length) return err(res, 404, 'HEARTBEAT_TENANT_NOT_FOUND', 'Unknown tenant');
      tenantId = t.rows[0].id;
    }
    await db.withTenant(tenantId, (client) => client.query(
      `INSERT INTO collectors (tenant_id, key_id, name, platform, version, last_ip, events_total)
       VALUES ($1, NULL, $2, 'generic', $3, $4, 0)
       ON CONFLICT (tenant_id, name) DO UPDATE SET
         version = COALESCE(EXCLUDED.version, collectors.version), last_ip = EXCLUDED.last_ip, last_seen = localtimestamp`,
      [tenantId, name, clip(b.version, 50), clientIp(req)]));
    res.status(200).json({ success: true, interval_seconds: INTERVAL_S });
  } catch (e) {
    console.error('Broker heartbeat failed:', e.message);
    err(res, 500, 'HEARTBEAT_ERROR', 'Failed to record heartbeat');
  }
});

router.use('/v1/ingest/heartbeat', (e, req, res, next) => {
  if (e && e.status) return err(res, e.status, 'HEARTBEAT_BAD_BODY', 'Malformed or oversized request body');
  next(e);
});

module.exports = { router, describeBeat, INTERVAL_S, authKey };
