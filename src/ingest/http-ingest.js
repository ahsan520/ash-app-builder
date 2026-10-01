'use strict';
// HTTP ingestion lane for installers / scripts / webhooks.
//
//   POST /v1/ingest/http          Authorization: Bearer asix_ik_...
//     text/plain   newline-separated log lines (headers X-ASIX-Collector, -Platform, -Os,
//                  -Version, -Source-Type)
//     application/json  { collector: {name, platform, os, version}, source_type,
//                         events: [ { message | raw, time?, host?, fields? } ] }
//
// Each ingestion key belongs to one tenant, is stored only as a SHA-256 hash and can be
// revoked. The first batch from a new sender registers it in the `collectors` table.
// (The broker lane, POST /v1/ingest/events with the shared BROKER_INGEST_TOKEN, is separate.)

const crypto = require('crypto');
const express = require('express');
const db = require('../db');

const KEY_PREFIX = 'asix_ik_';
const MAX_EVENTS = 1000;
const MAX_RAW = 8192;
const MAX_BODY = '1mb';
const RATE_PER_MIN = Math.max(1, Number(process.env.INGEST_RATE_PER_MIN || 300));
const NAME_RE = /^[A-Za-z0-9._:-]{1,100}$/;
const SOURCE_RE = /^[A-Za-z0-9._-]{1,50}$/;
const PLATFORMS = ['linux', 'macos', 'windows', 'generic'];

const generateKey = () => KEY_PREFIX + crypto.randomBytes(32).toString('base64url');
const hashKey = (k) => crypto.createHash('sha256').update(k).digest('hex');

// --- tiny in-memory sliding-window limiter (per API replica) -------------------------
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

// --- parsing --------------------------------------------------------------------------
// "2026-10-01T10:00:00+00:00 host sshd[12]: msg", journald short-iso, macOS `log stream --style syslog`,
// and classic "Oct  1 10:00:00 host sshd[12]: msg".
const FILE_SYSLOG_RE = /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*|[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s:[\]]+)(?:\[(\d+)\])?:\s*(.*)$/;

function parseTime(s) {
  if (!s) return null;
  let t = String(s).trim();
  if (!/^\d{4}-\d{2}-\d{2}/.test(t)) return null; // classic syslog stamps carry no year: use arrival time
  t = t.replace(/^(\d{4}-\d{2}-\d{2}) /, '$1T').replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
  const d = new Date(t);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function parseLine(line, collector) {
  const raw = line.slice(0, MAX_RAW);
  const m = raw.match(FILE_SYSLOG_RE);
  if (m) {
    return { raw, time: parseTime(m[1]), parsed: { format: 'syslog-file', host: m[2], app_name: m[3], proc_id: m[4] || null, message: m[5] } };
  }
  return { raw, time: null, parsed: { format: 'plain', host: collector, message: raw } };
}

function jsonEvent(e, collector) {
  if (!e || typeof e !== 'object') return null;
  const raw = String(e.raw ?? e.message ?? '').slice(0, MAX_RAW);
  if (!raw.trim()) return null;
  const fields = e.fields && typeof e.fields === 'object' && !Array.isArray(e.fields) ? e.fields : {};
  return { raw, time: parseTime(e.time), parsed: { ...fields, format: 'json', host: String(e.host || collector).slice(0, 200), message: String(e.message ?? raw).slice(0, MAX_RAW) } };
}

// --- auth: before any body parsing, so unauthenticated callers cost almost nothing -------
async function authKey(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  const fail = () => (limited('fail:' + clientIp(req), 30)
    ? err(res, 429, 'INGEST_RATE_LIMITED', 'Too many failed attempts')
    : err(res, 401, 'INGEST_AUTH_INVALID', 'Invalid, revoked or missing ingestion key'));
  if (!token.startsWith(KEY_PREFIX)) return fail();
  try {
    const r = await db.query(
      "SELECT id, tenant_id, name, platform FROM ingestion_keys WHERE key_hash = $1 AND status = 'active'", [hashKey(token)]);
    if (!r.rows.length) return fail();
    req.ingestKey = r.rows[0];
  } catch (e) {
    console.error('Ingestion key lookup failed:', e.message);
    return err(res, 500, 'INGEST_ERROR', 'Ingestion is temporarily unavailable');
  }
  if (limited('key:' + req.ingestKey.id, RATE_PER_MIN)) {
    res.set('Retry-After', '30');
    return err(res, 429, 'INGEST_RATE_LIMITED', `Rate limit: ${RATE_PER_MIN} requests per minute per key`);
  }
  next();
}

const router = express.Router();

router.post(
  '/v1/ingest/http',
  authKey,
  express.json({ limit: MAX_BODY }),
  express.text({ limit: MAX_BODY, type: ['text/plain', 'application/x-ndjson', 'application/octet-stream'] }),
  async (req, res) => {
    const key = req.ingestKey;
    const hdr = (n) => (req.headers[n] ? String(req.headers[n]).slice(0, 100) : null);
    const body = req.body;
    let collector, platform, os, version, sourceType, items;

    if (typeof body === 'string') {
      collector = hdr('x-asix-collector') || key.name;
      platform = hdr('x-asix-platform'); os = hdr('x-asix-os'); version = hdr('x-asix-version');
      sourceType = hdr('x-asix-source-type') || 'syslog';
      items = body.split(/\r?\n/).filter((l) => l.trim()).map((l) => parseLine(l, collector));
    } else if (body && typeof body === 'object' && Array.isArray(body.events)) {
      const c = body.collector && typeof body.collector === 'object' ? body.collector : {};
      collector = String(c.name || hdr('x-asix-collector') || key.name);
      platform = c.platform ? String(c.platform) : null; os = c.os ? String(c.os).slice(0, 100) : null; version = c.version ? String(c.version).slice(0, 50) : null;
      sourceType = String(body.source_type || 'json');
      items = body.events.map((e) => jsonEvent(e, collector)).filter(Boolean);
    } else {
      return err(res, 400, 'INGEST_INVALID_BODY', 'Send text/plain lines or JSON {"events":[{"message":"..."}]}');
    }
    if (!NAME_RE.test(collector)) return err(res, 400, 'INGEST_INVALID_COLLECTOR', 'Collector name: 1-100 chars of letters, digits . _ : -');
    if (!SOURCE_RE.test(sourceType)) return err(res, 400, 'INGEST_INVALID_SOURCE', 'source_type: 1-50 chars of letters, digits . _ -');
    if (!items.length) return err(res, 400, 'INGEST_NO_EVENTS', 'No events in request');
    if (items.length > MAX_EVENTS) return err(res, 413, 'INGEST_BATCH_TOO_LARGE', `Max ${MAX_EVENTS} events per request`);
    platform = PLATFORMS.includes(String(platform || '').toLowerCase()) ? platform.toLowerCase() : key.platform;
    const ip = clientIp(req);
    for (const it of items) Object.assign(it.parsed, { transport: 'http', remote_address: ip, collector_id: collector });

    try {
      await db.withTenant(key.tenant_id, async (client) => {
        await client.query(
          `INSERT INTO events (tenant_id, source_type, collector_id, event_time, raw, parsed)
           SELECT $1, $2, $3, x.t, x.r, x.p::jsonb
           FROM unnest($4::timestamp[], $5::text[], $6::text[]) AS x(t, r, p)`,
          [key.tenant_id, sourceType, collector, items.map((i) => i.time), items.map((i) => i.raw), items.map((i) => JSON.stringify(i.parsed))]);
        await client.query(
          `INSERT INTO collectors (tenant_id, key_id, name, platform, os, version, last_ip, events_total)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (tenant_id, name) DO UPDATE SET
             key_id = EXCLUDED.key_id, platform = COALESCE(EXCLUDED.platform, collectors.platform),
             os = COALESCE(EXCLUDED.os, collectors.os), version = COALESCE(EXCLUDED.version, collectors.version),
             last_ip = EXCLUDED.last_ip, last_seen = localtimestamp, events_total = collectors.events_total + EXCLUDED.events_total`,
          [key.tenant_id, key.id, collector, platform, os, version, ip, items.length]);
        await client.query('UPDATE ingestion_keys SET last_used_at = localtimestamp WHERE id = $1', [key.id]);
        await client.query(
          "INSERT INTO audit_events (tenant_id, action, resource, result) VALUES ($1, 'ingest:http:create', $2, 'success')",
          [key.tenant_id, `${sourceType}:${collector}`]);
      });
      res.status(202).json({ success: true, accepted: items.length });
    } catch (e) {
      console.error('HTTP ingestion failed:', e.message);
      err(res, 500, 'INGEST_ERROR', 'Failed to persist events');
    }
  }
);

// Body-parser errors (too large / malformed) as JSON instead of an HTML error page.
router.use('/v1/ingest/http', (e, req, res, next) => {
  if (e && e.status) {
    return err(res, e.status, 'INGEST_BAD_BODY', e.type === 'entity.too.large' ? 'Body too large (max 1 MB)' : 'Malformed request body');
  }
  next(e);
});

module.exports = { router, generateKey, hashKey, PLATFORMS, KEY_PREFIX };
