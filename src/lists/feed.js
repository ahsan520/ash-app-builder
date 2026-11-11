'use strict';
// The published address of a list (task L1, docs/lists.md): GET /v1/list-feed/<token>, plain text, one value per line, for a firewall (or anything else) to poll.
// Mounted BEFORE the JSON parser and the sign-in chain, like the ingestion lane (src/gateway/index.js): a firewall cannot sign in, so the secret in the address
// is the whole credential. Rules: only a hash of the token is stored; a token that is wrong, revoked or replaced gets the same plain 404 (nothing says which); the
// answer carries an ETag, so a poll with If-None-Match gets a 304 and costs nothing; a token is limited to ASIX_LIST_FEED_RATE_PER_MIN requests a minute per
// API replica; the time and address of the last fetch are written at most once a minute, so a person can see that the firewall really picked the list up.
// Not behind the licensing gate (src/licensing/gate.js): a firewall must not lose its block list because a license ran out. A deleted list or a revoked address stops it.
const express = require('express');
const db = require('../db');
const model = require('./model');
const service = require('./service');

const RATE_PER_MIN = Math.max(1, Number(process.env.ASIX_LIST_FEED_RATE_PER_MIN || 120));
const router = express.Router();

const hits = new Map();
function limited(key) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < 60000);
  const over = arr.length >= RATE_PER_MIN;
  if (!over) arr.push(now);
  hits.set(key, arr);
  return over;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, a] of hits) { const f = a.filter((t) => now - t < 60000); f.length ? hits.set(k, f) : hits.delete(k); }
}, 60000).unref();

const clientIp = (req) => String(req.headers['x-real-ip'] || req.socket.remoteAddress || '').slice(0, 64);
const plain = (res, status, text) => res.status(status).set({ 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).send(text);

router.get('/v1/list-feed/:token', async (req, res) => {
  const token = req.params.token;
  if (!model.tokenShape(token)) return plain(res, 404, 'Not found\n');   // the wrong shape never reaches the database
  const hash = model.hashToken(token);
  if (limited(hash)) return plain(res, 429, 'Too many requests\n');
  try {
    const found = await db.query('SELECT id, tenant_id FROM lists WHERE feed_token_hash = $1', [hash]);
    if (!found.rows.length) return plain(res, 404, 'Not found\n');
    const { id, tenant_id: tenantId } = found.rows[0];
    const values = await db.withTenant(tenantId, (client) => service.activeValues(client, tenantId, id));
    const body = model.feedText(values);
    const etag = model.etagOf(body);
    res.set({ 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff', ETag: etag, 'X-ASIX-List-Count': String(values.length) });
    // best effort and rare: a failure here never changes the answer
    db.query(
      `UPDATE lists SET feed_last_fetch_at = localtimestamp, feed_last_fetch_ip = $2
       WHERE id = $1 AND (feed_last_fetch_at IS NULL OR feed_last_fetch_at < localtimestamp - interval '1 minute')`, [id, clientIp(req)])
      .catch((e) => console.error('List feed: could not record the fetch:', e.message));
    if (req.get('if-none-match') === etag) return res.status(304).end();
    return res.status(200).send(body);
  } catch (e) {
    console.error('List feed failed:', e.message);   // never the token
    return plain(res, 500, 'Error\n');
  }
});

module.exports = { router, RATE_PER_MIN };
