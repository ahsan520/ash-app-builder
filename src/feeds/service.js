'use strict';
// Database side of IOC feeds (docs/ioc-feeds.md). The import rules, in the order they matter:
//  1. One run per feed at a time (a lease, running_since, works across API replicas; a lease older than 15 minutes is taken over).
//  2. The address, format and token come from the feed's integration (src/integrations/service.js useCredentials, which audits the use). Nothing is stored here.
//  3. The fetch (src/feeds/fetcher.js) and the parse (src/feeds/parser.js) happen with no database transaction open.
//  4. A feed with nothing valid in it fails the run and changes nothing. A feed that lists under a fifth of what it listed last time (and it listed 20 or more)
//     fails the run with FEED_SHRANK and changes nothing, unless a person forces it: a broken feed must not wipe the store.
//  5. Indicators are written with source 'feed:<feed id>' and an expiry of now + the feed's days. An indicator that already exists from ANOTHER source (typed by a
//     person, or from another feed) is never touched. One a person switched off stays switched off (`enabled` is never written on update).
//  6. Indicators of this feed that the feed no longer lists expire at once (expires_at = now; the matcher ignores expired indicators). Nothing is deleted.
//  7. The run records what changed: items, added, updated, expired, invalid, skipped (owned by another source). The last 100 runs of a feed are kept.
const db = require('../db');
const model = require('./model');
const fetcher = require('./fetcher');
const parser = require('./parser');
const integrations = require('../integrations/service');
const casesService = require('../cases/service');

const audit = (client, tenantId, actorId, action, resource) => client.query(
  'INSERT INTO audit_events (tenant_id, user_id, action, resource, result) VALUES ($1, $2, $3, $4, $5)', [tenantId, actorId, action, String(resource).slice(0, 255), 'success']);
const sourceOf = (id) => `feed:${id}`;
const short = (s, n = 300) => String(s || '').slice(0, n);

const FEED_COLS = `f.id, f.integration_id, f.name, f.severity, f.ttl_days, f.interval_hours, f.enabled, f.last_run_at, f.last_status, f.last_error, f.last_item_count, f.running_since, f.created_by_name, f.created_at, f.updated_at,
  i.name AS integration_name, i.enabled AS integration_enabled, i.credential_fields AS integration_credentials`;
const shape = (r) => ({ id: r.id, integration_id: r.integration_id, integration_name: r.integration_name, name: r.name, severity: r.severity, ttl_days: r.ttl_days, interval_hours: r.interval_hours, enabled: r.enabled,
  last_run_at: r.last_run_at, last_status: r.last_status, last_error: r.last_error, last_item_count: r.last_item_count, running: !!r.running_since && !r.lease_expired, created_by_name: r.created_by_name, created_at: r.created_at, updated_at: r.updated_at });
const SELECT = `SELECT ${FEED_COLS}, (f.running_since IS NOT NULL AND f.running_since < localtimestamp - interval '${model.LIMITS.leaseMinutes} minutes') AS lease_expired
  FROM ioc_feeds f JOIN integration_instances i ON i.id = f.integration_id AND i.tenant_id = f.tenant_id`;

async function listAll(client, tenantId) { return (await client.query(`${SELECT} WHERE f.tenant_id = $1 ORDER BY lower(f.name), f.id`, [tenantId])).rows.map(shape); }
async function getRow(client, tenantId, id) { return (await client.query(`${SELECT} WHERE f.id = $1 AND f.tenant_id = $2`, [id, tenantId])).rows[0] || null; }
async function get(client, tenantId, id) { const r = await getRow(client, tenantId, id); return r ? shape(r) : null; }
// The integrations a feed can use: threat-feed accounts of this tenant (no secrets in them).
async function eligibleIntegrations(client, tenantId) { return (await integrations.listAll(client, tenantId)).filter((i) => i.definition_id === 'threat-feed').map((i) => ({ id: i.id, name: i.name, status: i.status, config: i.config })); }
const nameTaken = async (client, tenantId, name, exceptId) => (await client.query('SELECT 1 FROM ioc_feeds WHERE tenant_id = $1 AND lower(name) = lower($2) AND ($3::uuid IS NULL OR id <> $3::uuid)', [tenantId, name, exceptId || null])).rows.length > 0;

async function create(client, tenantId, userId, v) {
  const inst = (await client.query(`SELECT id, definition_id FROM integration_instances WHERE id = $1 AND tenant_id = $2`, [v.integration_id, tenantId])).rows[0];
  if (!inst) return { code: 'INTEGRATION_NOT_FOUND', message: 'That integration does not exist' };
  if (inst.definition_id !== 'threat-feed') return { code: 'WRONG_INTEGRATION', message: 'A feed needs an integration of the type Threat feed (HTTP)' };
  if ((await client.query('SELECT COUNT(*)::int AS n FROM ioc_feeds WHERE tenant_id = $1', [tenantId])).rows[0].n >= model.LIMITS.perTenant) return { code: 'TOO_MANY', message: `A tenant can have ${model.LIMITS.perTenant} feeds` };
  if (await nameTaken(client, tenantId, v.name)) return { code: 'NAME_TAKEN', message: 'A feed with this name already exists' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const r = await client.query('INSERT INTO ioc_feeds (tenant_id, integration_id, name, severity, ttl_days, interval_hours, created_by_name) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id',
    [tenantId, v.integration_id, v.name, v.severity, v.ttl_days, v.interval_hours, actor.name]);
  await audit(client, tenantId, actor.id, 'threatintel:feed:create', `${v.name} every=${v.interval_hours}h ttl=${v.ttl_days}d`);
  return { feed: await get(client, tenantId, r.rows[0].id) };
}
async function update(client, tenantId, userId, id, patch) {
  const cur = await getRow(client, tenantId, id); if (!cur) return { code: 'NOT_FOUND' };
  if (patch.name !== undefined && await nameTaken(client, tenantId, patch.name, id)) return { code: 'NAME_TAKEN', message: 'A feed with this name already exists' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const sets = []; const params = [id, tenantId];
  for (const k of ['name', 'severity', 'ttl_days', 'interval_hours', 'enabled']) if (patch[k] !== undefined) { params.push(patch[k]); sets.push(`${k} = $${params.length}`); }   // fixed column names
  await client.query(`UPDATE ioc_feeds SET ${sets.join(', ')}, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2`, params);
  await audit(client, tenantId, actor.id, 'threatintel:feed:update', `${patch.name || cur.name} fields=${Object.keys(patch).join(',')}`);
  return { feed: await get(client, tenantId, id) };
}
// The indicators the feed imported stay (they expire on their own) unless removeIndicators is true.
async function remove(client, tenantId, userId, id, removeIndicators) {
  const cur = await getRow(client, tenantId, id); if (!cur) return { code: 'NOT_FOUND' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  let removed = 0;
  if (removeIndicators) removed = (await client.query('DELETE FROM threat_indicators WHERE tenant_id = $1 AND source = $2', [tenantId, sourceOf(id)])).rowCount;
  await client.query('DELETE FROM ioc_feeds WHERE id = $1 AND tenant_id = $2', [id, tenantId]);
  await audit(client, tenantId, actor.id, 'threatintel:feed:delete', `${cur.name} indicators_removed=${removed}`);
  return { removed: true, indicators_removed: removed };
}
async function runs(client, tenantId, feedId, limit) {
  const f = await getRow(client, tenantId, feedId); if (!f) return { code: 'NOT_FOUND' };
  const r = await client.query(
    `SELECT id, run_kind, started_at, finished_at, status, items, added, updated, expired, invalid, skipped_other, error_code, error_message FROM ioc_feed_runs
     WHERE feed_id = $1 AND tenant_id = $2 ORDER BY started_at DESC, id LIMIT $3`, [feedId, tenantId, Math.min(Math.max(1, limit || 20), model.LIMITS.runsPage)]);
  return { runs: r.rows };
}

// ---- one run ---------------------------------------------------------------------------------------------------------------------------
// -> { run } (status ok or failed) or { code: 'NOT_FOUND' | 'BUSY' }. Never throws for a feed's own problems: they are a failed run with a code and a message safe to show.
async function runFeed(tenantId, feedId, { kind = 'manual', userId = null, force = false } = {}) {
  // 1. the lease, the run row, and the account
  const start = await db.withTenant(tenantId, async (client) => {
    const lease = await client.query(
      `UPDATE ioc_feeds SET running_since = localtimestamp, last_run_at = localtimestamp WHERE id = $1 AND tenant_id = $2
         AND (running_since IS NULL OR running_since < localtimestamp - interval '${model.LIMITS.leaseMinutes} minutes') RETURNING name, severity, ttl_days, integration_id, last_item_count`, [feedId, tenantId]);
    if (!lease.rows.length) return (await getRow(client, tenantId, feedId)) ? { code: 'BUSY', message: 'This feed is already being imported' } : { code: 'NOT_FOUND' };
    const feed = lease.rows[0];
    const run = (await client.query(`INSERT INTO ioc_feed_runs (tenant_id, feed_id, run_kind) VALUES ($1, $2, $3) RETURNING id`, [tenantId, feedId, kind])).rows[0].id;
    const acct = await integrations.useCredentials(client, tenantId, feed.integration_id, 'ioc.feed:' + feed.name);
    return { feed, runId: run, acct };
  });
  if (start.code) return start;
  const { feed, runId, acct } = start;
  const stats = { items: null, added: null, updated: null, expired: null, invalid: null, skipped_other: null };
  try {
    if (acct.code) throw Object.assign(new Error(acct.message || acct.code), { code: acct.code });
    if (!acct.config.feed_url || !['plain-text', 'csv', 'json'].includes(acct.config.format)) throw Object.assign(new Error('The integration has no feed address or format'), { code: 'NOT_CONFIGURED' });
    // 2. fetch and read, no transaction open
    const got = await fetcher.fetchFeed(acct.config.feed_url, { token: acct.credentials.token });
    const parsed = parser.parseFeed(acct.config.format, got.body);
    stats.items = parsed.items.length; stats.invalid = parsed.invalid;
    if (!parsed.items.length) throw Object.assign(new Error(`The feed has no valid indicator (${parsed.invalid} lines were not recognised)`), { code: 'NO_VALID_INDICATORS' });
    if (!force && model.shrank(feed.last_item_count, parsed.items.length)) throw Object.assign(new Error(`The feed lists ${parsed.items.length} indicators, far fewer than the ${feed.last_item_count} last time. Nothing was changed. Run it with force if this is right.`), { code: 'FEED_SHRANK' });
    // 3. write
    const src = sourceOf(feedId);
    const done = await db.withTenant(tenantId, async (client) => {
      const up = await client.query(
        `INSERT INTO threat_indicators (tenant_id, type, value, source, severity, expires_at)
         SELECT $1, x.t, x.v, $4, $5, localtimestamp + ($6::int * interval '1 day') FROM unnest($2::text[], $3::text[]) AS x(t, v)
         ON CONFLICT (tenant_id, type, value) DO UPDATE SET severity = EXCLUDED.severity, expires_at = EXCLUDED.expires_at, updated_at = localtimestamp
           WHERE threat_indicators.source = EXCLUDED.source
         RETURNING (xmax = 0) AS inserted`,
        [tenantId, parsed.items.map((x) => x.type), parsed.items.map((x) => x.value), src, feed.severity, feed.ttl_days]);
      const added = up.rows.filter((x) => x.inserted).length;
      const listed = new Set(parsed.items.map((x) => x.type + ':' + x.value));
      const mine = await client.query(`SELECT id, type, value FROM threat_indicators WHERE tenant_id = $1 AND source = $2 AND (expires_at IS NULL OR expires_at > localtimestamp)`, [tenantId, src]);
      const gone = mine.rows.filter((x) => !listed.has(x.type + ':' + x.value)).map((x) => x.id);
      let expired = 0;
      if (gone.length) expired = (await client.query(`UPDATE threat_indicators SET expires_at = localtimestamp, updated_at = localtimestamp WHERE tenant_id = $1 AND id = ANY($2::uuid[])`, [tenantId, gone])).rowCount;
      return { added, updated: up.rows.length - added, expired, skipped_other: parsed.items.length - up.rows.length };
    });
    Object.assign(stats, done);
    return await finish(tenantId, feedId, runId, feed.name, userId, 'ok', stats, null);
  } catch (e) {
    const code = e && e.code && /^[A-Z_]+$/.test(String(e.code)) ? e.code : 'IMPORT_FAILED';
    if (code === 'IMPORT_FAILED') console.error(`[feeds] run failed for ${feedId}:`, e.message);   // an unexpected error: the log has it, the run row says only that it failed
    return await finish(tenantId, feedId, runId, feed.name, userId, 'failed', stats, { code, message: code === 'IMPORT_FAILED' ? 'The import failed unexpectedly (see the API log)' : short(e.message) });
  }
}

async function finish(tenantId, feedId, runId, feedName, userId, status, s, err) {
  return db.withTenant(tenantId, async (client) => {
    const row = (await client.query(
      `UPDATE ioc_feed_runs SET finished_at = localtimestamp, status = $3, items = $4, added = $5, updated = $6, expired = $7, invalid = $8, skipped_other = $9, error_code = $10, error_message = $11
       WHERE id = $1 AND tenant_id = $2 RETURNING id, run_kind, started_at, finished_at, status, items, added, updated, expired, invalid, skipped_other, error_code, error_message`,
      [runId, tenantId, status, s.items, s.added, s.updated, s.expired, s.invalid, s.skipped_other, err && err.code, err && short(err.message)])).rows[0];
    await client.query(
      `UPDATE ioc_feeds SET running_since = NULL, last_status = $3::varchar, last_error = $4::varchar, last_item_count = CASE WHEN $3::text = 'ok' THEN $5::int ELSE last_item_count END, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2`,
      [feedId, tenantId, status, err && short(err.message), s.items]);
    await client.query(`DELETE FROM ioc_feed_runs WHERE feed_id = $1 AND tenant_id = $2 AND id NOT IN (SELECT id FROM ioc_feed_runs WHERE feed_id = $1 AND tenant_id = $2 ORDER BY started_at DESC, id LIMIT ${model.LIMITS.runsKept})`, [feedId, tenantId]);
    const actor = userId ? await casesService.resolveActor(client, tenantId, userId) : { id: null };
    await audit(client, tenantId, actor.id, 'threatintel:feed:run', `${feedName} ${row.run_kind} ${status}${err ? ' code=' + err.code : ''} items=${s.items == null ? '-' : s.items} added=${s.added == null ? '-' : s.added} expired=${s.expired == null ? '-' : s.expired}`);
    return { run: row };
  });
}

// ---- the schedule (src/feeds/runner.js) -------------------------------------------------------------------------------------------------
// Feeds whose interval has passed, across tenants (the API role bypasses row-level security). Also closes runs that never finished.
async function runDue(limit = 5) {
  await db.query(`UPDATE ioc_feed_runs SET status = 'failed', finished_at = localtimestamp, error_code = 'INTERRUPTED', error_message = 'The run did not finish (the API restarted?)'
                  WHERE status = 'running' AND started_at < localtimestamp - interval '${model.LIMITS.leaseMinutes} minutes'`);
  const due = (await db.query(
    `SELECT f.id, f.tenant_id FROM ioc_feeds f WHERE f.enabled
       AND (f.last_run_at IS NULL OR f.last_run_at + make_interval(hours => f.interval_hours) <= localtimestamp)
       AND (f.running_since IS NULL OR f.running_since < localtimestamp - interval '${model.LIMITS.leaseMinutes} minutes')
     ORDER BY f.last_run_at NULLS FIRST LIMIT $1`, [limit])).rows;
  let ran = 0;
  for (const f of due) { const r = await runFeed(f.tenant_id, f.id, { kind: 'schedule' }); if (r.run) ran++; }
  return { due: due.length, ran };
}

module.exports = { listAll, get, eligibleIntegrations, create, update, remove, runs, runFeed, runDue, sourceOf };
