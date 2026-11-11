'use strict';
// Database side of lists (task L1, docs/lists.md). Every function takes an open tenant-scoped client (from db.withTenant) and filters on tenant_id
// explicitly, because the API connects as the table owner, which bypasses row-level security (same rule as src/cases/service.js).
// Functions that can be refused return { code, message? } instead of throwing: NOT_FOUND, NAME_TAKEN, TOO_MANY_LISTS, LIST_FULL, ALREADY_EXPIRED, ALLOW_SET_TOO_LARGE.
// Times are written with the database's own clock (localtimestamp), never the application's, and read back as text where they have to be written again
// (undo), so no time zone conversion can move them. audit_events gets one row per change, with counts and the list name, never the values.
const model = require('./model');
const casesService = require('../cases/service');

const ENTRY_ACTIVE = '(e.expires_at IS NULL OR e.expires_at > localtimestamp)';
const ALLOW_SET_MAX = 200000;

const audit = (client, tenantId, actorId, action, resource) => client.query(
  'INSERT INTO audit_events (tenant_id, user_id, action, resource, result) VALUES ($1, $2, $3, $4, $5)',
  [tenantId, actorId, action, String(resource).slice(0, 255), 'success']);

const LIST_COLS = `l.id, l.name, l.kind, l.item_type, l.description, l.allow_private, l.created_by_name, l.created_at, l.updated_at,
  (l.feed_token_hash IS NOT NULL) AS feed_enabled, l.feed_token_hint, l.feed_created_at, l.feed_last_fetch_at, l.feed_last_fetch_ip,
  (SELECT COUNT(*)::int FROM list_entries e WHERE e.list_id = l.id AND e.tenant_id = l.tenant_id AND ${ENTRY_ACTIVE}) AS entry_count`;

async function listAll(client, tenantId) {
  const r = await client.query(`SELECT ${LIST_COLS} FROM lists l WHERE l.tenant_id = $1 ORDER BY lower(l.name), l.id`, [tenantId]);
  return r.rows;
}
async function get(client, tenantId, id) {
  const r = await client.query(`SELECT ${LIST_COLS} FROM lists l WHERE l.id = $1 AND l.tenant_id = $2`, [id, tenantId]);
  return r.rows[0] || null;
}
// The row a change works on, locked so two requests cannot both pass the size check (kind and item_type are what values are checked against).
async function lock(client, tenantId, id) {
  const r = await client.query('SELECT id, name, kind, item_type, allow_private FROM lists WHERE id = $1 AND tenant_id = $2 FOR UPDATE', [id, tenantId]);
  return r.rows[0] || null;
}
const nameTaken = async (client, tenantId, name, exceptId) => (await client.query(
  'SELECT 1 FROM lists WHERE tenant_id = $1 AND lower(name) = lower($2) AND ($3::uuid IS NULL OR id <> $3::uuid)', [tenantId, name, exceptId || null])).rows.length > 0;

async function create(client, tenantId, userId, v) {
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const n = await client.query('SELECT COUNT(*)::int AS n FROM lists WHERE tenant_id = $1', [tenantId]);
  if (n.rows[0].n >= model.LIMITS.listsPerTenant) return { code: 'TOO_MANY_LISTS', message: `A tenant can have ${model.LIMITS.listsPerTenant} lists` };
  if (await nameTaken(client, tenantId, v.name)) return { code: 'NAME_TAKEN', message: 'A list with this name already exists' };
  const r = await client.query(
    `INSERT INTO lists (tenant_id, name, kind, item_type, description, allow_private, created_by_name) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
    [tenantId, v.name, v.kind, v.item_type, v.description, v.allow_private, actor.name]);
  await audit(client, tenantId, actor.id, 'soar:list:create', `${v.name} kind=${v.kind} type=${v.item_type}`);
  return { list: await get(client, tenantId, r.rows[0].id) };
}

async function update(client, tenantId, userId, id, patch) {
  const cur = await lock(client, tenantId, id); if (!cur) return { code: 'NOT_FOUND' };
  if (patch.name !== undefined && await nameTaken(client, tenantId, patch.name, id)) return { code: 'NAME_TAKEN', message: 'A list with this name already exists' };
  if (patch.allow_private !== undefined && patch.allow_private && cur.item_type !== 'ip') return { code: 'INVALID_BODY', message: 'allow_private only applies to a list of IP addresses' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const sets = []; const params = [id, tenantId];
  for (const k of ['name', 'description', 'allow_private']) if (patch[k] !== undefined) { params.push(patch[k]); sets.push(`${k} = $${params.length}`); }   // a fixed list of columns: a name is never taken from a request
  await client.query(`UPDATE lists SET ${sets.join(', ')}, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2`, params);
  await audit(client, tenantId, actor.id, 'soar:list:update', `${patch.name || cur.name} fields=${Object.keys(patch).join(',')}`);
  return { list: await get(client, tenantId, id) };
}

async function remove(client, tenantId, userId, id) {
  const cur = await lock(client, tenantId, id); if (!cur) return { code: 'NOT_FOUND' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const c = await client.query('SELECT COUNT(*)::int AS n FROM list_entries WHERE list_id = $1 AND tenant_id = $2', [id, tenantId]);
  await client.query('DELETE FROM lists WHERE id = $1 AND tenant_id = $2', [id, tenantId]);   // the entries go with it (ON DELETE CASCADE); a published address stops answering at once
  await audit(client, tenantId, actor.id, 'soar:list:delete', `${cur.name} entries=${c.rows[0].n}`);
  return { removed: true };
}

// ---- entries -----------------------------------------------------------------------------------------------------------------------
async function entries(client, tenantId, id, q) {
  const cur = await get(client, tenantId, id); if (!cur) return { code: 'NOT_FOUND' };
  const params = [id, tenantId]; const where = ['e.list_id = $1', 'e.tenant_id = $2', q.expired ? '(e.expires_at IS NOT NULL AND e.expires_at <= localtimestamp)' : ENTRY_ACTIVE];
  if (q.q) { params.push(q.q.toLowerCase()); where.push(`position($${params.length} in lower(e.value)) > 0`); }   // a plain substring: no pattern characters to escape
  const total = await client.query(`SELECT COUNT(*)::int AS n FROM list_entries e WHERE ${where.join(' AND ')}`, params);
  params.push(q.limit, q.offset);
  const r = await client.query(
    `SELECT e.value, e.note, e.source, e.added_by_name, e.added_at, e.expires_at FROM list_entries e WHERE ${where.join(' AND ')}
     ORDER BY e.added_at DESC, e.value LIMIT $${params.length - 1} OFFSET $${params.length}`, params);
  return { list: cur, entries: r.rows, total: total.rows[0].n };
}

// input: { values, note, expires: { never } | { seconds } | { at }, source }. Valid values are added; a value already on the list is left as it is; a value a
// block list refuses (too wide, private, or covered by an allow list) is reported in `refused` and the rest still goes in. Whole-request refusals: NOT_FOUND,
// LIST_FULL, ALREADY_EXPIRED, ALLOW_SET_TOO_LARGE.
async function addEntries(client, tenantId, userId, id, input) {
  const list = await lock(client, tenantId, id); if (!list) return { code: 'NOT_FOUND' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const refused = []; const valid = new Map();   // normal form -> what was typed
  for (const raw of input.values) {
    const r = model.normalizeValue(list, raw);
    if (r.error) refused.push({ value: String(raw).slice(0, 200), code: r.error.code, message: r.error.message });
    else if (!valid.has(r.value.text)) valid.set(r.value.text, raw);
  }
  if (input.expires.at) {
    const f = await client.query('SELECT ($1::timestamp > localtimestamp) AS future', [input.expires.at]);
    if (!f.rows[0].future) return { code: 'ALREADY_EXPIRED', message: 'That expiry time has already passed' };
  }
  if (list.kind === 'block' && valid.size) {
    const a = await client.query(
      `SELECT l.name AS list_name, e.value FROM list_entries e JOIN lists l ON l.id = e.list_id AND l.tenant_id = e.tenant_id
       WHERE e.tenant_id = $1 AND l.kind = 'allow' AND l.item_type = $2 AND ${ENTRY_ACTIVE} LIMIT ${ALLOW_SET_MAX + 1}`, [tenantId, list.item_type]);
    if (a.rows.length > ALLOW_SET_MAX) return { code: 'ALLOW_SET_TOO_LARGE', message: 'The allow lists are too large to check against' };
    const hit = model.makeAllowMatcher(list.item_type, a.rows);
    for (const text of [...valid.keys()]) {
      const row = hit(text);
      if (row) { refused.push({ value: text, code: 'ON_ALLOW_LIST', message: `${text} is covered by the allow list "${row.list_name}" (${row.value}), so it cannot be blocked` }); valid.delete(text); }
    }
  }
  await client.query(`DELETE FROM list_entries WHERE list_id = $1 AND tenant_id = $2 AND expires_at < localtimestamp - interval '1 day'`, [id, tenantId]);   // keeps expired rows from piling up
  const count = await client.query(`SELECT COUNT(*)::int AS n FROM list_entries e WHERE e.list_id = $1 AND e.tenant_id = $2 AND ${ENTRY_ACTIVE}`, [id, tenantId]);
  if (count.rows[0].n + valid.size > model.LIMITS.entriesPerList) return { code: 'LIST_FULL', message: `A list holds at most ${model.LIMITS.entriesPerList} entries` };
  let added = [];
  if (valid.size) {
    const exp = input.expires.at ? '$7::timestamp' : input.expires.seconds ? 'localtimestamp + make_interval(secs => $7::int)' : '$7::timestamp';
    const expParam = input.expires.at ? input.expires.at : input.expires.seconds ? input.expires.seconds : null;
    const r = await client.query(
      `INSERT INTO list_entries (tenant_id, list_id, value, note, source, added_by_name, expires_at)
       SELECT $1, $2, v, $4, $5, $6, ${exp} FROM unnest($3::text[]) AS v
       ON CONFLICT (list_id, value) DO UPDATE SET note = EXCLUDED.note, source = EXCLUDED.source, added_by_name = EXCLUDED.added_by_name, added_at = localtimestamp, expires_at = EXCLUDED.expires_at
         WHERE list_entries.expires_at IS NOT NULL AND list_entries.expires_at <= localtimestamp
       RETURNING value`,
      [tenantId, id, [...valid.keys()], input.note, input.source || 'manual', actor.name, expParam]);
    added = r.rows.map((x) => x.value).sort();
  }
  const got = new Set(added);
  const existing = [...valid.keys()].filter((t) => !got.has(t)).sort();
  if (added.length) await client.query('UPDATE lists SET updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2', [id, tenantId]);
  await audit(client, tenantId, actor.id, 'soar:list:add', `${list.name} added=${added.length} already=${existing.length} refused=${refused.length}`);
  return { list: await get(client, tenantId, id), added, existing, refused };
}

// -> { list, removed: [{ value, note, expires_at }], missing: [text] }. `expires_at` is the text the database wrote, so an undo can put the same time back.
async function removeEntries(client, tenantId, userId, id, values) {
  const list = await lock(client, tenantId, id); if (!list) return { code: 'NOT_FOUND' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const lenient = { ...list, kind: 'watch' };   // removing needs no block-list rule: it only has to name the stored form
  const want = new Map(); const missing = [];
  for (const raw of values) { const r = model.normalizeValue(lenient, raw); if (r.error) missing.push(String(raw).slice(0, 200)); else want.set(r.value.text, raw); }
  let removed = [];
  if (want.size) {
    const r = await client.query(
      `DELETE FROM list_entries e WHERE e.list_id = $1 AND e.tenant_id = $2 AND e.value = ANY($3::text[])
       RETURNING e.value, e.note, to_char(e.expires_at, 'YYYY-MM-DD"T"HH24:MI:SS') AS expires_at, (e.expires_at IS NOT NULL AND e.expires_at <= localtimestamp) AS was_expired`,
      [id, tenantId, [...want.keys()]]);
    removed = r.rows.filter((x) => !x.was_expired).map(({ value, note, expires_at }) => ({ value, note, expires_at })).sort((a, b) => a.value.localeCompare(b.value));
    const gone = new Set(r.rows.map((x) => x.value));
    for (const t of want.keys()) if (!gone.has(t)) missing.push(t);   // not on the list; an entry that had already expired is gone but not counted as removed
  }
  if (removed.length) await client.query('UPDATE lists SET updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2', [id, tenantId]);
  await audit(client, tenantId, actor.id, 'soar:list:remove', `${list.name} removed=${removed.length} missing=${missing.length}`);
  return { list: await get(client, tenantId, id), removed, missing };
}

// ---- the published address ---------------------------------------------------------------------------------------------------------
// Making one again replaces the old (the old address stops answering at once). The token is returned once and never stored.
async function createFeed(client, tenantId, userId, id) {
  const cur = await lock(client, tenantId, id); if (!cur) return { code: 'NOT_FOUND' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  const token = model.newToken();
  await client.query(
    `UPDATE lists SET feed_token_hash = $3, feed_token_hint = $4, feed_created_at = localtimestamp, feed_last_fetch_at = NULL, feed_last_fetch_ip = NULL, updated_at = localtimestamp
     WHERE id = $1 AND tenant_id = $2`, [id, tenantId, model.hashToken(token), token.slice(-4)]);
  await audit(client, tenantId, actor.id, 'soar:list:feed-create', cur.name);
  return { token, list: await get(client, tenantId, id) };
}
async function revokeFeed(client, tenantId, userId, id) {
  const cur = await lock(client, tenantId, id); if (!cur) return { code: 'NOT_FOUND' };
  const actor = await casesService.resolveActor(client, tenantId, userId);
  await client.query('UPDATE lists SET feed_token_hash = NULL, feed_token_hint = NULL, feed_created_at = NULL, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $2', [id, tenantId]);
  await audit(client, tenantId, actor.id, 'soar:list:feed-revoke', cur.name);
  return { list: await get(client, tenantId, id) };
}

// The values a list publishes right now (not expired).
async function activeValues(client, tenantId, id) {
  const r = await client.query(`SELECT e.value FROM list_entries e WHERE e.list_id = $1 AND e.tenant_id = $2 AND ${ENTRY_ACTIVE} ORDER BY e.value`, [id, tenantId]);
  return r.rows.map((x) => x.value);
}

module.exports = { listAll, get, create, update, remove, entries, addEntries, removeEntries, createFeed, revokeFeed, activeValues, ALLOW_SET_MAX };
