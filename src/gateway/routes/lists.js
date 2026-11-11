const express = require('express');
const router = express.Router();
const { db, guarded, UUID_RE, apiError } = require('../shared');

// ---- Lists (task L1, docs/lists.md): block, allow and watch lists, their entries, and the address a firewall polls ------------------------------
// Two new permissions: `soar:lists:read` and `soar:lists:write`; scripts/deploy/bootstrap-portal.sh gives both to the portal-admin role.
// Rules: src/lists/model.js; SQL: src/lists/service.js; the public text address itself is src/lists/feed.js (mounted before sign-in, see src/gateway/index.js).
const model = require('../../lists/model');
const service = require('../../lists/service');
require('../../lists/actions');   // list.add_entry and list.remove_entry join the action registry (docs/actions.md)
const modules = require('../../modules');

async function requireModule(req, res, next) {
  try {
    if (await modules.isEnabled('lists')) return next();
    return apiError(res, 403, 'MODULE_DISABLED', 'The Lists module is not enabled on this deployment');
  } catch (e) {
    console.error('Module check failed:', e.message);
    return apiError(res, 500, 'MODULES_ERROR', 'Failed to resolve modules');
  }
}

const fail = (res, e, what, code) => { console.error(`${what} failed:`, e.message); apiError(res, 500, code, `Failed to ${what}`); };
const idOk = (req, res) => (UUID_RE.test(req.params.id) ? true : (apiError(res, 400, 'INVALID_ID', 'Invalid list id'), false));
const STATUS = { NOT_FOUND: 404, NAME_TAKEN: 409, TOO_MANY_LISTS: 409, LIST_FULL: 409, ALLOW_SET_TOO_LARGE: 409, ALREADY_EXPIRED: 400, INVALID_BODY: 400 };
const refused = (res, out) => apiError(res, STATUS[out.code] || 400, out.code, out.message || (out.code === 'NOT_FOUND' ? 'List not found' : 'Request refused'));

// What the page needs to draw its forms, so the lists of choices live in one place.
const choices = () => ({ kinds: model.KINDS, item_types: model.ITEM_TYPES, expires: Object.keys(model.EXPIRES), entries_per_list: model.LIMITS.entriesPerList, batch_max: model.LIMITS.batchMax, min_prefix: model.MIN_PREFIX });

// The address a firewall can poll, built from what the caller reached us by (behind a proxy that is the forwarded host). null when it cannot be told.
function feedUrl(req, token) {
  const proto = String(req.get('x-forwarded-proto') || req.protocol || '').split(',')[0].trim();
  const host = String(req.get('x-forwarded-host') || req.get('host') || '').split(',')[0].trim();
  if (!/^https?$/.test(proto) || !/^[a-z0-9.:[\]-]+$/i.test(host)) return null;
  return `${proto}://${host}/v1/list-feed/${token}`;
}

router.get('/v1/lists', ...guarded('soar:lists:read'), requireModule, async (req, res) => {
  try {
    const lists = await db.withTenant(req.tenant_id, (client) => service.listAll(client, req.tenant_id));
    res.status(200).json({ success: true, lists, ...choices() });
  } catch (e) { fail(res, e, 'list the lists', 'LISTS_LIST_ERROR'); }
});

router.post('/v1/lists', ...guarded('soar:lists:write'), requireModule, async (req, res) => {
  const p = model.parseCreate(req.body);
  if (p.error) return apiError(res, 400, p.error.code, p.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.create(client, req.tenant_id, req.user_id, p.value));
    if (out.code) return refused(res, out);
    res.status(201).json({ success: true, list: out.list });
  } catch (e) { fail(res, e, 'create the list', 'LIST_CREATE_ERROR'); }
});

router.get('/v1/lists/:id', ...guarded('soar:lists:read'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const list = await db.withTenant(req.tenant_id, (client) => service.get(client, req.tenant_id, req.params.id));
    if (!list) return refused(res, { code: 'NOT_FOUND' });
    res.status(200).json({ success: true, list });
  } catch (e) { fail(res, e, 'read the list', 'LIST_READ_ERROR'); }
});

// body: { name?, description?, allow_private? }. The kind and the type of a list never change.
router.put('/v1/lists/:id', ...guarded('soar:lists:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  const p = model.parsePatch(req.body);
  if (p.error) return apiError(res, 400, p.error.code, p.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.update(client, req.tenant_id, req.user_id, req.params.id, p.value));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, list: out.list });
  } catch (e) { fail(res, e, 'change the list', 'LIST_UPDATE_ERROR'); }
});

router.delete('/v1/lists/:id', ...guarded('soar:lists:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.remove(client, req.tenant_id, req.user_id, req.params.id));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true });
  } catch (e) { fail(res, e, 'delete the list', 'LIST_DELETE_ERROR'); }
});

router.get('/v1/lists/:id/entries', ...guarded('soar:lists:read'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  const q = model.parseEntriesQuery(req.query);
  if (q.error) return apiError(res, 400, q.error.code, q.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.entries(client, req.tenant_id, req.params.id, q.value));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, list: out.list, entries: out.entries, total: out.total, limit: q.value.limit, offset: q.value.offset });
  } catch (e) { fail(res, e, 'read the entries', 'LIST_ENTRIES_ERROR'); }
});

// body: { values: [...] } or { text: "one per line" }, note?, expires? (never, 1h, 24h, 7d, 30d, 90d; default never) or expires_at?.
// 200 even when some values were refused: `added`, `existing` (already on the list, left as they were) and `refused` (value, code, message) say what happened to each.
router.post('/v1/lists/:id/entries', ...guarded('soar:lists:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  const p = model.parseEntriesBody(req.body);
  if (p.error) return apiError(res, 400, p.error.code, p.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.addEntries(client, req.tenant_id, req.user_id, req.params.id, { ...p.value, source: 'manual' }));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, list: out.list, added: out.added, existing: out.existing, refused: out.refused });
  } catch (e) { fail(res, e, 'add the entries', 'LIST_ADD_ERROR'); }
});

// A POST, not a DELETE, because some proxies drop the body of a DELETE.
router.post('/v1/lists/:id/entries/remove', ...guarded('soar:lists:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  const p = model.parseRemoveBody(req.body);
  if (p.error) return apiError(res, 400, p.error.code, p.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.removeEntries(client, req.tenant_id, req.user_id, req.params.id, p.value.values));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, list: out.list, removed: out.removed.map((x) => x.value), missing: out.missing });
  } catch (e) { fail(res, e, 'remove the entries', 'LIST_REMOVE_ERROR'); }
});

// Makes (or replaces) the address a firewall polls. The secret is in this answer once and is never stored or shown again.
router.post('/v1/lists/:id/feed', ...guarded('soar:lists:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.createFeed(client, req.tenant_id, req.user_id, req.params.id));
    if (out.code) return refused(res, out);
    res.status(201).json({ success: true, list: out.list, feed_path: `/v1/list-feed/${out.token}`, feed_url: feedUrl(req, out.token) });
  } catch (e) { fail(res, e, 'make the list address', 'LIST_FEED_ERROR'); }
});

router.delete('/v1/lists/:id/feed', ...guarded('soar:lists:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.revokeFeed(client, req.tenant_id, req.user_id, req.params.id));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, list: out.list });
  } catch (e) { fail(res, e, 'turn the list address off', 'LIST_FEED_REVOKE_ERROR'); }
});

module.exports = router;
