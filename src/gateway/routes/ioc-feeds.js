const express = require('express');
const router = express.Router();
const { db, guarded, UUID_RE, apiError } = require('../shared');

// ---- IOC feeds (docs/ioc-feeds.md): scheduled import of an indicator feed into the IOC store ------------------------------------------------------
// Two new permissions: `threatintel:feeds:read` and `threatintel:feeds:write`; scripts/deploy/bootstrap-portal.sh gives both to the portal-admin role.
// A feed uses a `threat-feed` integration (docs/integrations.md) for its address, format and token; the schedule is src/feeds/runner.js.
const model = require('../../feeds/model');
const service = require('../../feeds/service');
const modules = require('../../modules');

async function requireModule(req, res, next) {
  try {
    if (await modules.isEnabled('ioc-feeds')) return next();
    return apiError(res, 403, 'MODULE_DISABLED', 'The IOC feeds module is not enabled on this deployment');
  } catch (e) { console.error('Module check failed:', e.message); return apiError(res, 500, 'MODULES_ERROR', 'Failed to resolve modules'); }
}
const fail = (res, e, what, code) => { console.error(`${what} failed:`, e.message); apiError(res, 500, code, `Failed to ${what}`); };
const idOk = (req, res) => (UUID_RE.test(req.params.id) ? true : (apiError(res, 400, 'INVALID_ID', 'Invalid feed id'), false));
const STATUS = { NOT_FOUND: 404, INTEGRATION_NOT_FOUND: 400, WRONG_INTEGRATION: 400, NAME_TAKEN: 409, TOO_MANY: 409, BUSY: 409, INVALID_BODY: 400 };
const refused = (res, out) => apiError(res, STATUS[out.code] || 400, out.code, out.message || (out.code === 'NOT_FOUND' ? 'Feed not found' : 'Request refused'));
const choices = () => ({ severities: model.SEVERITIES, intervals: model.INTERVALS, ttl_min: model.LIMITS.ttlMin, ttl_max: model.LIMITS.ttlMax });

router.get('/v1/ioc-feeds', ...guarded('threatintel:feeds:read'), requireModule, async (req, res) => {
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => ({ feeds: await service.listAll(client, req.tenant_id), integrations: await service.eligibleIntegrations(client, req.tenant_id) }));
    res.status(200).json({ success: true, ...out, ...choices() });
  } catch (e) { fail(res, e, 'list the feeds', 'FEEDS_LIST_ERROR'); }
});

router.post('/v1/ioc-feeds', ...guarded('threatintel:feeds:write'), requireModule, async (req, res) => {
  const p = model.parseCreate(req.body, UUID_RE);
  if (p.error) return apiError(res, 400, p.error.code, p.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.create(client, req.tenant_id, req.user_id, p.value));
    if (out.code) return refused(res, out);
    res.status(201).json({ success: true, feed: out.feed });
  } catch (e) { fail(res, e, 'create the feed', 'FEED_CREATE_ERROR'); }
});

router.get('/v1/ioc-feeds/:id', ...guarded('threatintel:feeds:read'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => { const feed = await service.get(client, req.tenant_id, req.params.id); return feed ? { feed, ...(await service.runs(client, req.tenant_id, req.params.id, 20)) } : null; });
    if (!out) return refused(res, { code: 'NOT_FOUND' });
    res.status(200).json({ success: true, feed: out.feed, runs: out.runs });
  } catch (e) { fail(res, e, 'read the feed', 'FEED_READ_ERROR'); }
});

router.put('/v1/ioc-feeds/:id', ...guarded('threatintel:feeds:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  const p = model.parsePatch(req.body);
  if (p.error) return apiError(res, 400, p.error.code, p.error.message);
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.update(client, req.tenant_id, req.user_id, req.params.id, p.value));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, feed: out.feed });
  } catch (e) { fail(res, e, 'change the feed', 'FEED_UPDATE_ERROR'); }
});

// ?remove_indicators=true also deletes the indicators this feed imported; otherwise they stay and expire on their own.
router.delete('/v1/ioc-feeds/:id', ...guarded('threatintel:feeds:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  if (req.query.remove_indicators !== undefined && req.query.remove_indicators !== 'true' && req.query.remove_indicators !== 'false') return apiError(res, 400, 'INVALID_QUERY', 'remove_indicators must be true or false');
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.remove(client, req.tenant_id, req.user_id, req.params.id, req.query.remove_indicators === 'true'));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, indicators_removed: out.indicators_removed });
  } catch (e) { fail(res, e, 'delete the feed', 'FEED_DELETE_ERROR'); }
});

router.get('/v1/ioc-feeds/:id/runs', ...guarded('threatintel:feeds:read'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  const limit = req.query.limit === undefined ? 20 : Number(req.query.limit);
  if (!Number.isInteger(limit) || limit < 1 || limit > model.LIMITS.runsPage) return apiError(res, 400, 'INVALID_QUERY', `limit must be 1 to ${model.LIMITS.runsPage}`);
  try {
    const out = await db.withTenant(req.tenant_id, (client) => service.runs(client, req.tenant_id, req.params.id, limit));
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, runs: out.runs });
  } catch (e) { fail(res, e, 'read the runs', 'FEED_RUNS_ERROR'); }
});

// Runs the import now and answers when it has finished (the fetch has a 20 second limit). A run that fails is still a 200 with run.status "failed" and its reason.
// body: { force?: true } lets a feed that lists far fewer indicators than last time go through.
router.post('/v1/ioc-feeds/:id/run', ...guarded('threatintel:feeds:write'), requireModule, async (req, res) => {
  if (!idOk(req, res)) return;
  const p = model.parseRun(req.body);
  if (p.error) return apiError(res, 400, p.error.code, p.error.message);
  try {
    const out = await service.runFeed(req.tenant_id, req.params.id, { kind: 'manual', userId: req.user_id, force: p.value.force });
    if (out.code) return refused(res, out);
    res.status(200).json({ success: true, run: out.run });
  } catch (e) { fail(res, e, 'run the feed', 'FEED_RUN_ERROR'); }
});

module.exports = router;
