'use strict';
// IOC feed import against a real PostgreSQL (platform schema applied) and a real local feed server: the real routes, the real SQL, the real fetcher and parser,
// the real integrations and secrets, the real audit table. Only the sign-in chain is replaced (as in tests/lists-db.test.js).
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_USER=asix_admin DB_NAME=asix_platform DB_PASSWORD=... node tests/feeds-db.test.js
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
process.env.ASIX_PROFILE = process.env.ASIX_PROFILE || 'home';
process.env.NOTIFY_ENCRYPTION_KEY = Buffer.alloc(32, 5).toString('base64');
process.env.ASIX_FEED_ALLOW_PRIVATE = '1';   // the feed server below listens on 127.0.0.1

const assert = require('assert');
const http = require('http');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT; let USER; const asked = [];
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared,
  guarded: (permission) => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = USER; asked.push([req.method, req.route ? req.route.path : req.path, permission]); next(); }],
};
const modules = require('../src/modules');
const feeds = require('../src/feeds/service');

const TOKEN = 'feed-token-7e1c-SECRET'; const KEY_IN_URL = 'apikey-5d2b-INURL';
async function main() {
  const stamp = Date.now();
  const q = (t, p) => db.query(t, p);
  const rows = async (sql, p) => (await q(sql, p)).rows;
  const mkTenant = async (n) => (await q('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['feeds-' + n + '-' + stamp])).rows[0].id;
  const mkUser = async (t, n) => (await q('INSERT INTO users (tenant_id, username, email) VALUES ($1, $2, $3) RETURNING id', [t, `${n}-${stamp}`, `${n}-${stamp}@example.test`])).rows[0].id;
  const A = await mkTenant('a'); const B = await mkTenant('b'); const alice = await mkUser(A, 'alice'); const eve = await mkUser(B, 'eve');

  // the feed server: its body, status and delay can be changed between runs; every request is recorded
  const feedSrv = { body: '', status: 200, requests: [] };
  const fs = http.createServer((req, res) => { feedSrv.requests.push({ url: req.url, auth: req.headers.authorization || null }); res.writeHead(feedSrv.status, { 'Content-Type': 'text/plain' }); res.end(feedSrv.body); });
  await new Promise((r) => fs.listen(0, '127.0.0.1', r)); const FEED = `http://127.0.0.1:${fs.address().port}`;

  const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/integrations')); app.use(require('../src/gateway/routes/ioc-feeds'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const seen = [];
  const call = async (method, p, body) => {
    const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text(); seen.push(text); let json = null; try { json = JSON.parse(text); } catch { /* */ }
    return { status: r.status, json, text };
  };
  const code = (r) => r.json && r.json.error && r.json.error.code;
  const as = (t, u) => { TENANT = t; USER = u; };
  const ind = (t, extra = '') => rows(`SELECT type, value, source, severity, enabled, expires_at, (expires_at IS NOT NULL AND expires_at <= localtimestamp) AS expired, (expires_at > localtimestamp + interval '29 days' AND expires_at < localtimestamp + interval '31 days') AS thirty FROM threat_indicators WHERE tenant_id = $1 ${extra} ORDER BY type, value`, [t]);
  const lines = (n, from = 1) => Array.from({ length: n }, (_, i) => `198.51.${(i + from) >> 8 & 255}.${(i + from) & 255}`).join('\n');
  const mkInteg = async (name, config) => { const r = await call('POST', '/v1/integrations', { definition_id: 'threat-feed', name, config }); assert.strictEqual(r.status, 201, JSON.stringify(r.json)); return r.json.integration; };
  const mkFeed = async (integ, name, extra) => { const r = await call('POST', '/v1/ioc-feeds', { integration_id: integ.id, name, ...(extra || {}) }); assert.strictEqual(r.status, 201, JSON.stringify(r.json)); return r.json.feed; };
  const runNow = (id, body) => call('POST', `/v1/ioc-feeds/${id}/run`, body);
  as(A, alice);

  try {
    // 1. the account, a feed on it, and what a feed needs
    const integ = await mkInteg('Blocklist feed', { feed_url: `${FEED}/list.txt?key=${KEY_IN_URL}`, format: 'plain-text' });
    let r = await call('PUT', `/v1/integrations/${integ.id}/credentials`, { values: { token: TOKEN } }); assert.strictEqual(r.status, 200);
    r = await call('GET', '/v1/ioc-feeds');
    assert.deepStrictEqual([r.status, r.json.feeds, r.json.integrations.map((i) => [i.id, i.name, i.status]), r.json.severities, r.json.intervals], [200, [], [[integ.id, 'Blocklist feed', 'configured']], ['low', 'medium', 'high', 'critical'], [1, 6, 12, 24]]);
    const vtInteg = (await call('POST', '/v1/integrations', { definition_id: 'virustotal', name: 'VT' })).json.integration;
    r = await call('POST', '/v1/ioc-feeds', { integration_id: vtInteg.id, name: 'x' }); assert.deepStrictEqual([r.status, code(r)], [400, 'WRONG_INTEGRATION']);
    as(B, eve); const bInteg = await mkInteg('B feed', { feed_url: `${FEED}/b.txt`, format: 'plain-text' }); as(A, alice);
    r = await call('POST', '/v1/ioc-feeds', { integration_id: bInteg.id, name: 'x' }); assert.deepStrictEqual([r.status, code(r)], [400, 'INTEGRATION_NOT_FOUND'], 'another tenant\'s account');
    for (const b of [{}, { integration_id: integ.id }, { integration_id: integ.id, name: 'a', ttl_days: 0 }, { integration_id: integ.id, name: 'a', interval_hours: 5 }]) { r = await call('POST', '/v1/ioc-feeds', b); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY']); }
    const feed = await mkFeed(integ, 'Main blocklist', { severity: 'high' });
    assert.deepStrictEqual([feed.severity, feed.ttl_days, feed.interval_hours, feed.enabled, feed.last_status, feed.running, feed.integration_name], ['high', 30, 24, true, null, false, 'Blocklist feed']);
    r = await call('POST', '/v1/ioc-feeds', { integration_id: integ.id, name: 'main BLOCKLIST' }); assert.deepStrictEqual([r.status, code(r)], [409, 'NAME_TAKEN']);
    as(B, eve); r = await call('GET', '/v1/ioc-feeds/' + feed.id); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']); r = await runNow(feed.id); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']); as(A, alice);

    // 2. a first import: valid lines in normal form, the rest counted; severity, source and expiry set; the token reaches the feed and nothing else
    await q(`INSERT INTO threat_indicators (tenant_id, type, value, source, severity) VALUES ($1, 'ip', '203.0.113.50', 'manual', 'low')`, [A]);
    feedSrv.body = '# my list\n198.51.100.1 ; one\nEvil.Example.COM\nhxxp://bad[.]example.org/x\n203.0.113.50\nnot an indicator\n198.51.100.1\n8.8.8.0/24\nd41d8cd98f00b204e9800998ecf8427e\n';
    r = await runNow(feed.id);
    assert.strictEqual(r.status, 200);
    let run = r.json.run;
    assert.deepStrictEqual([run.status, run.run_kind, run.items, run.added, run.updated, run.expired, run.invalid, run.skipped_other, run.error_code], ['ok', 'manual', 5, 4, 0, 0, 2, 1, null]);
    assert.deepStrictEqual(feedSrv.requests.map((x) => [x.url, x.auth]), [[`/list.txt?key=${KEY_IN_URL}`, 'Bearer ' + TOKEN]]);
    let got = await ind(A, `AND source = 'feed:${feed.id}'`);
    assert.deepStrictEqual(got.map((x) => `${x.type}:${x.value}`), ['domain:evil.example.com', 'ip:198.51.100.1', 'md5:d41d8cd98f00b204e9800998ecf8427e', 'url:http://bad.example.org/x']);
    assert.ok(got.every((x) => x.severity === 'high' && x.enabled && x.thirty), 'severity of the feed, enabled, expiring in 30 days');
    // an indicator from another source is never touched
    let man = (await ind(A, `AND value = '203.0.113.50'`))[0]; assert.deepStrictEqual([man.source, man.severity, man.expires_at, man.enabled], ['manual', 'low', null, true]);
    let f = (await call('GET', '/v1/ioc-feeds/' + feed.id)).json.feed; assert.deepStrictEqual([f.last_status, f.last_item_count, f.last_error, f.running], ['ok', 5, null, false]);

    // 3. a second import changes nothing but the expiry; a person's choice to switch an indicator off is kept
    await q(`UPDATE threat_indicators SET enabled = false WHERE tenant_id = $1 AND value = 'evil.example.com'`, [A]);
    await q(`UPDATE threat_indicators SET expires_at = localtimestamp + interval '1 day' WHERE tenant_id = $1 AND source = $2`, [A, 'feed:' + feed.id]);
    r = await runNow(feed.id); run = r.json.run;
    assert.deepStrictEqual([run.items, run.added, run.updated, run.expired, run.skipped_other], [5, 0, 4, 0, 1]);
    got = await ind(A, `AND source = 'feed:${feed.id}'`); assert.ok(got.every((x) => x.thirty), 'the expiry is renewed');
    assert.strictEqual(got.find((x) => x.value === 'evil.example.com').enabled, false, 'an indicator a person switched off stays off');

    // 4. what the feed stops listing expires at once; what comes back is active again; nothing is deleted
    feedSrv.body = '198.51.100.1\nhxxp://bad[.]example.org/x\n';
    r = await runNow(feed.id, { force: true }); run = r.json.run; assert.deepStrictEqual([run.status, run.items, run.added, run.updated, run.expired], ['ok', 2, 0, 2, 2]);
    got = await ind(A, `AND source = 'feed:${feed.id}'`); assert.strictEqual(got.length, 4, 'nothing deleted');
    assert.deepStrictEqual(got.filter((x) => x.expired).map((x) => x.value).sort(), ['d41d8cd98f00b204e9800998ecf8427e', 'evil.example.com']);
    const matcherSees = (await rows(`SELECT value FROM threat_indicators WHERE tenant_id = $1 AND enabled = true AND (expires_at IS NULL OR expires_at > localtimestamp) ORDER BY value`, [A])).map((x) => x.value);
    assert.deepStrictEqual(matcherSees, ['198.51.100.1', '203.0.113.50', 'http://bad.example.org/x'], 'the matcher no longer sees what expired');
    feedSrv.body = '198.51.100.1\nEvil.Example.com\n'; r = await runNow(feed.id, { force: true });
    assert.strictEqual(r.json.run.added, 0); assert.strictEqual((await ind(A, `AND value = 'evil.example.com'`))[0].expired, false, 'back in the feed: active again');
    assert.strictEqual((await ind(A, `AND value = '203.0.113.50'`))[0].source, 'manual');

    // 5. a broken feed must not wipe the store
    const big = await mkInteg('Big feed', { feed_url: `${FEED}/big.txt`, format: 'plain-text' }); const bigFeed = await mkFeed(big, 'Big feed', { severity: 'medium' });
    feedSrv.body = lines(25); r = await runNow(bigFeed.id); assert.deepStrictEqual([r.json.run.status, r.json.run.items, r.json.run.added], ['ok', 25, 25]);
    feedSrv.body = lines(2); r = await runNow(bigFeed.id);
    assert.deepStrictEqual([r.status, r.json.run.status, r.json.run.error_code, r.json.run.expired], [200, 'failed', 'FEED_SHRANK', null]);
    assert.strictEqual((await ind(A, `AND source = 'feed:${bigFeed.id}' AND NOT (expires_at IS NULL OR expires_at > localtimestamp)`)).length, 0, 'nothing expired');
    f = (await call('GET', '/v1/ioc-feeds/' + bigFeed.id)).json.feed; assert.deepStrictEqual([f.last_status, f.last_item_count, /force/.test(f.last_error)], ['failed', 25, true]);
    feedSrv.body = ''; r = await runNow(bigFeed.id, { force: true }); assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'NO_VALID_INDICATORS']);
    feedSrv.body = '<html>Service unavailable</html>'; r = await runNow(bigFeed.id, { force: true }); assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'NO_VALID_INDICATORS'], 'not even force imports nothing');
    feedSrv.body = lines(2); r = await runNow(bigFeed.id, { force: true }); assert.deepStrictEqual([r.json.run.status, r.json.run.items, r.json.run.expired], ['ok', 2, 23]);

    // 6. other ways a feed fails: a failed run changes nothing and its message is safe
    feedSrv.status = 500; feedSrv.body = 'oops'; r = await runNow(feed.id); run = r.json.run;
    assert.deepStrictEqual([run.status, run.error_code], ['failed', 'HTTP_STATUS']); assert.ok(!run.error_message.includes(KEY_IN_URL), run.error_message);
    feedSrv.status = 200;
    const jsonInteg = await mkInteg('Json feed', { feed_url: `${FEED}/x.json`, format: 'json' }); const jsonFeed = await mkFeed(jsonInteg, 'Json feed');
    feedSrv.body = 'this is not json'; r = await runNow(jsonFeed.id); assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'BAD_FORMAT']);
    feedSrv.body = JSON.stringify({ indicators: ['7.7.7.7', { value: 'j.example.net' }] }); r = await runNow(jsonFeed.id); assert.deepStrictEqual([r.json.run.status, r.json.run.added], ['ok', 2]);
    const dead = await mkInteg('Dead feed', { feed_url: 'http://127.0.0.1:1/x?token=' + KEY_IN_URL, format: 'plain-text' }); const deadFeed = await mkFeed(dead, 'Dead feed');
    r = await runNow(deadFeed.id); assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'CONNECTION_REFUSED']); assert.ok(!r.text.includes(KEY_IN_URL));
    await call('PUT', `/v1/integrations/${dead.id}`, { enabled: false }); r = await runNow(deadFeed.id); assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'DISABLED']);
    delete process.env.ASIX_FEED_ALLOW_PRIVATE;
    await call('PUT', `/v1/integrations/${dead.id}`, { enabled: true }); r = await runNow(feed.id); assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'BLOCKED_ADDRESS'], 'without the switch an internal feed server is refused');
    process.env.ASIX_FEED_ALLOW_PRIVATE = '1';

    // 7. one run at a time: a lease, and an old lease is taken over
    await q(`UPDATE ioc_feeds SET running_since = localtimestamp WHERE id = $1`, [feed.id]);
    r = await runNow(feed.id); assert.deepStrictEqual([r.status, code(r)], [409, 'BUSY']);
    assert.strictEqual((await call('GET', '/v1/ioc-feeds/' + feed.id)).json.feed.running, true);
    await q(`UPDATE ioc_feeds SET running_since = localtimestamp - interval '20 minutes' WHERE id = $1`, [feed.id]);
    assert.strictEqual((await call('GET', '/v1/ioc-feeds/' + feed.id)).json.feed.running, false, 'a stale lease does not count');
    feedSrv.body = '198.51.100.1\nevil.example.com\n'; r = await runNow(feed.id); assert.strictEqual(r.json.run.status, 'ok');
    assert.strictEqual((await rows('SELECT running_since FROM ioc_feeds WHERE id = $1', [feed.id]))[0].running_since, null, 'the lease is released');

    // 8. the schedule: only what is due, across tenants, disabled ones left alone, unfinished runs closed
    as(B, eve); const bFeed = await mkFeed(bInteg, 'B list'); as(A, alice);
    const ids = [feed.id, bigFeed.id, jsonFeed.id, deadFeed.id, bFeed.id];
    await q(`UPDATE ioc_feeds SET last_run_at = localtimestamp WHERE id = ANY($1::uuid[])`, [ids]);
    await q(`UPDATE ioc_feeds SET last_run_at = localtimestamp - interval '25 hours' WHERE id = ANY($1::uuid[])`, [[feed.id, bFeed.id]]);
    await q(`UPDATE ioc_feeds SET last_run_at = localtimestamp - interval '2 hours', interval_hours = 6 WHERE id = $1`, [jsonFeed.id]);   // 6 hourly, run 2 hours ago: not due
    await q(`UPDATE ioc_feeds SET last_run_at = localtimestamp - interval '30 hours', enabled = false WHERE id = $1`, [bigFeed.id]);          // due but switched off
    await q(`INSERT INTO ioc_feed_runs (tenant_id, feed_id, run_kind, started_at) VALUES ($1, $2, 'schedule', localtimestamp - interval '1 hour')`, [A, jsonFeed.id]);
    feedSrv.requests.length = 0; feedSrv.body = '198.51.100.1\nevil.example.com\n';
    const before = (await rows('SELECT COUNT(*)::int AS n FROM ioc_feed_runs WHERE run_kind = $1', ['schedule']))[0].n;
    const due = await feeds.runDue(10);
    assert.deepStrictEqual(due, { due: 2, ran: 2 });
    assert.strictEqual((await rows('SELECT COUNT(*)::int AS n FROM ioc_feed_runs WHERE run_kind = $1', ['schedule']))[0].n, before + 2);
    assert.deepStrictEqual((await rows(`SELECT error_code FROM ioc_feed_runs WHERE feed_id = $1 AND status = 'failed' AND error_code = 'INTERRUPTED'`, [jsonFeed.id])).map((x) => x.error_code), ['INTERRUPTED'], 'an unfinished run is closed');
    assert.deepStrictEqual((await feeds.runDue(10)), { due: 0, ran: 0 }, 'nothing is due straight after');
    assert.strictEqual((await rows(`SELECT COUNT(*)::int AS n FROM ioc_feed_runs WHERE feed_id = $1 AND run_kind = 'schedule' AND status = 'ok'`, [bFeed.id]))[0].n, 1);

    // 9. history: newest first, trimmed to 100
    await q(`INSERT INTO ioc_feed_runs (tenant_id, feed_id, run_kind, status, started_at, finished_at) SELECT $1, $2, 'schedule', 'ok', localtimestamp - (g || ' minutes')::interval - interval '1 day', localtimestamp FROM generate_series(1, 110) g`, [A, jsonFeed.id]);
    await q(`UPDATE ioc_feeds SET running_since = NULL WHERE id = $1`, [jsonFeed.id]); feedSrv.body = '7.7.7.7\n'; await runNow(jsonFeed.id);
    assert.strictEqual((await rows('SELECT COUNT(*)::int AS n FROM ioc_feed_runs WHERE feed_id = $1', [jsonFeed.id]))[0].n, 100);
    r = await call('GET', `/v1/ioc-feeds/${jsonFeed.id}/runs?limit=5`); assert.strictEqual(r.json.runs.length, 5); assert.ok(new Date(r.json.runs[0].started_at) >= new Date(r.json.runs[4].started_at));
    r = await call('GET', `/v1/ioc-feeds/${jsonFeed.id}/runs?limit=0`); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_QUERY']);

    // 10. changing and deleting
    r = await call('PUT', '/v1/ioc-feeds/' + feed.id, { severity: 'critical', ttl_days: 7, interval_hours: 6, enabled: false }); assert.deepStrictEqual([r.status, r.json.feed.severity, r.json.feed.ttl_days, r.json.feed.interval_hours, r.json.feed.enabled], [200, 'critical', 7, 6, false]);
    r = await call('PUT', '/v1/ioc-feeds/' + feed.id, { integration_id: vtInteg.id }); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY']);
    r = await call('PUT', '/v1/ioc-feeds/' + feed.id, { name: 'big feed' }); assert.deepStrictEqual([r.status, code(r)], [409, 'NAME_TAKEN']);
    const keepN = (await ind(A, `AND source = 'feed:${jsonFeed.id}'`)).length; assert.ok(keepN >= 2);
    r = await call('DELETE', '/v1/ioc-feeds/' + jsonFeed.id); assert.deepStrictEqual([r.status, r.json.indicators_removed], [200, 0]);
    assert.strictEqual((await ind(A, `AND source = 'feed:${jsonFeed.id}'`)).length, keepN, 'the indicators stay and expire on their own');
    r = await call('DELETE', `/v1/ioc-feeds/${bigFeed.id}?remove_indicators=true`); assert.deepStrictEqual([r.status, r.json.indicators_removed], [200, 25]);
    assert.strictEqual((await ind(A, `AND source = 'feed:${bigFeed.id}'`)).length, 0);
    r = await call('DELETE', `/v1/ioc-feeds/${bigFeed.id}`); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']);
    r = await call('DELETE', `/v1/ioc-feeds/${feed.id}?remove_indicators=maybe`); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_QUERY']);
    r = await call('DELETE', `/v1/integrations/${dead.id}`); assert.strictEqual(r.status, 200);
    assert.strictEqual((await call('GET', '/v1/ioc-feeds/' + deadFeed.id)).status, 404, 'deleting the account removes the feeds that used it');

    // 11. no secret anywhere it should not be; every use of the account is audited; runs are audited with counts
    const everything = JSON.stringify([await rows('SELECT * FROM ioc_feeds'), await rows('SELECT * FROM ioc_feed_runs'), await rows('SELECT * FROM audit_events WHERE tenant_id IN ($1, $2)', [A, B]), seen]);
    assert.ok(!everything.includes(TOKEN), 'the token appears nowhere');
    const aud = await rows(`SELECT action, resource FROM audit_events WHERE tenant_id = $1 AND (action LIKE 'threatintel:feed:%' OR action = 'soar:integration:credentials-use')`, [A]);
    assert.ok(aud.some((x) => x.action === 'soar:integration:credentials-use' && /purpose=ioc\.feed:Main blocklist/.test(x.resource)));
    assert.ok(aud.some((x) => x.action === 'threatintel:feed:run' && /Main blocklist manual ok items=5 added=4 expired=0/.test(x.resource)));
    assert.ok(aud.some((x) => x.action === 'threatintel:feed:run' && /failed code=FEED_SHRANK/.test(x.resource)));
    for (const a of ['threatintel:feed:create', 'threatintel:feed:update', 'threatintel:feed:delete']) assert.ok(aud.some((x) => x.action === a), a);

    // 12. permissions per route and the module switch
    const perm = (m, p) => [...new Set(asked.filter((x) => x[0] === m && x[1] === p).map((x) => x[2]))];
    for (const [m, p, want] of [['GET', '/v1/ioc-feeds', 'threatintel:feeds:read'], ['GET', '/v1/ioc-feeds/:id', 'threatintel:feeds:read'], ['GET', '/v1/ioc-feeds/:id/runs', 'threatintel:feeds:read'],
      ['POST', '/v1/ioc-feeds', 'threatintel:feeds:write'], ['PUT', '/v1/ioc-feeds/:id', 'threatintel:feeds:write'], ['DELETE', '/v1/ioc-feeds/:id', 'threatintel:feeds:write'], ['POST', '/v1/ioc-feeds/:id/run', 'threatintel:feeds:write']]) assert.deepStrictEqual(perm(m, p), [want], `${m} ${p}`);
    const real = modules.isEnabled; modules.isEnabled = async (id) => (id === 'ioc-feeds' ? false : real(id));
    for (const [m, p, body] of [['GET', '/v1/ioc-feeds'], ['POST', '/v1/ioc-feeds', { integration_id: integ.id, name: 'z' }], ['GET', `/v1/ioc-feeds/${feed.id}`], ['PUT', `/v1/ioc-feeds/${feed.id}`, { enabled: true }], ['DELETE', `/v1/ioc-feeds/${feed.id}`], ['GET', `/v1/ioc-feeds/${feed.id}/runs`], ['POST', `/v1/ioc-feeds/${feed.id}/run`, {}]]) {
      r = await call(m, p, body); assert.deepStrictEqual([r.status, code(r)], [403, 'MODULE_DISABLED'], `${m} ${p}`);
    }
    modules.isEnabled = real;
    console.log('feeds-db: all checks passed');
  } finally {
    srv.close(); fs.closeAllConnections(); fs.close();
    for (const t of [A, B]) {
      for (const tbl of ['ioc_feed_runs', 'ioc_feeds', 'threat_indicators', 'integration_instances', 'audit_events', 'case_events', 'case_alerts', 'cases', 'users']) await q(`DELETE FROM ${tbl} WHERE tenant_id = $1`, [t]).catch((e) => console.error('cleanup', tbl, e.message));
      await q('DELETE FROM tenants WHERE id = $1', [t]).catch((e) => console.error('cleanup tenants', e.message));
    }
    await db.close();
  }
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
