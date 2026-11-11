'use strict';
// L1 against a real PostgreSQL (platform schema applied): the real routes, the real SQL in src/lists/service.js, the real public address (src/lists/feed.js),
// the real list actions inside the real action registry, and the real audit_events table. Only the sign-in chain is replaced (the same way as tests/actions-db.test.js).
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_USER=asix_admin DB_NAME=asix_platform DB_PASSWORD=... node tests/lists-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
process.env.ASIX_PROFILE = process.env.ASIX_PROFILE || 'home';

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT; let USER; const asked = [];
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared,
  guarded: (permission) => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = USER; asked.push([req.method, req.route ? req.route.path : req.path, permission]); next(); }],
};
const modules = require('../src/modules');
const model = require('../src/lists/model');

async function main() {
  const stamp = Date.now();
  const q = (t, p) => db.query(t, p);
  const mkTenant = async (n) => (await q('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['lists-' + n + '-' + stamp])).rows[0].id;
  const mkUser = async (t, n) => (await q('INSERT INTO users (tenant_id, username, email) VALUES ($1, $2, $3) RETURNING id', [t, `${n}-${stamp}`, `${n}-${stamp}@example.test`])).rows[0].id;
  const A = await mkTenant('a'); const B = await mkTenant('b');
  const alice = await mkUser(A, 'alice'); const eve = await mkUser(B, 'eve');

  const app = express();
  app.use(require('../src/lists/feed').router);   // before the JSON parser, as in the gateway
  app.use(express.json()); app.use(require('../src/gateway/routes/actions')); app.use(require('../src/gateway/routes/cases')); app.use(require('../src/gateway/routes/lists'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body, headers) => {
    const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...(headers || {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { /* plain text */ }
    return { status: r.status, json, text, headers: r.headers };
  };
  const code = (r) => r.json && r.json.error && r.json.error.code;
  const as = (t, u) => { TENANT = t; USER = u; };
  const rows = async (sql, p) => (await q(sql, p)).rows;
  const mkList = async (body) => { const r = await call('POST', '/v1/lists', body); assert.strictEqual(r.status, 201, JSON.stringify(r.json)); return r.json.list; };
  const add = (id, body) => call('POST', `/v1/lists/${id}/entries`, body);
  const values = async (id) => (await rows('SELECT value FROM list_entries WHERE list_id = $1 ORDER BY value', [id])).map((x) => x.value);
  const auditCount = async (t, action) => (await rows('SELECT COUNT(*)::int AS n FROM audit_events WHERE tenant_id = $1 AND action = $2', [t, action]))[0].n;
  as(A, alice);

  try {
    // 1. making lists: the choices, the unique name (any capitals), another tenant may use the same name, bad bodies
    let r = await call('GET', '/v1/lists');
    assert.deepStrictEqual([r.status, r.json.lists.length, r.json.kinds, r.json.item_types], [200, 0, ['block', 'allow', 'watch'], ['ip', 'domain', 'url', 'hash']]);
    assert.deepStrictEqual(r.json.expires, ['never', '1h', '24h', '7d', '30d', '90d']);
    const block = await mkList({ name: 'Bad IPs', kind: 'block', item_type: 'ip', description: 'from the blog' });
    assert.deepStrictEqual([block.kind, block.item_type, block.entry_count, block.feed_enabled, block.created_by_name, block.allow_private], ['block', 'ip', 0, false, 'alice-' + stamp, false]);
    r = await call('POST', '/v1/lists', { name: 'bad ips', kind: 'allow', item_type: 'ip' }); assert.deepStrictEqual([r.status, code(r)], [409, 'NAME_TAKEN']);
    for (const b of [{}, { name: 'x', kind: 'deny', item_type: 'ip' }, { name: 'x', kind: 'block', item_type: 'ip', extra: 1 }]) { r = await call('POST', '/v1/lists', b); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY']); }
    as(B, eve); const bList = await mkList({ name: 'Bad IPs', kind: 'block', item_type: 'ip' }); as(A, alice);
    assert.notStrictEqual(bList.id, block.id);
    r = await call('GET', '/v1/lists/' + bList.id); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND'], 'another tenant\'s list is not found');
    r = await call('GET', '/v1/lists/not-an-id'); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_ID']);
    assert.strictEqual(await auditCount(A, 'soar:list:create'), 1);

    // 2. adding: every value in its normal form; what a block list refuses is reported value by value and the rest still goes in
    r = await add(block.id, { text: '203.0.113.7\n198.51.100.77/24\n2001:DB8:0:0:0:0:0:1\n0.0.0.0/0\n10.1.2.3\n127.0.0.1\nnot an address\n203.0.113.7' });
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.json.added, ['198.51.100.0/24', '2001:db8::1', '203.0.113.7']);
    assert.deepStrictEqual(r.json.existing, []);
    assert.deepStrictEqual(r.json.refused.map((x) => [x.value, x.code]).sort(), [['0.0.0.0/0', 'TOO_WIDE'], ['10.1.2.3', 'PRIVATE_ADDRESS'], ['127.0.0.1', 'NOT_LISTABLE'], ['not an address', 'INVALID_VALUE']].sort());
    assert.strictEqual(r.json.list.entry_count, 3);
    assert.deepStrictEqual(await values(block.id), ['198.51.100.0/24', '2001:db8::1', '203.0.113.7']);
    let e = (await rows('SELECT * FROM list_entries WHERE list_id = $1 AND value = $2', [block.id, '203.0.113.7']))[0];
    assert.deepStrictEqual([e.source, e.added_by_name, e.expires_at, e.note, e.tenant_id], ['manual', 'alice-' + stamp, null, null, A]);
    // already on the list: left as it was (the note is not overwritten), reported as existing
    r = await add(block.id, { values: ['203.0.113.7', '192.0.2.1'], note: 'second note' });
    assert.deepStrictEqual([r.json.added, r.json.existing], [['192.0.2.1'], ['203.0.113.7']]);
    e = (await rows('SELECT note FROM list_entries WHERE list_id = $1 AND value = $2', [block.id, '203.0.113.7']))[0]; assert.strictEqual(e.note, null);
    // a list that allows private addresses takes them; the unusable ones are still refused
    const home = await mkList({ name: 'Home', kind: 'block', item_type: 'ip', allow_private: true });
    r = await add(home.id, { values: ['192.168.1.50', '127.0.0.1'] });
    assert.deepStrictEqual([r.json.added, r.json.refused.map((x) => x.code)], [['192.168.1.50'], ['NOT_LISTABLE']]);
    r = await call('PUT', '/v1/lists/' + home.id, { allow_private: false }); assert.strictEqual(r.json.list.allow_private, false);
    assert.deepStrictEqual(await values(home.id), ['192.168.1.50'], 'turning it off does not delete what is there');
    r = await add(home.id, { values: ['192.168.1.51'] }); assert.deepStrictEqual(r.json.refused.map((x) => x.code), ['PRIVATE_ADDRESS']);
    // bad requests
    for (const b of [{}, { values: [] }, { values: ['a'], expires: 'forever' }, { text: '# nothing' }]) { r = await add(block.id, b); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY']); }
    r = await add(bList.id, { values: ['1.2.3.4'] }); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND'], 'not another tenant\'s list');
    assert.deepStrictEqual(await values(bList.id), []);

    // 3. time: the database clock does the arithmetic; expired entries are not counted, not served, and can be added again
    r = await add(block.id, { values: ['192.0.2.50'], expires: '1h', note: 'for an hour' });
    assert.strictEqual(r.json.added.length, 1);
    e = (await rows(`SELECT note, (expires_at BETWEEN localtimestamp + interval '59 minutes' AND localtimestamp + interval '61 minutes') AS near FROM list_entries WHERE list_id = $1 AND value = '192.0.2.50'`, [block.id]))[0];
    assert.deepStrictEqual([e.note, e.near], ['for an hour', true]);
    await q(`UPDATE list_entries SET expires_at = localtimestamp - interval '1 hour' WHERE list_id = $1 AND value = '192.0.2.50'`, [block.id]);
    r = await call('GET', `/v1/lists/${block.id}/entries`); assert.ok(!r.json.entries.some((x) => x.value === '192.0.2.50')); assert.strictEqual(r.json.total, 4);
    r = await call('GET', `/v1/lists/${block.id}/entries?expired=true`); assert.deepStrictEqual(r.json.entries.map((x) => x.value), ['192.0.2.50']);
    assert.strictEqual((await call('GET', '/v1/lists/' + block.id)).json.list.entry_count, 4);
    r = await add(block.id, { values: ['192.0.2.50'], expires: '7d' }); assert.deepStrictEqual([r.json.added, r.json.existing], [['192.0.2.50'], []], 'an expired entry comes back as a new one');
    e = (await rows(`SELECT (expires_at > localtimestamp + interval '6 days') AS far FROM list_entries WHERE list_id = $1 AND value = '192.0.2.50'`, [block.id]))[0]; assert.strictEqual(e.far, true);
    await q(`UPDATE list_entries SET expires_at = localtimestamp - interval '3 days' WHERE list_id = $1 AND value = '192.0.2.50'`, [block.id]);
    await add(block.id, { values: ['192.0.2.60'] });
    assert.ok(!(await values(block.id)).includes('192.0.2.50'), 'entries expired for over a day are deleted on the next change');
    r = await add(block.id, { values: ['192.0.2.61'], expires_at: '2020-01-01T00:00:00' }); assert.deepStrictEqual([r.status, code(r)], [400, 'ALREADY_EXPIRED']);
    await call('POST', `/v1/lists/${block.id}/entries/remove`, { values: ['192.0.2.60'] });

    // 4. entries: search, paging, total
    const many = await mkList({ name: 'Many names', kind: 'watch', item_type: 'domain' });
    await add(many.id, { values: Array.from({ length: 120 }, (_, i) => `host${String(i).padStart(3, '0')}.example.org`).concat(['other.net']), note: 'bulk' });
    r = await call('GET', `/v1/lists/${many.id}/entries?limit=50&offset=100`);
    assert.deepStrictEqual([r.json.total, r.json.entries.length, r.json.limit, r.json.offset], [121, 21, 50, 100]);
    r = await call('GET', `/v1/lists/${many.id}/entries?q=OTHER`); assert.deepStrictEqual(r.json.entries.map((x) => x.value), ['other.net']);
    r = await call('GET', `/v1/lists/${many.id}/entries?q=%25`); assert.strictEqual(r.json.total, 0, 'a percent sign is text, not a pattern');
    r = await call('GET', `/v1/lists/${many.id}/entries?limit=999`); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_QUERY']);

    // 5. what an allow list protects: a block list refuses it, per value, and only this tenant's active allow entries count
    const allowIp = await mkList({ name: 'Office', kind: 'allow', item_type: 'ip' });
    const allowDom = await mkList({ name: 'Partners', kind: 'allow', item_type: 'domain' });
    r = await add(allowIp.id, { values: ['10.0.0.0/8', '203.0.113.128/25'] }); assert.strictEqual(r.json.added.length, 2, 'an allow list takes private addresses');
    await add(allowDom.id, { values: ['example.com', 'ok.bad.org'] });
    r = await add(block.id, { values: ['203.0.113.200', '203.0.113.0/24', '203.0.112.1', '8.8.8.8'] });
    assert.deepStrictEqual(r.json.added.sort(), ['203.0.112.1', '8.8.8.8']);
    assert.deepStrictEqual(r.json.refused.map((x) => [x.value, x.code]).sort(), [['203.0.113.0/24', 'ON_ALLOW_LIST'], ['203.0.113.200', 'ON_ALLOW_LIST']]);
    assert.ok(/Office/.test(r.json.refused[0].message), 'the message names the allow list');
    const blockDom = await mkList({ name: 'Bad names', kind: 'block', item_type: 'domain' });
    r = await add(blockDom.id, { values: ['evil.example.com', 'example.com', 'bad.org', 'badexample.com', 'evil.org'] });
    assert.deepStrictEqual(r.json.added.sort(), ['badexample.com', 'evil.org']);
    assert.deepStrictEqual(r.json.refused.map((x) => x.code), ['ON_ALLOW_LIST', 'ON_ALLOW_LIST', 'ON_ALLOW_LIST']);
    r = await add(many.id, { values: ['example.com'] }); assert.strictEqual(r.json.added.length, 1, 'a watch list is not checked against an allow list');
    as(B, eve); const bAllowFree = await mkList({ name: 'Mine', kind: 'block', item_type: 'ip' });
    r = await add(bAllowFree.id, { values: ['203.0.113.200'] }); assert.strictEqual(r.json.added.length, 1, 'another tenant\'s allow list does not apply'); as(A, alice);
    await q(`UPDATE list_entries SET expires_at = localtimestamp - interval '1 minute' WHERE list_id = $1 AND value = '203.0.113.128/25'`, [allowIp.id]);
    r = await add(block.id, { values: ['203.0.113.200'] }); assert.deepStrictEqual(r.json.added, ['203.0.113.200'], 'an expired allow entry protects nothing');

    // 6. the size limit: a request that would pass it is refused as a whole
    const big = await mkList({ name: 'Big', kind: 'watch', item_type: 'url' });
    await q(`INSERT INTO list_entries (tenant_id, list_id, value, added_by_name) SELECT $1, $2, 'http://h' || g || '.example.com/', 'test' FROM generate_series(1, $3) g`, [A, big.id, model.LIMITS.entriesPerList - 1]);
    r = await add(big.id, { values: ['http://a.example.com/', 'http://b.example.com/'] }); assert.deepStrictEqual([r.status, code(r)], [409, 'LIST_FULL']);
    assert.strictEqual((await rows('SELECT COUNT(*)::int AS n FROM list_entries WHERE list_id = $1', [big.id]))[0].n, model.LIMITS.entriesPerList - 1, 'nothing was added');
    r = await add(big.id, { values: ['http://a.example.com/'] }); assert.strictEqual(r.json.added.length, 1);

    // 7. removing: any way of writing the value finds it; what is not there is reported
    r = await call('POST', `/v1/lists/${blockDom.id}/entries/remove`, { values: ['EVIL.org.', 'nothing.net', 'bad value'] });
    assert.deepStrictEqual([r.status, r.json.removed, r.json.missing.sort()], [200, ['evil.org'], ['bad value', 'nothing.net']]);
    assert.deepStrictEqual(await values(blockDom.id), ['badexample.com']);
    r = await call('POST', `/v1/lists/${blockDom.id}/entries/remove`, { values: [] }); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY']);

    // 8. renaming and changing: only name, description and allow_private; the new name must be free
    r = await call('PUT', '/v1/lists/' + block.id, { name: 'Office' }); assert.deepStrictEqual([r.status, code(r)], [409, 'NAME_TAKEN']);
    r = await call('PUT', '/v1/lists/' + block.id, { name: 'Bad IPs (renamed)', description: null }); assert.deepStrictEqual([r.status, r.json.list.name, r.json.list.description], [200, 'Bad IPs (renamed)', null]);
    r = await call('PUT', '/v1/lists/' + block.id, { kind: 'allow' }); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY']);
    r = await call('PUT', '/v1/lists/' + blockDom.id, { allow_private: true }); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY'], 'private addresses make no sense for names');
    r = await call('PUT', '/v1/lists/' + bList.id, { name: 'x' }); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']);

    // 9. the address a firewall polls: made once, only a hash is kept, served as plain text, replaced, turned off
    r = await call('POST', `/v1/lists/${block.id}/feed`, {});
    assert.strictEqual(r.status, 201);
    const t1 = r.json.feed_path.split('/').pop();
    assert.ok(model.tokenShape(t1)); assert.strictEqual(r.json.feed_url, base + '/v1/list-feed/' + t1, 'built from the address the caller used');
    let li = (await rows('SELECT feed_token_hash, feed_token_hint, feed_created_at FROM lists WHERE id = $1', [block.id]))[0];
    assert.deepStrictEqual([li.feed_token_hash, li.feed_token_hint], [model.hashToken(t1), t1.slice(-4)]); assert.ok(li.feed_created_at);
    assert.ok(!JSON.stringify(await rows('SELECT * FROM lists')).includes(t1), 'the token itself is stored nowhere');
    assert.ok(!JSON.stringify(await rows('SELECT * FROM audit_events WHERE tenant_id = $1', [A])).includes(t1), 'nor in the audit log');
    r = await call('GET', '/v1/lists/' + block.id); assert.deepStrictEqual([r.json.list.feed_enabled, r.json.list.feed_token_hint, 'feed_token_hash' in r.json.list], [true, t1.slice(-4), false]);
    r = await call('GET', '/v1/list-feed/' + t1);   // no sign-in: the harness does not even pass one
    assert.strictEqual(r.status, 200); assert.match(r.headers.get('content-type'), /^text\/plain/);
    const published = (await values(block.id));
    const live = (await rows(`SELECT value FROM list_entries WHERE list_id = $1 AND (expires_at IS NULL OR expires_at > localtimestamp) ORDER BY value`, [block.id])).map((x) => x.value);
    assert.strictEqual(r.text, [...live].sort().join('\n') + '\n'); assert.ok(published.length >= live.length);
    assert.ok(!r.text.includes('Bad IPs') && !r.text.includes('from the blog'), 'only values: no name, no note, no comments');
    await new Promise((res) => setTimeout(res, 200));
    li = (await rows('SELECT feed_last_fetch_at, feed_last_fetch_ip FROM lists WHERE id = $1', [block.id]))[0]; assert.ok(li.feed_last_fetch_at); assert.ok(li.feed_last_fetch_ip);
    assert.strictEqual((await call('GET', '/v1/lists/' + block.id)).json.list.feed_last_fetch_ip, li.feed_last_fetch_ip);
    const etag = r.headers.get('etag'); r = await call('GET', '/v1/list-feed/' + t1, undefined, { 'If-None-Match': etag }); assert.strictEqual(r.status, 304);
    await add(block.id, { values: ['192.0.2.99'] }); r = await call('GET', '/v1/list-feed/' + t1, undefined, { 'If-None-Match': etag }); assert.strictEqual(r.status, 200, 'a changed list is sent again');
    assert.ok(r.text.includes('192.0.2.99'));
    r = await call('GET', '/v1/list-feed/' + t1 + 'x'); assert.strictEqual(r.status, 404);
    // a new address replaces the old at once
    r = await call('POST', `/v1/lists/${block.id}/feed`, {}); const t2 = r.json.feed_path.split('/').pop(); assert.notStrictEqual(t1, t2);
    assert.strictEqual((await call('GET', '/v1/list-feed/' + t1)).status, 404); assert.strictEqual((await call('GET', '/v1/list-feed/' + t2)).status, 200);
    await new Promise((res) => setTimeout(res, 200));   // the fetch record is written after the answer
    li = (await rows('SELECT feed_last_fetch_at FROM lists WHERE id = $1', [block.id]))[0]; assert.strictEqual(!!li.feed_last_fetch_at && new Date(li.feed_last_fetch_at) > new Date(Date.now() - 600000), true, 'fetch record restarts');
    // another tenant's list has its own address and never shows this one's values
    as(B, eve); r = await call('POST', `/v1/lists/${bAllowFree.id}/feed`, {}); const tb = r.json.feed_path.split('/').pop(); as(A, alice);
    r = await call('GET', '/v1/list-feed/' + tb); assert.strictEqual(r.text, '203.0.113.200\n');
    r = await call('POST', `/v1/lists/${bList.id}/feed`, {}); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']);
    // off
    r = await call('DELETE', `/v1/lists/${block.id}/feed`); assert.deepStrictEqual([r.status, r.json.list.feed_enabled], [200, false]);
    assert.strictEqual((await call('GET', '/v1/list-feed/' + t2)).status, 404);
    for (const a of ['soar:list:feed-create', 'soar:list:feed-revoke']) assert.ok(await auditCount(A, a) >= 1, a);

    // 10. the two actions in the registry: off until enabled, run by a person, undone, refused by the same rules, waiting for approval when automation asks
    const act = require('../src/actions/service');
    r = await call('POST', '/v1/actions/list.add_entry/run', { parameters: { list_id: block.id, value: '192.0.2.10' } });
    assert.deepStrictEqual([r.status, code(r)], [409, 'ACTION_DISABLED']); assert.ok(!(await values(block.id)).includes('192.0.2.10'));
    for (const id of ['list.add_entry', 'list.remove_entry']) { r = await call('PUT', `/v1/actions/${id}/setting`, { enabled: true }); assert.strictEqual(r.status, 200, id); }
    r = await call('PUT', '/v1/actions/list.add_entry/setting', { autonomy: 4 }); assert.deepStrictEqual([r.status, code(r)], [400, 'AUTONOMY_TOO_HIGH'], 'medium risk never runs at level 4');
    r = await call('POST', '/v1/actions/list.add_entry/run', { parameters: { list_id: block.id, value: '192.0.2.10', note: 'from a playbook' } });
    assert.strictEqual(r.status, 201); assert.strictEqual(r.json.run.status, 'succeeded'); assert.deepStrictEqual(r.json.run.undo, { action: 'list.remove_entry', params: { list_id: block.id, value: '192.0.2.10' } });
    e = (await rows(`SELECT source, note, (expires_at BETWEEN localtimestamp + interval '29 days' AND localtimestamp + interval '31 days') AS thirty FROM list_entries WHERE list_id = $1 AND value = '192.0.2.10'`, [block.id]))[0];
    assert.deepStrictEqual([e.source, e.note, e.thirty], ['action', 'from a playbook', true], 'an action adds for 30 days unless told otherwise');
    const addRun = r.json.run;
    r = await call('POST', `/v1/actions/runs/${addRun.id}/undo`); assert.strictEqual(r.status, 200); assert.ok(!(await values(block.id)).includes('192.0.2.10'), 'undo takes it off');
    // the same value again: already there -> nothing to undo
    await call('POST', '/v1/actions/list.add_entry/run', { parameters: { list_id: block.id, value: '192.0.2.10' } });
    r = await call('POST', '/v1/actions/list.add_entry/run', { parameters: { list_id: block.id, value: '192.0.2.10' } });
    assert.deepStrictEqual([r.json.run.status, r.json.run.result.added, r.json.run.result.already, r.json.run.undo], ['succeeded', 0, 1, null]);
    // refused by the list's own rules: the run is recorded as failed, with the reason, and nothing was added
    r = await call('POST', '/v1/actions/list.add_entry/run', { parameters: { list_id: block.id, value: '10.9.9.9' } });
    assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'PRIVATE_ADDRESS']); assert.match(r.json.run.error_message, /private address/);
    r = await call('POST', '/v1/actions/list.add_entry/run', { parameters: { list_id: block.id, value: '203.0.113.130' } });
    assert.strictEqual(r.json.run.status, 'succeeded', 'the allow entry that covered it has expired in this test, so it is allowed now');
    await q(`INSERT INTO list_entries (tenant_id, list_id, value, added_by_name) VALUES ($1, $2, '192.0.2.250', 'test')`, [A, allowIp.id]);
    r = await call('POST', '/v1/actions/list.add_entry/run', { parameters: { list_id: block.id, value: '192.0.2.250' } });
    assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'ON_ALLOW_LIST']); assert.ok(!(await values(block.id)).includes('192.0.2.250'));
    r = await call('POST', '/v1/actions/list.add_entry/run', { parameters: { list_id: bList.id, value: '192.0.2.11' } }); assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'NOT_FOUND'], 'not another tenant\'s list');
    r = await call('POST', '/v1/actions/list.add_entry/run', { parameters: { list_id: block.id, value: '192.0.2.11', expires: 'forever' } }); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_PARAMETER']);
    // remove, then undo: the entry comes back with its note and its exact expiry time
    await add(block.id, { values: ['192.0.2.20'], note: 'keep this note', expires: '24h' });
    const before = (await rows(`SELECT to_char(expires_at, 'YYYY-MM-DD"T"HH24:MI:SS') AS t FROM list_entries WHERE list_id = $1 AND value = '192.0.2.20'`, [block.id]))[0].t;
    r = await call('POST', '/v1/actions/list.remove_entry/run', { parameters: { list_id: block.id, value: '192.0.2.20' } });
    assert.strictEqual(r.json.run.status, 'succeeded'); assert.deepStrictEqual(r.json.run.undo.params, { list_id: block.id, value: '192.0.2.20', note: 'keep this note', expires_at: before });
    assert.ok(!(await values(block.id)).includes('192.0.2.20'));
    r = await call('POST', `/v1/actions/runs/${r.json.run.id}/undo`); assert.strictEqual(r.status, 200);
    e = (await rows(`SELECT note, source, to_char(expires_at, 'YYYY-MM-DD"T"HH24:MI:SS') AS t FROM list_entries WHERE list_id = $1 AND value = '192.0.2.20'`, [block.id]))[0];
    assert.deepStrictEqual([e.note, e.t], ['keep this note', before], 'undo restores the entry exactly');
    r = await call('POST', '/v1/actions/list.remove_entry/run', { parameters: { list_id: block.id, value: '192.0.2.222' } });
    assert.deepStrictEqual([r.json.run.status, r.json.run.result.removed, r.json.run.undo], ['succeeded', 0, null]);
    // automation asking waits for a person at level 2 and at level 3 (medium risk)
    const wait = await db.withTenant(A, (c) => act.request(c, A, alice, 'list.add_entry', { list_id: block.id, value: '192.0.2.30' }, 'automation'));
    assert.strictEqual(wait.run.status, 'awaiting_approval'); assert.ok(!(await values(block.id)).includes('192.0.2.30'));
    r = await call('POST', `/v1/actions/runs/${wait.run.id}/approve`); assert.strictEqual(r.json.run.status, 'succeeded'); assert.ok((await values(block.id)).includes('192.0.2.30'));
    assert.strictEqual((await rows(`SELECT source FROM list_entries WHERE list_id = $1 AND value = '192.0.2.30'`, [block.id]))[0].source, 'action');

    // 11. the audit log: one row per change, counts and list names, never a value
    for (const a of ['soar:list:create', 'soar:list:add', 'soar:list:remove', 'soar:list:update']) assert.ok(await auditCount(A, a) >= 1, a);
    const resources = (await rows('SELECT resource FROM audit_events WHERE tenant_id = $1 AND action LIKE $2', [A, 'soar:list:%'])).map((x) => x.resource).join('\n');
    assert.ok(!/\d+\.\d+\.\d+\.\d+/.test(resources.replace(/\bBad IPs\b/g, '')), 'no address in the audit log: ' + resources.slice(0, 300));
    assert.match(resources, /added=3 already=0 refused=4/);

    // 12. which permission each route asks for
    const perm = (m, p) => [...new Set(asked.filter((x) => x[0] === m && x[1] === p).map((x) => x[2]))];
    for (const [m, p, want] of [['GET', '/v1/lists', 'soar:lists:read'], ['GET', '/v1/lists/:id', 'soar:lists:read'], ['GET', '/v1/lists/:id/entries', 'soar:lists:read'],
      ['POST', '/v1/lists', 'soar:lists:write'], ['PUT', '/v1/lists/:id', 'soar:lists:write'], ['POST', '/v1/lists/:id/entries', 'soar:lists:write'],
      ['POST', '/v1/lists/:id/entries/remove', 'soar:lists:write'], ['POST', '/v1/lists/:id/feed', 'soar:lists:write'], ['DELETE', '/v1/lists/:id/feed', 'soar:lists:write']]) {
      assert.deepStrictEqual(perm(m, p), [want], `${m} ${p} asked for ${perm(m, p)}`);
    }

    // 13. deleting a list: its entries go, its address stops, the audit row counts what went
    r = await call('POST', `/v1/lists/${bList.id}/feed`, {}); assert.strictEqual(r.status, 404);
    await call('POST', `/v1/lists/${home.id}/feed`, {}).then((x) => { global.tHome = x.json.feed_path.split('/').pop(); });
    assert.strictEqual((await call('GET', '/v1/list-feed/' + global.tHome)).status, 200);
    r = await call('DELETE', '/v1/lists/' + home.id); assert.strictEqual(r.status, 200);
    assert.strictEqual((await rows('SELECT COUNT(*)::int AS n FROM list_entries WHERE list_id = $1', [home.id]))[0].n, 0);
    assert.strictEqual((await call('GET', '/v1/list-feed/' + global.tHome)).status, 404);
    assert.deepStrictEqual([(await call('GET', '/v1/lists/' + home.id)).status, (await call('DELETE', '/v1/lists/' + home.id)).status], [404, 404]);
    assert.ok((await rows('SELECT resource FROM audit_events WHERE tenant_id = $1 AND action = $2', [A, 'soar:list:delete']))[0].resource.includes('Home entries=1'));
    as(B, eve); r = await call('DELETE', '/v1/lists/' + block.id); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']); as(A, alice);
    assert.ok((await call('GET', '/v1/lists/' + block.id)).status === 200, 'another tenant cannot delete it');
    assert.deepStrictEqual([...new Set(asked.filter((x) => x[0] === 'DELETE' && x[1] === '/v1/lists/:id').map((x) => x[2]))], ['soar:lists:write']);
    r = await call('GET', '/v1/lists'); assert.ok(r.json.lists.every((l) => l.created_by_name.endsWith(String(stamp))));
    assert.ok(!r.json.lists.some((l) => l.id === bList.id), 'the list of lists is this tenant\'s only');

    // 14. a deployment with the module off answers 403 on every authenticated route (the public address is not one of them)
    const real = modules.isEnabled; modules.isEnabled = async (id) => (id === 'lists' ? false : real(id));
    for (const [m, p, body] of [['GET', '/v1/lists'], ['POST', '/v1/lists', { name: 'x', kind: 'block', item_type: 'ip' }], ['GET', `/v1/lists/${block.id}`], ['PUT', `/v1/lists/${block.id}`, { name: 'y' }], ['DELETE', `/v1/lists/${block.id}`],
      ['GET', `/v1/lists/${block.id}/entries`], ['POST', `/v1/lists/${block.id}/entries`, { values: ['1.2.3.4'] }], ['POST', `/v1/lists/${block.id}/entries/remove`, { values: ['1.2.3.4'] }], ['POST', `/v1/lists/${block.id}/feed`, {}], ['DELETE', `/v1/lists/${block.id}/feed`]]) {
      r = await call(m, p, body); assert.deepStrictEqual([r.status, code(r)], [403, 'MODULE_DISABLED'], `${m} ${p}`);
    }
    modules.isEnabled = real;
    console.log('lists-db: all checks passed');
  } finally {
    srv.close();
    for (const t of [A, B]) {
      for (const tbl of ['action_runs', 'action_settings', 'audit_events', 'list_entries', 'lists', 'case_events', 'case_alerts', 'cases', 'alerts', 'users']) await q(`DELETE FROM ${tbl} WHERE tenant_id = $1`, [t]).catch((e) => console.error('cleanup', tbl, e.message));
      await q('DELETE FROM tenants WHERE id = $1', [t]).catch((e) => console.error('cleanup tenants', e.message));
    }
    await db.close();
  }
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
