'use strict';
// L1: the address a firewall polls (src/lists/feed.js), on a real Express app over a real socket, with the database replaced by a small fake.
// What is checked: no sign-in is needed (the secret in the address is the credential), a wrong or revoked address is a plain 404 that never reaches the
// database when the shape is wrong, the text and ETag, 304 on If-None-Match, the rate limit, the fetch record, and that nothing logs the token.
process.env.ASIX_LIST_FEED_RATE_PER_MIN = '10';
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const http = require('http');
const express = require('express');
const model = require('../src/lists/model');

const TOKEN = model.newToken();
const OTHER = model.newToken();
const state = { queries: [], values: ['9.9.9.9', '1.1.1.1', '203.0.113.0/24'], tenantCalls: [] };
const fakeDb = {
  async query(text, params) {
    state.queries.push({ text, params });
    if (/FROM lists WHERE feed_token_hash/.test(text)) return { rows: params[0] === model.hashToken(TOKEN) ? [{ id: 'list-1', tenant_id: 'tenant-1' }] : [] };
    return { rows: [] };
  },
  async withTenant(tenantId, cb) { state.tenantCalls.push(tenantId); return cb({ async query(text, params) { state.queries.push({ text, params }); return { rows: state.values.map((value) => ({ value })) }; } }); },
};
require.cache[require.resolve('../src/db')] = { id: require.resolve('../src/db'), filename: require.resolve('../src/db'), loaded: true, exports: fakeDb };
const { router } = require('../src/lists/feed');

let server; let port; const logged = [];
const realError = console.error;
before(async () => {
  console.error = (...a) => { logged.push(a.join(' ')); };
  const app = express(); app.use(router);
  await new Promise((r) => { server = app.listen(0, '127.0.0.1', r); }); port = server.address().port;
});
after(() => { console.error = realError; server.close(); });

const get = (p, headers = {}) => new Promise((resolve, reject) => {
  http.get({ port, path: p, headers }, (res) => { let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b })); }).on('error', reject);
});

describe('the list address', () => {
  it('answers a good address with sorted plain text, no sign-in needed', async () => {
    const r = await get('/v1/list-feed/' + TOKEN);
    assert.strictEqual(r.status, 200);
    assert.match(r.headers['content-type'], /^text\/plain/);
    assert.strictEqual(r.body, '1.1.1.1\n203.0.113.0/24\n9.9.9.9\n');
    assert.strictEqual(r.headers['x-asix-list-count'], '3');
    assert.match(r.headers.etag, /^"[0-9a-f]{32}"$/);
    assert.strictEqual(r.headers['x-content-type-options'], 'nosniff');
    assert.deepStrictEqual(state.tenantCalls, ['tenant-1']);   // read as the list's own tenant
  });
  it('looks the address up by its hash, never by the secret itself', () => {
    const lookup = state.queries.find((q) => /feed_token_hash/.test(q.text));
    assert.deepStrictEqual(lookup.params, [model.hashToken(TOKEN)]);
    assert.ok(!state.queries.some((q) => JSON.stringify(q.params).includes(TOKEN)));
  });
  it('answers 304 when the person already has this version', async () => {
    const first = await get('/v1/list-feed/' + TOKEN);
    const r = await get('/v1/list-feed/' + TOKEN, { 'If-None-Match': first.headers.etag });
    assert.strictEqual(r.status, 304); assert.strictEqual(r.body, '');
  });
  it('changes the ETag when the list changes, and an empty list is an empty 200', async () => {
    const before = (await get('/v1/list-feed/' + TOKEN)).headers.etag;
    state.values = ['8.8.8.8'];
    const changed = await get('/v1/list-feed/' + TOKEN);
    assert.notStrictEqual(changed.headers.etag, before);
    state.values = [];
    const empty = await get('/v1/list-feed/' + TOKEN);
    assert.strictEqual(empty.status, 200); assert.strictEqual(empty.body, ''); assert.strictEqual(empty.headers['x-asix-list-count'], '0');
    state.values = ['9.9.9.9', '1.1.1.1', '203.0.113.0/24'];
  });
});

describe('a wrong address', () => {
  it('a token of the wrong shape is a 404 that never touches the database', async () => {
    const n = state.queries.length;
    for (const p of ['/v1/list-feed/x', '/v1/list-feed/asix_lt_short', '/v1/list-feed/asix_ik_' + 'a'.repeat(43), '/v1/list-feed/' + 'a'.repeat(100)]) {
      const r = await get(p); assert.strictEqual(r.status, 404, p); assert.strictEqual(r.body, 'Not found\n');
    }
    assert.strictEqual(state.queries.length, n);
  });
  it('an unknown, revoked or replaced token is the same plain 404', async () => {
    const r = await get('/v1/list-feed/' + OTHER);
    assert.strictEqual(r.status, 404); assert.strictEqual(r.body, 'Not found\n'); assert.match(r.headers['content-type'], /^text\/plain/);
    assert.strictEqual(r.headers['cache-control'], 'no-store');
  });
  it('is limited per address, and the limit is per token', async () => {
    const t = model.newToken(); const seen = [];
    for (let i = 0; i < 12; i++) seen.push((await get('/v1/list-feed/' + t)).status);
    assert.deepStrictEqual(seen, [...Array(10).fill(404), 429, 429]);
    assert.strictEqual((await get('/v1/list-feed/' + OTHER)).status, 404);   // another token still gets through
  });
});

describe('the fetch record', () => {
  it('is written by the database clock, at most once a minute, and a failure never changes the answer', async () => {
    const t = model.newToken();
    const orig = fakeDb.query;
    let updates = 0;
    fakeDb.query = async (text, params) => {
      if (/FROM lists WHERE feed_token_hash/.test(text)) return { rows: [{ id: 'list-2', tenant_id: 'tenant-2' }] };
      if (/UPDATE lists SET feed_last_fetch_at/.test(text)) { updates++; assert.match(text, /localtimestamp/); assert.match(text, /interval '1 minute'/); throw new Error('database is busy'); }
      return orig(text, params);
    };
    const r = await get('/v1/list-feed/' + t);
    await new Promise((res) => setImmediate(res));
    fakeDb.query = orig;
    assert.strictEqual(r.status, 200); assert.strictEqual(updates, 1);
    assert.ok(logged.some((l) => /could not record the fetch/.test(l)));
  });
  it('a database error is a plain 500 with no detail', async () => {
    const orig = fakeDb.query; fakeDb.query = async () => { throw new Error('password authentication failed for user asix_admin'); };
    const r = await get('/v1/list-feed/' + model.newToken());
    fakeDb.query = orig;
    assert.strictEqual(r.status, 500); assert.strictEqual(r.body, 'Error\n');
  });
  it('nothing the module logged contains a token', () => {
    for (const l of logged) assert.ok(!l.includes('asix_lt_'), l);
  });
});

describe('where it is mounted', () => {
  const fs = require('fs'); const path = require('path');
  const index = fs.readFileSync(path.join(__dirname, '../src/gateway/index.js'), 'utf8');
  it('before the JSON parser and the sign-in chain, and not behind the licensing gate', () => {
    const feed = index.indexOf("require('../lists/feed')");
    assert.ok(feed > 0);
    assert.ok(feed < index.indexOf('app.use(express.json())'));
    assert.ok(feed < index.indexOf("require('../licensing/gate')"));
  });
  it('the authenticated routes come after the gate and the action registry', () => {
    assert.ok(index.indexOf("require('./routes/lists')") > index.indexOf("require('./routes/actions')"));
    assert.ok(index.indexOf("require('./routes/lists')") > index.indexOf("require('../licensing/gate')"));
  });
});
