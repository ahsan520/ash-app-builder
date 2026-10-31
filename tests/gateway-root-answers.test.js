'use strict';
// Regression test: every request that passes through the gateway must still be answered.
// Found 2026-10-31: wazuh-manager.js exported its helper as `module.exports.handle`, but module.exports is an Express router and `router.handle`
// is the method Express calls to run each request through it. Overwriting it made every request that reached that router hang forever
// (GET / and every route mounted after it, the Endpoints page included), so the liveness probe killed the API pods.
const { describe, it } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const express = require('express');

function get(port, path) {
  return new Promise((resolve) => {
    const q = http.get({ port, path, timeout: 3000 }, (r) => { r.resume(); resolve(r.statusCode); });
    q.on('timeout', () => { q.destroy(); resolve('HANG'); });
    q.on('error', () => resolve('ERROR'));
  });
}

describe('gateway answers every request', () => {
  it('no route file overwrites a method Express uses on its router', () => {
    for (const f of ['wazuh-manager', 'endpoint-checks', 'endpoint-alerts', 'agent-alert']) {
      const r = require('../src/gateway/routes/' + f);
      assert.strictEqual(r.handle, express.Router().handle, f + ' replaced router.handle: Express could no longer run requests through it');
    }
  });
  it('GET / and an unknown path are answered by the real gateway app', async () => {
    const app = require('../src/gateway');
    const server = app.listen(0);
    try {
      const port = server.address().port;
      assert.strictEqual(await get(port, '/'), 200);
      assert.strictEqual(await get(port, '/no-such-path'), 404);
      assert.strictEqual(await get(port, '/v1/endpoints/agents/002/sca'), 401);   // reaches the new route file and is refused for want of a token, not left hanging
    } finally { server.close(); }
  });
});
