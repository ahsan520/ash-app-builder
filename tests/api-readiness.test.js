'use strict';
// H1 (2026-10-31): the API must not be able to go down because of one bad build or one slow moment.
// What happened: a route file overwrote router.handle, every request that reached that router hung, /v1/health/status (mounted early) still answered,
// so the new pods became Ready, replaced the old ones, and the 1 s liveness probe on / then killed them in a loop (502/504 in the portal).
const { describe, it } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');

const manifest = fs.readFileSync(path.join(__dirname, '..', 'k8s', '30-asix-api.yaml'), 'utf8');
const probe = (name) => {
  const m = new RegExp('\\n {10}' + name + ':\\n((?: {12}.*\\n| {14}.*\\n)+)').exec(manifest);
  assert.ok(m, name + ' is missing from k8s/30-asix-api.yaml');
  const pick = (k) => { const x = new RegExp('\\b' + k + ': (\\S+)').exec(m[1]); return x ? x[1] : null; };
  return { path: pick('path'), timeout: Number(pick('timeoutSeconds')), failure: Number(pick('failureThreshold')), period: Number(pick('periodSeconds')) };
};

function get(port, p) {
  return new Promise((resolve) => {
    const q = http.get({ port, path: p, timeout: 3000 }, (r) => { let b = ''; r.on('data', (c) => { b += c; }); r.on('end', () => resolve({ status: r.statusCode, body: b })); });
    q.on('timeout', () => { q.destroy(); resolve({ status: 'HANG' }); });
    q.on('error', () => resolve({ status: 'ERROR' }));
  });
}

describe('API readiness (route)', () => {
  it('/v1/health/ready is mounted after every router, so it only answers when the whole chain passes requests on', () => {
    const app = require('../src/gateway');
    const stack = (app.router || app._router).stack;
    const ready = stack.findIndex((l) => l.route && l.route.path === '/v1/health/ready');
    assert.ok(ready >= 0, 'no /v1/health/ready route');
    const lastRouter = stack.reduce((n, l, i) => (l.name === 'router' ? i : n), -1);
    assert.ok(lastRouter >= 0 && ready > lastRouter, 'the ready route must come after the last mounted router (index ' + ready + ' vs ' + lastRouter + ')');
  });
  it('answers 200 when the database answers and 503 when it does not (the real gateway app)', async () => {
    const db = require('../src/db');
    const original = db.healthCheck;
    const app = require('../src/gateway');
    const server = app.listen(0);
    try {
      const port = server.address().port;
      db.healthCheck = async () => true;
      const ok = await get(port, '/v1/health/ready');
      assert.strictEqual(ok.status, 200);
      assert.strictEqual(JSON.parse(ok.body).status, 'ok');
      db.healthCheck = async () => { throw new Error('connection refused'); };
      assert.strictEqual((await get(port, '/v1/health/ready')).status, 503);
      db.healthCheck = async () => false;
      assert.strictEqual((await get(port, '/v1/health/ready')).status, 503);
    } finally { db.healthCheck = original; server.close(); }
  });
  it('a router that never answers makes the ready route hang too, which is the point: the pod would not become Ready', async () => {
    const app = express();
    const broken = express.Router();
    broken.handle = () => {};                                    // the 2026-10-31 bug in one line
    app.use(broken);
    app.get('/v1/health/status', (req, res) => res.json({ ok: true }));   // mounted before: still fine, which is why it was not a good readiness check
    app.get('/v1/health/ready', (req, res) => res.json({ ok: true }));
    const server = app.listen(0);
    try {
      const port = server.address().port;
      assert.strictEqual((await get(port, '/v1/health/ready')).status, 'HANG');
    } finally { server.close(); }
  });
});

describe('API deployment manifest (k8s/30-asix-api.yaml)', () => {
  it('readiness uses the ready route, liveness uses /, startup uses the ready route', () => {
    assert.strictEqual(probe('readinessProbe').path, '/v1/health/ready');
    assert.strictEqual(probe('livenessProbe').path, '/');
    assert.strictEqual(probe('startupProbe').path, '/v1/health/ready');
  });
  it('no probe keeps the 1 second Kubernetes default timeout', () => {
    for (const n of ['readinessProbe', 'livenessProbe', 'startupProbe']) assert.ok(probe(n).timeout >= 5, n + ' timeout must be at least 5 seconds');
  });
  it('liveness tolerates two minutes of silence before a restart, startup allows three minutes to start', () => {
    const l = probe('livenessProbe'); assert.ok(l.failure * l.period >= 120, 'liveness window ' + l.failure * l.period + ' s');
    const s = probe('startupProbe'); assert.ok(s.failure * s.period >= 180, 'startup window ' + s.failure * s.period + ' s');
  });
  it('a rolling update never removes an old pod before a new one is Ready, and a build that never gets Ready fails the rollout', () => {
    assert.ok(/strategy:\n\s+type: RollingUpdate\n\s+rollingUpdate:\n\s+maxUnavailable: 0\n\s+maxSurge: 1/.test(manifest));
    assert.ok(/progressDeadlineSeconds: (\d+)/.test(manifest) && Number(/progressDeadlineSeconds: (\d+)/.exec(manifest)[1]) <= 600);
  });
});
