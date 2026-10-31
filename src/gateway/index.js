const path = require('path');
const express = require('express');
const db = require('../db');

const {
  authMiddleware,
  tenantMiddleware,
  rbacMiddleware,
  auditMiddleware,
  brokerAuthMiddleware,
} = require('./middleware');

const app = express();

app.disable('x-powered-by');

// HTTP ingestion lane (per-key auth). Mounted BEFORE the global JSON parser: it authenticates
// first and then parses with its own, larger body limit.
app.use(require('../ingest/http-ingest').router);
app.use(require('../ingest/heartbeat').router);
app.use(require('../ingest/broker-config').router);

app.use(express.json());

// Central portal (static SPA). Unauthenticated on purpose: it is only HTML/JS;
// every data call it makes goes through the Bearer-token middleware below.
app.use(
  '/portal',
  (req, res, next) => {
    res.set({
      'Content-Security-Policy':
        "default-src 'self'; connect-src 'self' https:; style-src 'self' 'unsafe-inline'; " +
        "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    });
    next();
  },
  express.static(path.join(__dirname, '..', 'portal'))
);

// Kubernetes / load-balancer health endpoint.
// Intentionally unauthenticated so health checks do not require a JWT.

app.use(require('./routes/core'));
app.use(require('./routes/detections'));
app.use(require('./routes/search'));
app.use(require('./routes/alerts'));
app.use(require('./routes/alert-triage'));
app.use(require('./routes/alert-dedupe'));
app.use(require('./routes/my-alerts'));
app.use(require('./routes/threat-intel'));
app.use(require('./routes/collectors'));
app.use(require('./routes/collector-threshold'));
app.use(require('./routes/collector-watch'));
app.use(require('./routes/collector-silent'));
app.use(require('./routes/collector-watch-all'));
app.use(require('./routes/collector-watch-exclude'));
app.use(require('./routes/brokers'));
app.use(require('./routes/broker-settings'));
app.use(require('./routes/broker-config'));
app.use(require('./routes/broker-port'));
app.use(require('./routes/broker-port-exclude'));
app.use(require('./routes/broker-tls-port'));
app.use(require('./routes/broker-inputs'));
app.use(require('./routes/notifications'));
app.use(require('./routes/storage'));
app.use(require('./routes/capacity'));
app.use(require('./routes/parsing'));
app.use(require('./routes/data-model'));
app.use(require('./routes/modules'));
app.use(require('./routes/packs'));
app.use(require('./routes/parser-status'));
app.use(require('./routes/parser-alert'));
app.use(require('./routes/win-filter'));
app.use(require('./routes/wazuh-manager'));
app.use(require('./routes/agent-alert'));
app.use(require('./routes/endpoint-alerts'));
app.use(require('./routes/endpoint-checks'));

// Readiness (k8s/30-asix-api.yaml). Mounted AFTER every router on purpose: a request only gets here if each router above passed it on, so a pod whose route chain is
// broken (found 2026-10-31: a router that never answered hung every request after it, while /v1/health/status, mounted early, still looked fine) is never marked Ready,
// the rolling update stops, and the old pods keep serving. It also checks the database, like /v1/health/status.
app.get('/v1/health/ready', async (req, res) => {
  try {
    const ok = await db.healthCheck();
    res.status(ok ? 200 : 503).json({ success: ok, status: ok ? 'ok' : 'degraded', service: 'asix-api', check: 'ready' });
  } catch (error) {
    console.error('Ready check failed:', error.message);
    res.status(503).json({ success: false, status: 'degraded', service: 'asix-api', check: 'ready' });
  }
});

app.get('/', (req, res) => {
  res.json({
    service: 'asix-api',
    status: 'running',
  });
});

module.exports = app;
