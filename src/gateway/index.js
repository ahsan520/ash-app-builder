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
app.use(require('./routes/brokers'));
app.use(require('./routes/notifications'));
app.use(require('./routes/storage'));
app.use(require('./routes/capacity'));
app.use(require('./routes/parsing'));
app.use(require('./routes/data-model'));
app.use(require('./routes/modules'));
app.use(require('./routes/packs'));
app.use(require('./routes/parser-status'));

app.get('/', (req, res) => {
  res.json({
    service: 'asix-api',
    status: 'running',
  });
});

module.exports = app;
