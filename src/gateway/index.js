const path = require('path');
const express = require('express');
const db = require('../db');
const { portalHeaders, appHeaders, moduleFiles } = require('./portal-headers');

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
app.use(require('../lists/feed').router);   // L1: the address a firewall polls for a list (docs/lists.md); the secret in the address is the credential

app.use(express.json());

// Central portal (static SPA). Unauthenticated on purpose: it is only HTML/JS;
// every data call it makes goes through the Bearer-token middleware below.
// Headers and the module-page rules live in ./portal-headers (docs/portal-shell.md): the portal may frame only its own
// origin, module page files are served only as /portal/modules/<module id>/<name>.js|css, and /app/* (the embedded
// open-source tools, S4) gets its own headers.
const portalDir = path.join(__dirname, '..', 'portal');
app.use('/portal', portalHeaders);
app.use('/portal/modules', moduleFiles(path.join(portalDir, 'modules')));
app.use('/portal', express.static(portalDir));
app.use('/app', appHeaders);

// Kubernetes / load-balancer health endpoint.
// Intentionally unauthenticated so health checks do not require a JWT.

app.use(require('../licensing/gate').gate);   // licensing (docs/licensing.md): refuses a locked module's routes; does nothing while licensing is off
app.use(require('./routes/core'));
app.use(require('./routes/detections'));
app.use(require('./routes/search'));
app.use(require('./routes/alerts'));
app.use(require('./routes/alert-triage'));
app.use(require('./routes/alert-dedupe'));
app.use(require('./routes/cases'));   // CS1: before anything that could take /v1/alerts/:id/case or /v1/cases/:x
app.use(require('./routes/actions')); // SR2: the action registry (docs/actions.md)
app.use(require('./routes/integrations')); // SR1: integrations and their write-only credentials (docs/integrations.md)
app.use(require('./routes/lists'));   // L1: lists and their entries (docs/lists.md); also adds list.add_entry and list.remove_entry to the registry
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
app.use(require('./routes/broker-placement'));
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
app.use(require('./routes/wazuh-indexer'));
app.use(require('./routes/agent-alert'));
app.use(require('./routes/vuln-trend'));
app.use(require('./routes/alert-machines'));   // E6t: before endpoint-alerts, whose /alerts/:id would otherwise take "by-machine"
app.use(require('./routes/endpoint-alerts'));
app.use(require('./routes/endpoint-checks'));
app.use(require('./routes/score-alert'));
app.use(require('./routes/endpoint-notices'));
app.use(require('./routes/group-config'));
app.use(require('./routes/group-winlog'));   // E11: the Windows events block of a group (same limits as group-config)
app.use(require('./routes/group-linuxlog'));   // E13: the Linux logs block of a group (same limits)
app.use(require('../licensing/routes'));   // the License API: never gated by a license

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
