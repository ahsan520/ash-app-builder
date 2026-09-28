// Standalone process for the syslog broker/collector. This is the
// "Collector + Broker" tier — it never talks to Postgres. It parses
// syslog and forwards batches to the data node's ingestion API
// (src/gateway/index.js's POST /v1/ingest/events).
//
// Required env:
//   INGEST_API_URL      - e.g. http://asix-api:3000/v1/ingest/events
//                          (in-cluster) or https://<data-node>/v1/ingest/events
//                          (broker VM outside the cluster)
//   INGEST_API_TOKEN     - shared broker ingest token (Phase 1: a single
//                          token, analogous to Splunk's HEC token; see
//                          note in src/gateway/middleware.js about
//                          upgrading this to per-broker service identities)
//   One of:
//     SYSLOG_TENANT_ID   - UUID of the tenant this broker belongs to
//     SYSLOG_TENANT_NAME - resolved by the data node, not locally
//                          (the broker has no DB access to resolve it itself)
// Optional env:
//   SYSLOG_COLLECTOR_ID (default: syslog-local)
//   SYSLOG_UDP_PORT     (default: 5514)
//   SYSLOG_TCP_PORT     (default: 5514)
//   SYSLOG_BIND_HOST    (default: 0.0.0.0)
//   SYSLOG_SPOOL_PATH   (default: /var/lib/asix/syslog-spool.ndjson)
//   SYSLOG_SPOOL_MAX_BYTES (default: 50MB) - bounds disk use during a
//     prolonged data-node/network outage; oldest-write events drop once
//     the cap is hit
//
// Ports default to 5514, not 514, so this can run unprivileged.

const { SyslogListener } = require('./syslog-listener');

const tenantId = process.env.SYSLOG_TENANT_ID;
const tenantName = process.env.SYSLOG_TENANT_NAME;
const ingestApiUrl = process.env.INGEST_API_URL;
const ingestApiToken = process.env.INGEST_API_TOKEN;

if (!tenantId && !tenantName) {
  console.error('Either SYSLOG_TENANT_ID or SYSLOG_TENANT_NAME is required');
  process.exit(1);
}
if (!ingestApiUrl || !ingestApiToken) {
  console.error('INGEST_API_URL and INGEST_API_TOKEN are required (where/how to reach the data node)');
  process.exit(1);
}

const listener = new SyslogListener({
  tenantId,
  tenantName,
  ingestApiUrl,
  ingestApiToken,
  collectorId: process.env.SYSLOG_COLLECTOR_ID || 'syslog-local',
  udpPort: Number(process.env.SYSLOG_UDP_PORT || 5514),
  tcpPort: Number(process.env.SYSLOG_TCP_PORT || 5514),
  bindHost: process.env.SYSLOG_BIND_HOST || '0.0.0.0',
  spoolPath: process.env.SYSLOG_SPOOL_PATH || '/var/lib/asix/syslog-spool.ndjson',
  spoolMaxBytes: process.env.SYSLOG_SPOOL_MAX_BYTES
    ? Number(process.env.SYSLOG_SPOOL_MAX_BYTES)
    : undefined,
  onEvent: (envelope) => {
    console.log(
      `[syslog] ${envelope.host || envelope.remote_address} ${envelope.facility || '-'}/${envelope.severity || '-'}: ${envelope.message?.slice(0, 200)}`
    );
  },
});

listener.start();

function shutdown(signal) {
  console.log(`${signal} received, shutting down syslog broker`);
  listener.stop();
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
