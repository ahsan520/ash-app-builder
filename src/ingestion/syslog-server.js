// Standalone process for the syslog collector. Run separately from the
// API gateway (`src/server.js`) — same pattern, its own port(s).
//
// Required env:
//   SYSLOG_TENANT_ID   — UUID of the tenant this collector is assigned to
// Optional env:
//   SYSLOG_COLLECTOR_ID (default: syslog-local)
//   SYSLOG_UDP_PORT     (default: 5514)
//   SYSLOG_TCP_PORT     (default: 5514)
//   SYSLOG_BIND_HOST    (default: 0.0.0.0)
//   SYSLOG_SPOOL_PATH   (default: /var/lib/asix/syslog-spool.ndjson)
//   SYSLOG_SPOOL_MAX_BYTES (default: 50MB) — bounds disk use during a
//     prolonged DB outage; oldest-write events drop once the cap is hit
//
// Ports default to 5514, not 514, so this can run unprivileged; point
// rsyslog at 5514 locally, or forward 514 -> 5514 if you need the
// standard port for external devices.

const { SyslogListener } = require('./syslog-listener');

const tenantId = process.env.SYSLOG_TENANT_ID;

if (!tenantId) {
  console.error('SYSLOG_TENANT_ID is required (which tenant this collector belongs to)');
  process.exit(1);
}

const listener = new SyslogListener({
  tenantId,
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
  console.log(`${signal} received, shutting down syslog listener`);
  listener.stop();
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
