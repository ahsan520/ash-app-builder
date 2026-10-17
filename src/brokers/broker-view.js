'use strict';
// Read-only view of the broker VMs (docs/broker-vm.md). A broker is not a separate kind of row: it is a collector
// that sends the heartbeat from deploy/broker/asix-broker-heartbeat.sh, whose version reads "vector-<version>".
// This file recognises those rows and shapes them for the Brokers page. Pure functions, no database.
const { effectiveMinutes, isCustom, statusOf, tsMs } = require('../collectors/status');

const BROKER_VERSION_SQL = 'vector-%';              // the same rule as isBroker(), for the query
const isBroker = (row) => !!row && /^vector-/i.test(String(row.version || ''));

// What is wrong with this broker, in words an operator can act on. Empty list = nothing to report.
function problemsOf(b, now = Date.now()) {
  const out = [];
  if (!b.installer) out.push('Its installer key was deleted. The broker cannot send until it has a new one.');
  else if (b.installer.status === 'revoked') out.push('Its installer key is revoked, so ASIX rejects what it sends. Create a new installer and re-run the bootstrap script on the broker.');
  if (b.status === 'disconnected') {
    const ms = now - tsMs(b.last_seen);
    out.push(Number.isFinite(ms) ? `Not seen for ${Math.round(ms / 60000)} minutes (it counts as Connected within ${b.connected_within_min}). Check Vector on the broker: the heartbeat is not sent while Vector is unhealthy.` : 'Never seen.');
  }
  return out;
}

function shape(row, { now = Date.now(), events24h = 0 } = {}) {
  const b = {
    id: row.id, name: row.name, alias: row.alias || null,
    vector_version: String(row.version || '').replace(/^vector-/i, '') || null,
    os: row.os || null, last_ip: row.last_ip || null,
    first_seen: row.first_seen, last_seen: row.last_seen,
    events_total: Number(row.events_total) || 0, events_24h: events24h,
    connected_within_min: effectiveMinutes(row.connected_within_min), connected_custom: isCustom(row.connected_within_min),
    status: statusOf(row.last_seen, row.connected_within_min, now), watch_disconnect: row.watch_disconnect === true,
    installer: row.key_id ? { id: row.key_id, name: row.installer_name || null, status: row.key_status || 'active', key_prefix: row.key_prefix || null, last_used_at: row.key_last_used_at || null } : null,
  };
  b.problems = problemsOf(b, now);
  return b;
}

// Totals for the top of the page, and the Vector versions in use (more than one means the fleet is part-upgraded).
function summarize(brokers) {
  const versions = {};
  for (const b of brokers) { const v = b.vector_version || 'unknown'; versions[v] = (versions[v] || 0) + 1; }
  return {
    total: brokers.length,
    connected: brokers.filter((b) => b.status === 'connected').length,
    disconnected: brokers.filter((b) => b.status === 'disconnected').length,
    with_problems: brokers.filter((b) => b.problems.length).length,
    events_24h: brokers.reduce((n, b) => n + b.events_24h, 0),
    versions, mixed_versions: Object.keys(versions).length > 1,
  };
}

// The command to run on a new broker. The key is shown once when the installer is created and is never stored in
// plain text, so it stays a placeholder here.
const installCommand = () => [
  'sudo ./scripts/deploy/bootstrap-broker.sh \\',
  '  --url https://<asix-host>/v1/ingest/http --key <installer key, asix_ik_...> \\',
  '  --name <broker name>   # add --ca, or --tls-cert and --tls-key, as in docs/broker-vm.md',
].join('\n');

module.exports = { BROKER_VERSION_SQL, isBroker, shape, summarize, problemsOf, installCommand };
