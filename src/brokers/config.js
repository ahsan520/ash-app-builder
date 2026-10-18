'use strict';
// Broker config pull, first slice: ONE setting the brokers may pick up, the syslog port. ASIX still runs nothing on a broker:
// a broker that was set up with `bootstrap-broker.sh --accept-config` asks for this document itself every few minutes
// (deploy/broker/asix-broker-config.sh) and applies it only after its own checks. A broker without that flag never asks.
// Pure rules plus two small database helpers; the broker repeats the port rules on its side, so a wrong value here cannot lock a broker out.

// Ports a broker must never be told to listen on: SSH, HTTPS, Vector's local health API, and the ASIX HTTPS NodePort.
const RESERVED = { 22: 'SSH', 443: 'HTTPS', 8686: "Vector's local health API", 30443: 'ASIX HTTPS' };

// Validates what the operator typed. Empty or null clears the setting. Returns { value } or { error }.
function checkSyslogPort(v) {
  if (v === null || v === undefined || (typeof v === 'string' && v.trim() === '')) return { value: null };
  const t = typeof v === 'number' ? String(v) : typeof v === 'string' ? v.trim() : '';
  if (!/^[0-9]{1,5}$/.test(t)) return { error: 'Syslog port must be a whole number from 1 to 65535, or empty to leave the brokers alone' };
  const n = Number(t);
  if (n < 1 || n > 65535 || String(n) !== t) return { error: 'Syslog port must be a whole number from 1 to 65535 (no leading zeros)' };
  if (RESERVED[n]) return { error: `Port ${n} is used for ${RESERVED[n]} and cannot be a syslog port` };
  return { value: n };
}

async function readSyslogPort(client, tenantId) {
  const r = await client.query('SELECT syslog_port FROM broker_settings WHERE tenant_id = $1', [tenantId]);
  return r.rows[0] && r.rows[0].syslog_port != null ? Number(r.rows[0].syslog_port) : null;
}

// Touches only syslog_port, so the Vector version target on the same row is kept.
async function writeSyslogPort(client, tenantId, port, userId = null) {
  await client.query(
    `INSERT INTO broker_settings (tenant_id, syslog_port, updated_by) VALUES ($1, $2, $3)
     ON CONFLICT (tenant_id) DO UPDATE SET syslog_port = EXCLUDED.syslog_port, updated_at = localtimestamp, updated_by = EXCLUDED.updated_by`,
    [tenantId, port, userId ? String(userId) : null]);
  return port;
}

const view = (port) => ({ syslog_port: port, reserved_ports: Object.keys(RESERVED).map(Number) });

module.exports = { RESERVED, checkSyslogPort, readSyslogPort, writeSyslogPort, view };
