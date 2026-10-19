'use strict';
// Broker config pull, first slice: ONE setting the brokers may pick up, the syslog port. ASIX still runs nothing on a broker:
// a broker that was set up with `bootstrap-broker.sh --accept-config` asks for this document itself every few minutes
// (deploy/broker/asix-broker-config.sh) and applies it only after its own checks. A broker without that flag never asks.
// Pure rules plus two small database helpers; the broker repeats the port rules on its side, so a wrong value here cannot lock a broker out.

const { tsMs } = require('../collectors/status');

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

// ---- What each broker says it applied ------------------------------------------------------------------------------------
// A broker that pulls its config also tells ASIX, after every pull, which syslog port it is listening on and which one it rejected
// (POST /v1/ingest/broker-config/report). That is information, never an instruction: it changes no setting and is stored on the
// broker's own collector row, so the Brokers page can say Applied, Pending or Rejected instead of only showing the setting.
const REPORT_FRESH_MS = 15 * 60 * 1000;   // three pull intervals; a report older than this no longer says what the broker is doing

// What a broker says about ASIX's signature on its config (see "Signed config" in docs/broker-vm.md), sent as `signature` in the report:
//   off        no public key on the broker: it acts on the plain answer and does not check anything
//   unchecked  it has a public key but did not get as far as checking (could not fetch the answer)
//   ok         the last answer's signature, broker name and age all passed
//   everything else: the last answer was REFUSED for that reason (unsigned, bad_signature, wrong_broker, clock_skew, bad_format, no_key_file, no_openssl)
const SIGNATURE_PROBLEMS = ['unsigned', 'bad_signature', 'wrong_broker', 'clock_skew', 'bad_format', 'no_key_file', 'no_openssl'];
const SIGNATURE_VALUES = ['off', 'unchecked', 'ok', ...SIGNATURE_PROBLEMS];

const portOrNull = (v) => {
  if (v === null || v === undefined) return { value: null };
  const n = typeof v === 'number' ? v : (typeof v === 'string' && /^[0-9]{1,5}$/.test(v) ? Number(v) : NaN);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? { value: n } : { error: true };
};

// Validates the report body: { collector: 'broker-1', syslog_port: 1514, rejected_port: 2514 | null }. Returns { name, port, rejected } or { error }.
function checkReport(body) {
  const b = body && typeof body === 'object' && !Array.isArray(body) ? body : null;
  if (!b) return { error: 'Send a JSON object with collector and syslog_port' };
  const name = typeof b.collector === 'string' ? b.collector : '';
  if (!/^[A-Za-z0-9._:-]{1,100}$/.test(name)) return { error: 'collector: 1-100 chars of letters, digits . _ : -' };
  const port = portOrNull(b.syslog_port), rej = portOrNull(b.rejected_port);
  if (port.error || port.value === null) return { error: 'syslog_port must be a whole number from 1 to 65535' };
  if (rej.error) return { error: 'rejected_port must be a whole number from 1 to 65535, or null' };
  // Optional (scripts older than signature reporting do not send it): what this broker does with ASIX's signature. Stored as sent, from a fixed list.
  let signature = null;
  if (b.signature !== undefined && b.signature !== null) {
    if (typeof b.signature !== 'string' || !SIGNATURE_VALUES.includes(b.signature)) return { error: 'signature must be one of: ' + SIGNATURE_VALUES.join(', ') };
    signature = b.signature;
  }
  return { name, port: port.value, rejected: rej.value, signature };
}

// Stores a report on the collector row of THE KEY'S OWN broker (same name, key_id = the key that sent it), so one key cannot write
// another broker's row. Returns true if a row was updated. Nothing is inserted: a broker that has not sent a heartbeat has no row yet.
async function recordReport(client, tenantId, keyId, report) {
  const r = await client.query(
    `UPDATE collectors SET config_syslog_port = $4, config_rejected_port = $5, config_reported_at = localtimestamp, config_signature = $6
     WHERE tenant_id = $1 AND key_id = $2 AND name = $3`, [tenantId, keyId, report.name, report.port, report.rejected, report.signature || null]);
  return r.rowCount > 0;
}

// Whether a broker checks ASIX's signature, from what it last reported. `signingOn` = ASIX has a usable signing key. `row` carries config_signature
// and config_reported_at. Information only: never a "needs attention" problem and never an alert.
//   unknown        never reported it (the broker did not opt in with --accept-config, or its config script predates this report)
//   not_verifying  it has no public key: it acts on unsigned answers (`signing_on` says whether ASIX would sign them)
//   verifying      it checks, and the last answer passed
//   waiting        it checks, but has not had an answer to check yet (could not fetch)
//   refused        it checks, and the last answer was refused: `problem` says why (it changed nothing)
//   stale          as verifying / waiting / refused but the report is older than 15 minutes: it is not asking any more
function signatureState(signingOn, row, now = Date.now()) {
  const sig = row && typeof row.config_signature === 'string' ? row.config_signature : null;
  const at = row && row.config_reported_at ? tsMs(row.config_reported_at) : NaN;
  const out = { state: 'unknown', problem: null, signing_on: !!signingOn, reported_at: row && row.config_reported_at ? row.config_reported_at : null };
  if (sig === null || !SIGNATURE_VALUES.includes(sig)) return out;
  if (sig === 'off') return { ...out, state: 'not_verifying' };
  const fresh = !(Number.isFinite(at) && now - at > REPORT_FRESH_MS);
  if (sig === 'ok') return { ...out, state: fresh ? 'verifying' : 'stale' };
  if (sig === 'unchecked') return { ...out, state: fresh ? 'waiting' : 'stale' };
  return { ...out, state: fresh ? 'refused' : 'stale', problem: sig };
}

// One line an operator can act on for each refusal reason.
const SIGNATURE_HELP = {
  unsigned: 'ASIX did not sign its answer. Is the signing key set on ASIX (Secret asix-config-signing)?',
  bad_signature: 'The signature does not match the public key on this broker: wrong key, or the answer was changed on the way. Compare key ids; see Signed config in docs/broker-vm.md.',
  wrong_broker: 'The answer was made for another broker name. Check ASIX_BROKER_NAME in broker.env.',
  clock_skew: 'The answer was too far from this machine\'s clock (replayed, or a clock is wrong). Check time sync on the broker.',
  bad_format: 'The signed part of the answer could not be read.',
  no_key_file: 'The public key file named in broker.env cannot be read. Re-run the bootstrap script with --config-pubkey.',
  no_openssl: 'openssl is not installed on the broker, so it cannot check the signature.',
};


// The state of one broker against the port ASIX is asking for. `row` carries config_syslog_port, config_rejected_port, config_reported_at.
//   none      ASIX has no port set (the broker's own port, if it reported one, is still returned)
//   unknown   a port is set but this broker never reported: it did not opt in (--accept-config), or its script predates reporting
//   applied   the broker reports listening on that port
//   rejected  the broker reports it tried that port and put its old settings back (journalctl -u asix-broker-config on the broker)
//   pending   the broker reports a different port and has not rejected this one: it has not picked it up yet
//   stale     as pending, but its last report is older than 15 minutes: it is not asking any more (timer stopped, Vector unhealthy, VM off)
function configState(configured, row, now = Date.now()) {
  const reported = row && row.config_syslog_port != null ? Number(row.config_syslog_port) : null;
  const rejected = row && row.config_rejected_port != null ? Number(row.config_rejected_port) : null;
  const at = row && row.config_reported_at ? tsMs(row.config_reported_at) : NaN;
  const out = { state: 'none', configured_port: configured, reported_port: reported, rejected_port: rejected, reported_at: row && row.config_reported_at ? row.config_reported_at : null };
  if (configured === null || configured === undefined) return out;
  if (reported === null) return { ...out, state: 'unknown' };
  if (reported === configured) return { ...out, state: 'applied' };
  if (rejected === configured) return { ...out, state: 'rejected' };
  return { ...out, state: Number.isFinite(at) && now - at > REPORT_FRESH_MS ? 'stale' : 'pending' };
}

// ---- One broker's own port ------------------------------------------------------------------------------------------------
// The tenant-wide port is one value for every broker that opted in. A broker can also be given ITS OWN port (collectors.syslog_port_override,
// set from the Brokers page); it wins over the tenant-wide value for that broker only. Same port rules, same pull: the broker asks with
// GET /v1/ingest/broker-config?collector=<its name> and its own key, and is told its effective port. A broker whose script does not send the
// name (older than this) is told the tenant-wide value, so an override needs the new script on that broker.
const COLLECTOR_NAME_RE = /^[A-Za-z0-9._:-]{1,100}$/;   // the same rule checkReport applies; every character is safe in a URL
const nameOrNull = (v) => (typeof v === 'string' && COLLECTOR_NAME_RE.test(v) ? v : null);

// The port this broker is asked for: its own if it has one, else the tenant-wide one, else null (no opinion). A broker that is LEFT OUT of the
// tenant-wide port (collectors.syslog_port_exclude) is not asked for the tenant-wide port: null, so it keeps whatever it listens on now. Its own
// port still applies, because that was chosen for it alone.
const effectivePort = (tenantPort, overridePort, exclude = false) => (overridePort != null ? Number(overridePort) : exclude ? null : tenantPort != null ? Number(tenantPort) : null);
// broker = its own port; excluded = a tenant-wide port is set but this broker is left out of it; tenant = follows it; none = nothing asked.
const portSource = (tenantPort, overridePort, exclude = false) => (overridePort != null ? 'broker' : tenantPort != null ? (exclude ? 'excluded' : 'tenant') : 'none');

// Found by key AND name, so one key cannot read another broker's override. No such row = no override.
async function readOverride(client, tenantId, keyId, name) {
  const r = await client.query('SELECT syslog_port_override FROM collectors WHERE tenant_id = $1 AND key_id = $2 AND name = $3', [tenantId, keyId, name]);
  return r.rows[0] && r.rows[0].syslog_port_override != null ? Number(r.rows[0].syslog_port_override) : null;
}

// Sets or clears one broker's override (a broker = a collector whose version reads vector-<version>). Returns { id, name } or null if there is no such broker.
async function writeOverride(client, tenantId, brokerId, port) {
  const r = await client.query(
    "UPDATE collectors SET syslog_port_override = $3 WHERE id = $1 AND tenant_id = $2 AND version ILIKE 'vector-%' RETURNING id, name", [brokerId, tenantId, port]);
  return r.rows[0] ? { id: r.rows[0].id, name: r.rows[0].name } : null;
}

// ---- Leaving one broker out of the tenant-wide port -----------------------------------------------------------------------
// Found by key AND name like the override, so one key cannot read another broker's flag. No such row = not left out.
async function readExclude(client, tenantId, keyId, name) {
  const r = await client.query('SELECT syslog_port_exclude FROM collectors WHERE tenant_id = $1 AND key_id = $2 AND name = $3', [tenantId, keyId, name]);
  return !!(r.rows[0] && r.rows[0].syslog_port_exclude === true);
}

// Sets or clears the flag on one broker (a collector whose version reads vector-<version>). Returns { id, name, syslog_port_exclude } or null if there is no such broker.
async function writeExclude(client, tenantId, brokerId, exclude) {
  const r = await client.query(
    "UPDATE collectors SET syslog_port_exclude = $3 WHERE id = $1 AND tenant_id = $2 AND version ILIKE 'vector-%' RETURNING id, name, syslog_port_exclude", [brokerId, tenantId, exclude]);
  return r.rows[0] ? { id: r.rows[0].id, name: r.rows[0].name, syslog_port_exclude: r.rows[0].syslog_port_exclude === true } : null;
}

const view = (port) => ({ syslog_port: port, reserved_ports: Object.keys(RESERVED).map(Number) });

module.exports = { RESERVED, REPORT_FRESH_MS, SIGNATURE_VALUES, SIGNATURE_PROBLEMS, SIGNATURE_HELP, signatureState, checkSyslogPort, readSyslogPort, writeSyslogPort, view, checkReport, recordReport, configState,
  nameOrNull, effectivePort, portSource, readOverride, writeOverride, readExclude, writeExclude };
