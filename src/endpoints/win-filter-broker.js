'use strict';
// The Windows event filter on a BROKER (docs/endpoints.md, task E3). The policy saved in ASIX (win-filter-store.js) becomes ONE Vector program, `win-filter.vrl`, that a broker
// pulls with its own key, checks, and puts in /etc/vector. ASIX runs nothing on the broker: a broker that opted in (bootstrap-broker.sh --accept-config) does the pulling and
// applies the program only after its own checks (hash, `vector validate`, restart and health when something reads the file, way back on any failure).
//
// How the pieces fit:
//   - The broker config pull (src/ingest/broker-config.js) says WHICH program the broker should have as `win_filter`: the SHA-256 of the program text, nothing else. A hash is small
//     enough to sit in the signed payload (the script accepts at most 2000 base64 characters there) and it names the content, so a program changed in transit, or served
//     while the policy changed, does not match and is refused.
//   - The program itself is fetched from GET /v1/ingest/broker-config/win-filter (plain text, same key) and must hash to the announced value before anything is touched.
//   - The program is a Vector `remap` program (VRL) for a transform with `drop_on_abort: true`, read from a FILE (`file:` in the transform), not pasted into a config. A file is not
//     subject to Vector's environment variable interpolation, so a regex that ends in `$` or holds `${...}` reaches the program as written.
//   - NO POLICY is the program `.` (keep every event, change nothing), so a transform that reads the file always has something valid to read.
//   - Nothing on a broker reads `win-filter.vrl` until a Windows events input exists (task E4, Wazuh); until then the program is placed and checked and Vector is not restarted.
// The revision number is for people; what identifies a program is its hash (a tenant that removes its policy and saves a new one starts again at revision 1).
const crypto = require('crypto');
const wf = require('./win-filter');
const { tsMs } = require('../collectors/status');
const store = require('./win-filter-store');

const HEADER = '# ASIX Windows event filter (Settings > Windows event filter in ASIX). ASIX replaces this file: do not edit it.\n';
const IDENTITY_TEXT = HEADER + '# No policy is set: every event is kept and nothing is changed.\n.\n';
const SHA_RE = /^[0-9a-f]{64}$/;

const sha256 = (text) => crypto.createHash('sha256').update(text, 'utf8').digest('hex');
const IDENTITY_SHA = sha256(IDENTITY_TEXT);

// The program for a stored policy (as read from win_filter_policy), or { error } when it cannot be sent: not a valid policy any more (the rules changed after it was saved),
// or too big. { text, sha256, bytes } otherwise.
function program(policy) {
  const v = wf.validate(policy);
  if (!v.ok) return { error: 'the stored policy is not valid: ' + v.errors.slice(0, 3).join('; ') };
  const text = HEADER + wf.toVrl(v.policy) + '\n', bytes = Buffer.byteLength(text, 'utf8');
  if (bytes > wf.MAX_PROGRAM_BYTES) return { error: 'the policy makes a program of ' + bytes + ' bytes, more than the ' + wf.MAX_PROGRAM_BYTES + ' a broker takes' };   // read live: a policy bigger than a broker takes is refused when saved (win-filter-store.js) and never announced
  return { text, sha256: sha256(text), bytes };
}
const identity = () => ({ text: IDENTITY_TEXT, sha256: IDENTITY_SHA, bytes: Buffer.byteLength(IDENTITY_TEXT, 'utf8') });

// What the tenant's brokers should have right now: { sha256, text, revision } (revision 0 and the identity program when there is no policy), or { error } for an invalid or
// oversize stored policy (nothing is asked of the brokers then and the problem is logged by the caller).
async function current(client, tenantId) {
  const row = await store.readRow(client, tenantId);
  if (!row) return { ...identity(), revision: 0, policy: false };
  const p = program(row.policy);
  return p.error ? { error: p.error } : { ...p, revision: row.revision, policy: true };
}

// What the config pull says. Returns the hash the broker should have (a 64 hex string), or undefined for "no opinion" (the answer keeps the shape it had before):
//   - the tenant has a policy: its program's hash, every pull;
//   - the tenant has none: nothing, unless THIS broker (found by key AND name) last reported a program other than the identity one, then the identity hash (take the filter away).
// Its own transaction in the caller: a database without the table or the column throws and the pull simply leaves the field out.
async function readForPull(client, tenantId, keyId, name) {
  const cur = await current(client, tenantId);
  if (cur.error) { console.error('Windows filter not sent to brokers:', cur.error); return undefined; }
  if (cur.policy) return cur.sha256;
  if (!name) return undefined;
  const r = await client.query('SELECT config_win_filter FROM collectors WHERE tenant_id = $1 AND key_id = $2 AND name = $3', [tenantId, keyId, name]);
  const has = r.rows[0] ? r.rows[0].config_win_filter : null;
  return typeof has === 'string' && SHA_RE.test(has) && has !== IDENTITY_SHA ? IDENTITY_SHA : undefined;
}

// ---- The report: which program the broker has now and which one it rejected ----
// Both optional (a script from before E3 sends neither). `win_filter` is '' (no program file) or the hash of the file the broker has; `rejected_win_filter` is '' / null or a hash.
function checkReport(b) {
  if (!b || b.win_filter === undefined) return {};
  const ok = (v) => v === '' || (typeof v === 'string' && SHA_RE.test(v));
  if (!ok(b.win_filter)) return { error: 'win_filter must be empty or a 64-character lower-case hex hash' };
  let rejected = '';
  if (b.rejected_win_filter !== undefined && b.rejected_win_filter !== null) {
    if (!ok(b.rejected_win_filter)) return { error: 'rejected_win_filter must be empty or a 64-character lower-case hex hash' };
    rejected = b.rejected_win_filter;
  }
  return { winFilter: b.win_filter, winFilterRejected: rejected };
}

// Lands on the broker's own row (key AND name). Its own statement in the caller: a database without the columns must not stop the port report from being stored.
async function recordReport(client, tenantId, keyId, name, applied, rejected) {
  const r = await client.query('UPDATE collectors SET config_win_filter = $4, config_rejected_win_filter = $5 WHERE tenant_id = $1 AND key_id = $2 AND name = $3',
    [tenantId, keyId, name, applied, rejected === '' || rejected === undefined ? null : rejected]);
  return r.rowCount > 0;
}

// ---- What the Brokers page shows ----
// One broker against the program ASIX wants it to have. `cur` is current() (or null when it could not be read), `row` the collector row (config_win_filter = the hash it reports, '' = no file,
// NULL = never said; config_rejected_win_filter; config_reported_at). Information only: never a problem and never an alert.
//   none      no policy, and the broker has no program (or only the keep-everything one)
//   unknown   a policy is set but this broker never reported: it did not opt in (--accept-config) or its config script is older than E3
//   applied   the broker has exactly the program ASIX wants (also: no policy and it has none)
//   rejected  it tried this program and put its old one back
//   pending   it has another program (or none) and has not rejected this one; `removing` is true when the policy is gone and the broker still has the old program
//   stale     as pending, but its last report is older than 15 minutes
const FRESH_MS = 15 * 60 * 1000;   // the same line config.REPORT_FRESH_MS draws (a test pins them equal)
function winFilterState(row, cur, now = Date.now()) {
  const has = row && typeof row.config_win_filter === 'string' ? row.config_win_filter : null;
  const rej = row && row.config_rejected_win_filter ? row.config_rejected_win_filter : null;
  const at = row && row.config_reported_at ? tsMs(row.config_reported_at) : NaN;
  const out = { state: 'none', revision: cur && cur.policy ? cur.revision : 0, reported_at: row && row.config_reported_at ? row.config_reported_at : null, removing: false };
  if (!cur || cur.error) return out;
  if (!cur.policy) {
    if (has === null || has === '' || has === IDENTITY_SHA) return out;
    return { ...out, state: Number.isFinite(at) && now - at > FRESH_MS ? 'stale' : 'pending', removing: true };
  }
  if (has === null) return { ...out, state: 'unknown' };
  if (has === cur.sha256) return { ...out, state: 'applied' };
  if (rej === cur.sha256) return { ...out, state: 'rejected' };
  return { ...out, state: Number.isFinite(at) && now - at > FRESH_MS ? 'stale' : 'pending' };
}

module.exports = { winFilterState, FRESH_MS, HEADER, IDENTITY_TEXT, IDENTITY_SHA, SHA_RE, sha256, program, identity, current, readForPull, checkReport, recordReport };
