#!/usr/bin/env node
'use strict';
// Operator tool: register, show, check or remove the central Wazuh manager of ONE tenant (docs/endpoints.md, task E4c). It lives under src/ so it is inside the API image and
// runs where the database and NOTIFY_ENCRYPTION_KEY already are:
//
//   kubectl -n asix-platform exec -i deploy/asix-api -- node src/endpoints/wazuh-manager-cli.js register --tenant "Acme Corp" < registration.json
//   kubectl -n asix-platform exec    deploy/asix-api -- node src/endpoints/wazuh-manager-cli.js show     --tenant "Acme Corp"
//   kubectl -n asix-platform exec    deploy/asix-api -- node src/endpoints/wazuh-manager-cli.js check    --tenant "Acme Corp"
//   kubectl -n asix-platform exec    deploy/asix-api -- node src/endpoints/wazuh-manager-cli.js remove   --tenant "Acme Corp"
//
// --tenant is the tenant's name or its id. The registration is JSON on STANDARD INPUT, never on the command line (a password in an argument shows in the process list):
//   { "url": "https://wazuh-acme.internal:55000", "user": "asix-readonly", "password": "...", "ca_pem": "-----BEGIN CERTIFICATE-----...", "label": "Acme central manager" }
// scripts/deploy/wazuh-api-setup.sh, run on the manager machine, writes exactly this file.
// `register` first signs in to the manager with what it was given (trusting only the certificate in the file) and reads its version; it saves only if that works, unless
// --no-check is given (the manager is not up yet). Nothing here is reachable from a route: see src/endpoints/wazuh-manager-store.js.
const db = require('../db');
const store = require('./wazuh-manager-store');
const api = require('./wazuh-api');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const USAGE = 'usage:\n  wazuh-manager-cli.js register --tenant <name|id> [--no-check] < registration.json\n  wazuh-manager-cli.js show     --tenant <name|id>\n  wazuh-manager-cli.js check    --tenant <name|id>\n  wazuh-manager-cli.js remove   --tenant <name|id>';

function parseArgs(argv) {
  const [cmd, ...rest] = argv; const o = { cmd, tenant: null, noCheck: false };
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '--tenant' && rest[i + 1] !== undefined) { o.tenant = rest[++i]; }
    else if (rest[i] === '--no-check') o.noCheck = true;
    else return { error: 'Unknown or incomplete option: ' + rest[i] };
  }
  if (!['register', 'show', 'check', 'remove'].includes(cmd)) return { error: 'Unknown command' };
  if (!o.tenant) return { error: '--tenant is required' };
  if (o.noCheck && cmd !== 'register') return { error: '--no-check only goes with register' };
  return o;
}

async function tenantId(name) {
  if (UUID_RE.test(name)) { const r = await db.query('SELECT id, name FROM tenants WHERE id = $1', [name]); return r.rows[0] || null; }
  const r = await db.query('SELECT id, name FROM tenants WHERE name = $1', [name]);
  if (r.rows.length > 1) throw new Error('More than one tenant is called "' + name + '": use its id');
  return r.rows[0] || null;
}
const readAll = (stream) => new Promise((resolve, reject) => { let s = ''; stream.setEncoding('utf8'); stream.on('data', (c) => { s += c; if (s.length > 100000) reject(new Error('The registration on standard input is too large')); }); stream.on('end', () => resolve(s)); stream.on('error', reject); });

// Signs in to the manager and reads its version, the way the proxy will. Returns { ok: true, version } or { ok: false, code, message }.
async function probe(m) {
  try { api.forget(m.tenant_id); return { ok: true, ...(await api.managerInfo(m)) }; }
  catch (e) { return { ok: false, code: e.code || 'ERROR', message: e.message }; }
}

// io = { stdin, out(line), err(line) }; returns the exit code. Exported so the tests run it without a process.
async function run(argv, io) {
  const o = parseArgs(argv);
  if (o.error) { io.err(o.error + '\n' + USAGE); return 2; }
  let t;
  try { t = await tenantId(o.tenant); } catch (e) { io.err(e.message); return 1; }
  if (!t) { io.err('No tenant "' + o.tenant + '"'); return 1; }
  try {
    if (o.cmd === 'register') {
      let input;
      try { input = JSON.parse(await readAll(io.stdin)); } catch (e) { io.err('Standard input must hold the registration as JSON' + (e && e.message && !/JSON/.test(e.message) ? ': ' + e.message : '')); return 2; }
      const p = store.parseRegistration(input);
      if (p.error) { io.err('Not saved: ' + p.error); return 2; }
      const reg = p.reg;
      if (!require('../notifications/secret-box').configured()) { io.err('Not saved: NOTIFY_ENCRYPTION_KEY is not set in this environment, so the password cannot be stored safely'); return 1; }
      if (!o.noCheck) {
        const r = await probe({ tenant_id: t.id, api_url: reg.api_url, api_user: reg.api_user, api_password: reg.password, ca_pem: reg.ca_pem, cert_sha256: reg.cert_sha256, api_secret_enc_hash: 'probe' });
        if (!r.ok) { io.err('Not saved: the manager did not accept the registration (' + r.code + '): ' + r.message + '\nFix it, or use --no-check to save it anyway.'); return 1; }
        io.out('The manager answered: Wazuh ' + r.version);
      }
      await db.withTenant(t.id, (c) => store.writeRow(c, t.id, reg, 'cli'));
      api.forget(t.id);
      io.out('Registered for tenant "' + t.name + '": ' + reg.api_url + ' as ' + reg.api_user + ' (certificate sha256 ' + reg.cert_sha256 + ', valid until ' + reg.not_after + ')');
      return 0;
    }
    const row = await db.withTenant(t.id, (c) => store.readRow(c, t.id));
    if (o.cmd === 'show') {
      if (!row) { io.out('Tenant "' + t.name + '" has no central manager registered.'); return 0; }
      const v = store.view(row);
      io.out('Tenant "' + t.name + '": ' + row.api_url + ' as ' + v.api_user + ', certificate sha256 ' + v.cert_sha256 + (v.label ? ', label "' + v.label + '"' : '') + ', saved ' + new Date(v.updated_at).toISOString());
      return 0;
    }
    if (o.cmd === 'check') {
      if (!row) { io.err('Tenant "' + t.name + '" has no central manager registered.'); return 1; }
      const r = await probe(store.credentials(row));
      if (!r.ok) { io.err('Not working (' + r.code + '): ' + r.message); return 1; }
      io.out('Working: Wazuh ' + r.version + ' at ' + row.api_url); return 0;
    }
    if (o.cmd === 'remove') {
      const n = await db.withTenant(t.id, (c) => store.clearRow(c, t.id)); api.forget(t.id);
      io.out(n ? 'Removed the manager registration of tenant "' + t.name + '". The manager itself is untouched.' : 'Tenant "' + t.name + '" had no central manager registered.'); return 0;
    }
  } catch (e) {
    if (store.isMissingTable(e)) { io.err('The database has no wazuh_managers table yet: run the schema job (a normal deploy does)'); return 1; }
    if (e && e.code === 'NO_KEY') { io.err('NOTIFY_ENCRYPTION_KEY is not set in this environment'); return 1; }
    io.err('Failed: ' + e.message); return 1;
  }
  return 2;
}

module.exports = { run, parseArgs };

if (require.main === module) {
  run(process.argv.slice(2), { stdin: process.stdin, out: (l) => console.log(l), err: (l) => console.error(l) })
    .then((code) => db.close().finally(() => process.exit(code)));
}
