#!/usr/bin/env node
'use strict';
// Operator tool: register, show, check or remove the central Wazuh indexer entry of ONE tenant (docs/endpoints.md, task E6e; set-up in docs/wazuh-indexer.md). It lives under src/ so it
// is inside the API image and runs where the database and NOTIFY_ENCRYPTION_KEY already are:
//
//   kubectl -n asix-platform exec -i deploy/asix-api -- node src/endpoints/wazuh-indexer-cli.js register --tenant "Acme Corp" < indexer-registration.json
//   kubectl -n asix-platform exec    deploy/asix-api -- node src/endpoints/wazuh-indexer-cli.js show     --tenant "Acme Corp"
//   kubectl -n asix-platform exec    deploy/asix-api -- node src/endpoints/wazuh-indexer-cli.js check    --tenant "Acme Corp"
//   kubectl -n asix-platform exec    deploy/asix-api -- node src/endpoints/wazuh-indexer-cli.js remove   --tenant "Acme Corp"
//
// --tenant is the tenant's name or its id. The registration is JSON on STANDARD INPUT, never on the command line (a password in an argument shows in the process list):
//   { "url": "https://wazuh-indexer.internal:9200", "user": "asix-vuln-acme", "password": "...", "ca_pem": "-----BEGIN CERTIFICATE-----...", "index": "wazuh-states-vulnerabilities-acme-mgr", "label": "Acme" }
// `register` first reads the index (a count, trusting only the certificate in the file) and saves only if that works, unless --no-check is given (the manager has not sent findings yet, so the
// index does not exist). Nothing here is reachable from a route: see src/endpoints/wazuh-indexer-store.js.
const db = require('../db');
const store = require('./wazuh-indexer-store');
const indexer = require('./wazuh-indexer');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const USAGE = 'usage:\n  wazuh-indexer-cli.js register --tenant <name|id> [--no-check] < indexer-registration.json\n  wazuh-indexer-cli.js show     --tenant <name|id>\n  wazuh-indexer-cli.js check    --tenant <name|id>\n  wazuh-indexer-cli.js remove   --tenant <name|id>';

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

// Reads the index the way the proxy will. { ok: true, count } or { ok: false, code, message }.
async function probe(m) {
  try { return { ok: true, ...(await indexer.count(m)) }; }
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
        const r = await probe({ tenant_id: t.id, index_url: reg.index_url, index_user: reg.index_user, index_password: reg.password, ca_pem: reg.ca_pem, index_name: reg.index_name });
        if (!r.ok) { io.err('Not saved: the indexer did not accept the registration (' + r.code + '): ' + r.message + '\nFix it, or use --no-check to save it anyway.'); return 1; }
        io.out('The index answered: ' + r.count + ' finding' + (r.count === 1 ? '' : 's'));
      }
      await db.withTenant(t.id, (c) => store.writeRow(c, t.id, reg, 'cli'));
      io.out('Registered for tenant "' + t.name + '": ' + reg.index_url + ' index ' + reg.index_name + ' as ' + reg.index_user + ' (certificate sha256 ' + reg.cert_sha256 + ', valid until ' + reg.not_after + ')');
      return 0;
    }
    const row = await db.withTenant(t.id, (c) => store.readRow(c, t.id));
    if (o.cmd === 'show') {
      if (!row) { io.out('Tenant "' + t.name + '" has no indexer registered.'); return 0; }
      const v = store.view(row);
      io.out('Tenant "' + t.name + '": ' + row.index_url + ' index ' + row.index_name + ' as ' + v.index_user + ', certificate sha256 ' + v.cert_sha256 + (v.label ? ', label "' + v.label + '"' : '') + ', saved ' + new Date(v.updated_at).toISOString());
      return 0;
    }
    if (o.cmd === 'check') {
      if (!row) { io.err('Tenant "' + t.name + '" has no indexer registered.'); return 1; }
      const r = await probe(store.credentials(row));
      if (!r.ok) { io.err('Not working (' + r.code + '): ' + r.message); return 1; }
      io.out('Working: ' + r.count + ' finding' + (r.count === 1 ? '' : 's') + ' in ' + row.index_name + ' at ' + row.index_url); return 0;
    }
    if (o.cmd === 'remove') {
      const n = await db.withTenant(t.id, (c) => store.clearRow(c, t.id));
      io.out(n ? 'Removed the indexer registration of tenant "' + t.name + '". The indexer and its data are untouched.' : 'Tenant "' + t.name + '" had no indexer registered.'); return 0;
    }
  } catch (e) {
    if (store.isMissingTable(e)) { io.err('The database has no wazuh_indexers table yet: run the schema job (a normal deploy does)'); return 1; }
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
