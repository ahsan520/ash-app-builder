'use strict';
// Needs a real Postgres with the platform schema applied and a real Vector binary (VECTOR_BIN, or `vector` on PATH):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-wazuh-db.test.js
// Skips itself otherwise. The whole chain of the broker's Windows events input (docs/endpoints.md, E4a): Wazuh archive lines -> REAL Vector with the config
// bootstrap installs and the REAL filter program ASIX makes from the tenant's policy -> the REAL ingest route (key lookup, JSON array body, parsing rules,
// data model, event store) on a real Postgres -> the stored events.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
const { spawnSync, spawn } = require('child_process');
const VECTOR = process.env.VECTOR_BIN || (spawnSync('vector', ['--version']).status === 0 ? 'vector' : null);
if (!VECTOR) { console.log('skipped (no Vector binary: set VECTOR_BIN or put `vector` on PATH)'); process.exit(0); }

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const db = require('../src/db');
const { router: httpIngest, generateKey, hashKey } = require('../src/ingest/http-ingest');
const F = require('./fixtures/wazuh-windows');
const wf = require('../src/endpoints/win-filter');
const wb = require('../src/endpoints/win-filter-broker');

const root = path.join(__dirname, '..');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const stamp = Date.now();
  const T = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wazuh-' + stamp])).rows[0].id;
  const key = generateKey();
  await db.withTenant(T, (c) => c.query("INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,'wz-key','linux',$2,$3)", [T, key.slice(0, 12), hashKey(key)]));
  const app = express(); app.use(httpIngest); const srv = app.listen(0);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wazuhdb-'));
  const rows = async () => (await db.withTenant(T, (c) => c.query("SELECT collector_id, source_type, event_time, raw, parsed FROM events WHERE source_type = 'windows-event' ORDER BY raw"))).rows;
  let v;
  try {
    const arch = path.join(tmp, 'archives.json'), vrl = path.join(tmp, 'win-filter.vrl'), base = path.join(tmp, 'base.yaml'), mine = path.join(tmp, 'vector-wazuh.yaml');
    // the program ASIX makes from the suggested starting point (messages stripped, noisy Security events dropped)
    fs.writeFileSync(vrl, wb.program(wf.toInput(wf.validate(wf.presetNoisySecurity()).policy)).text);
    fs.writeFileSync(arch, ''); fs.writeFileSync(base, `data_dir: ${tmp}\n`); fs.copyFileSync(path.join(root, 'deploy/broker/vector-wazuh.yaml'), mine);
    const env = { PATH: process.env.PATH, VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: 'true', ASIX_INGEST_KEY: key, ASIX_BROKER_NAME: 'broker-wz', ASIX_INGEST_URL: `http://127.0.0.1:${srv.address().port}/v1/ingest/http`, ASIX_WAZUH_ARCHIVES: arch, ASIX_WIN_FILTER_VRL: vrl };
    v = spawn(VECTOR, ['--config', base, '--config', mine], { env, stdio: 'ignore' });
    await sleep(3500);
    fs.appendFileSync(arch, [F.garbageLine, F.linuxLine, ...Object.values(F.events).map(F.line)].join('\n') + '\n');
    const want = Object.keys(F.events).length - 1;   // everything but 5156, which the policy drops
    for (let i = 0; i < 120 && (await rows()).length < want; i++) await sleep(250);
    await sleep(1500);
    const got = await rows(); assert.strictEqual(got.length, want, 'stored: ' + got.map((r) => r.parsed.win_event_id).join(','));
    const by = (id) => got.find((r) => r.parsed.win_event_id === String(id));
    assert.ok(!by(5156), 'the noisy event was dropped by the filter on the broker');

    // every row: right collector and source type, the event's own time, a host, the message line, the named fields
    for (const r of got) { assert.strictEqual(r.collector_id, 'broker-wz'); assert.strictEqual(r.source_type, 'windows-event'); assert.strictEqual(new Date(r.event_time).toISOString(), '2026-10-24T13:00:00.123Z'); assert.strictEqual(r.parsed.host, 'WIN-DC01.corp.local'); assert.match(r.raw, /^\[[^\]]+\] .+ id=\d+ $/, 'messages are stripped by the policy'); }
    // parsed by the field-based rules although the message text is gone
    let p = by(4625).parsed;
    assert.deepStrictEqual([p._content_id, p.event_id, p.event_category, p.event_outcome, p.target_user, p.target_domain, p.logon_type, p.failure_reason, p.src_ip, p.src_port, p.workstation, p.auth_package],
      ['wazuh_windows_logon', 4625, 'authentication', 'failure', 'admin', 'CORP', 3, 'Unknown user name or bad password.', '10.0.0.99', 51234, 'WIN-PC', 'NTLM']);
    p = by(4624).parsed; assert.deepStrictEqual([p._content_id, p.event_outcome, p.target_user, p.logon_type, p.src_ip], ['wazuh_windows_logon', 'success', 'alice', 10, '10.0.0.50']);
    p = by(4688).parsed; assert.deepStrictEqual([p._content_id, p.user, p.process_name, p.parent_name, p.command_line], ['wazuh_windows_process', 'alice', 'cmd.exe', 'explorer.exe', 'cmd.exe /c whoami /all']);
    p = by(4720).parsed; assert.deepStrictEqual([p._content_id, p.event_action, p.user, p.target_user], ['wazuh_windows_account', 'user_created', 'Administrator', 'backdoor']);
    p = by(4732).parsed; assert.deepStrictEqual([p._content_id, p.event_action, p.group_name, p.member_name], ['wazuh_windows_group', 'member_added', 'Administrators', 'CN=backdoor,CN=Users,DC=corp,DC=local']);
    p = by(4698).parsed; assert.deepStrictEqual([p._content_id, p.event_action, p.task_name, p.command_line], ['wazuh_windows_scheduled_task', 'task_created', '\\Updater', 'C:\\Temp\\u.exe -q']);
    p = by(7045).parsed; assert.deepStrictEqual([p._content_id, p.service_name, p.service_path], ['wazuh_windows_service', 'Updater Svc', 'C:\\Temp\\svc.exe -k run']);
    p = by(1).parsed; assert.deepStrictEqual([p._content_id, p.process_name, p.command_line, p.user_domain], ['sysmon_process', 'powershell.exe', 'powershell -enc AAAA', 'CORP']);
    p = by(1102).parsed; assert.deepStrictEqual([p._content_id, p.event_category, p.event_action], ['windows_log_cleared', 'log_cleared', 'security_log_cleared']);
    // the broker shows up as a collector with the events counted
    const c = (await db.query("SELECT events_total, platform, version FROM collectors WHERE tenant_id = $1 AND name = 'broker-wz'", [T])).rows[0];
    assert.ok(c && c.events_total >= want && c.platform === 'linux' && c.version === 'vector-broker', JSON.stringify(c));
    console.log('broker-wazuh-db: ok (' + got.length + ' events stored and parsed)');
  } finally {
    if (v) v.kill('SIGKILL'); srv.close(); fs.rmSync(tmp, { recursive: true, force: true });
    await db.withTenant(T, (c) => c.query('DELETE FROM events')).catch(() => {});
    for (const t of ['audit_events', 'collectors', 'ingestion_keys']) await db.query(`DELETE FROM ${t} WHERE tenant_id = $1`, [T]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = $1', [T]).catch(() => {});
    await db.close().catch(() => {});
  }
}
main().then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });
