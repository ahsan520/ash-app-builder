'use strict';
// E4l against a real PostgreSQL (platform schema applied; k8s/12-schema-init.yaml's schema.sql): the real wazuh_managers registry, the real alerts and alert_notes
// tables and the real watchdog cycle (runOnce), with the manager's API replaced by a recorder (no Wazuh manager is needed; wazuh-api.js has its own tests).
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/agent-watch-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const db = require('../src/db');
const w = require('../src/endpoints/agent-watch');
const managerStore = require('../src/endpoints/wazuh-manager-store');
const wazuhApi = require('../src/endpoints/wazuh-api');

const NOW = Date.now();
const iso = (minAgo) => new Date(NOW - minAgo * 60000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const sha = 'a'.repeat(64);

async function main() {
  const stamp = NOW;
  const mk = async (n) => (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['agentwatch-' + n + '-' + stamp])).rows[0].id;
  const T = await mk('a'); const OTHER = await mk('b'); const NOMGR = await mk('c');
  const register = (t) => db.query(
    `INSERT INTO wazuh_managers (tenant_id, api_url, api_user, api_secret_enc, ca_pem, cert_sha256) VALUES ($1, 'https://10.0.0.1:55000', 'asix-readonly', 'sealed', 'pem', $2)
     ON CONFLICT (tenant_id) DO NOTHING`, [t, sha]);
  await register(T); await register(OTHER);

  // the manager, as a recorder: `agents` is what it lists, `fail` makes every call fail
  const mgr = { agents: [], fail: null, calls: [] };
  const api = {
    parseAgentQuery: wazuhApi.parseAgentQuery,
    listAgents: async (m, parsed) => { mgr.calls.push('list ' + parsed.query); if (mgr.fail) throw mgr.fail; const d = mgr.agents.filter((a) => a.status === 'disconnected'); return { total: d.length, limit: parsed.limit, offset: parsed.offset, agents: d }; },
    getAgent: async (m, id) => { mgr.calls.push('get ' + id); if (mgr.fail) throw mgr.fail; return mgr.agents.find((a) => a.id === id) || null; },
  };
  const store = { readRow: managerStore.readRow, isMissingTable: managerStore.isMissingTable, credentials: () => ({ stub: true }) };
  const agent = (id, status, minAgo, extra = {}) => ({ id, name: 'pc-' + id, ip: '192.168.68.' + Number(id), status, version: 'Wazuh v4.14.9', groups: ['default'], last_keep_alive: iso(minAgo), os: { name: 'Microsoft Windows 11 Pro' }, ...extra });
  const run = (t, o = {}) => w.runTenant(t, { now: NOW, cfg: { minutes: 30 }, api, store, ...o });
  const alerts = async (t, extra = '') => (await db.query(`SELECT id, status, severity, title, summary, group_key, rule_id, details FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ${extra} ORDER BY created_at, id`, [t, w.RULE_NAME])).rows;
  const notes = async (id) => (await db.query('SELECT author_name, body FROM alert_notes WHERE alert_id = $1', [id])).rows;
  const hand = (id) => db.query("UPDATE alerts SET status = 'closed', updated_at = localtimestamp WHERE id = $1", [id]);   // as an analyst on the Alerts page

  try {
    // 1. off: nothing read, nothing written
    mgr.agents = [agent('002', 'disconnected', 120)];
    assert.deepStrictEqual(await run(T, { cfg: { minutes: 0 } }), { raised: 0, closed: 0 });
    assert.strictEqual((await alerts(T)).length, 0); assert.deepStrictEqual(mgr.calls, [], 'off must not call the manager');

    // 2. on: a disconnected agent past the limit raises one alert; a younger one and an Active one do not; a second cycle adds nothing
    mgr.agents = [agent('002', 'disconnected', 120), agent('003', 'disconnected', 10), agent('001', 'active', 0), agent('004', 'pending', 200), agent('005', 'never_connected', 9999, { last_keep_alive: null })];
    assert.deepStrictEqual(await run(T, { sev: 'high' }), { raised: 1, closed: 0 });
    let a = await alerts(T); assert.strictEqual(a.length, 1);
    assert.deepStrictEqual([a[0].group_key, a[0].status, a[0].severity, a[0].rule_id, a[0].title], ['endpointagent:002', 'open', 'high', null, 'Endpoint agent disconnected: pc-002 (192.168.68.2)']);
    assert.deepStrictEqual([a[0].details.agent_id, a[0].details.agent, a[0].details.last_keep_alive, a[0].details.threshold_min, a[0].details.minutes], ['002', 'pc-002', iso(120), 30, 120]);
    assert.deepStrictEqual(await run(T), { raised: 0, closed: 0 }); assert.strictEqual((await alerts(T)).length, 1);

    // 3. the manager cannot be read: NOTHING is closed or raised (an outage of the manager is not "everyone is back")
    mgr.fail = new wazuhApi.WazuhApiError('UNREACHABLE', 'The manager cannot be reached'); mgr.agents = [];
    const warn = console.warn; const logged = []; console.warn = (m) => logged.push(m);
    try { assert.deepStrictEqual(await run(T), { raised: 0, closed: 0 }); assert.deepStrictEqual(await run(T), { raised: 0, closed: 0 }); } finally { console.warn = warn; }
    assert.strictEqual((await alerts(T, "AND status = 'open'")).length, 1, 'the open alert must stay open');
    assert.strictEqual(logged.length, 1, 'the same problem is logged once, not every cycle');
    mgr.fail = null;

    // 4. the agent is back: closed with an ASIX note and closed_by asix
    mgr.agents = [agent('002', 'active', 0)];
    assert.deepStrictEqual(await run(T), { raised: 0, closed: 1 });
    a = await alerts(T); assert.strictEqual(a[0].status, 'closed'); assert.strictEqual(a[0].details.closed_by, 'asix');
    assert.deepStrictEqual(await notes(a[0].id), [{ author_name: 'ASIX', body: 'The agent is connected (Active) again.' }]);

    // 5. a new outage of the same agent is a new alert; one closed by hand is not raised again for the same outage, but is for the next one
    mgr.agents = [agent('002', 'disconnected', 50)];
    assert.deepStrictEqual(await run(T), { raised: 1, closed: 0 });
    a = await alerts(T, "AND status = 'open'"); assert.strictEqual(a.length, 1);
    await hand(a[0].id);
    assert.deepStrictEqual(await run(T), { raised: 0, closed: 0 }, 'closed by hand: same outage, same last keep-alive');
    mgr.agents = [agent('002', 'disconnected', 50, { last_keep_alive: iso(49) })];   // the agent reported once more, then went quiet again
    assert.deepStrictEqual(await run(T), { raised: 1, closed: 0 });

    // 6. the manager lost the agent (deleted): the open alert closes, saying so
    mgr.agents = [];
    assert.deepStrictEqual(await run(T), { raised: 0, closed: 1 });
    a = await alerts(T, "AND status = 'closed'"); assert.ok((await Promise.all(a.map((x) => notes(x.id)))).flat().some((n) => /removed/.test(n.body)));

    // 7. another tenant is never touched by this tenant's run, and a tenant with no manager registered raises nothing
    mgr.agents = [agent('002', 'disconnected', 300)];
    await run(OTHER); assert.strictEqual((await alerts(OTHER)).length, 1);
    assert.deepStrictEqual(await run(NOMGR), { raised: 0, closed: 0 }); assert.strictEqual((await alerts(NOMGR)).length, 0);
    mgr.agents = []; await run(T);
    assert.strictEqual((await alerts(OTHER, "AND status = 'open'")).length, 1, "another tenant's alert is not closed by this tenant's run");

    // 8. the manager is unregistered: that tenant's open alert closes, saying so
    await db.query('DELETE FROM wazuh_managers WHERE tenant_id = $1', [OTHER]);
    assert.deepStrictEqual(await run(OTHER), { raised: 0, closed: 1 });
    assert.ok((await notes((await alerts(OTHER))[0].id)).some((n) => /registered/.test(n.body)));

    // 9. turned off again: an open alert closes without the manager being called
    await register(OTHER); mgr.agents = [agent('002', 'disconnected', 300)]; await run(OTHER);
    assert.strictEqual((await alerts(OTHER, "AND status = 'open'")).length, 1);
    mgr.calls.length = 0;
    assert.deepStrictEqual(await run(OTHER, { cfg: { minutes: 0 } }), { raised: 0, closed: 1 }); assert.deepStrictEqual(mgr.calls, []);

    // 10. the start-up grace of the watchdog: nothing is raised, nothing is lost
    mgr.agents = [agent('009', 'disconnected', 300)];
    assert.deepStrictEqual(await run(T, { raiseAllowed: false }), { raised: 0, closed: 0 });
    assert.deepStrictEqual(await run(T), { raised: 1, closed: 0 });

    // 11. the Resolved-message query (src/notifications/recovered.js) reads these alerts like every watchdog alert: closed by ASIX, no rule, an ASIX note
    mgr.agents = [agent('009', 'active', 0)]; await run(T);
    const rec = (await db.query(
      `SELECT a.id FROM alerts a WHERE a.tenant_id = $1 AND a.rule_name = $2 AND a.status = 'closed' AND a.rule_id IS NULL AND a.details->>'closed_by' = 'asix'
         AND EXISTS (SELECT 1 FROM alert_notes n WHERE n.alert_id = a.id AND n.author_name = 'ASIX')`, [T, w.RULE_NAME])).rows;
    assert.ok(rec.length >= 2);
    console.log('agent-watch-db: ok');
  } finally {
    for (const t of [T, OTHER, NOMGR]) {
      await db.query('DELETE FROM alert_notes WHERE tenant_id = $1', [t]).catch(() => {});
      await db.query('DELETE FROM alerts WHERE tenant_id = $1', [t]).catch(() => {});
      await db.query('DELETE FROM wazuh_managers WHERE tenant_id = $1', [t]).catch(() => {});
      await db.query('DELETE FROM tenants WHERE id = $1', [t]).catch(() => {});
    }
    await db.close();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
