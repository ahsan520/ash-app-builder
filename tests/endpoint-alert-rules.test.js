'use strict';
// E4e: ASIX alerts raised from the alerts a Wazuh manager writes (source type endpoint-alert; docs/endpoints.md, "E4e as built").
//   1. the parsing rule's new fields (alert_target, alert_key);
//   2. the four built-in rules (src/detection/rule-runner.js) are valid and well formed;
//   3. each rule run the way the rule runner runs it (buildRuleMatch + the event store's matchGroups, here the in-memory store)
//      over events made from the sample alerts and parsed by the REAL default parsing rules.
const { describe, it } = require('node:test');
const assert = require('assert');
const { compile, apply } = require('../src/ingestion/parsing-rules');
const { jsonEvent } = require('../src/ingest/http-ingest');
const { MemoryEventStore } = require('../src/events/memory-store');
const { BUILTIN_RULES, ensureBuiltinRules } = require('../src/detection/rule-runner');
const { normalizeDefinition, buildRuleMatch } = require('../src/detection/rule-query');

const defaults = compile(require('../src/ingestion/default-parsing-rules'));
const TENANT = '11111111-1111-4111-8111-111111111111';
const NOW = new Date('2026-10-26T12:00:00.000Z');
const RULES = Object.fromEntries(BUILTIN_RULES.filter((r) => r.key.startsWith('endpoint-')).map((r) => [r.key, r]));

// An alert as the broker sends it (fields as text), parsed by the real rules, as an envelope `minsAgo` minutes before NOW.
let seq = 0;
function alertEvent({ level = 10, ruleId = '5763', agent = 'web1', minsAgo = 1, fields = {}, sourceType = 'endpoint-alert' } = {}) {
  const f = { asix_via: 'wazuh', rule_id: ruleId, rule_level: String(level), rule_description: 'd', ...(agent ? { agent_name: agent } : {}), ...fields };
  const x = jsonEvent({ message: `[Endpoint alert] rule ${ruleId} level ${level}: d`, time: new Date(NOW - minsAgo * 60000).toISOString(), host: agent || undefined, fields: f }, 'broker-test');
  const rec = { source_type: sourceType, raw: x.raw, time: x.time, parsed: x.parsed };
  const out = apply([defaults.rules], rec);
  seq += 1;
  return { id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`, source_type: sourceType, collector_id: 'broker-test', received_at: new Date(NOW - minsAgo * 60000).toISOString(), event_time: new Date(NOW - minsAgo * 60000).toISOString(), raw: x.raw, parsed: out.parsed };
}
async function run(key, events) {
  const store = new MemoryEventStore();
  if (events.length) await store.insertBatch(TENANT, events);
  const rows = await store.matchGroups(TENANT, buildRuleMatch(RULES[key].definition, { now: NOW }));
  return Object.fromEntries(rows.map((r) => [r.key, r.n]));
}

describe('the parsing rule: the grouping fields', () => {
  it('alert_key is "<rule id> on <machine>" and alert_target is the machine', () => {
    const p = alertEvent({ ruleId: '5763', agent: 'web1' }).parsed;
    assert.deepStrictEqual([p.alert_target, p.alert_key], ['web1', '5763 on web1']);
  });
  it('an alert with no agent name is grouped under "unknown" rather than dropped', () => {
    const p = alertEvent({ ruleId: '5763', agent: null }).parsed;
    assert.deepStrictEqual([p.alert_target, p.alert_key], ['unknown', '5763 on unknown']);
  });
  it('a machine name with odd characters stays text', () => {
    assert.strictEqual(alertEvent({ agent: 'a b; DROP TABLE x' }).parsed.alert_key, '5763 on a b; DROP TABLE x');
  });
});

describe('the built-in endpoint rules', () => {
  it('there are four, with unique keys, valid definitions and the endpoint category', () => {
    assert.deepStrictEqual(Object.keys(RULES).sort(), ['endpoint-alert-critical', 'endpoint-alert-high', 'endpoint-alert-repeated', 'endpoint-fim-sensitive']);
    assert.strictEqual(new Set(BUILTIN_RULES.map((r) => r.key)).size, BUILTIN_RULES.length);
    for (const r of Object.values(RULES)) {
      assert.ok(!normalizeDefinition(r.definition).error, `${r.key}: ${JSON.stringify(normalizeDefinition(r.definition))}`);
      assert.strictEqual(r.category, 'Endpoint Security'); assert.strictEqual(r.kind, 'bioc');
      assert.ok(['low', 'medium', 'high', 'critical'].includes(r.severity));
      assert.strictEqual(r.definition.source_type, 'endpoint-alert'); assert.strictEqual(r.definition.group_by, 'field:alert_key');
      assert.deepStrictEqual(r.definition.suppression, { enabled: true, minutes: 60 });
    }
  });
  it('severity matches the level band each rule covers', () => {
    assert.deepStrictEqual([RULES['endpoint-alert-critical'].severity, RULES['endpoint-alert-high'].severity, RULES['endpoint-alert-repeated'].severity, RULES['endpoint-fim-sensitive'].severity], ['critical', 'high', 'medium', 'high']);
  });
  it('the portal offers the category, so editing a rule does not blank it', () => {
    assert.ok(/const CATS = \[[^\]]*'Endpoint Security'/.test(require('fs').readFileSync(require('path').join(__dirname, '..', 'src/portal/index.html'), 'utf8')));
  });
  it('every tenant gets them: ensureBuiltinRules inserts each key once and a repeat changes nothing (ON CONFLICT DO NOTHING)', async () => {
    const calls = []; await ensureBuiltinRules({ query: async (sql, args) => { calls.push({ sql, args }); } }, TENANT);
    const inserts = calls.filter((c) => /^\s*INSERT/.test(c.sql));
    const keys = inserts.map((c) => c.args[4]); for (const k of Object.keys(RULES)) assert.strictEqual(keys.filter((x) => x === k).length, 1, k);
    assert.ok(inserts.every((c) => /ON CONFLICT \(tenant_id, builtin_key\) DO NOTHING/.test(c.sql)));
  });
  it('E4k: a stored rule is replaced only while its query is still exactly the old shipped text', async () => {
    const calls = []; await ensureBuiltinRules({ query: async (sql, args) => { calls.push({ sql, args }); } }, TENANT);
    const ups = calls.filter((c) => /^\s*UPDATE/.test(c.sql));
    assert.strictEqual(ups.length, 1);
    assert.ok(/definition->>'xql' = \$3/.test(ups[0].sql) && /tenant_id = \$1 AND builtin_key = \$2/.test(ups[0].sql));
    assert.deepStrictEqual(ups[0].args.slice(0, 4), [TENANT, 'endpoint-alert-repeated', 'alert_level >= 5 and alert_level < 8', RULES['endpoint-alert-repeated'].definition.xql]);
    assert.ok(RULES['endpoint-alert-repeated'].definition.xql.includes('data_sca_policy'));
  });
});

describe('the rules run over alerts the way the rule runner runs them', () => {
  it('critical: level 12 and up only; one alert per rule per machine', async () => {
    const r = await run('endpoint-alert-critical', [
      alertEvent({ level: 12, ruleId: '100100', agent: 'web1' }), alertEvent({ level: 15, ruleId: '100100', agent: 'web1', minsAgo: 2 }),
      alertEvent({ level: 13, ruleId: '100100', agent: 'db1' }), alertEvent({ level: 11, ruleId: '5763', agent: 'web1' }), alertEvent({ level: 3, ruleId: '5402', agent: 'web1' })]);
    assert.deepStrictEqual(r, { '100100 on web1': 2, '100100 on db1': 1 });
  });
  it('high: levels 8 to 11 only', async () => {
    const r = await run('endpoint-alert-high', [alertEvent({ level: 7, ruleId: '1' }), alertEvent({ level: 8, ruleId: '2' }), alertEvent({ level: 11, ruleId: '3' }), alertEvent({ level: 12, ruleId: '4' })]);
    assert.deepStrictEqual(Object.keys(r).sort(), ['2 on web1', '3 on web1']);
  });
  it('two different manager rules on one machine are two groups, so one cannot hide the other', async () => {
    const r = await run('endpoint-alert-high', [alertEvent({ level: 9, ruleId: '5763' }), alertEvent({ level: 9, ruleId: '5710' })]);
    assert.deepStrictEqual(r, { '5763 on web1': 1, '5710 on web1': 1 });
  });
  it('repeated: medium alerts count only from ten in 15 minutes, per rule per machine', async () => {
    const ten = Array.from({ length: 10 }, (_, i) => alertEvent({ level: 6, ruleId: '60122', agent: 'WIN-DC01', minsAgo: i }));
    const nine = Array.from({ length: 9 }, (_, i) => alertEvent({ level: 6, ruleId: '60122', agent: 'WIN-FS01', minsAgo: i }));
    const old = Array.from({ length: 10 }, (_, i) => alertEvent({ level: 6, ruleId: '60122', agent: 'WIN-OLD', minsAgo: 14 + i }));   // only the first falls inside 15 minutes
    const wrongLevel = Array.from({ length: 10 }, () => alertEvent({ level: 9, ruleId: '60122', agent: 'WIN-HI' }));
    assert.deepStrictEqual(await run('endpoint-alert-repeated', [...ten, ...nine, ...old, ...wrongLevel]), { '60122 on WIN-DC01': 10 });
  });
  it('E4k repeated: configuration check alerts (a failed check each, after a scan) never count, other alerts of the same rule still do', async () => {
    const sca = (agent, i, ruleId = '19007') => alertEvent({ level: 7, ruleId, agent, minsAgo: i % 10, fields: { data_sca_policy: 'CIS Ubuntu', data_sca_check_result: 'failed' } });
    const scaOnly = Array.from({ length: 40 }, (_, i) => sca('asix1', i));
    const plain = Array.from({ length: 10 }, (_, i) => alertEvent({ level: 7, ruleId: '60122', agent: 'win1', minsAgo: i }));
    const mixedSca = Array.from({ length: 12 }, (_, i) => sca('web2', i, '60122'));
    const mixedPlain = Array.from({ length: 9 }, (_, i) => alertEvent({ level: 7, ruleId: '60122', agent: 'web2', minsAgo: i }));
    assert.deepStrictEqual(await run('endpoint-alert-repeated', [...scaOnly, ...plain, ...mixedSca, ...mixedPlain]), { '60122 on win1': 10 });
    assert.deepStrictEqual(await run('endpoint-alert-repeated', [...mixedSca, ...mixedPlain, alertEvent({ level: 7, ruleId: '60122', agent: 'web2', minsAgo: 1 })]), { '60122 on web2': 10 });
  });
  it('E4k: the other endpoint rules are not changed by the configuration check condition', async () => {
    const hi = alertEvent({ level: 9, ruleId: '19009', agent: 'asix1', fields: { data_sca_policy: 'p' } });
    assert.deepStrictEqual(await run('endpoint-alert-high', [hi]), { '19009 on asix1': 1 });
    for (const k of ['endpoint-alert-critical', 'endpoint-alert-high', 'endpoint-fim-sensitive']) assert.ok(!RULES[k].definition.xql.includes('data_sca_policy'), k);
  });
  it('sensitive file: Linux and Windows paths below level 8; not other paths; not level 8 and up (the level rules own those)', async () => {
    const f = (path, level = 7, agent = 'web1') => alertEvent({ level, ruleId: '550', agent, fields: { syscheck_path: path, syscheck_event: 'modified' } });
    const r = await run('endpoint-fim-sensitive', [
      f('/etc/passwd'), f('/etc/sudoers.d/x', 7, 'a'), f('/etc/cron.daily/job', 7, 'b'), f('/root/.ssh/authorized_keys', 7, 'c'), f('/home/alice/.ssh/authorized_keys', 7, 'd'),
      f('c:\\windows\\system32\\drivers\\etc\\hosts', 7, 'e'), f('C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk', 7, 'f'),
      f('/tmp/notes.txt', 7, 'g'), f('/etc/passwd-backup-notes/readme', 7, 'h'), f('/etc/passwd', 8, 'i'), f('/var/www/index.html', 5, 'j')]);
    assert.deepStrictEqual(Object.keys(r).sort(), ['550 on a', '550 on b', '550 on c', '550 on d', '550 on e', '550 on f', '550 on web1']);
  });
  it('an alert with no file path never matches the file rule', async () => {
    assert.deepStrictEqual(await run('endpoint-fim-sensitive', [alertEvent({ level: 7 })]), {});
  });
  it('other source types are never matched, even with the same field names', async () => {
    const e = alertEvent({ level: 14, sourceType: 'windows-event' });
    e.parsed.alert_level = 14; e.parsed.alert_key = 'x on y';
    for (const k of Object.keys(RULES)) assert.deepStrictEqual(await run(k, [e]), {}, k);
  });
  it('alerts older than the rule window are not counted', async () => {
    assert.deepStrictEqual(await run('endpoint-alert-critical', [alertEvent({ level: 13, minsAgo: 6 })]), {});
    assert.deepStrictEqual(await run('endpoint-alert-critical', [alertEvent({ level: 13, minsAgo: 4 })]), { '5763 on web1': 1 });
  });
  it('a level that is not a number never matches a level rule', async () => {
    const e = alertEvent({ level: 13 }); e.parsed.alert_level = 'high';
    for (const k of ['endpoint-alert-critical', 'endpoint-alert-high', 'endpoint-alert-repeated']) assert.deepStrictEqual(await run(k, [e]), {}, k);
  });
});
