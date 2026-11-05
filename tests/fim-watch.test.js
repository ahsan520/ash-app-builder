'use strict';
// E10b: the alert rule for the folders chosen in Group settings (src/endpoints/fim-watch.js). Each rule is run the way the rule runner runs it (buildRuleMatch, then the event
// store's matchGroups, here the in-memory store) over events parsed by the REAL default parsing rules.
const { describe, it } = require('node:test');
const assert = require('assert');
const { compile, apply } = require('../src/ingestion/parsing-rules');
const { jsonEvent } = require('../src/ingest/http-ingest');
const { MemoryEventStore } = require('../src/events/memory-store');
const { buildRuleMatch, normalizeDefinition } = require('../src/detection/rule-query');
const fw = require('../src/endpoints/fim-watch');

const defaults = compile(require('../src/ingestion/default-parsing-rules'));
const TENANT = '11111111-1111-4111-8111-111111111111';
const NOW = new Date('2026-11-05T12:00:00.000Z');
let seq = 0;
function fimEvent(path, { level = 5, ruleId = '554', event = 'added', agent = 'INAAYA-PC', minsAgo = 1 } = {}) {
  const t = new Date(NOW - minsAgo * 60000).toISOString();
  const x = jsonEvent({ message: 'm', time: t, host: agent, fields: { asix_via: 'wazuh', rule_id: ruleId, rule_level: String(level), rule_description: 'd', agent_name: agent, syscheck_path: path, syscheck_event: event } }, 'b');
  const out = apply([defaults.rules], { source_type: 'endpoint-alert', raw: x.raw, time: x.time, parsed: x.parsed });
  seq += 1;
  return { id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`, source_type: 'endpoint-alert', collector_id: 'b', received_at: t, event_time: t, raw: x.raw, parsed: out.parsed };
}
async function fires(entries, ev) {
  const store = new MemoryEventStore(); await store.insertBatch(TENANT, Array.isArray(ev) ? ev : [ev]);
  return (await store.matchGroups(TENANT, buildRuleMatch(fw.definition(entries), { now: NOW }))).length > 0;
}
const WIN = [{ system: 'windows', path: 'C:\\ASIX-Test', realtime: true }];
const LIN = [{ system: 'linux', path: '/srv/data' }];

describe('the watched-folder rule query', () => {
  it('is a valid rule definition, also with no folders', () => {
    assert.ok(!normalizeDefinition(fw.definition(WIN.concat(LIN))).error);
    assert.ok(!normalizeDefinition(fw.definition([])).error);
  });
  it('fires for a file in a watched Windows folder, in any letter case and with either slash', async () => {
    for (const p of ['C:\\ASIX-Test\\a.txt', 'c:\\asix-test\\sub\\b.txt', 'C:/ASIX-Test/a.txt', 'C:\\ASIX-Test']) assert.strictEqual(await fires(WIN, fimEvent(p)), true, p);
  });
  it('does not fire for a look-alike folder or another folder', async () => {
    for (const p of ['C:\\ASIX-Testing\\a.txt', 'C:\\Other\\a.txt', 'D:\\ASIX-Test\\a.txt']) assert.strictEqual(await fires(WIN, fimEvent(p)), false, p);
  });
  it('Linux paths match the folder and what is under it, not a longer name (XQL ~= ignores letter case)', async () => {
    assert.strictEqual(await fires(LIN, fimEvent('/srv/data/x')), true);
    assert.strictEqual(await fires(LIN, fimEvent('/srv/data')), true);
    assert.strictEqual(await fires(LIN, fimEvent('/srv/database/x')), false);
  });
  it('a path with regex characters is taken literally', async () => {
    const e = [{ system: 'linux', path: '/srv/a.b+c(1)' }];
    assert.strictEqual(await fires(e, fimEvent('/srv/a.b+c(1)/f')), true);
    assert.strictEqual(await fires(e, fimEvent('/srv/aXb+c(1)/f')), false);
  });
  it('a trailing slash on the folder makes no difference', async () => {
    assert.strictEqual(await fires([{ system: 'windows', path: 'C:\\ASIX-Test\\' }], fimEvent('C:\\ASIX-Test\\a.txt')), true);
  });
  it('level 8 and up is left to the level rules; modified and deleted (level 7) fire', async () => {
    assert.strictEqual(await fires(WIN, fimEvent('C:\\ASIX-Test\\a.txt', { level: 8, ruleId: '100' })), false);
    assert.strictEqual(await fires(WIN, fimEvent('C:\\ASIX-Test\\a.txt', { level: 7, ruleId: '553', event: 'deleted' })), true);
    assert.strictEqual(await fires(WIN, fimEvent('C:\\ASIX-Test\\a.txt', { level: 7, ruleId: '550', event: 'modified' })), true);
  });
  it('a group with no folders matches nothing', async () => {
    assert.strictEqual(await fires([], fimEvent('C:\\ASIX-Test\\a.txt')), false);
    assert.strictEqual(fw.queryFor([]), fw.NO_FOLDERS);
  });
  it('one alert per rule and machine: added and deleted are two groups', async () => {
    const store = new MemoryEventStore();
    await store.insertBatch(TENANT, [fimEvent('C:\\ASIX-Test\\a.txt'), fimEvent('C:\\ASIX-Test\\b.txt'), fimEvent('C:\\ASIX-Test\\a.txt', { level: 7, ruleId: '553', event: 'deleted' })]);
    const rows = await store.matchGroups(TENANT, buildRuleMatch(fw.definition(WIN), { now: NOW }));
    assert.deepStrictEqual(rows.map((r) => r.key).sort(), ['553 on INAAYA-PC', '554 on INAAYA-PC']);
  });
});

describe('writing the rule', () => {
  it('inserts one rule per group with a key of its own, and on a repeat changes only the query and the description', async () => {
    const calls = []; const client = { query: async (sql, args) => { calls.push({ sql, args }); return { rows: [] }; } };
    const xql = await fw.sync(client, TENANT, 'default', WIN);
    const { sql, args } = calls[0];
    assert.strictEqual(args[3], 'endpoint-fim-watched:default'); assert.strictEqual(args[5], xql);
    assert.match(sql, /ON CONFLICT \(tenant_id, builtin_key\) DO UPDATE/);
    assert.ok(!/enabled|severity\s*=/.test(sql.split('DO UPDATE')[1]), 'a switch or severity an operator changed must stay');
    assert.strictEqual(JSON.parse(args[4]).xql, xql);
  });
});
