'use strict';
// E4n: the built-in rule "Endpoint configuration check score low" (docs/endpoints.md, "E4n as built").
// Summary alerts are made the way the broker sends them (data.sca.* flattened to data_sca_*, every value text), parsed by the REAL default parsing rules,
// (null for a field = the field is left out), and the rule is run the way the rule runner runs it (buildRuleMatch + the event store's matchGroups, here the in-memory store).
const { describe, it } = require('node:test');
const assert = require('assert');
const { compile, apply } = require('../src/ingestion/parsing-rules');
const { jsonEvent } = require('../src/ingest/http-ingest');
const { MemoryEventStore } = require('../src/events/memory-store');
const { BUILTIN_RULES } = require('../src/detection/rule-runner');
const { normalizeDefinition, buildRuleMatch } = require('../src/detection/rule-query');

const defaults = compile(require('../src/ingestion/default-parsing-rules'));
const TENANT = '11111111-1111-4111-8111-111111111111';
const NOW = new Date('2026-10-31T12:00:00.000Z');
const RULE = BUILTIN_RULES.find((r) => r.key === 'endpoint-config-score-low');
const CIS = 'CIS Distribution Independent Linux Benchmark v2.0.0.';

let seq = 0;
function event({ type = 'summary', score = '49', policy = CIS, agent = 'web1', minsAgo = 1, level = 7, ruleId = '19004', extra = {}, sourceType = 'endpoint-alert' } = {}) {
  const f = { asix_via: 'wazuh', rule_id: ruleId, rule_level: String(level), rule_description: 'SCA summary', agent_name: agent, ...(type === null ? {} : { data_sca_type: type }), ...(policy ? { data_sca_policy: policy } : {}), ...(score === null ? {} : { data_sca_score: score }), ...extra };
  const x = jsonEvent({ message: `[Endpoint alert] rule ${ruleId} level ${level}: d`, time: new Date(NOW - minsAgo * 60000).toISOString(), host: agent, fields: f }, 'broker-test');
  const out = apply([defaults.rules], { source_type: sourceType, raw: x.raw, time: x.time, parsed: x.parsed });
  seq += 1;
  const at = new Date(NOW - minsAgo * 60000).toISOString();
  return { id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`, source_type: sourceType, collector_id: 'broker-test', received_at: at, event_time: at, raw: x.raw, parsed: out.parsed };
}
async function run(events, rule = RULE) {
  const store = new MemoryEventStore();
  if (events.length) await store.insertBatch(TENANT, events);
  const rows = await store.matchGroups(TENANT, buildRuleMatch(rule.definition, { now: NOW }));
  return Object.fromEntries(rows.map((r) => [r.key, r.n]));
}

describe('the parsing rule: sca_score and sca_key', () => {
  it('a scan summary gets the score as a number and a key of policy and machine', () => {
    const p = event({ score: '49' }).parsed;
    assert.strictEqual(p.sca_score, 49); assert.strictEqual(p.sca_key, `${CIS} on web1`);
  });
  it('a single check alert has neither, even if it carries a score field', () => {
    const p = event({ type: 'check', score: '10' }).parsed;
    assert.ok(p.sca_score == null && p.sca_key == null);
  });
  it('a score that is not a number, or missing, is null (never 0)', () => {
    assert.ok(event({ score: 'seventy' }).parsed.sca_score == null);
    assert.ok(event({ score: null }).parsed.sca_score == null);
  });
  it('a summary with no policy name is keyed under "unknown policy"', () => {
    assert.strictEqual(event({ policy: null }).parsed.sca_key, 'unknown policy on web1');
  });
  it('an alert that is not about configuration checks is untouched', () => {
    const p = event({ type: null, ruleId: '5763', level: 10 }).parsed;
    assert.ok(p.sca_score == null); assert.strictEqual(p.alert_key, '5763 on web1');
  });
});

describe('the rule "Endpoint configuration check score low"', () => {
  it('is a valid built-in rule in the endpoint category, medium, one alert a day per policy and machine', () => {
    assert.ok(RULE);
    assert.ok(!normalizeDefinition(RULE.definition).error, JSON.stringify(normalizeDefinition(RULE.definition)));
    assert.deepStrictEqual([RULE.kind, RULE.category, RULE.severity, RULE.definition.source_type, RULE.definition.group_by], ['bioc', 'Endpoint Security', 'medium', 'endpoint-alert', 'field:sca_key']);
    assert.deepStrictEqual(RULE.definition.suppression, { enabled: true, minutes: 1440 });
    assert.strictEqual(RULE.definition.threshold, 1);
  });
  it('fires on a summary under 50, one group per policy and machine', async () => {
    assert.deepStrictEqual(await run([event({ score: '49' })]), { [`${CIS} on web1`]: 1 });
  });
  it('the boundary: 49 and 0 fire, 50 and 100 do not', async () => {
    assert.deepStrictEqual(await run([event({ score: '49' }), event({ score: '0', agent: 'db1' })]), { [`${CIS} on web1`]: 1, [`${CIS} on db1`]: 1 });
    assert.deepStrictEqual(await run([event({ score: '50' }), event({ score: '100', agent: 'db1' })]), {});
  });
  it('a failed check alert never fires it (no score), however many there are', async () => {
    assert.deepStrictEqual(await run(Array.from({ length: 30 }, () => event({ type: 'check', score: null, ruleId: '19007' }))), {});
  });
  it('a score that is not a number does not fire', async () => {
    assert.deepStrictEqual(await run([event({ score: 'low' }), event({ score: null })]), {});
  });
  it('two policies on one machine and one policy on two machines are separate groups', async () => {
    const r = await run([event({ policy: 'P1' }), event({ policy: 'P2' }), event({ agent: 'db1', policy: 'P1' })]);
    assert.deepStrictEqual(r, { 'P1 on web1': 1, 'P2 on web1': 1, 'P1 on db1': 1 });
  });
  it('the same summary twice in one window is one group with a count of two (the duplicate seen on a real scan)', async () => {
    assert.deepStrictEqual(await run([event(), event({ minsAgo: 2 })]), { [`${CIS} on web1`]: 2 });
  });
  it('only the last 60 minutes count, only source type endpoint-alert', async () => {
    assert.deepStrictEqual(await run([event({ minsAgo: 61 })]), {});
    assert.deepStrictEqual(await run([event({ sourceType: 'syslog' })]), {});
  });
  it('the other endpoint rules do not also fire on the same level 7 summary (one finding, one alert)', async () => {
    for (const r of BUILTIN_RULES.filter((b) => b.key.startsWith('endpoint-') && b !== RULE)) {
      assert.deepStrictEqual(await run([event({ score: '49' })], r), {}, r.key);
    }
  });
});
