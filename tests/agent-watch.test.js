'use strict';
// E4l: the endpoint agent disconnected alert, pure parts (docs/endpoints.md, "E4l as built"). The database part is tests/agent-watch-db.test.js.
const { describe, it } = require('node:test');
const assert = require('assert');
const w = require('../src/endpoints/agent-watch');
const wazuhApi = require('../src/endpoints/wazuh-api');

const NOW = Date.parse('2026-10-30T12:00:00Z');
const ago = (min) => new Date(NOW - min * 60000).toISOString().replace('.000Z', 'Z');
const agent = (id, min, extra = {}) => ({ id, name: 'pc-' + id, ip: '10.0.0.' + Number(id), status: 'disconnected', version: 'Wazuh v4.14.9', groups: ['default'], last_keep_alive: ago(min), os: { name: 'Microsoft Windows 11 Pro' }, ...extra });
const cfg = (minutes) => ({ minutes });
const A = (id, key = w.keyOf(id)) => ({ id: 'alert-' + id, group_key: key });

describe('config', () => {
  it('is off unless ASIX_AGENT_WATCH_MIN is a whole number from 5 to 10080', () => {
    const m = (v) => w.config({ ASIX_AGENT_WATCH_MIN: v }).minutes;
    assert.deepStrictEqual([m(undefined), m(''), m('0'), m('abc'), m('4'), m('7.5'), m('-30'), m('10081'), m(' ')], [0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert.deepStrictEqual([m('5'), m('30'), m('10080')], [5, 30, 10080]);
    assert.strictEqual(w.config({}).minutes, 0);
  });
});

describe('ageMin', () => {
  it('counts whole minutes since the last keep-alive and never guesses', () => {
    assert.strictEqual(w.ageMin(ago(45), NOW), 45);
    assert.strictEqual(w.ageMin(ago(0), NOW), 0);
    assert.strictEqual(w.ageMin(new Date(NOW + 5 * 60000).toISOString(), NOW), 0);   // a clock a little ahead is not negative
    for (const bad of [null, undefined, '', 'never', 'x', 12345, {}]) assert.strictEqual(w.ageMin(bad, NOW), null, String(bad));
  });
});

describe('plan: raising', () => {
  it('raises for an agent down at least the limit, not before', () => {
    const p = w.plan({ disconnected: [agent('001', 29), agent('002', 30), agent('003', 31)] }, cfg(30), { now: NOW });
    assert.deepStrictEqual(p.raise.map((r) => r.agent_id).sort(), ['002', '003']);
    assert.deepStrictEqual(p.close, []);
  });
  it('the raise carries what the alert text and details need', () => {
    const [r] = w.plan({ disconnected: [agent('002', 90)] }, cfg(30), { now: NOW }).raise;
    assert.deepStrictEqual([r.agent_id, r.name, r.ip, r.group_key, r.minutes, r.threshold, r.os, r.version, r.groups, r.last_keep_alive], ['002', 'pc-002', '10.0.0.2', 'endpointagent:002', 90, 30, 'Microsoft Windows 11 Pro', 'Wazuh v4.14.9', ['default'], ago(90)]);
  });
  it('an agent with no readable last keep-alive raises nothing (no guessing)', () => {
    const d = [agent('001', 99, { last_keep_alive: null }), agent('002', 99, { last_keep_alive: 'soon' }), { id: null, last_keep_alive: ago(99) }];
    assert.deepStrictEqual(w.plan({ disconnected: d }, cfg(5), { now: NOW }).raise, []);
  });
  it('one alert per agent: an open alert for the agent stops a second', () => {
    const p = w.plan({ disconnected: [agent('002', 90)], active: [A('002')] }, cfg(30), { now: NOW });
    assert.deepStrictEqual([p.raise.length, p.close.length], [0, 0]);
  });
  it('an alert closed by hand is not raised again for the SAME outage, but is for a new one', () => {
    const d = [agent('002', 90)];
    const same = w.plan({ disconnected: d, latest: [{ group_key: 'endpointagent:002', status: 'closed', last_keep_alive: ago(90) }] }, cfg(30), { now: NOW });
    assert.strictEqual(same.raise.length, 0);
    const later = w.plan({ disconnected: d, latest: [{ group_key: 'endpointagent:002', status: 'closed', last_keep_alive: ago(500) }] }, cfg(30), { now: NOW });
    assert.strictEqual(later.raise.length, 1);
  });
  it('an alert ASIX closed itself (check turned off, manager unregistered) is raised again if the same outage is still going', () => {
    const p = w.plan({ disconnected: [agent('002', 90)], latest: [{ group_key: 'endpointagent:002', status: 'closed', closed_by: 'asix', last_keep_alive: ago(90) }] }, cfg(30), { now: NOW });
    assert.strictEqual(p.raise.length, 1);
  });
  it('a previous alert still open (latest not closed) does not matter here: the open list decides', () => {
    const p = w.plan({ disconnected: [agent('002', 90)], latest: [{ group_key: 'endpointagent:002', status: 'open', last_keep_alive: ago(500) }] }, cfg(30), { now: NOW });
    assert.strictEqual(p.raise.length, 1);
  });
  it('raises at most MAX_RAISE per cycle, the longest outages first, and the rest on later cycles', () => {
    const d = Array.from({ length: 60 }, (_, i) => agent(String(100 + i), 40 + i));
    const first = w.plan({ disconnected: d }, cfg(30), { now: NOW });
    assert.strictEqual(first.raise.length, w.MAX_RAISE);
    assert.deepStrictEqual(first.raise.slice(0, 3).map((r) => r.minutes), [99, 98, 97]);
    const have = first.raise.map((r) => A(r.agent_id));
    const second = w.plan({ disconnected: d, active: have }, cfg(30), { now: NOW });
    assert.strictEqual(second.raise.length, w.MAX_RAISE);
    assert.ok(second.raise.every((r) => !have.some((h) => h.group_key === r.group_key)));
  });
  it('raiseAllowed false (start-up grace) raises nothing but still closes with evidence', () => {
    const p = w.plan({ disconnected: [agent('002', 90)], active: [A('003')], lookups: { '003': { id: '003', status: 'active' } } }, cfg(30), { now: NOW, raiseAllowed: false });
    assert.deepStrictEqual([p.raise.length, p.close.length], [0, 1]);
  });
});

describe('plan: closing', () => {
  const run = (active, lookups, disconnected = []) => w.plan({ disconnected, active, lookups }, cfg(30), { now: NOW }).close;
  it('closes when the agent is no longer Disconnected, saying what it is now', () => {
    const c = run([A('002')], { '002': { id: '002', status: 'active' } });
    assert.deepStrictEqual(c.map((x) => x.alert_id), ['alert-002']);
    assert.ok(/connected \(Active\) again/.test(c[0].reason));
    assert.ok(/no longer Disconnected \(the manager now says pending\)/.test(run([A('002')], { '002': { id: '002', status: 'pending' } })[0].reason));
  });
  it('closes when the manager no longer has the agent', () => {
    assert.ok(/removed/.test(run([A('002')], { '002': null })[0].reason));
  });
  it('keeps the alert while the agent is still Disconnected', () => {
    assert.deepStrictEqual(run([A('002')], {}, [agent('002', 90)]), []);
    assert.deepStrictEqual(run([A('002')], { '002': { id: '002', status: 'disconnected' } }), []);   // beyond the pages read
  });
  it('closes nothing without evidence: no lookup, a key that is not an agent key, or a lookup for another agent', () => {
    assert.deepStrictEqual(run([A('002')], {}), []);
    assert.deepStrictEqual(run([A('x', 'something-else')], { x: null }), []);
    assert.deepStrictEqual(run([A('002')], { '003': null }), []);
  });
  it('turned off: closes every open alert of the rule and raises nothing', () => {
    const p = w.plan({ disconnected: [agent('002', 900)], active: [A('002'), A('003')] }, cfg(0), { now: NOW });
    assert.deepStrictEqual([p.raise.length, p.close.length], [0, 2]);
    assert.ok(/turned off/.test(p.close[0].reason));
  });
  it('no manager registered: closes every open alert, raises nothing', () => {
    const p = w.plan({ disconnected: [agent('002', 900)], active: [A('002')], registered: false }, cfg(30), { now: NOW });
    assert.deepStrictEqual([p.raise.length, p.close.length], [0, 1]);
    assert.ok(/registered/.test(p.close[0].reason));
  });
});

describe('raiseText', () => {
  it('names the machine and says what to check', () => {
    const t = w.raiseText({ agent_id: '002', name: 'inaaya-pc', ip: '192.168.68.56', minutes: 45, threshold: 30, os: 'Microsoft Windows 11 Pro' });
    assert.strictEqual(t.title, 'Endpoint agent disconnected: inaaya-pc (192.168.68.56)');
    assert.ok(/45 minutes/.test(t.summary) && /power saving/.test(t.summary) && /1514 and 1515/.test(t.summary) && /Windows 11 Pro/.test(t.summary));
  });
  it('long outages read in hours; "any" or no address and no name fall back', () => {
    assert.ok(/3 hours/.test(w.raiseText({ agent_id: '5', name: 'x', ip: null, minutes: 200, threshold: 30 }).summary));
    assert.strictEqual(w.raiseText({ agent_id: '009', name: 'x', ip: 'any', minutes: 40, threshold: 30 }).title, 'Endpoint agent disconnected: x');
    assert.strictEqual(w.raiseText({ agent_id: '009', name: null, ip: null, minutes: 40, threshold: 30 }).title, 'Endpoint agent disconnected: 009');
  });
});

describe('readDisconnected', () => {
  const fake = (pages, calls = []) => ({
    parseAgentQuery: wazuhApi.parseAgentQuery,
    listAgents: async (m, parsed) => { calls.push(parsed.query); const p = pages[calls.length - 1] || { total: 0, agents: [] }; return { total: p.total, limit: parsed.limit, offset: parsed.offset, agents: p.agents }; },
  });
  const many = (n, from = 0) => Array.from({ length: n }, (_, i) => ({ id: String(from + i).padStart(3, '0') }));
  it('asks only for Disconnected agents, oldest keep-alive first, and stops when it has them all', async () => {
    const calls = []; const out = await w.readDisconnected({}, fake([{ total: 3, agents: many(3) }], calls));
    assert.strictEqual(out.length, 3); assert.strictEqual(calls.length, 1);
    const q = new URLSearchParams(calls[0]);
    assert.deepStrictEqual([q.get('status'), q.get('sort'), q.get('limit'), q.get('offset')], ['disconnected', '+lastKeepAlive', '500', '0']);
  });
  it('reads further pages, and no more than MAX_PAGES', async () => {
    const calls = []; const pages = [0, 1, 2, 3, 4, 5].map((i) => ({ total: 9999, agents: many(500, i * 500) }));
    const out = await w.readDisconnected({}, fake(pages, calls));
    assert.strictEqual(calls.length, 4); assert.strictEqual(out.length, 2000);
    assert.deepStrictEqual(calls.map((c) => new URLSearchParams(c).get('offset')), ['0', '500', '1000', '1500']);
  });
  it('an error from the manager is thrown, not turned into an empty list', async () => {
    await assert.rejects(w.readDisconnected({}, { parseAgentQuery: wazuhApi.parseAgentQuery, listAgents: async () => { throw new wazuhApi.WazuhApiError('UNREACHABLE', 'down'); } }), /down/);
  });
});

describe('wiring', () => {
  const fs = require('fs'), path = require('path');
  const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
  it('the watchdog runs it in its own try, after the other checks', () => {
    const s = read('src/collectors/watchdog.js');
    assert.ok(/require\('\.\.\/endpoints\/agent-watch'\)/.test(s));
    assert.ok(/try \{ const r = await agentWatch\.runTenant\(t\.id, opts\)[^\n]*\n\s*catch \(e\)[^\n]*endpoint agent check/.test(s));
    assert.ok(s.indexOf('parseWatch.runTenant') < s.indexOf('agentWatch.runTenant'));
  });
  it('it is off by default in the API manifest', () => {
    assert.ok(/- name: ASIX_AGENT_WATCH_MIN\n\s+value: "0"/.test(read('k8s/30-asix-api.yaml')));
  });
});
