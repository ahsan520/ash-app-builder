'use strict';
// E4m: the disconnected-agent alert card and the per-agent button (src/portal/index.html). Same approach as portal-parse-alert.test.js: the functions are cut out of the
// page and run with small stand-ins for el(), card(), pill(), api() and alert().
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const aa = require('../src/endpoints/agent-alert');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (name) => { const i = html.indexOf('function ' + name + '('); assert.ok(i >= 0, name + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const el = (tag, props, ...kids) => { const n = Object.assign({ tag, kids: kids.flat(Infinity) }, props || {}); n.props = n; return n; };
const card = (title, ...kids) => ({ tag: 'card', props: { title }, kids: kids.flat(Infinity) });
const pill = (text, cls) => ({ pill: text, cls });
const calls = []; const alerts = []; let failNext = null;
const api = async (p, o) => { calls.push({ p, o }); if (failNext) { const e = new Error(failNext); failNext = null; throw e; } return { settings: { marker: 'new' } }; };
const { agentAlertCard, agentSkipButton } = new Function('el', 'card', 'pill', 'api', 'alert', cut('agentAlertCard') + cut('agentSkipButton') + '\nreturn { agentAlertCard, agentSkipButton };')(el, card, pill, api, (m) => alerts.push(m));

const all = (n) => (n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(all)] : []);
const texts = (n) => all(n).flatMap((x) => [x.pill, x.props && x.props.textContent, ...(x.kids || []).filter((k) => typeof k === 'string')]).filter((x) => typeof x === 'string' && x);
const buttons = (n, label) => all(n).filter((x) => x.tag === 'button' && x.props.textContent === label);
const input = (n) => all(n).find((x) => x.tag === 'input');
const view = (row, server = 0) => aa.view(row, { minutes: server });

describe('Endpoints: disconnected-agent alert card', () => {
  it('nothing saved, server off: Off, from the server setting (off), no Turn off, no Follow', () => {
    const c = agentAlertCard(view(null), () => {});
    assert.ok(texts(c).includes('Off')); assert.ok(texts(c).includes('From the server setting (off).'));
    assert.strictEqual(buttons(c, 'Turn off').length, 0); assert.strictEqual(buttons(c, 'Follow the server setting').length, 0); assert.strictEqual(buttons(c, 'Save').length, 1);
    assert.strictEqual(input(c).props.value, '0'); assert.deepStrictEqual([input(c).props.min, input(c).props.max], [5, 10080]);
    assert.ok(texts(c).some((t) => /No machine is left out/.test(t)));
  });
  it('a saved limit says so and offers Follow; the server value is stated', () => {
    const c = agentAlertCard(view({ minutes: 60, skip_agents: [] }, 240), () => {});
    assert.ok(texts(c).includes('On: after 60 min')); assert.ok(texts(c).includes('Set here.')); assert.strictEqual(buttons(c, 'Follow the server setting').length, 1);
    assert.match(texts(c).join(' '), /The server setting is 240 minutes/);
  });
  it('off for this tenant while the server is on: Off, set here, Follow offered, no Turn off', () => {
    const c = agentAlertCard(view({ minutes: 0, skip_agents: [] }, 30), () => {});
    assert.ok(texts(c).includes('Off')); assert.strictEqual(buttons(c, 'Turn off').length, 0); assert.strictEqual(buttons(c, 'Follow the server setting').length, 1);
  });
  it('machines not watched are listed with a Watch again button each', () => {
    const c = agentAlertCard(view({ minutes: null, skip_agents: ['002', '017'] }), () => {});
    assert.ok(texts(c).some((t) => /Machines not watched \(2\)/.test(t))); assert.ok(texts(c).includes('agent 002 ') && texts(c).includes('agent 017 '));
    assert.strictEqual(buttons(c, 'Watch again').length, 2);
  });
  it('a missing table shows a notice and no inputs; an unreadable setting shows a short line', () => {
    const c = agentAlertCard(aa.view(null, { minutes: 0 }, true), () => {}); assert.ok(texts(c).includes('Not ready')); assert.strictEqual(all(c).filter((x) => x.tag === 'input').length, 0);
    assert.match(texts(agentAlertCard(null, () => {})).join(' '), /could not be read/);
  });
  it('Save, Turn off, Follow and Watch again send the right body and hand the answer to apply (no page reload)', async () => {
    calls.length = 0; let got = null; const apply = (x) => { got = x; };
    let c = agentAlertCard(view({ minutes: 60, skip_agents: ['002'] }), apply);
    input(c).props.value = ' 120 '; await buttons(c, 'Save')[0].onclick();
    assert.deepStrictEqual(calls[0], { p: '/v1/endpoints/agent-alert', o: { method: 'PUT', body: { minutes: '120' } } }); assert.deepStrictEqual(got, { marker: 'new' });
    await buttons(c, 'Turn off')[0].onclick(); assert.deepStrictEqual(calls[1].o.body, { minutes: 0 });
    await buttons(c, 'Follow the server setting')[0].onclick(); assert.deepStrictEqual(calls[2].o.body, { follow_server: true });
    await buttons(c, 'Watch again')[0].onclick(); assert.deepStrictEqual(calls[3].o.body, { skip_agent: '002', skip: false });
  });
  it('a refused save shows the message and does not call apply', async () => {
    let called = false; alerts.length = 0; failNext = 'Limit (minutes) must be 0 (off) or a whole number from 5 to 10080';
    const c = agentAlertCard(view(null), () => { called = true; }); input(c).props.value = '3'; await buttons(c, 'Save')[0].onclick();
    assert.strictEqual(called, false); assert.match(alerts[0], /whole number from 5/);
  });
});

describe('Endpoints: per-agent switch', () => {
  it('offers to stop alerting for a watched machine and to alert again for one left out, with the right body', async () => {
    calls.length = 0; let got = null;
    let b = agentSkipButton(view(null), '002', (x) => { got = x; }); assert.strictEqual(b.textContent, 'Never alert when this machine is disconnected');
    await b.onclick(); assert.deepStrictEqual(calls[0].o.body, { skip_agent: '002', skip: true }); assert.deepStrictEqual(got, { marker: 'new' });
    b = agentSkipButton(view({ minutes: null, skip_agents: ['002'] }), '002', () => {}); assert.strictEqual(b.textContent, 'Alert when disconnected again');
    await b.onclick(); assert.deepStrictEqual(calls[1].o.body, { skip_agent: '002', skip: false });
  });
  it('the Agents tab and the agent detail use them, and a failed read of the setting never hides the page', () => {
    assert.match(html, /agentAlertCard\(aa, setAA\)/); assert.match(html, /agentSkipButton\(aa, a\.id,/);
    assert.match(html, /aa = \(await api\('\/v1\/endpoints\/agent-alert'\)\)\.settings; \} catch \(e\) \{ aa = null; \}/);
  });
});
