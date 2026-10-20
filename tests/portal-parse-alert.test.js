'use strict';
// The unparsed-events alert card on Settings, Parser pool (src/portal/index.html). Same approach as portal-broker-tls-own.test.js:
// the function is cut out of the page and run with small stand-ins for el(), card(), pill(), api(), route() and alert().
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const pa = require('../src/ingestion/parse-alert');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (name) => { const i = html.indexOf('function ' + name + '('); assert.ok(i >= 0, name + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const el = (tag, props, ...kids) => { const n = Object.assign({ tag, kids: kids.flat(Infinity) }, props || {}); n.props = n; return n; };   // like the page's el(): props become properties of the node
const card = (title, ...kids) => ({ tag: 'card', props: { title }, kids: kids.flat(Infinity) });
const pill = (text, cls) => ({ pill: text, cls });
const calls = []; const alerts = []; let routed = 0; let failNext = null;
const api = async (p, o) => { calls.push({ p, o }); if (failNext) { const e = new Error(failNext); failNext = null; throw e; } return {}; };
const { parserAlertCard } = new Function('el', 'card', 'pill', 'api', 'route', 'alert', cut('parserAlertCard') + '\nreturn { parserAlertCard };')(el, card, pill, api, () => { routed += 1; }, (m) => alerts.push(m));

const all = (n) => (n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(all)] : []);
const texts = (n) => all(n).flatMap((x) => [x.pill, x.props && x.props.textContent]).filter((x) => typeof x === 'string' && x);
const button = (n, label) => all(n).find((x) => x.tag === 'button' && x.props.textContent === label);
const input = (n, i) => all(n).filter((x) => x.tag === 'input')[i];
const server = (min, win = 15) => ({ threshold: min, windowMin: win });
const view = (row, srv = server(0)) => pa.view(row, srv);

describe('Parser pool: unparsed-events alert card', () => {
  it('nothing saved and the server off: Off, "From the server setting (off)", no Turn off and no Follow button', () => {
    const c = parserAlertCard(view(null));
    assert.ok(texts(c).includes('Off')); assert.ok(texts(c).includes('From the server setting (off).'));
    assert.ok(!button(c, 'Turn off')); assert.ok(!button(c, 'Follow the server setting')); assert.ok(button(c, 'Save'));
    assert.strictEqual(input(c, 0).props.value, '0'); assert.strictEqual(input(c, 1).props.value, '15');
  });
  it('the server on: shows its limit and window, Turn off is offered, Follow is not (nothing to follow away from)', () => {
    const c = parserAlertCard(view(null, server(30, 60)));
    assert.ok(texts(c).includes('On: 30 in 60 min')); assert.ok(texts(c).includes('From the server setting.'));
    assert.ok(button(c, 'Turn off')); assert.ok(!button(c, 'Follow the server setting'));
    assert.match(texts(c).join(' '), /The server setting is 30 in 60 minutes/);
  });
  it('a saved limit: says it was set here and offers Follow the server setting', () => {
    const c = parserAlertCard(view({ min_events: 20, window_min: 30 }));
    assert.ok(texts(c).includes('On: 20 in 30 min')); assert.ok(texts(c).includes('Set here.')); assert.ok(button(c, 'Follow the server setting'));
    assert.strictEqual(input(c, 0).props.value, '20'); assert.strictEqual(input(c, 1).props.value, '30');
    assert.match(texts(c).join(' '), /The server setting is off/);
  });
  it('off for this tenant while the server is on: Off, set here, can follow the server again', () => {
    const c = parserAlertCard(view({ min_events: 0, window_min: 15 }, server(9)));
    assert.ok(texts(c).includes('Off')); assert.ok(texts(c).includes('Set here.')); assert.ok(button(c, 'Follow the server setting')); assert.ok(!button(c, 'Turn off'));
  });
  it('inputs carry the allowed ranges', () => {
    const c = parserAlertCard(view(null));
    assert.deepStrictEqual([input(c, 0).props.min, input(c, 0).props.max, input(c, 1).props.min, input(c, 1).props.max], [0, 1000000, 5, 1440]);
  });
  it('a database without the table shows a notice and no inputs; an unreadable setting shows a short line', () => {
    const c = parserAlertCard(pa.view(null, server(0), true)); assert.ok(texts(c).includes('Not ready')); assert.strictEqual(all(c).filter((x) => x.tag === 'input').length, 0);
    assert.match(texts(parserAlertCard(null)).join(' '), /could not be read/);
  });
  it('Save sends what is typed, Turn off sends 0, Follow sends follow_server; each reloads the page', async () => {
    calls.length = 0; routed = 0;
    let c = parserAlertCard(view({ min_events: 20, window_min: 30 }));
    input(c, 0).props.value = ' 50 '; input(c, 1).props.value = '45';
    await button(c, 'Save').props.onclick();
    await button(c, 'Turn off').props.onclick();
    await button(c, 'Follow the server setting').props.onclick();
    assert.deepStrictEqual(calls.map((x) => [x.p, x.o.method, x.o.body]), [
      ['/v1/parser/alert', 'PUT', { min_events: '50', window_min: '45' }], ['/v1/parser/alert', 'PUT', { min_events: 0 }], ['/v1/parser/alert', 'PUT', { follow_server: true }]]);
    assert.strictEqual(routed, 3);
  });
  it('a refused save shows the reason and does not reload', async () => {
    calls.length = 0; routed = 0; alerts.length = 0; failNext = 'Limit (events) must be a whole number from 0 to 1000000';
    const c = parserAlertCard(view(null)); input(c, 0).props.value = 'many';
    await button(c, 'Save').props.onclick();
    assert.deepStrictEqual(alerts, ['Limit (events) must be a whole number from 0 to 1000000']); assert.strictEqual(routed, 0);
  });
});

describe('Parser pool page wiring', () => {
  it('reads /v1/parser/alert without letting a failure hide the page, and draws the card before the unparsed table', () => {
    assert.match(html, /const alertSetting = await api\('\/v1\/parser\/alert'\)\.then\(\(x\) => x\.settings\)\.catch\(\(\) => null\)/);
    const page = cut('pgParserPool'); assert.ok(page.indexOf('parserAlertCard(alertSetting)') > 0);
    assert.ok(page.indexOf('parserAlertCard(alertSetting)') < page.indexOf("'Events stored unparsed' })"));
    assert.ok(!/Read-only\./.test(page), 'the page no longer claims to be read-only');
  });
  it('the whole page script still parses', () => {
    const m = /<script>([\s\S]*)<\/script>/.exec(html); assert.ok(m); assert.doesNotThrow(() => new Function(m[1]));
  });
});
