'use strict';
// E4o: the score alert card on the Configuration checks tab (src/portal/index.html). Same approach as portal-agent-alert.test.js: the function is cut out of the page and run
// with small stand-ins for el(), card(), pill(), api() and alert().
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const sa = require('../src/endpoints/score-alert');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (name) => { const i = html.indexOf('function ' + name + '('); assert.ok(i >= 0, name + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const el = (tag, props, ...kids) => { const n = Object.assign({ tag, kids: kids.flat(Infinity) }, props || {}); n.props = n; n.replaceChildren = (...k) => { n.kids = k.flat(Infinity); }; return n; };
const card = (title, ...kids) => ({ tag: 'card', props: { title }, kids: kids.flat(Infinity) });
const pill = (text, cls) => ({ pill: text, cls });
const calls = []; const alerts = []; let failNext = null;
const api = async (p, o) => { calls.push({ p, o }); if (failNext) { const e = new Error(failNext); failNext = null; throw e; } return { settings: { marker: 'new' } }; };
const { scoreAlertCard } = new Function('el', 'card', 'pill', 'api', 'alert', cut('scoreAlertCard') + '\nreturn { scoreAlertCard };')(el, card, pill, api, (m) => alerts.push(m));

const all = (n) => (n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(all)] : []);
const texts = (n) => all(n).flatMap((x) => [x.pill, x.props && x.props.textContent, ...(x.kids || []).filter((k) => typeof k === 'string')]).filter((x) => typeof x === 'string' && x);
const buttons = (n, label) => all(n).filter((x) => x.tag === 'button' && x.props.textContent === label);
const input = (n) => all(n).find((x) => x.tag === 'input');
const view = (xql = sa.queryFor(50), enabled = true) => sa.view({ id: 'r1', enabled, severity: 'medium', xql, updated_at: new Date('2026-10-31T10:00:00Z') });

describe('Endpoints, Configuration checks: score alert card', () => {
  it('on at the shipped limit: On: score under 50%, the limit in the input with its bounds, Save and Turn off', () => {
    const c = scoreAlertCard(view(), () => {});
    assert.ok(texts(c).includes('On: score under 50%')); assert.strictEqual(input(c).props.value, '50'); assert.deepStrictEqual([input(c).props.min, input(c).props.max], [1, 100]);
    assert.strictEqual(buttons(c, 'Save').length, 1); assert.strictEqual(buttons(c, 'Turn off').length, 1); assert.strictEqual(buttons(c, 'Save and turn on').length, 0);
    assert.match(texts(c).join(' '), /Shipped limit: 50%/); assert.match(texts(c).join(' '), /severity medium/);
  });
  it('off: says Off, keeps the saved limit in the input, offers Save and turn on and no Turn off', () => {
    const c = scoreAlertCard(view(sa.queryFor(35), false), () => {});
    assert.ok(texts(c).includes('Off')); assert.strictEqual(input(c).props.value, '35'); assert.strictEqual(buttons(c, 'Turn off').length, 0); assert.strictEqual(buttons(c, 'Save and turn on').length, 1); assert.strictEqual(buttons(c, 'Save').length, 0);
  });
  it('a hand-edited query: no input, no Save, the way back is named, Turn off is still offered while it is on', () => {
    const c = scoreAlertCard(view('sca_score != null and sca_score < 50 and agent_name = "x"'), () => {});
    assert.strictEqual(all(c).filter((x) => x.tag === 'input').length, 0); assert.strictEqual(buttons(c, 'Save').length, 0); assert.ok(texts(c).includes('On (edited)'));
    assert.match(texts(c).join(' '), /Reset on the rule/); assert.strictEqual(buttons(c, 'Turn off').length, 1);
    const o = scoreAlertCard(view('alert_level >= 1', false), () => {}); assert.ok(texts(o).includes('Off')); assert.strictEqual(buttons(o, 'Turn off').length, 0);
  });
  it('the rule not created yet shows Not ready and no inputs; an unreadable setting shows a short line', () => {
    const c = scoreAlertCard(sa.view(null), () => {}); assert.ok(texts(c).includes('Not ready')); assert.strictEqual(all(c).filter((x) => x.tag === 'input').length, 0);
    assert.match(texts(scoreAlertCard(null, () => {})).join(' '), /could not be read/);
  });
  it('Save sends the trimmed text as { limit } and Turn off sends { off: true }; the answer goes to apply, with no page reload', async () => {
    calls.length = 0; let got = null; const apply = (x) => { got = x; };
    const c = scoreAlertCard(view(), apply);
    input(c).props.value = ' 30 '; await buttons(c, 'Save')[0].onclick();
    assert.deepStrictEqual(calls[0], { p: '/v1/endpoints/score-alert', o: { method: 'PUT', body: { limit: '30' } } }); assert.deepStrictEqual(got, { marker: 'new' });
    await buttons(c, 'Turn off')[0].onclick(); assert.deepStrictEqual(calls[1], { p: '/v1/endpoints/score-alert', o: { method: 'PUT', body: { off: true } } });
    const o = scoreAlertCard(view(sa.queryFor(35), false), apply); await buttons(o, 'Save and turn on')[0].onclick(); assert.deepStrictEqual(calls[2].o.body, { limit: '35' });
    const e = scoreAlertCard(view('alert_level >= 1'), apply); await buttons(e, 'Turn off')[0].onclick(); assert.deepStrictEqual(calls[3].o.body, { off: true });
  });
  it('a refused save shows the message and does not call apply', async () => {
    alerts.length = 0; let applied = 0; const c = scoreAlertCard(view(), () => { applied += 1; });
    failNext = 'The rule\'s query was edited on the Detections page'; await buttons(c, 'Save')[0].onclick();
    assert.deepStrictEqual(alerts, ['The rule\'s query was edited on the Detections page']); assert.strictEqual(applied, 0);
  });
});

describe('preview (E4p)', () => {
  it('Preview asks for the typed limit (encoded) with a GET and shows the count and the list as text', async () => {
    calls.length = 0;
    const saved = api; // the stand-in api returns { settings } for everything, so build a card whose api answers the preview
    const mk = new Function('el', 'card', 'pill', 'api', 'alert', cut('scoreAlertCard') + '\nreturn scoreAlertCard;');
    const seen = []; const c = mk(el, card, pill, async (p, o) => { seen.push({ p, o }); return { preview: { limit: 60, days: 7, read: 9, truncated: true, summaries: 5, under: 2, list: [{ key: 'P on a', score: 10 }, { key: 'P on b', score: 45 }] } }; }, () => {})(view(), () => {});
    input(c).props.value = ' 60 '; await buttons(c, 'Preview')[0].onclick();
    assert.deepStrictEqual(seen, [{ p: '/v1/endpoints/score-alert/preview?limit=60', o: undefined }]);
    const t = texts(c).join(' | ');
    assert.match(t, /2 of 5 policy and machine pairs scored under 60%/); assert.match(t, /only the newest 9 summaries were read/); assert.match(t, /10%  P on a/); assert.match(t, /45%  P on b/); assert.ok(saved);
  });
  it('a failed preview shows the message; a hand-edited rule has no preview button (no number box)', async () => {
    const mk = new Function('el', 'card', 'pill', 'api', 'alert', cut('scoreAlertCard') + '\nreturn scoreAlertCard;');
    const c = mk(el, card, pill, async () => { throw new Error('boom'); }, () => {})(view(), () => {}); await buttons(c, 'Preview')[0].onclick(); assert.ok(texts(c).includes('boom'));
    assert.strictEqual(buttons(scoreAlertCard(view('alert_level >= 1'), () => {}), 'Preview').length, 0);
  });
});

describe('the Configuration checks tab', () => {
  const view_ = html.slice(html.indexOf('const alertsView = (kind) => {'), html.indexOf('const notices = () =>'));
  it('reads the setting only on the Configuration checks tab and draws the card above the filters', () => {
    assert.match(view_, /if \(cfg\) api\('\/v1\/endpoints\/score-alert'\)\.then\(\(r\) => drawScore\(r\.settings\)\)\.catch\(\(\) => drawScore\(null\)\)/);
    assert.match(view_, /return \[\.\.\.\(cfg \? \[scoreBox\] : \[\]\), el\('div'/);
    assert.ok(view_.includes('const drawScore = (x) => scoreBox.replaceChildren(scoreAlertCard(x, drawScore));'));
  });
  it('the function does not use innerHTML (every value is shown as text) and the whole script parses', () => {
    assert.ok(!/innerHTML/.test(cut('scoreAlertCard')));
    const i = html.indexOf('<script'); const j = html.lastIndexOf('</script>'); assert.doesNotThrow(() => new Function(html.slice(html.indexOf('>', i) + 1, j)));
  });
});
