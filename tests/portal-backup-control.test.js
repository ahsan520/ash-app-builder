'use strict';
// The Backup control card on the Data safety page (src/portal/index.html): the function is cut out of the page and run with small stand-ins for el(), card(), pill(), api()
// and route(), as in portal-broker-paused.test.js.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const line = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); return html.slice(i, html.indexOf('\n', i)); };
const el = (tag, attrs, ...kids) => Object.assign({ tag, attrs: attrs || {}, kids: kids.flat(Infinity) }, attrs || {});
const pill = (text, cls) => ({ pill: text, cls });
const walk = (n) => (n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
const find = (tree, f) => walk(tree).filter(f);
const text = (tree) => walk(tree).map((x) => (x.attrs && x.attrs.textContent) || (typeof x === 'string' ? x : '')).filter(Boolean).join(' | ');

// state shared with the stand-ins; safetyMsg is a page variable the card reads
function make() {
  const log = { api: [], alerts: [], routes: 0 };
  const io = { fail: null };
  const api = async (p, o = {}) => { log.api.push({ p, method: o.method || 'GET', body: o.body }); if (io.fail) throw new Error(io.fail); return { success: true }; };
  const fn = new Function('el', 'card', 'pill', 'when', 'api', 'route', 'alert',
    line('let safetyMsg') + '\n' + line('const SAFETY_DAYS') + '\n' + cut('function backupControlCard(') + '\nreturn { build: backupControlCard, msg: () => safetyMsg };')(
    el, (title, ...kids) => el('card', { title }, ...kids), pill, (v) => String(v).replace('T', ' ').replace(/\.\d+Z?$/, ''), api, () => { log.routes += 1; }, (m) => log.alerts.push(m));
  return { ...fn, log, io };
}
const control = (o = {}) => ({ enabled: true, time_utc: '02:17', days: [0, 1, 2, 3, 4, 5, 6], retain_days: 2, next_run: '2026-10-31T02:17:00.000Z', run_requested_at: null, run_requested_by: null, running: null, ...o });
const R = (o) => ({ control: control(o) });
const button = (tree, label) => find(tree, (x) => x.tag === 'button' && x.attrs.textContent === label)[0];
const inputs = (tree, type) => find(tree, (x) => x.tag === 'input' && x.attrs.type === type);
const flush = () => new Promise((r) => setImmediate(r));

describe('Backup control card', () => {
  it('shows the saved schedule, retention and the next run (UTC), and what retention does', () => {
    const { build } = make(); const t = build(R({ retain_days: 2 }));
    assert.strictEqual(inputs(t, 'time')[0].value, '02:17'); assert.strictEqual(inputs(t, 'number')[0].value, 2);
    assert.deepStrictEqual(inputs(t, 'checkbox').map((c) => c.checked), [true, true, true, true, true, true, true, true]);             // schedule on + 7 days
    assert.match(text(t), /Next scheduled backup: 2026-10-31 02:17:00 UTC/); assert.match(text(t), /older than 2 days are deleted from this VM, then the new one runs/);
    assert.match(text(t), /newest complete backup is never deleted/); assert.match(text(make().build(R({ retain_days: 1 }))), /older than 1 day are deleted/);
  });
  it('reflects a partial week and a switched-off schedule', () => {
    const t = build(R({ enabled: false, days: [1, 4] })); function build(r) { return make().build(r); }
    const boxes = inputs(t, 'checkbox'); assert.strictEqual(boxes[0].checked, false); assert.deepStrictEqual(boxes.slice(1).map((c) => c.checked), [false, true, false, false, true, false, false]);
    assert.match(text(t), /Scheduled backups are switched off/);
  });
  it('"Back up now" posts the request and re-draws; while one is waiting or running the button is disabled and says why', async () => {
    const m = make(); let t = m.build(R()); const b = button(t, 'Back up now'); assert.strictEqual(b.disabled, false);
    b.onclick(); await flush(); assert.deepStrictEqual(m.log.api, [{ p: '/v1/storage/backup/run', method: 'POST', body: undefined }]); assert.strictEqual(m.log.routes, 1); assert.match(m.msg(), /Backup requested/);
    t = make().build(R({ run_requested_at: '2026-10-30T12:00:00Z' })); assert.strictEqual(button(t, 'Starting...').disabled, true);
    t = make().build(R({ running: { trigger: 'manual', started_at: '2026-10-30T12:00:00.000Z' } })); assert.strictEqual(button(t, 'Backup running...').disabled, true); assert.ok(find(t, (x) => x.pill && /running since 2026-10-30 12:00:00 UTC \(manual\)/.test(x.pill)).length);
  });
  it('a refused request shows the server\'s reason and still re-draws', async () => {
    const m = make(); m.io.fail = '409 A backup is running now (BACKUP_RUNNING)'; button(m.build(R()), 'Back up now').onclick(); await flush();
    assert.deepStrictEqual(m.log.alerts, ['409 A backup is running now (BACKUP_RUNNING)']); assert.strictEqual(m.log.routes, 1);
  });
  it('Save schedule sends the form as it stands', async () => {
    const m = make(); const t = m.build(R()); const [on] = inputs(t, 'checkbox'), time = inputs(t, 'time')[0], keep = inputs(t, 'number')[0], days = inputs(t, 'checkbox').slice(1);
    on.checked = false; time.value = '04:30'; keep.value = '3'; days.forEach((d, i) => { d.checked = [1, 2, 3, 4, 5].includes(i); });
    button(t, 'Save schedule').onclick(); await flush();
    assert.deepStrictEqual(m.log.api, [{ p: '/v1/storage/backup/settings', method: 'PUT', body: { enabled: false, time_utc: '04:30', days: [1, 2, 3, 4, 5], retain_days: 3 } }]); assert.match(m.msg(), /schedule saved/);
  });
  it('Save schedule refuses a bad form before calling the server: no days, no time, retention out of range or not whole', async () => {
    for (const [mut, re] of [[(f) => f.days.forEach((d) => { d.checked = false; }), /at least one day/], [(f) => { f.time.value = ''; }, /time of day/], [(f) => { f.keep.value = '0'; }, /1 to 365/],
      [(f) => { f.keep.value = '366'; }, /1 to 365/], [(f) => { f.keep.value = '1.5'; }, /1 to 365/], [(f) => { f.keep.value = ''; }, /1 to 365/]]) {
      const m = make(), t = m.build(R()); mut({ days: inputs(t, 'checkbox').slice(1), time: inputs(t, 'time')[0], keep: inputs(t, 'number')[0] });
      button(t, 'Save schedule').onclick(); await flush(); assert.strictEqual(m.log.api.length, 0); assert.match(m.log.alerts[0], re);
    }
  });
});
