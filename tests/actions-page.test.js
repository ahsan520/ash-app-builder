'use strict';
// SR2: the Actions page, a page the module brings itself (docs/portal-shell.md). Same method as tests/cases-page.test.js: the page file is copied to a
// temporary .mjs file and imported; it draws only through ctx.el, so a fake el() and a fake server are enough.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');
const catalog = require('../src/actions/catalog');

const PAGE = path.join(__dirname, '../src/portal/modules/actions/actions.js');
let tmp; let page;
before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-actions-'));
  fs.copyFileSync(PAGE, path.join(tmp, 'actions.mjs'));
  page = await import(pathToFileURL(path.join(tmp, 'actions.mjs')).href);
});
after(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

// ---- fakes -----------------------------------------------------------------------------------------------------
const clean = (k) => k.flat(Infinity).filter((x) => x !== '' && x != null);
const fakeEl = (tag, props, ...kids) => ({ tag, ...(props || {}), kids: clean(kids), replaceChildren(...k) { this.kids = clean(k); } });
const fakeHost = () => ({ kids: [], replaceChildren(...k) { this.kids = clean(k); } });
const walk = (n) => (n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(walk)] : []);
const allText = (host) => host.kids.flatMap(walk).flatMap((x) => [x.textContent, ...(x.kids || []).filter((c) => typeof c === 'string')]).filter((x) => typeof x === 'string').join(' | ');
const all = (host) => host.kids.flatMap(walk);
const buttons = (host, label) => all(host).filter((n) => n.tag === 'button' && (label === undefined || n.textContent === label));
const tick = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };
const click = async (host, label, nth = 0) => { const b = buttons(host, label)[nth]; assert.ok(b, `no button "${label}" in: ${allText(host).slice(0, 500)}`); assert.ok(!b.disabled, `"${label}" is disabled`); b.onclick(); await tick(); };
const selects = (host) => all(host).filter((n) => n.tag === 'select');
const textareas = (host) => all(host).filter((n) => n.tag === 'textarea');
const inputs = (host) => all(host).filter((n) => n.tag === 'input' && n.type === 'text');
const selectedValue = (sel) => (sel.kids.find((o) => o.selected) || {}).value;

const ID = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const LEVELS = { 0: 'Observe only', 1: 'Recommend only', 2: 'Ask for approval', 3: 'Run low-risk actions by itself', 4: 'Run by itself (approved class)' };
// the real definitions, as the server sends them, plus this tenant's setting
const mkAction = (def, over = {}) => ({ ...catalog.publicView(def), enabled: false, autonomy: def.default_autonomy, autonomy_label: LEVELS[def.default_autonomy], configured: false, updated_by_name: null, updated_at: null, runs: 0, last_run_at: null, ...over });
const mkRun = (n, over = {}) => ({ id: ID(n), action_id: 'case.add_note', origin: 'user', status: 'succeeded', risk_class: 'low', autonomy_level: 2, params: { case_id: ID(1), body: 'hi' }, result: {}, error_code: null, error_message: null, undo: null, undone_by_run_id: null, undo_of_run_id: null,
  requested_by_name: 'alice', decided_by_name: 'alice', decided_at: '2026-11-09T10:00:00.000Z', decision_note: null, created_at: '2026-11-09T10:00:00.000Z', finished_at: '2026-11-09T10:00:00.000Z', ...over });

function server(opts = {}) {
  const actions = catalog.list().filter((d) => d.id.startsWith('case.')).map((d) => mkAction(d, opts.enabled && opts.enabled.includes(d.id) ? { enabled: true, configured: true } : {}));
  const runs = opts.runs || [];
  const calls = [];
  const api = async (p, o = {}) => {
    const method = o.method || 'GET'; calls.push({ key: method + ' ' + p.split('?')[0], url: p, body: o.body });
    if (opts.fail && opts.fail[method + ' ' + p]) throw opts.fail[method + ' ' + p];
    let m;
    if (method === 'GET' && p === '/v1/actions') return { success: true, actions, levels: LEVELS };
    if (method === 'GET' && p.startsWith('/v1/actions/runs?')) {
      const st = new URLSearchParams(p.split('?')[1]).get('status'); const list = runs.filter((r) => !st || r.status === st);
      return { success: true, runs: list, total: opts.total || list.length, limit: 100, offset: 0 };
    }
    if (method === 'PUT' && (m = /^\/v1\/actions\/([^/]+)\/setting$/.exec(p))) {
      const a = actions.find((x) => x.id === m[1]); if (o.body.enabled !== undefined) { a.enabled = o.body.enabled; a.configured = true; } if (o.body.autonomy !== undefined) a.autonomy = o.body.autonomy;
      return { success: true, action: a };
    }
    if (method === 'POST' && (m = /^\/v1\/actions\/([^/]+)\/run$/.exec(p))) { const r = mkRun(80, { action_id: m[1], params: o.body.parameters, status: opts.runStatus || 'succeeded' }); runs.unshift(r); return { success: true, run: r }; }
    if (method === 'POST' && (m = /^\/v1\/actions\/runs\/([^/]+)\/(approve|reject|undo)$/.exec(p))) {
      const r = runs.find((x) => x.id === m[1]);
      if (m[2] === 'approve') r.status = 'succeeded'; if (m[2] === 'reject') r.status = 'rejected'; if (m[2] === 'undo') r.undone_by_run_id = ID(99);
      return { success: true, run: r };
    }
    throw new Error('unexpected call ' + method + ' ' + p);
  };
  return { api, calls, actions, runs };
}
const err = (status, msg, code) => Object.assign(new Error(`${status} ${msg}${code ? ' (' + code + ')' : ''}`), { status });
async function open(srv, perms = ['soar:actions:read', 'soar:actions:write']) {
  const host = fakeHost(); const toasts = [];
  await page.mount(host, { api: srv.api, el: fakeEl, can: (p) => perms.includes(p), toast: (t, k) => toasts.push([t, k]) });
  return { host, toasts };
}
const card = (host, name) => host.kids.find((n) => n.className === 'card' && allText({ kids: [n] }).includes(name));
const cardText = (host, name) => allText({ kids: [card(host, name)] });

describe('the page file follows the module-page rules', () => {
  const src = fs.readFileSync(PAGE, 'utf8');
  it('exports mount and unmount', () => { assert.strictEqual(typeof page.mount, 'function'); assert.strictEqual(typeof page.unmount, 'function'); });
  it('uses no browser globals, dialogs or innerHTML', () => {
    const code = src.replace(/'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|`(?:\\.|[^`\\])*`/g, '""').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
    for (const w of ['document', 'window', 'alert', 'confirm', 'prompt', 'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'localStorage', 'sessionStorage', 'eval', 'Function', 'fetch']) assert.ok(!new RegExp('(?<![.\\w$])' + w + '\\b(?!\\s*:)').test(code), `the page must not use ${w}`);
    assert.ok(code.includes('ctx.api') && code.includes('ctx.el'));
  });
  it('talks only to the action registry routes', () => {
    const urls = [...src.matchAll(/ctx\.api\(\s*'([^']+)'/g)].map((m) => m[1]);
    assert.ok(urls.length >= 5);
    for (const u of urls) assert.ok(u.startsWith('/v1/actions'), u);
  });
});

describe('the actions tab', () => {
  it('lists every action, all off, with risk and kind', async () => {
    const { host } = await open(server());
    const t = allText(host);
    for (const n of ['Open a case', 'Add a note to a case', 'Set the status of a case', 'Add alerts to a case']) assert.ok(t.includes(n), n);
    assert.strictEqual(t.split('Off').length - 1 >= 7, true, 'every action says Off');
    assert.ok(cardText(host, 'Set the status of a case').includes('medium risk'));
    assert.ok(cardText(host, 'Add a note to a case').includes('low risk'));
    assert.ok(t.includes('off until you enable it'));
  });
  it('an off action cannot be run: there is no Run button until it is enabled', async () => {
    const { host } = await open(server());
    assert.strictEqual(buttons(host, 'Run…').length, 0);
  });
  it('Enable sends the setting, says so, and the action then shows its level and a Run button', async () => {
    const srv = server(); const { host, toasts } = await open(srv);
    const b = buttons(card(host, 'Add a note to a case'), 'Enable')[0]; assert.ok(b);
    b.onclick(); await tick();
    assert.deepStrictEqual(srv.calls.filter((c) => c.key.startsWith('PUT')).map((c) => [c.key, c.body]), [['PUT /v1/actions/case.add_note/setting', { enabled: true }]]);
    assert.deepStrictEqual(toasts, [['Action enabled', undefined]]);
    const t = cardText(host, 'Add a note to a case');
    assert.ok(t.includes('Enabled') && t.includes('Level 2: Ask for approval'));
    assert.strictEqual(buttons(card(host, 'Add a note to a case'), 'Run…').length, 1);
    assert.strictEqual(buttons(card(host, 'Add a note to a case'), 'Disable').length, 1);
  });
  it('Disable turns it off again', async () => {
    const srv = server({ enabled: ['case.add_note'] }); const { host } = await open(srv);
    buttons(card(host, 'Add a note to a case'), 'Disable')[0].onclick(); await tick();
    assert.deepStrictEqual(srv.calls.filter((c) => c.key.startsWith('PUT')).map((c) => c.body), [{ enabled: false }]);
    assert.strictEqual(buttons(card(host, 'Add a note to a case'), 'Run…').length, 0);
  });
  it('the level choice stops at the action\'s own highest level', async () => {
    const { host } = await open(server());
    const levels = (name) => selects(card(host, name))[0].kids.map((o) => o.value);
    assert.deepStrictEqual(levels('Set the status of a case'), ['0', '1', '2', '3']);
    assert.deepStrictEqual(levels('Add a note to a case'), ['0', '1', '2', '3', '4']);
  });
  it('choosing a level sends it', async () => {
    const srv = server({ enabled: ['case.set_status'] }); const { host, toasts } = await open(srv);
    selects(card(host, 'Set the status of a case'))[0].onchange({ target: { value: '3' } }); await tick();
    assert.deepStrictEqual(srv.calls.filter((c) => c.key.startsWith('PUT')).map((c) => c.body), [{ autonomy: 3 }]);
    assert.ok(toasts.some((t) => t[0] === 'Level changed'));
  });
  it('Details shows the publisher, the source, whether it can be undone, and each parameter', async () => {
    const { host } = await open(server());
    await click(card(host, 'Set the status of a case'), 'Details'); const t = cardText(host, 'Set the status of a case');
    assert.ok(t.includes('Publisher: ASIX') && t.includes('Can be undone') && t.includes('Highest level allowed: 3') && t.includes('Never enabled'));
    assert.ok(t.includes('case_id (uuid, required)') && t.includes('status (enum, required: open / investigating / closed)'));
    await click(card(host, 'Add a note to a case'), 'Details');
    assert.ok(cardText(host, 'Add a note to a case').includes('Only adds information'));
    await click(card(host, 'Add a note to a case'), 'Hide details');
    assert.ok(!cardText(host, 'Add a note to a case').includes('Publisher'));
  });
  it('someone who may only read sees no Enable, level or Run controls', async () => {
    const { host } = await open(server({ enabled: ['case.add_note'] }), ['soar:actions:read']);
    assert.strictEqual(buttons(host, 'Enable').length + buttons(host, 'Disable').length + buttons(host, 'Run…').length, 0);
    assert.strictEqual(selects(host).length, 0);
    assert.ok(allText(host).includes('Add a note to a case'));
  });
  it('a refused change shows the server\'s words, and the page stays usable', async () => {
    const srv = server({ fail: { 'PUT /v1/actions/case.set_status/setting': err(400, 'cannot be given a level above 3', 'AUTONOMY_TOO_HIGH') } }); const { host } = await open(srv);
    buttons(card(host, 'Set the status of a case'), 'Enable')[0].onclick(); await tick();
    assert.ok(allText(host).includes('cannot be given a level above 3'));
    assert.ok(buttons(host, 'Enable').length > 0);
  });
});

describe('running an action', () => {
  const enabled = ['case.add_note', 'case.add_alerts', 'case.set_owner', 'case.set_status', 'case.create'];
  it('Run… opens a form with one field per parameter, by type', async () => {
    const { host } = await open(server({ enabled }));
    await click(card(host, 'Add alerts to a case'), 'Run…');
    const c = card(host, 'Add alerts to a case');
    assert.strictEqual(inputs({ kids: [c] }).length, 1, 'case_id is a text box');
    assert.strictEqual(textareas({ kids: [c] }).length, 1, 'alert_ids is a box for a list');
    await click(card(host, 'Set the status of a case'), 'Run…');
    const sel = selects({ kids: [card(host, 'Set the status of a case')] }).find((s) => s.kids.some((o) => o.value === 'closed'));
    assert.deepStrictEqual(sel.kids.map((o) => o.value), ['', 'open', 'investigating', 'closed']);
    assert.ok(allText(host).includes('you are pressing Run yourself') || allText(host).includes('You are pressing Run yourself'));
  });
  it('sends the typed values as parameters and then shows the run on the Runs tab', async () => {
    const srv = server({ enabled, runs: [] }); const { host, toasts } = await open(srv);
    await click(card(host, 'Add a note to a case'), 'Run…');
    const c = card(host, 'Add a note to a case');
    inputs({ kids: [c] })[0].oninput({ target: { value: '  ' + ID(5) + ' ' } });
    inputs({ kids: [c] })[1].oninput({ target: { value: 'a note' } });
    await click(card(host, 'Add a note to a case'), 'Run');
    const run = srv.calls.find((x) => x.key === 'POST /v1/actions/case.add_note/run');
    assert.deepStrictEqual(run.body, { parameters: { case_id: ID(5), body: 'a note' } });
    assert.ok(toasts.some((t) => /Run recorded: Done/.test(t[0])));
    assert.ok(allText(host).includes('Runs') && allText(host).includes('Add a note to a case'));
    assert.ok(srv.calls.some((x) => x.url === '/v1/actions/runs?limit=100'));
  });
  it('a list of ids is split on spaces, commas and new lines', async () => {
    const srv = server({ enabled }); const { host } = await open(srv);
    await click(card(host, 'Add alerts to a case'), 'Run…');
    const c = card(host, 'Add alerts to a case');
    inputs({ kids: [c] })[0].oninput({ target: { value: ID(1) } });
    textareas({ kids: [c] })[0].oninput({ target: { value: `${ID(2)}, ${ID(3)}\n${ID(4)}  ${ID(5)}` } });
    await click(card(host, 'Add alerts to a case'), 'Run');
    assert.deepStrictEqual(srv.calls.find((x) => x.key.endsWith('/run')).body.parameters, { case_id: ID(1), alert_ids: [ID(2), ID(3), ID(4), ID(5)] });
  });
  it('an empty owner means nobody (null)', async () => {
    const srv = server({ enabled }); const { host } = await open(srv);
    await click(card(host, 'Set the owner of a case'), 'Run…');
    inputs({ kids: [card(host, 'Set the owner of a case')] })[0].oninput({ target: { value: ID(3) } });   // case_id; owner_id is left empty
    await click(card(host, 'Set the owner of a case'), 'Run');
    assert.deepStrictEqual(srv.calls.find((x) => x.key.endsWith('/run')).body.parameters, { case_id: ID(3), owner_id: null });
  });
  it('an enum left unchosen is left out of the request', async () => {
    const srv = server({ enabled }); const { host } = await open(srv);
    await click(card(host, 'Open a case'), 'Run…');
    inputs({ kids: [card(host, 'Open a case')] })[0].oninput({ target: { value: 'Router attack' } });   // title; severity stays "(leave out)"
    await click(card(host, 'Open a case'), 'Run');
    assert.deepStrictEqual(srv.calls.find((x) => x.key.endsWith('/run')).body.parameters, { title: 'Router attack' });
  });
  it('typed text survives a redraw', async () => {
    const srv = server({ enabled }); const { host } = await open(srv);
    await click(card(host, 'Add a note to a case'), 'Run…');
    const c = card(host, 'Add a note to a case');
    inputs({ kids: [c] })[0].oninput({ target: { value: ID(7) } });
    await click(card(host, 'Open a case'), 'Details');   // a redraw caused by another card
    assert.strictEqual(inputs({ kids: [card(host, 'Add a note to a case')] })[0].value, ID(7));
  });
  it('Cancel closes the form without calling the server', async () => {
    const srv = server({ enabled }); const { host } = await open(srv);
    await click(card(host, 'Add a note to a case'), 'Run…'); await click(card(host, 'Add a note to a case'), 'Cancel');
    assert.strictEqual(buttons(card(host, 'Add a note to a case'), 'Cancel').length, 0);
    assert.ok(!srv.calls.some((x) => x.key.endsWith('/run')));
  });
  it('a level that only recommends says so before the run', async () => {
    const srv = server({ enabled }); srv.actions.find((a) => a.id === 'case.add_note').autonomy = 1;
    const { host } = await open(srv); await click(card(host, 'Add a note to a case'), 'Run…');
    assert.ok(cardText(host, 'Add a note to a case').includes('Recommend only: the request is recorded and nothing is done'));
  });
  it('a refused run shows the server\'s words in the form page', async () => {
    const srv = server({ enabled, fail: { 'POST /v1/actions/case.add_note/run': err(409, 'This action is not enabled for this tenant', 'ACTION_DISABLED') } }); const { host } = await open(srv);
    await click(card(host, 'Add a note to a case'), 'Run…'); await click(card(host, 'Add a note to a case'), 'Run');
    assert.ok(allText(host).includes('not enabled for this tenant'));
  });
});

describe('the runs tab', () => {
  const runs = () => [
    mkRun(1, { status: 'awaiting_approval', origin: 'automation', requested_by_name: 'service account', decided_by_name: null, decided_at: null, decision_note: 'Waiting for a person to approve.', action_id: 'case.set_status', risk_class: 'medium' }),
    mkRun(2, { status: 'succeeded', action_id: 'case.set_status', risk_class: 'medium', undo: { action: 'case.set_status', params: {} } }),
    mkRun(3, { status: 'succeeded', action_id: 'case.set_status', undo: { action: 'x.y', params: {} }, undone_by_run_id: ID(9) }),
    mkRun(4, { status: 'refused', error_message: 'This action is not enabled for this tenant.', decided_by_name: null }),
    mkRun(5, { status: 'failed', error_message: 'Case not found' }),
    mkRun(6, { status: 'succeeded', origin: 'undo', undo: { action: 'a.b', params: {} } }),
  ];
  const openRuns = async (srv, perms) => { const o = await open(srv, perms); await click(o.host, 'Runs'); return o; };

  it('lists every run with its status, who, and the words of a refusal or failure', async () => {
    const { host } = await openRuns(server({ runs: runs() }));
    const t = allText(host);
    for (const w of ['Waiting for approval', 'Done', 'Refused', 'Failed', 'by alice', 'automation', 'This action is not enabled for this tenant.', 'Case not found']) assert.ok(t.includes(w), w);
    assert.ok(t.includes('Parameters: {"case_id"'));
  });
  it('shows Approve and Reject only on a run that waits, and Undo only on a finished change that has an undo and was not undone', async () => {
    const { host } = await openRuns(server({ runs: runs() }));
    assert.strictEqual(buttons(host, 'Approve and run').length, 1);
    assert.strictEqual(buttons(host, 'Reject').length, 1);
    assert.strictEqual(buttons(host, 'Undo').length, 1, 'run 2 only: run 3 was undone, run 6 is itself an undo, the rest have none');
    assert.ok(allText(host).includes('Undone.'));
  });
  it('Approve sends it and the run is then listed as done; Reject and Undo likewise', async () => {
    const srv = server({ runs: runs() }); const { host, toasts } = await openRuns(srv);
    await click(host, 'Approve and run');
    assert.ok(srv.calls.some((c) => c.key === `POST /v1/actions/runs/${ID(1)}/approve`));
    assert.strictEqual(buttons(host, 'Approve and run').length, 0);
    await click(host, 'Undo');
    assert.ok(srv.calls.some((c) => c.key === `POST /v1/actions/runs/${ID(2)}/undo`));
    assert.deepStrictEqual(toasts.map((t) => t[0]), ['Approved', 'Undone']);
    const srv2 = server({ runs: runs() }); const o2 = await openRuns(srv2);
    await click(o2.host, 'Reject');
    assert.ok(srv2.calls.some((c) => c.key === `POST /v1/actions/runs/${ID(1)}/reject`));
  });
  it('a reader sees the runs but none of the buttons', async () => {
    const { host } = await openRuns(server({ runs: runs() }), ['soar:actions:read']);
    assert.strictEqual(buttons(host, 'Approve and run').length + buttons(host, 'Reject').length + buttons(host, 'Undo').length, 0);
  });
  it('the filter asks the server for that status', async () => {
    const srv = server({ runs: runs() }); const { host } = await openRuns(srv);
    const sel = selects(host)[0]; assert.strictEqual(selectedValue(sel), '');
    sel.onchange({ target: { value: 'refused' } }); await tick();
    assert.ok(srv.calls.some((c) => c.url === '/v1/actions/runs?limit=100&status=refused'));
    assert.ok(!allText(host).includes('Case not found'));
  });
  it('says when there is nothing, and when the list is cut', async () => {
    assert.ok(allText((await openRuns(server())).host).includes('No runs here.'));
    assert.ok(allText((await openRuns(server({ runs: runs(), total: 250 }))).host).includes('Showing 6 of 250.'));
  });
  it('a failed approval shows the server\'s words', async () => {
    const srv = server({ runs: runs(), fail: { [`POST /v1/actions/runs/${ID(1)}/approve`]: err(409, 'A high-risk action must be approved by someone other than the person who requested it.', 'SELF_APPROVAL') } });
    const { host } = await openRuns(srv); await click(host, 'Approve and run');
    assert.ok(allText(host).includes('someone other than the person who requested it'));
  });
});

describe('loading', () => {
  it('a failure to load is thrown, so the shell shows its error card with Retry', async () => {
    const srv = { api: async () => { throw err(500, 'boom'); }, calls: [] };
    await assert.rejects(() => open(srv), /boom/);
  });
  it('after unmount nothing is drawn any more', async () => {
    const srv = server(); const { host } = await open(srv); const before = allText(host);
    page.unmount(); buttons(card(host, 'Add a note to a case'), 'Enable')[0].onclick(); await tick();
    assert.strictEqual(allText(host), before);
  });
});
