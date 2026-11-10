// Actions: the allow-list of things ASIX may do (docs/actions.md, task SR2). A page the module brings itself (docs/portal-shell.md).
// Rules of a module page: draw only through ctx.el and the host it is given, talk to the server only through ctx.api, and never use
// document, window, alert, confirm or innerHTML. Everything shown from the server is set as text. Text a person has typed is kept when the page redraws.

let alive = false;

export async function mount(host, ctx) {
  alive = true;
  const E = ctx.el;
  const canWrite = ctx.can('soar:actions:write');
  const S = { tab: 'actions', actions: [], levels: {}, runs: [], total: 0, filter: '', open: null, form: null, busy: false, msg: null };
  const RUN_STATUS = [['', 'All'], ['awaiting_approval', 'Waiting for approval'], ['succeeded', 'Done'], ['failed', 'Failed'], ['refused', 'Refused'], ['recommended', 'Recommended'], ['rejected', 'Rejected']];
  const STATUS_TEXT = { awaiting_approval: 'Waiting for approval', succeeded: 'Done', failed: 'Failed', refused: 'Refused', recommended: 'Recommended only', rejected: 'Rejected' };

  const T = (tag, className, text, extra) => E(tag, { className, textContent: text, ...(extra || {}) });
  const btn = (label, onclick, pri, off) => E('button', { className: 'btn' + (pri ? ' pri' : ''), textContent: label, onclick, disabled: !!off, style: 'margin-right:6px' });
  const pill = (text, cls) => E('span', { className: 'pill ' + cls, textContent: text, style: 'margin-right:6px' });
  const riskPill = (r) => pill(r + ' risk', r === 'high' ? 'bad' : 'off');
  const when = (v) => (v ? String(v).replace('T', ' ').slice(0, 16) : '');
  const draw = () => { if (alive) host.replaceChildren(...(S.tab === 'runs' ? runsPage() : actionsPage())); };
  const message = () => (S.msg ? E('div', { className: 'card' }, T('div', 'err', S.msg)) : '');

  const loadActions = async () => { const r = await ctx.api('/v1/actions'); S.actions = r.actions; S.levels = r.levels || {}; };
  const loadRuns = async () => {
    const r = await ctx.api('/v1/actions/runs?limit=100' + (S.filter ? '&status=' + S.filter : '')); S.runs = r.runs; S.total = r.total;
  };
  await loadActions();   // a failure here is the shell's error card, with Retry

  // Runs a change, then shows what the server answered.
  const run = async (fn, done) => {
    S.busy = true; S.msg = null; draw();
    try { await fn(); if (done) ctx.toast(done); await loadActions(); if (S.tab === 'runs') await loadRuns(); } catch (e) { S.msg = e.message; }
    S.busy = false; draw();
  };
  const setting = (a, body, done) => run(() => ctx.api('/v1/actions/' + a.id + '/setting', { method: 'PUT', body }), done);

  // ---- the actions ---------------------------------------------------------------------------------------------------------------------
  function actionsPage() {
    return [
      tabs(),
      T('h2', '', 'Actions'),
      T('div', 'mute', 'Everything ASIX may do on its own or on request. An action is off until you enable it. The level says how much it may do without a person: ' +
        Object.keys(S.levels).map((k) => k + ' ' + S.levels[k].toLowerCase()).join('; ') + '.'),
      message(),
      ...S.actions.map(card),
    ];
  }
  function tabs() {
    return E('div', { style: 'margin:0 0 12px' },
      btn('Actions', () => { S.tab = 'actions'; S.msg = null; draw(); }, S.tab === 'actions'),
      btn('Runs', async () => { S.tab = 'runs'; S.msg = null; try { await loadRuns(); } catch (e) { S.msg = e.message; } draw(); }, S.tab === 'runs'));
  }
  function card(a) {
    const open = S.open === a.id;
    const levels = [];
    for (let l = 0; l <= a.max_autonomy; l++) levels.push(E('option', { value: String(l), textContent: l + ' ' + (S.levels[l] || ''), selected: a.autonomy === l }));
    return E('div', { className: 'card' },
      E('div', {}, T('b', '', a.name), ' ', T('span', 'mute', a.id), ' ', riskPill(a.risk), pill(a.kind, 'off'), pill(a.enabled ? 'Enabled' : 'Off', a.enabled ? 'ok' : 'off'),
        a.enabled ? T('span', 'mute', 'Level ' + a.autonomy + ': ' + (S.levels[a.autonomy] || '')) : ''),
      T('div', 'mute', a.description),
      E('div', { style: 'margin-top:8px' },
        canWrite ? btn(a.enabled ? 'Disable' : 'Enable', () => setting(a, { enabled: !a.enabled }, a.enabled ? 'Action disabled' : 'Action enabled'), !a.enabled, S.busy) : '',
        canWrite ? E('select', { disabled: S.busy, style: 'margin-right:8px', onchange: (ev) => setting(a, { autonomy: Number(ev.target.value) }, 'Level changed') }, ...levels) : '',
        canWrite && a.enabled ? btn('Run…', () => { S.form = { id: a.id, values: {} }; S.open = a.id; draw(); }, false, S.busy) : '',
        btn(open ? 'Hide details' : 'Details', () => { S.open = open ? null : a.id; if (open) S.form = null; draw(); })),
      open ? details(a) : '',
      S.form && S.form.id === a.id ? runForm(a) : '');
  }
  function details(a) {
    return E('div', { style: 'margin-top:8px' },
      T('div', 'mute', `Publisher: ${a.publisher}. Source: ${a.source}. ${a.reversible ? 'Can be undone.' : a.append_only ? 'Only adds information (cannot be undone).' : 'Cannot be undone.'} Highest level allowed: ${a.max_autonomy}.`),
      a.configured ? T('div', 'mute', `Last changed by ${a.updated_by_name} on ${when(a.updated_at)}. ${a.runs} run${a.runs === 1 ? '' : 's'}${a.last_run_at ? ', the last on ' + when(a.last_run_at) : ''}.`) : T('div', 'mute', 'Never enabled for this tenant.'),
      T('b', '', 'Parameters'),
      ...a.parameters.map((q) => T('div', 'mute', `${q.name} (${q.type}${q.required ? ', required' : ''}${q.nullable ? ', may be empty' : ''}${q.values ? ': ' + q.values.join(' / ') : ''}) ${q.description}`)));
  }

  // One form field per parameter, by type. Typed text is kept in S.form.values when the page redraws.
  function runForm(a) {
    const v = S.form.values;
    const field = (q) => {
      const label = T('div', 'mute', q.name + (q.required ? ' *' : '') + ' ' + q.description);
      if (q.type === 'enum') return E('div', { style: 'margin:6px 0' }, label, E('select', { onchange: (ev) => { v[q.name] = ev.target.value; } }, E('option', { value: '', textContent: q.required ? 'Choose…' : '(leave out)', selected: !v[q.name] }), ...q.values.map((x) => E('option', { value: x, textContent: x, selected: v[q.name] === x }))));
      if (q.type === 'uuid_list') return E('div', { style: 'margin:6px 0' }, label, E('textarea', { rows: 2, style: 'width:100%', placeholder: 'ids separated by spaces, commas or new lines', value: v[q.name] || '', oninput: (ev) => { v[q.name] = ev.target.value; } }));
      return E('div', { style: 'margin:6px 0' }, label, E('input', { type: 'text', style: 'width:70%', placeholder: q.type === 'uuid' ? (q.nullable ? 'an id, or empty for nobody' : 'an id') : '', value: v[q.name] || '', oninput: (ev) => { v[q.name] = ev.target.value; } }));
    };
    const send = () => {
      const params = {};
      for (const q of a.parameters) {
        const raw = (v[q.name] || '').trim();
        if (q.type === 'uuid_list') { if (raw) params[q.name] = raw.split(/[\s,]+/).filter(Boolean); }
        else if (raw) params[q.name] = raw;
        else if (q.nullable && q.required) params[q.name] = null;
      }
      return run(async () => {
        const r = await ctx.api('/v1/actions/' + a.id + '/run', { method: 'POST', body: { parameters: params } });
        S.form = null; S.tab = 'runs'; await loadRuns();
        ctx.toast('Run recorded: ' + (STATUS_TEXT[r.run.status] || r.run.status));
      });
    };
    return E('div', { style: 'margin-top:10px' }, T('b', '', 'Run ' + a.name),
      ...a.parameters.map(field),
      E('div', {}, btn('Run', send, true, S.busy), btn('Cancel', () => { S.form = null; draw(); })),
      T('div', 'mute', a.autonomy <= 1 ? 'This action is set to ' + (S.levels[a.autonomy] || '') + ': the request is recorded and nothing is done.' : 'You are pressing Run yourself, so it runs now and the run is recorded under your name.'));
  }

  // ---- the runs ------------------------------------------------------------------------------------------------------------------------
  function runsPage() {
    return [
      tabs(),
      T('h2', '', 'Runs'),
      T('div', 'mute', 'Every request for an action is listed here, including the ones that were refused or are waiting for a person.'),
      E('div', { style: 'margin:10px 0' }, T('span', 'mute', 'Show: '), E('select', { onchange: async (ev) => { S.filter = ev.target.value; try { await loadRuns(); } catch (e) { S.msg = e.message; } draw(); } },
        ...RUN_STATUS.map(([val, text]) => E('option', { value: val, textContent: text, selected: S.filter === val })))),
      message(),
      ...(S.runs.length ? S.runs.map(runRow) : [T('div', 'mute', 'No runs here.')]),
      S.total > S.runs.length ? T('div', 'mute', `Showing ${S.runs.length} of ${S.total}.`) : '',
    ];
  }
  function runRow(r) {
    const name = (S.actions.find((a) => a.id === r.action_id) || {}).name || r.action_id;
    const bad = r.status === 'failed' || r.status === 'refused' || r.status === 'rejected';
    const post = (what, done) => run(() => ctx.api('/v1/actions/runs/' + r.id + '/' + what, { method: 'POST', body: {} }), done);
    return E('div', { className: 'card' },
      E('div', {}, T('b', '', name), ' ', pill(STATUS_TEXT[r.status] || r.status, r.status === 'succeeded' ? 'ok' : bad ? 'bad' : 'off'), riskPill(r.risk_class), T('span', 'mute', `${r.origin === 'automation' ? 'automation' : r.origin === 'undo' ? 'undo' : 'by ' + r.requested_by_name}, ${when(r.created_at)}`)),
      r.error_message ? T('div', 'err', r.error_message) : '',
      r.decided_by_name ? T('div', 'mute', (r.status === 'rejected' ? 'Rejected by ' : 'Decided by ') + r.decided_by_name + ' on ' + when(r.decided_at)) : (r.decision_note ? T('div', 'mute', r.decision_note) : ''),
      T('div', 'mute', Object.keys(r.params || {}).length ? 'Parameters: ' + JSON.stringify(r.params) : 'No parameters.'),
      r.undone_by_run_id ? T('div', 'mute', 'Undone.') : '',
      canWrite ? E('div', { style: 'margin-top:6px' },
        r.status === 'awaiting_approval' ? btn('Approve and run', () => post('approve', 'Approved'), true, S.busy) : '',
        r.status === 'awaiting_approval' ? btn('Reject', () => post('reject', 'Rejected'), false, S.busy) : '',
        r.status === 'succeeded' && r.undo && !r.undone_by_run_id && r.origin !== 'undo' ? btn('Undo', () => post('undo', 'Undone'), false, S.busy) : '') : '');
  }

  draw();
}

export function unmount() { alive = false; }
