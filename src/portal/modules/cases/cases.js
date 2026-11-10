// Cases: group alerts into a case with an owner, a status, notes and a timeline (docs/cases.md, task CS1). A page the module brings itself (docs/portal-shell.md).
// Rules of a module page: draw only through ctx.el and the host it is given, talk to the server only through ctx.api, and never use
// document, window, alert, confirm or innerHTML. Everything shown from the server is set as text. Text a person has typed is kept when the page redraws.

let alive = false;

export async function mount(host, ctx) {
  alive = true;
  const E = ctx.el;
  const canWrite = ctx.can('alerts:write');
  const S = { tab: 'active', mine: false, cases: [], total: 0, form: null, open: null, view: null, edit: null, note: '', adding: null, users: [], me: null, busy: false, msg: null };
  const SEV = ['critical', 'high', 'medium', 'low'];
  const STATUS = [['open', 'Open'], ['investigating', 'Investigating'], ['closed', 'Closed']];

  const T = (tag, className, text, extra) => E(tag, { className, textContent: text, ...(extra || {}) });
  const btn = (label, onclick, pri, off) => E('button', { className: 'btn' + (pri ? ' pri' : ''), textContent: label, onclick, disabled: !!off, style: 'margin-right:6px' });
  const pill = (text, cls) => E('span', { className: 'pill ' + cls, textContent: text, style: 'margin-right:6px' });
  const sevPill = (s) => pill(s, s === 'critical' || s === 'high' ? 'bad' : 'off');
  const when = (v) => (v ? String(v).replace('T', ' ').slice(0, 16) : '');
  const plural = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
  const draw = () => { if (alive) host.replaceChildren(...(S.open ? casePage() : listPage())); };
  const message = () => (S.msg ? E('div', { className: 'card' }, T('div', 'err', S.msg)) : '');

  // ---- loading and doing things ------------------------------------------------------------------------------------------------------
  const loadList = async () => {
    const qs = '?status=' + (S.tab === 'active' ? 'active' : S.tab === 'closed' ? 'closed' : 'all') + (S.mine ? '&owner=me' : '') + '&limit=100';
    const r = await ctx.api('/v1/cases' + qs); S.cases = r.cases; S.total = r.total;
  };
  const loadUsers = async () => { try { const r = await ctx.api('/v1/alert-assignees'); S.users = r.users; S.me = r.me; } catch { S.users = []; } };
  await loadList();   // a failure here is the shell's error card, with Retry
  await loadUsers();

  // Runs a change, then shows what the server answered. `view` is the case as the server now has it.
  const run = async (fn, done) => {
    S.busy = true; S.msg = null; draw();
    try { const r = await fn(); if (r && r.case) S.view = r; if (done) ctx.toast(done); await loadList(); } catch (e) { S.msg = e.message; }
    S.busy = false; draw();
  };
  const openCase = async (id) => {
    S.msg = null; S.edit = null; S.adding = null; S.note = '';
    try { S.view = await ctx.api('/v1/cases/' + id); S.open = id; } catch (e) { S.msg = e.message; }
    draw();
  };
  const patch = (body, done) => run(() => ctx.api('/v1/cases/' + S.open, { method: 'PATCH', body }), done);

  // ---- the list ------------------------------------------------------------------------------------------------------------------------
  function listPage() {
    const tab = (id, label) => btn(label, async () => { S.tab = id; S.msg = null; try { await loadList(); } catch (e) { S.msg = e.message; } draw(); }, S.tab === id);
    return [
      T('h2', '', 'Cases'),
      T('div', 'mute', 'A case groups related alerts under one owner, with a status, notes and a timeline. An alert can be in one case only.'),
      E('div', { style: 'margin:12px 0' }, tab('active', 'Active'), tab('closed', 'Closed'), tab('all', 'All'),
        E('label', { className: 'mute', style: 'margin:0 14px' }, E('input', { type: 'checkbox', checked: S.mine, onchange: async (ev) => { S.mine = ev.target.checked; try { await loadList(); } catch (e) { S.msg = e.message; } draw(); } }), ' Mine only'),
        canWrite ? btn('New case', () => { S.form = S.form || { title: '', severity: '', description: '' }; draw(); }, true) : ''),
      message(), S.form ? newForm() : '',
      ...(S.cases.length ? S.cases.map(row) : [T('div', 'mute', S.tab === 'active' ? 'No active cases.' : 'No cases here.')]),
      S.total > S.cases.length ? T('div', 'mute', `Showing ${S.cases.length} of ${S.total}.`) : '',
    ];
  }
  function newForm() {
    const f = S.form;
    return E('div', { className: 'card' },
      T('b', '', 'New case'),
      E('div', { style: 'margin:8px 0' }, E('input', { type: 'text', placeholder: 'Title', value: f.title, style: 'width:60%;margin-right:10px', oninput: (ev) => { f.title = ev.target.value; } }),
        E('select', { onchange: (ev) => { f.severity = ev.target.value; } }, E('option', { value: '', textContent: 'Severity: automatic', selected: f.severity === '' }), ...SEV.map((s) => E('option', { value: s, textContent: s, selected: f.severity === s })))),
      E('textarea', { placeholder: 'What is this about? (optional)', value: f.description, rows: 3, style: 'width:100%', oninput: (ev) => { f.description = ev.target.value; } }),
      E('div', { style: 'margin-top:8px' }, btn('Create case', () => { if (!f.title.trim()) { S.msg = 'Give the case a title.'; return draw(); } return create(); }, true, S.busy), btn('Cancel', () => { S.form = null; S.msg = null; draw(); })),
      T('div', 'mute', 'Severity is taken from the alerts you add later (the worst one) unless you choose it here.'));
  }
  const create = () => run(async () => {
    const f = S.form; const body = { title: f.title }; if (f.severity) body.severity = f.severity; if (f.description.trim()) body.description = f.description;
    const r = await ctx.api('/v1/cases', { method: 'POST', body }); S.form = null; S.open = r.case.id; S.note = ''; S.edit = null; S.adding = null; return r;
  }, 'Case created');
  function row(c) {
    return E('div', { className: 'card' },
      E('div', {}, T('b', '', '#' + c.case_number + '  ' + c.title), '  ', sevPill(c.severity), pill(c.status === 'investigating' ? 'Investigating' : c.status === 'closed' ? 'Closed' : 'Open', c.status === 'closed' ? 'ok' : 'off')),
      T('div', 'mute', `${c.owner_name ? 'Owner: ' + c.owner_name : 'No owner'} · ${plural(c.alert_count, 'alert')} · changed ${when(c.updated_at)}`),
      E('div', { style: 'margin-top:8px' }, btn('Open', () => openCase(c.id))));
  }

  // ---- one case ------------------------------------------------------------------------------------------------------------------------
  function casePage() {
    const v = S.view; const c = v.case; const closed = c.status === 'closed'; const off = S.busy || !canWrite;
    const owner = E('select', { disabled: off || closed, onchange: (ev) => patch({ owner_id: ev.target.value || null }) },
      E('option', { value: '', textContent: 'Nobody', selected: !c.owner_id }), ...S.users.map((u) => E('option', { value: u.id, textContent: u.username, selected: u.id === c.owner_id })));
    const sev = E('select', { disabled: off || closed, onchange: (ev) => patch({ severity: ev.target.value }) }, ...SEV.map((s) => E('option', { value: s, textContent: s, selected: s === c.severity })));
    return [
      btn('← Back', async () => { S.open = null; S.view = null; S.msg = null; try { await loadList(); } catch (e) { S.msg = e.message; } draw(); }),
      E('div', { style: 'margin:10px 0' }, T('h2', '', '#' + c.case_number + '  ' + c.title, { style: 'display:inline' }), '  ', sevPill(c.severity), pill(closed ? 'Closed' : c.status === 'investigating' ? 'Investigating' : 'Open', closed ? 'ok' : 'off')),
      T('div', 'mute', `Opened by ${c.created_by_name} · ${when(c.created_at)} · changed ${when(c.updated_at)}${c.closed_at ? ' · closed ' + when(c.closed_at) : ''}`),
      message(),
      canWrite ? E('div', { className: 'card', style: 'margin-top:10px' },
        E('div', {}, T('span', 'mute', 'Status  '), ...STATUS.filter(([s]) => s !== c.status).map(([s, label]) => btn(closed && s === 'open' ? 'Reopen' : closed ? 'Reopen as ' + label : label === 'Closed' ? 'Close case' : 'Mark ' + label.toLowerCase(), () => patch({ status: s }, 'Case ' + label.toLowerCase()), s === 'closed', S.busy))),
        E('div', { style: 'margin-top:8px' }, T('span', 'mute', 'Owner  '), owner, S.me && c.owner_id !== S.me && !closed ? btn('Take it', () => patch({ owner_id: S.me }, 'You own this case'), false, off) : '', T('span', 'mute', '   Severity  '), sev),
        closed ? T('div', 'mute', 'A closed case is read-only. Reopen it to change it. You can still add notes.') : '') : T('div', 'mute', 'Your role can look at cases but not change them.'),
      editBox(c, closed, off),
      alertsBox(v, closed, off),
      timelineBox(v, off),
    ];
  }
  function editBox(c, closed, off) {
    if (S.edit) {
      const f = S.edit;
      return E('div', { className: 'card' },
        E('input', { type: 'text', value: f.title, style: 'width:70%', oninput: (ev) => { f.title = ev.target.value; } }),
        E('textarea', { value: f.description, rows: 4, style: 'width:100%;margin-top:8px', oninput: (ev) => { f.description = ev.target.value; } }),
        E('div', { style: 'margin-top:8px' }, btn('Save', () => {
          if (!f.title.trim()) { S.msg = 'The title cannot be empty.'; return draw(); }
          const b = {}; if (f.title.trim() !== c.title) b.title = f.title; if ((f.description.trim() || null) !== (c.description || null)) b.description = f.description;
          S.edit = null; return Object.keys(b).length ? patch(b, 'Saved') : draw();
        }, true, S.busy), btn('Cancel', () => { S.edit = null; draw(); })));
    }
    return E('div', { className: 'card' }, c.description ? T('div', '', c.description, { style: 'white-space:pre-wrap' }) : T('div', 'mute', 'No description.'),
      canWrite && !closed ? E('div', { style: 'margin-top:8px' }, btn('Edit title and description', () => { S.edit = { title: c.title, description: c.description || '' }; draw(); }, false, off)) : '');
  }
  function alertsBox(v, closed, off) {
    const addable = canWrite && !closed;
    const rows = v.alerts.map((a) => E('tr', {}, E('td', {}, sevPill(a.severity)), E('td', {}, a.title, T('div', 'mute', a.rule_name + ' · ' + a.status, { style: 'font-size:12px' })), E('td', { className: 'mute' }, when(a.last_event_at)),
      E('td', {}, addable ? btn('Remove', () => run(() => ctx.api('/v1/cases/' + S.open + '/alerts/' + a.id, { method: 'DELETE' }), 'Alert removed'), false, off) : '')));
    return E('div', { className: 'card' },
      E('div', {}, T('b', '', plural(v.alerts.length, 'alert')), '   ', addable ? btn(S.adding ? 'Hide the list' : 'Add alerts', async () => {
        if (S.adding) { S.adding = null; return draw(); }
        try { S.adding = (await ctx.api('/v1/cases/candidates')).alerts; S.msg = null; } catch (e) { S.msg = e.message; }
        return draw();
      }, false, off) : ''),
      v.alerts.length ? E('table', {}, E('tbody', {}, ...rows)) : T('div', 'mute', 'No alerts in this case yet.'),
      S.adding ? E('div', { style: 'margin-top:10px' }, T('div', 'mute', S.adding.length ? 'Open alerts that are not in a case, worst first:' : 'Every open alert is already in a case.'),
        ...S.adding.map((a) => E('div', { style: 'margin:4px 0' }, sevPill(a.severity), a.title, T('span', 'mute', '  ' + a.rule_name + '  '),
          btn('Add', () => run(async () => { const r = await ctx.api('/v1/cases/' + S.open + '/alerts', { method: 'POST', body: { alert_ids: [a.id] } }); S.adding = (await ctx.api('/v1/cases/candidates')).alerts; return r; }, 'Alert added'), false, off)))) : '');
  }
  function timelineBox(v, off) {
    return E('div', { className: 'card' }, T('b', '', 'Timeline'),
      ...v.timeline.map((e) => E('div', { style: 'margin:8px 0' }, T('span', 'mute', when(e.created_at) + '  ' + e.actor_name + '  '), e.kind === 'note' ? T('div', '', e.text, { style: 'white-space:pre-wrap;margin-top:2px' }) : T('span', '', e.text))),
      canWrite ? E('div', { style: 'margin-top:10px' },
        E('textarea', { placeholder: 'Add a note', value: S.note, rows: 3, style: 'width:100%', oninput: (ev) => { S.note = ev.target.value; } }),
        E('div', { style: 'margin-top:6px' }, btn('Add note', () => { if (!S.note.trim()) { S.msg = 'Write a note first.'; return draw(); } return run(async () => { const r = await ctx.api('/v1/cases/' + S.open + '/notes', { method: 'POST', body: { body: S.note } }); S.note = ''; return r; }, 'Note added'); }, true, off))) : '');
  }

  draw();
}

export function unmount() { alive = false; }
