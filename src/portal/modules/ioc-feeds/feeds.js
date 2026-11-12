// IOC feeds: scheduled import of an indicator feed into the IOC store (docs/ioc-feeds.md).
// A page the module brings itself (docs/portal-shell.md). Rules of a module page: draw only through ctx.el, talk to the server only through ctx.api, never use
// document, window, alert, confirm or innerHTML; everything from the server is set as text. Deleting a feed takes two presses.

let alive = false;

export async function mount(host, ctx) {
  alive = true;
  const E = ctx.el;
  const canWrite = ctx.can('threatintel:feeds:write');
  const S = { feeds: [], integrations: [], choices: { severities: [], intervals: [] }, view: 'index', open: null, runs: [], creating: false,
    form: { integration_id: '', name: '', severity: 'medium', ttl_days: '30', interval_hours: '24' }, edit: {}, lastRun: null, confirm: null, alsoRemove: false, busy: false, msg: null };
  const T = (tag, className, text, extra) => E(tag, { className, textContent: text, ...(extra || {}) });
  const btn = (label, onclick, pri, off) => E('button', { className: 'btn' + (pri ? ' pri' : ''), textContent: label, onclick, disabled: !!off, style: 'margin-right:6px' });
  const pill = (text, cls) => E('span', { className: 'pill ' + cls, textContent: text, style: 'margin-right:6px' });
  const field = (label, control) => E('div', { style: 'margin:6px 0' }, T('div', 'mute', label), control);
  const when = (v) => (v ? String(v).replace('T', ' ').slice(0, 16) : '');
  const EVERY = { 1: 'every hour', 6: 'every 6 hours', 12: 'every 12 hours', 24: 'every day' };
  const draw = () => { if (alive) host.replaceChildren(...(S.view === 'detail' ? detailPage() : indexPage())); };
  const message = () => (S.msg ? E('div', { className: 'card' }, T('div', 'err', S.msg)) : '');
  const current = () => S.feeds.find((f) => f.id === S.open) || null;
  const statusPill = (f) => (f.running ? pill('Running', 'off') : !f.last_status ? pill('Never run', 'off') : f.last_status === 'ok' ? pill('Last run succeeded', 'ok') : pill('Last run failed', 'bad'));

  const load = async () => {
    const r = await ctx.api('/v1/ioc-feeds');
    S.feeds = r.feeds; S.integrations = r.integrations; S.choices = { severities: r.severities, intervals: r.intervals };
  };
  const loadRuns = async () => { const r = await ctx.api('/v1/ioc-feeds/' + S.open + '/runs?limit=20'); S.runs = r.runs; };
  await load();   // a failure here is the shell's error card, with Retry

  const run = async (fn, done) => {
    S.busy = true; S.msg = null; draw();
    try { await fn(); if (done) ctx.toast(done); } catch (e) { S.msg = e.message; }
    S.busy = false; draw();
  };
  const openIt = async (f) => {
    S.open = f.id; S.view = 'detail'; S.edit = { severity: f.severity, ttl_days: String(f.ttl_days), interval_hours: String(f.interval_hours) }; S.lastRun = null; S.confirm = null; S.alsoRemove = false; S.msg = null; S.runs = [];
    try { await loadRuns(); } catch (e) { S.msg = e.message; }
    draw();
  };
  const back = async () => { S.view = 'index'; S.open = null; S.msg = null; S.confirm = null; try { await load(); } catch (e) { S.msg = e.message; } draw(); };

  // ---- the feeds -----------------------------------------------------------------------------------------------------------------------
  function indexPage() {
    return [
      T('h2', '', 'IOC feeds'),
      T('div', 'mute', 'A feed brings indicators (addresses, domains, URLs, file hashes) into the IOC store on a schedule. Each feed uses a Threat feed integration for its address and token. Indicators the feed stops listing expire; indicators typed by a person or from another source are never changed.'),
      message(),
      canWrite ? E('div', { style: 'margin:10px 0' }, btn(S.creating ? 'Cancel' : 'Add a feed', () => { S.creating = !S.creating; S.msg = null; draw(); }, !S.creating, S.busy)) : '',
      S.creating ? newForm() : '',
      ...(S.feeds.length ? S.feeds.map(card) : [T('div', 'mute', 'There are no feeds yet.')]),
    ];
  }
  function newForm() {
    const f = S.form;
    if (!S.integrations.length) return E('div', { className: 'card' }, T('div', 'mute', 'A feed needs an integration of the type Threat feed (HTTP). Add one under Settings, Integrations, then come back.'));
    const create = () => run(async () => {
      const ttl = Number(f.ttl_days);
      const r = await ctx.api('/v1/ioc-feeds', { method: 'POST', body: { integration_id: f.integration_id, name: f.name, severity: f.severity, ttl_days: ttl, interval_hours: Number(f.interval_hours) } });
      S.creating = false; S.form = { integration_id: '', name: '', severity: 'medium', ttl_days: '30', interval_hours: '24' };
      await load(); ctx.toast('Feed added'); await openIt(r.feed);
    });
    return E('div', { className: 'card' }, T('b', '', 'Add a feed'),
      field('Integration (the address and token of the feed)', E('select', { onchange: (ev) => { f.integration_id = ev.target.value; draw(); } }, E('option', { value: '', textContent: 'Choose…', selected: !f.integration_id }),
        ...S.integrations.map((i) => E('option', { value: i.id, textContent: i.name + (i.status === 'configured' ? '' : ' (not configured)'), selected: f.integration_id === i.id })))),
      field('Name', E('input', { type: 'text', style: 'width:60%', value: f.name, oninput: (ev) => { f.name = ev.target.value; } })),
      field('Severity of its indicators', E('select', { onchange: (ev) => { f.severity = ev.target.value; } }, ...S.choices.severities.map((s) => E('option', { value: s, textContent: s, selected: f.severity === s })))),
      field('Keep an indicator for this many days after it was last listed', E('input', { type: 'text', style: 'width:8em', value: f.ttl_days, oninput: (ev) => { f.ttl_days = ev.target.value; } })),
      field('Import', E('select', { onchange: (ev) => { f.interval_hours = ev.target.value; } }, ...S.choices.intervals.map((h) => E('option', { value: String(h), textContent: EVERY[h] || h + ' hours', selected: f.interval_hours === String(h) })))),
      E('div', {}, btn('Add', create, true, S.busy || !f.integration_id), btn('Cancel', () => { S.creating = false; draw(); })));
  }
  function card(f) {
    return E('div', { className: 'card' },
      E('div', {}, T('b', '', f.name), ' ', statusPill(f), f.enabled ? '' : pill('Switched off', 'bad'), T('span', 'mute', `${f.integration_name} · ${EVERY[f.interval_hours] || ''} · ${f.severity}`)),
      f.last_run_at ? T('div', 'mute', `Last run ${when(f.last_run_at)}${f.last_item_count != null ? ', ' + f.last_item_count + ' indicators' : ''}.`) : '',
      f.last_status === 'failed' && f.last_error ? T('div', 'err', f.last_error) : '',
      E('div', { style: 'margin-top:8px' }, btn('Open', () => openIt(f))));
  }

  // ---- one feed ------------------------------------------------------------------------------------------------------------------------
  function detailPage() {
    const f = current();
    const head = [E('div', { style: 'margin:0 0 12px' }, btn('Back to the feeds', back)), message()];
    if (!f) return [...head, T('div', 'mute', 'This feed no longer exists.')];
    return [...head, T('h2', '', f.name), E('div', {}, statusPill(f), f.enabled ? '' : pill('Switched off', 'bad'), T('span', 'mute', f.integration_name)),
      canWrite ? runCard(f) : '', settingsCard(f), historyCard(), canWrite ? dangerCard(f) : ''];
  }
  function runCard(f) {
    const go = (force) => run(async () => {
      const r = await ctx.api('/v1/ioc-feeds/' + f.id + '/run', { method: 'POST', body: force ? { force: true } : {} });
      S.lastRun = r.run; await load(); await loadRuns();
    });
    const lr = S.lastRun;
    return E('div', { className: 'card' }, T('b', '', 'Import now'),
      T('div', 'mute', 'Fetches the feed and updates the IOC store straight away. Runs also happen on the schedule.'),
      E('div', { style: 'margin-top:8px' }, btn(S.busy ? 'Running…' : 'Run now', () => go(false), true, S.busy),
        lr && lr.status === 'failed' && lr.error_code === 'FEED_SHRANK' ? btn('Run anyway', () => go(true), false, S.busy) : ''),
      lr ? E('div', { style: 'margin-top:8px' }, lr.status === 'ok' ? T('div', '', `Done: ${lr.items} indicators in the feed, ${lr.added} added, ${lr.updated} refreshed, ${lr.expired} expired.`) : T('div', 'err', `Failed (${lr.error_code}): ${lr.error_message}`)) : '');
  }
  function settingsCard(f) {
    const e = S.edit;
    const save = () => run(async () => {
      const body = {};
      if (e.severity !== f.severity) body.severity = e.severity;
      if (e.ttl_days !== String(f.ttl_days)) body.ttl_days = Number(e.ttl_days);
      if (e.interval_hours !== String(f.interval_hours)) body.interval_hours = Number(e.interval_hours);
      if (!Object.keys(body).length) { S.msg = 'Nothing has changed.'; return; }
      await ctx.api('/v1/ioc-feeds/' + f.id, { method: 'PUT', body }); await load();
    }, 'Saved');
    const toggle = () => run(async () => { await ctx.api('/v1/ioc-feeds/' + f.id, { method: 'PUT', body: { enabled: !f.enabled } }); await load(); }, f.enabled ? 'Switched off' : 'Switched on');
    return E('div', { className: 'card' }, T('b', '', 'Settings'),
      !canWrite ? T('div', 'mute', `${f.severity} severity, kept ${f.ttl_days} days after last listed, imported ${EVERY[f.interval_hours] || ''}.`) : E('div', {},
        field('Severity of its indicators', E('select', { onchange: (ev) => { e.severity = ev.target.value; } }, ...S.choices.severities.map((s) => E('option', { value: s, textContent: s, selected: e.severity === s })))),
        field('Keep an indicator for this many days after it was last listed', E('input', { type: 'text', style: 'width:8em', value: e.ttl_days, oninput: (ev) => { e.ttl_days = ev.target.value; } })),
        field('Import', E('select', { onchange: (ev) => { e.interval_hours = ev.target.value; } }, ...S.choices.intervals.map((h) => E('option', { value: String(h), textContent: EVERY[h] || h + ' hours', selected: e.interval_hours === String(h) })))),
        E('div', {}, btn('Save settings', save, true, S.busy), btn(f.enabled ? 'Switch off' : 'Switch on', toggle, false, S.busy))));
  }
  function historyCard() {
    return E('div', { className: 'card' }, T('b', '', 'Recent runs'),
      ...(S.runs.length ? S.runs.map((r) => E('div', { style: 'padding:4px 0;border-top:1px solid var(--line)' },
        pill(r.status === 'ok' ? 'Succeeded' : r.status === 'running' ? 'Running' : 'Failed', r.status === 'ok' ? 'ok' : r.status === 'running' ? 'off' : 'bad'),
        T('span', 'mute', `${when(r.started_at)} · ${r.run_kind === 'schedule' ? 'scheduled' : 'by hand'}`),
        r.status === 'ok' ? T('div', 'mute', `${r.items} in the feed · ${r.added} added · ${r.updated} refreshed · ${r.expired} expired · ${r.invalid} not recognised · ${r.skipped_other} owned by another source`) : '',
        r.status === 'failed' ? T('div', 'err', `${r.error_code}: ${r.error_message}`) : '')) : [T('div', 'mute', 'It has not run yet.')]));
  }
  function dangerCard(f) {
    const del = () => run(async () => { await ctx.api('/v1/ioc-feeds/' + f.id + (S.alsoRemove ? '?remove_indicators=true' : ''), { method: 'DELETE' }); ctx.toast('Feed deleted'); S.view = 'index'; S.open = null; S.confirm = null; await load(); });
    const c = S.confirm;
    return E('div', { className: 'card' }, T('b', '', 'Delete this feed'),
      T('div', 'mute', 'Its indicators stay in the IOC store and expire on their own, unless you also remove them here.'),
      E('div', { style: 'margin:6px 0' }, E('label', {}, E('input', { type: 'checkbox', style: 'width:auto;margin-right:8px;vertical-align:middle', checked: !!S.alsoRemove, onchange: (ev) => { S.alsoRemove = ev.target.checked; } }), ' Also remove the indicators this feed imported')),
      c ? E('div', {}, T('span', 'err', `Delete "${f.name}"${S.alsoRemove ? ' and its indicators' : ''}? `), btn('Yes, delete', del, true, S.busy), btn('No', () => { S.confirm = null; draw(); }))
        : btn('Delete the feed…', () => { S.confirm = true; draw(); }, false, S.busy));
  }
  draw();
}

export function unmount() { alive = false; }
