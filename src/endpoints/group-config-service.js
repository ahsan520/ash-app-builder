'use strict';
// Reading, previewing and changing the ASIX block of a group's agent.conf (docs/endpoints.md, task E10). The orchestration only: the rules for the text are in group-config.js, the calls to the
// manager in wazuh-api.js, the rows in group-config-store.js. Everything it touches is passed in (ctx), so tests run it against a stand-in manager and a recording history.
//
// ctx = { m, w, api, hist: { record(row) -> {id}, settle(id, result, afterSha, note) } }
//   m, w   the manager and the writer credentials as wazuh-api.js wants them
//   api    wazuh-api.js (or a stand-in with groupList / groupAgentConf / putGroupAgentConf)
//   hist   writes the history row BEFORE the manager is called and settles it after
const gc = require('./group-config');

const tails = new Map();   // one change at a time per tenant and group in THIS process (a second API pod is caught by the base hash instead)
async function withLock(key, fn) {
  const prev = tails.get(key) || Promise.resolve();
  let release; const gate = new Promise((r) => { release = r; });
  const tail = prev.then(() => gate); tails.set(key, tail);
  await prev;
  try { return await fn(); } finally { release(); if (tails.get(key) === tail) tails.delete(key); }
}

const fail = (code, message, extra = {}) => ({ ok: false, code, message, ...extra });
const STATE_TEXT = { none: 'ASIX has not set anything for this group', ok: 'ASIX manages the folders below', broken: 'markers damaged', edited: 'block edited by hand' };

async function read(ctx, group) {
  if (!gc.validGroup(group)) return fail('BAD_GROUP', 'A group name is 1 to 64 letters, digits, dots, dashes or underscores');
  const xml = await ctx.api.groupAgentConf(ctx.m, ctx.w, group);
  const f = gc.find(xml);
  return { ok: true, xml, sha256: gc.sha256(xml), find: f, bytes: Buffer.byteLength(xml, 'utf8') };
}

// What a group has now: the hash to send back with a change, the state of the ASIX block and its entries.
async function describe(ctx, group) {
  const r = await read(ctx, group); if (!r.ok) return r;
  return { ok: true, group, sha256: r.sha256, state: r.find.state, state_text: STATE_TEXT[r.find.state], entries: r.find.entries, bytes: r.bytes };
}

// What a change would do, without touching the manager (it reads only).
async function preview(ctx, group, entries) {
  const r = await read(ctx, group); if (!r.ok) return r;
  const c = gc.compose(r.xml, entries); if (!c.ok) return fail(c.code, c.message, { errors: c.errors, base_sha256: r.sha256 });
  const v = gc.validate(entries);
  return { ok: true, group, base_sha256: r.sha256, changed: c.changed, entries: v.entries, diff: gc.diff(r.find.entries, v.entries), bytes_after: Buffer.byteLength(c.xml, 'utf8'), outside_unchanged: true };
}

// Changes the block. `baseSha` is the hash the person saw; if the file has changed since, nothing is written. action: 'apply' | 'remove' | 'undo'.
async function apply(ctx, group, entries, { baseSha, action = 'apply' } = {}) {
  if (!gc.validGroup(group)) return fail('BAD_GROUP', 'A group name is 1 to 64 letters, digits, dots, dashes or underscores');
  if (typeof baseSha !== 'string' || !/^[0-9a-f]{64}$/.test(baseSha)) return fail('BASE_REQUIRED', 'base_sha256 is required: preview the change first');
  return withLock((ctx.m.tenant_id || '') + '|' + group, async () => {
    const r = await read(ctx, group); if (!r.ok) return r;
    if (r.sha256 !== baseSha) return fail('STALE', 'The group configuration changed since you looked at it. Preview again.', { current_sha256: r.sha256 });
    const c = gc.compose(r.xml, entries); if (!c.ok) return fail(c.code, c.message, { errors: c.errors });
    if (!c.changed) return { ok: true, changed: false, group, sha256: r.sha256, entries: r.find.entries, message: 'Nothing to change' };
    const v = gc.validate(entries);
    const row = await ctx.hist.record({ action, result: 'failed', entries_before: r.find.entries, entries_after: v.entries, before_sha256: r.sha256, before_content: r.xml, note: 'not finished' });
    let put;
    try { await ctx.api.putGroupAgentConf(ctx.m, ctx.w, group, c.xml); put = null; } catch (e) { put = e; }
    if (put) {
      // The manager says no, or did not answer. It may or may not have taken the file: look before claiming anything.
      let now = null; try { now = await ctx.api.groupAgentConf(ctx.m, ctx.w, group); } catch { /* unknown */ }
      const same = now !== null && gc.sha256(now) === r.sha256;
      await ctx.hist.settle(row.id, 'failed', now === null ? null : gc.sha256(now), put.message);
      return fail(put.code === 'REJECTED' ? 'REJECTED' : 'MANAGER', put.message, { unchanged: same ? true : now === null ? 'unknown' : false });
    }
    // Look again: the manager must hold the block as written (compared as entries, not as bytes: a manager may reformat the file).
    let back = null, readErr = null; try { back = await ctx.api.groupAgentConf(ctx.m, ctx.w, group); } catch (e) { readErr = e; }
    const fb = back === null ? null : gc.find(back);
    const good = fb && fb.state === (v.entries.length ? 'ok' : 'none') && JSON.stringify(fb.entries) === JSON.stringify(v.entries);
    if (good) { await ctx.hist.settle(row.id, 'applied', gc.sha256(back), null); return { ok: true, changed: true, group, before_sha256: r.sha256, sha256: gc.sha256(back), entries: v.entries, history_id: row.id }; }
    // Not what was written: put the file back as it was.
    let restored = false, why = readErr ? readErr.message : 'the manager returned a different configuration than the one written';
    try { await ctx.api.putGroupAgentConf(ctx.m, ctx.w, group, r.xml); const again = await ctx.api.groupAgentConf(ctx.m, ctx.w, group); restored = gc.sha256(again) === r.sha256 || JSON.stringify(gc.find(again).entries) === JSON.stringify(r.find.entries); } catch (e) { why += '; restoring also failed: ' + e.message; }
    await ctx.hist.settle(row.id, restored ? 'rolled_back' : 'failed', null, why);
    return fail('VERIFY_FAILED', 'The change was written but could not be confirmed (' + why + ').' + (restored ? ' The previous configuration was put back.' : ' The previous configuration could NOT be put back: check the group on the manager. The earlier file is kept in the history.'), { rolled_back: restored });
  });
}

module.exports = { describe, preview, apply, read, withLock, STATE_TEXT };
