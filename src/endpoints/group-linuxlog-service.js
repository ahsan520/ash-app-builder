'use strict';
// Reading, previewing and changing the ASIX block for Linux logs in a group's agent.conf (docs/endpoints.md, task E13). The same steps as group-winlog-service.js (read, check the hash the
// person saw, history row first, put, read again, compare, put the old file back if the manager holds something else); the rules for the text are in group-linuxlog.js.
// ctx = { m, w, api, hist: { record(row) -> {id}, settle(id, result, afterSha, note) } }.
const gc = require('./group-config');
const ll = require('./group-linuxlog');
const { withLock } = require('./group-config-service');

const fail = (code, message, extra = {}) => ({ ok: false, code, message, ...extra });
const STATE_TEXT = { none: 'ASIX has not set any Linux log for this group', ok: 'ASIX manages the Linux logs below', broken: 'markers damaged', edited: 'block edited by hand' };
const BAD_GROUP = () => fail('BAD_GROUP', 'A group name is 1 to 64 letters, digits, dots, dashes or underscores');

async function read(ctx, group) {
  if (!gc.validGroup(group)) return BAD_GROUP();
  const xml = await ctx.api.groupAgentConf(ctx.m, ctx.w, group);
  return { ok: true, xml, sha256: gc.sha256(xml), find: ll.find(xml), bytes: Buffer.byteLength(xml, 'utf8') };
}
async function describe(ctx, group) {
  const r = await read(ctx, group); if (!r.ok) return r;
  return { ok: true, group, sha256: r.sha256, state: r.find.state, state_text: STATE_TEXT[r.find.state], entries: r.find.entries, bytes: r.bytes };
}
async function preview(ctx, group, entries) {
  const r = await read(ctx, group); if (!r.ok) return r;
  const c = ll.compose(r.xml, entries); if (!c.ok) return fail(c.code, c.message, { errors: c.errors, base_sha256: r.sha256 });
  const v = ll.validateEntries(entries);
  return { ok: true, group, base_sha256: r.sha256, changed: c.changed, entries: v.entries, diff: ll.diff(r.find, v.entries), bytes_after: Buffer.byteLength(c.xml, 'utf8'), outside_unchanged: true };
}
async function apply(ctx, group, entries, { baseSha, action = 'apply' } = {}) {
  if (!gc.validGroup(group)) return BAD_GROUP();
  if (typeof baseSha !== 'string' || !/^[0-9a-f]{64}$/.test(baseSha)) return fail('BASE_REQUIRED', 'base_sha256 is required: preview the change first');
  return withLock((ctx.m.tenant_id || '') + '|' + group, async () => {   // the SAME key as the other two blocks: they all write the one agent.conf of the group, so they take turns
    const r = await read(ctx, group); if (!r.ok) return r;
    if (r.sha256 !== baseSha) return fail('STALE', 'The group configuration changed since you looked at it. Preview again.', { current_sha256: r.sha256 });
    const c = ll.compose(r.xml, entries); if (!c.ok) return fail(c.code, c.message, { errors: c.errors });
    const v = ll.validateEntries(entries);
    if (!c.changed) return { ok: true, changed: false, group, sha256: r.sha256, entries: r.find.entries, message: 'Nothing to change' };
    const row = await ctx.hist.record({ action, result: 'failed', entries_before: r.find.entries, entries_after: v.entries, before_sha256: r.sha256, before_content: r.xml, note: 'not finished' });
    let put;
    try { await ctx.api.putGroupAgentConf(ctx.m, ctx.w, group, c.xml); put = null; } catch (e) { put = e; }
    if (put) {
      let now = null; try { now = await ctx.api.groupAgentConf(ctx.m, ctx.w, group); } catch { /* unknown */ }
      await ctx.hist.settle(row.id, 'failed', now === null ? null : gc.sha256(now), put.message);
      return fail(put.code === 'REJECTED' ? 'REJECTED' : 'MANAGER', put.message, { unchanged: now !== null && gc.sha256(now) === r.sha256 ? true : now === null ? 'unknown' : false });
    }
    let back = null, readErr = null; try { back = await ctx.api.groupAgentConf(ctx.m, ctx.w, group); } catch (e) { readErr = e; }
    const fb = back === null ? null : ll.find(back);
    if (fb && fb.state === (v.entries.length ? 'ok' : 'none') && JSON.stringify(fb.entries) === JSON.stringify(v.entries)) {
      await ctx.hist.settle(row.id, 'applied', gc.sha256(back), null);
      return { ok: true, changed: true, group, before_sha256: r.sha256, sha256: gc.sha256(back), entries: v.entries, history_id: row.id };
    }
    let restored = false, why = readErr ? readErr.message : 'the manager returned a different configuration than the one written';
    try { await ctx.api.putGroupAgentConf(ctx.m, ctx.w, group, r.xml); const again = await ctx.api.groupAgentConf(ctx.m, ctx.w, group); restored = gc.sha256(again) === r.sha256 || JSON.stringify(ll.find(again).entries) === JSON.stringify(r.find.entries); } catch (e) { why += '; restoring also failed: ' + e.message; }
    await ctx.hist.settle(row.id, restored ? 'rolled_back' : 'failed', null, why);
    return fail('VERIFY_FAILED', 'The change was written but could not be confirmed (' + why + ').' + (restored ? ' The previous configuration was put back.' : ' The previous configuration could NOT be put back: check the group on the manager. The earlier file is kept in the history.'), { rolled_back: restored });
  });
}
module.exports = { describe, preview, apply, read, STATE_TEXT };
