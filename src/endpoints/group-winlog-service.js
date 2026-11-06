'use strict';
// Reading, previewing and changing the ASIX block for Windows events in a group's agent.conf (docs/endpoints.md, task E11). The same order of steps as group-config-service.js
// (read, check the hash the person saw, write the history row first, put, read again, compare, put the old file back if the manager holds something else); the rules for the text
// are in group-winlog.js. Everything it touches is passed in (ctx), so tests run it against the stand-in manager and a recording history.
//
// ctx = { m, w, api, hist: { record(row) -> {id}, settle(id, result, afterSha, note) } }; `policy` is a validated Windows filter policy (win-filter.js validate().policy).
const gc = require('./group-config');
const wl = require('./group-winlog');
const { withLock } = require('./group-config-service');

const fail = (code, message, extra = {}) => ({ ok: false, code, message, ...extra });
const STATE_TEXT = { none: 'ASIX has not set any Windows event channel for this group', ok: 'ASIX manages the Windows event channels below', broken: 'markers damaged', edited: 'block edited by hand' };
const BAD_GROUP = () => fail('BAD_GROUP', 'A group name is 1 to 64 letters, digits, dots, dashes or underscores');

async function read(ctx, group) {
  if (!gc.validGroup(group)) return BAD_GROUP();
  const xml = await ctx.api.groupAgentConf(ctx.m, ctx.w, group);
  return { ok: true, xml, sha256: gc.sha256(xml), find: wl.find(xml), bytes: Buffer.byteLength(xml, 'utf8') };
}

// What a group has now: the hash to send back with a change, the state of the block, its channels and how they compare with the current policy.
async function describe(ctx, group, policy) {
  const r = await read(ctx, group); if (!r.ok) return r;
  const st = wl.status(r.find, policy);
  return { ok: true, group, sha256: r.sha256, state: r.find.state, state_text: STATE_TEXT[r.find.state], channels: r.find.channels, items: r.find.items, in_step: st.in_step, rows: st.rows, bytes: r.bytes };
}

// What a change would do, without touching the manager (it reads only).
async function preview(ctx, group, policy, channels) {
  const r = await read(ctx, group); if (!r.ok) return r;
  const c = wl.compose(r.xml, policy, channels); if (!c.ok) return fail(c.code, c.message, { errors: c.errors, base_sha256: r.sha256 });
  const v = wl.validateChannels(channels);
  return { ok: true, group, base_sha256: r.sha256, changed: c.changed, channels: v.channels, pushes: wl.desired(policy, v.channels), diff: wl.diff(r.find, policy, v.channels), bytes_after: Buffer.byteLength(c.xml, 'utf8'), outside_unchanged: true };
}

// Changes the block. `baseSha` is the hash the person saw; if the file has changed since, nothing is written. action: 'apply' | 'remove' | 'undo'.
async function apply(ctx, group, policy, channels, { baseSha, action = 'apply', policyRevision = 0 } = {}) {
  if (!gc.validGroup(group)) return BAD_GROUP();
  if (typeof baseSha !== 'string' || !/^[0-9a-f]{64}$/.test(baseSha)) return fail('BASE_REQUIRED', 'base_sha256 is required: preview the change first');
  return withLock((ctx.m.tenant_id || '') + '|' + group, async () => {   // the SAME key as the folders block (E10): both write the one agent.conf of the group, so they take turns
    const r = await read(ctx, group); if (!r.ok) return r;
    if (r.sha256 !== baseSha) return fail('STALE', 'The group configuration changed since you looked at it. Preview again.', { current_sha256: r.sha256 });
    const c = wl.compose(r.xml, policy, channels); if (!c.ok) return fail(c.code, c.message, { errors: c.errors });
    const v = wl.validateChannels(channels);
    if (!c.changed) return { ok: true, changed: false, group, sha256: r.sha256, channels: r.find.channels, message: 'Nothing to change' };
    const row = await ctx.hist.record({ action, result: 'failed', channels_before: r.find.channels, channels_after: v.channels, policy_revision: policyRevision, before_sha256: r.sha256, before_content: r.xml, note: 'not finished' });
    let put;
    try { await ctx.api.putGroupAgentConf(ctx.m, ctx.w, group, c.xml); put = null; } catch (e) { put = e; }
    if (put) {
      let now = null; try { now = await ctx.api.groupAgentConf(ctx.m, ctx.w, group); } catch { /* unknown */ }
      const same = now !== null && gc.sha256(now) === r.sha256;
      await ctx.hist.settle(row.id, 'failed', now === null ? null : gc.sha256(now), put.message);
      return fail(put.code === 'REJECTED' ? 'REJECTED' : 'MANAGER', put.message, { unchanged: same ? true : now === null ? 'unknown' : false });
    }
    // Look again: the manager must hold the block as written, compared as channels and queries (a manager may reformat the file).
    let back = null, readErr = null; try { back = await ctx.api.groupAgentConf(ctx.m, ctx.w, group); } catch (e) { readErr = e; }
    const fb = back === null ? null : wl.find(back);
    const want = wl.desired(policy, v.channels).map((d) => ({ channel: d.channel, query: d.query }));
    const good = fb && fb.state === (v.channels.length ? 'ok' : 'none') && JSON.stringify(fb.items) === JSON.stringify(want);
    if (good) { await ctx.hist.settle(row.id, 'applied', gc.sha256(back), null); return { ok: true, changed: true, group, before_sha256: r.sha256, sha256: gc.sha256(back), channels: v.channels, history_id: row.id }; }
    let restored = false, why = readErr ? readErr.message : 'the manager returned a different configuration than the one written';
    try { await ctx.api.putGroupAgentConf(ctx.m, ctx.w, group, r.xml); const again = await ctx.api.groupAgentConf(ctx.m, ctx.w, group); restored = gc.sha256(again) === r.sha256 || JSON.stringify(wl.find(again).channels) === JSON.stringify(r.find.channels); } catch (e) { why += '; restoring also failed: ' + e.message; }
    await ctx.hist.settle(row.id, restored ? 'rolled_back' : 'failed', null, why);
    return fail('VERIFY_FAILED', 'The change was written but could not be confirmed (' + why + ').' + (restored ? ' The previous configuration was put back.' : ' The previous configuration could NOT be put back: check the group on the manager. The earlier file is kept in the history.'), { rolled_back: restored });
  });
}

module.exports = { describe, preview, apply, read, STATE_TEXT };
