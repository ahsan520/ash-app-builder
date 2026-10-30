'use strict';
// Backup schedule rules (pure: no database, no clock of its own). Used by the portal route, the Data safety report and the runner (src/backup/runner.js).
// A schedule is: on/off, a time of day in UTC, and the weekdays it runs on (0 = Sunday ... 6 = Saturday, like Date#getUTCDay).

const DEFAULTS = { enabled: true, time_utc: '02:17', days: [0, 1, 2, 3, 4, 5, 6], retain_days: 2 };
const TIME_RE = /^([01]\d|2[0-3]):([0-5]\d)$/;
const DAY_MS = 86400000;
const RETAIN_MIN = 1, RETAIN_MAX = 365;

// Checks a settings change. Only the fields that are present are checked; returns { value } (the cleaned fields) or { error }.
function check(body) {
  const b = body || {}, v = {};
  if (b.enabled !== undefined) { if (typeof b.enabled !== 'boolean') return { error: 'enabled must be true or false' }; v.enabled = b.enabled; }
  if (b.time_utc !== undefined) { if (typeof b.time_utc !== 'string' || !TIME_RE.test(b.time_utc)) return { error: 'time_utc must look like 02:17 (24-hour, UTC)' }; v.time_utc = b.time_utc; }
  if (b.days !== undefined) {
    if (!Array.isArray(b.days) || b.days.length === 0 || b.days.length > 7 || !b.days.every((d) => Number.isInteger(d) && d >= 0 && d <= 6)) return { error: 'days must be a list of weekday numbers from 0 (Sunday) to 6 (Saturday), at least one' };
    v.days = [...new Set(b.days)].sort((a, c) => a - c);
  }
  if (b.retain_days !== undefined) {
    if (!Number.isInteger(b.retain_days) || b.retain_days < RETAIN_MIN || b.retain_days > RETAIN_MAX) return { error: `retain_days must be a whole number from ${RETAIN_MIN} to ${RETAIN_MAX}` };
    v.retain_days = b.retain_days;
  }
  return { value: v };
}

const slotOn = (dayStart, time) => { const [h, m] = time.split(':').map(Number); return dayStart + (h * 60 + m) * 60000; };
const utcMidnight = (t) => { const d = new Date(t); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()); };

// The most recent scheduled moment at or before `now` (ms), or null when the schedule has no days.
function lastSlot(s, now) {
  const days = (s.days || []).filter((d) => d >= 0 && d <= 6); if (!days.length) return null;
  for (let back = 0; back <= 7; back += 1) {
    const day = utcMidnight(now) - back * DAY_MS, slot = slotOn(day, s.time_utc);
    if (slot <= now && days.includes(new Date(day).getUTCDay())) return slot;
  }
  return null;
}
// The next scheduled moment after `now` (ms), or null.
function nextSlot(s, now) {
  const days = (s.days || []).filter((d) => d >= 0 && d <= 6); if (!days.length) return null;
  for (let ahead = 0; ahead <= 8; ahead += 1) {
    const day = utcMidnight(now) + ahead * DAY_MS, slot = slotOn(day, s.time_utc);
    if (slot > now && days.includes(new Date(day).getUTCDay())) return slot;
  }
  return null;
}

// Is a scheduled run owed? Yes when the latest slot has not been run yet (`lastScheduledAt`, ms or null = never) - including a slot missed while the VM was off,
// which then runs once as soon as the runner is back. Saving new settings sets lastScheduledAt to "now", so a slot earlier today does not fire at once.
function due(s, lastScheduledAt, now) {
  if (!s.enabled) return false;
  const slot = lastSlot(s, now);
  return slot !== null && (lastScheduledAt == null || lastScheduledAt < slot);
}

// The longest gap between two runs, in days (a schedule that runs on Mon and Fri has gaps of 4 and 3 days). Used so the "backup is old" findings do not fire
// on a schedule that is meant to be slow.
function longestGapDays(days) {
  const d = [...new Set(days || [])].sort((a, b) => a - b); if (!d.length) return null;
  if (d.length === 1) return 7;
  let gap = d[0] + 7 - d[d.length - 1];
  for (let i = 1; i < d.length; i += 1) gap = Math.max(gap, d[i] - d[i - 1]);
  return gap;
}

module.exports = { DEFAULTS, TIME_RE, RETAIN_MIN, RETAIN_MAX, check, lastSlot, nextSlot, due, longestGapDays };
