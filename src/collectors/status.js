'use strict';
// When does a collector count as Connected? One rule, in one place, used by GET /v1/collectors.
// A collector is Connected if it was last seen within its threshold. The threshold is the default
// below unless the collector has its own (collectors.connected_within_min, NULL = use the default).
// A slow sender (a nightly job, a quiet broker) can be given a longer one; a chatty one a shorter one.

const DEFAULT_MINUTES = 15;
const MIN_MINUTES = 1;
const MAX_MINUTES = 7 * 24 * 60;   // one week

// `timestamp` columns arrive as Date objects (or strings); NaN on anything unreadable, which compares false.
const tsMs = (v) => {
  if (v instanceof Date) return v.getTime();
  if (v === null || v === undefined) return NaN;
  const s = String(v);
  return new Date(/Z$|[+-]\d\d:?\d\d$/.test(s) ? s : s + 'Z').getTime();
};

// Request value -> { value } (a whole number of minutes, or null to go back to the default) or { error }.
function checkMinutes(v) {
  if (v === null || v === undefined) return { value: null };
  if (typeof v !== 'number' || !Number.isInteger(v) || v < MIN_MINUTES || v > MAX_MINUTES) {
    return { error: `minutes must be a whole number from ${MIN_MINUTES} to ${MAX_MINUTES}, or null for the default (${DEFAULT_MINUTES})` };
  }
  return { value: v };
}

// Stored value -> minutes in force. Anything unusable (NULL, out of range) means the default.
function effectiveMinutes(stored) {
  const n = stored === null || stored === undefined ? NaN : Number(stored);
  return Number.isInteger(n) && n >= MIN_MINUTES && n <= MAX_MINUTES ? n : DEFAULT_MINUTES;
}

const isCustom = (stored) => stored !== null && stored !== undefined && effectiveMinutes(stored) === Number(stored);

function statusOf(lastSeen, minutes, now = Date.now()) {
  return tsMs(lastSeen) >= now - effectiveMinutes(minutes) * 60000 ? 'connected' : 'disconnected';
}

module.exports = { DEFAULT_MINUTES, MIN_MINUTES, MAX_MINUTES, tsMs, checkMinutes, effectiveMinutes, isCustom, statusOf };
