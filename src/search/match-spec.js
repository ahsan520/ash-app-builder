'use strict';
// The rule-match spec: what a detection rule asks of the event store ("which groups of events inside this time
// frame match this filter, and how many in each?"). Like a query plan it holds no SQL: the filter is the plan's
// expression tree (src/search/xql-plan.js) and every engine translates or evaluates it.
//
// spec = {
//   after,       // ISO-8601 UTC; only events with event time (else received time) STRICTLY after it
//   filter,      // plan expression or null (an event must make it true); fields may be "@path" (see xql-plan.js)
//   group,       // { by:'none' }                      one group, key 'all'
//                // { by:'field',   field }            the text of a field; a missing value is the group 'unknown'
//                // { by:'capture', pattern }          the first (capture) group of an unanchored, case-sensitive
//                //                                    match of pattern on raw; no match (or an empty capture) = 'unknown'
//   threshold,   // keep groups with at least this many events (1..100000, default 1)
//   limit,       // at most this many groups, biggest first (1..1000, default 1000)
// }
// Result rows: { key, n, first_at, last_at, sample_ids (up to 5, newest first), sample_raw (raw of the newest) }.
// first_at / last_at are the earliest / latest event time of the group as ISO strings; groups are ordered by n
// descending, then key ascending.

const { validatePlan, PlanError, PARSED_PATH_RE, IDENT_RE } = require('./xql-plan');

const MAX_GROUPS = 1000;
const MAX_THRESHOLD = 100000;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

// Returns a normalised copy of the spec; throws PlanError (message for the caller) when it is not valid.
function validateMatchSpec(spec) {
  const bad = (m) => { throw new PlanError(m); };
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) bad('match spec must be an object');
  if (typeof spec.after !== 'string' || !TIME_RE.test(spec.after)) bad('after must be an ISO-8601 UTC time');
  if (spec.filter !== null && spec.filter !== undefined) {
    // reuse the plan validator for the expression: same limits, same field rules, same regex safety
    validatePlan({ v: 1, from: null, to: null, mode: 'raw', limit: 1, columns: null, stages: [{ op: 'filter', expr: spec.filter }] });
  }
  const g = spec.group === undefined ? { by: 'none' } : spec.group;
  if (!g || typeof g !== 'object') bad('group must be an object');
  if (g.by === 'field') {
    if (typeof g.field !== 'string' || !(IDENT_RE.test(g.field) || PARSED_PATH_RE.test(g.field))) bad('group.field is not a valid name');
  } else if (g.by === 'capture') {
    if (typeof g.pattern !== 'string' || !g.pattern || g.pattern.length > 500 || g.pattern.includes('\0')) bad('group.pattern must be text of 1 to 500 characters');
    try { require('../security/regex-safety').assertSafeRegex(g.pattern, { mode: 'pg' }); } catch (e) { bad(e.message); }
  } else if (g.by !== 'none') bad("group.by must be 'none', 'field' or 'capture'");
  const threshold = spec.threshold === undefined ? 1 : spec.threshold;
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > MAX_THRESHOLD) bad(`threshold must be a whole number from 1 to ${MAX_THRESHOLD}`);
  const limit = spec.limit === undefined ? MAX_GROUPS : spec.limit;
  if (!Number.isInteger(limit) || limit < 1) bad('limit must be a whole number of at least 1');
  return { after: spec.after, filter: spec.filter || null, group: g, threshold, limit: Math.min(limit, MAX_GROUPS) };
}

module.exports = { validateMatchSpec, MAX_GROUPS, MAX_THRESHOLD };
