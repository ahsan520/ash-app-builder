# Working on this repo from multiple Claude sessions

This project has repeatedly hit the same failure mode: two sessions (or a session and a
teammate) editing `src/gateway/index.js` or `src/portal/index.html` at the same time, each
unaware of the other's changes. One side's work gets silently discarded when the other's zip
is uploaded. The fix is structural, not just "be careful."

## Backend: already split (as of this doc)
`src/gateway/index.js` is now a 60-line file that only sets up Express and mounts routers. All
route handlers live in `src/gateway/routes/<domain>.js`, one file per feature area:
`core`, `detections`, `search`, `alerts`, `threat-intel`, `collectors`, `notifications`,
`storage`, `capacity`, `parsing`, `data-model`. Shared helpers (`db`, the auth middleware chain,
`guarded()`, `apiError()`, `UUID_RE`, `SEVERITIES`, `ALERT_STATUSES`) live in `src/gateway/shared.js`
and are imported, never redefined, by each route file.

**Rule going forward:** a new feature's routes go in a NEW file under `src/gateway/routes/`, not
appended to an existing one unless they genuinely belong to that domain. Two sessions building
unrelated features then touch different files and cannot collide.

## Frontend: still one file, by necessity
`src/portal/index.html` has no build step — it is shipped and parsed as a single HTML+JS document,
so it cannot be split into real ES modules without introducing a bundler (a bigger change than
this pass covers). Collision risk here is reduced instead by convention:
- Every page is one `async function pgXxx()` with a unique name, plus whatever page-local
  `let`/`const` state it owns, grouped under a `// ---- <Feature name> ----` banner comment.
- When adding a page, **append a new banner + function** at the end of the relevant group rather
  than editing an existing one in place, and add exactly one line to `NAV` or `SETTINGS` to wire
  it in.
- Before editing, diff the live file against the last zip you were handed (or ask for the
  current one) so you know your starting point actually matches what you're about to change.

## Checklist for any session picking up a task here
1. Confirm which zip/version you're starting from; diff it against what's currently described as
   "latest" before writing anything.
2. State which task (see the task table) you're doing, in your first message, so a human
   coordinating multiple sessions can avoid double-booking a file.
3. Prefer new files over edits to shared files (`shared.js`, `index.html`, `index.js`,
   `12-schema-init.yaml`) wherever the feature allows it.
4. Run the existing test suites (`/mnt/user-data/outputs/*-test.js` from prior turns, or the
   in-repo equivalents once added — see Phase 1, CI) before declaring a feature done.
