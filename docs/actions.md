# Action registry

Status: **core built 2026-11-10 (task SR2 of `docs/product-plan.md`, "Status of Phase 5").** It is the allow-list of everything ASIX may do on its own or on request: firewall and endpoint actions will be added to it, and a playbook (SR3) may only call an action that is in it, enabled for the tenant.

## Why the core does not wait for SR1
The task table said SR2 needs SR1 (credentials and integrations). The registry itself does not: actions are defined in code, switched on per tenant, gated by an autonomy level and audited. **Integration-backed actions plug in later** with `register()` (`src/actions/catalog.js`) once SR1 exists. What SR2 ships today are real built-in actions on **cases** (the thing ASIX can change without an account elsewhere).

## What an action is
Defined in code (`src/actions/catalog.js`), never created by a tenant: `id` (`case.add_note`), `name`, `description`, `publisher`, `kind` (`builtin`; `integration` and `endpoint` come with SR1 and SR5), `source`, `parameters` (typed: `uuid`, `uuid_list`, `string`, `enum`), **risk class** (`low`, `medium`, `high`), `reversible` / `append_only`, `max_autonomy`, `default_autonomy`, and `execute()`. `register()` refuses a malformed definition when ASIX starts, not at a request.

Rules the definition check enforces (`checkDefinition`): a high-risk action never goes above level 2; a medium one never above 3; an action that is neither reversible nor append-only never above level 2, and cannot be "low" risk. A parameter is never a secret (it is stored with the run); credentials will be passed by reference to an integration instance (SR1).

### The built-in actions (seven on cases; two on lists, `docs/lists.md`)
| Action | Risk | What |
|---|---|---|
| `case.create` | low (adds) | Open a case, optionally with alerts. |
| `case.add_note` | low (adds) | Note on the timeline, also on a closed case. Cannot be removed. |
| `case.set_severity` | low, undo | Change severity; undo puts the old one back. |
| `case.set_owner` | low, undo | Owner or nobody (`null`); undo puts the old owner back. |
| `case.set_status` | **medium**, undo | Open, investigate, close, reopen. Closing takes a case out of the active lists, so it cannot run by itself above level 3. |
| `case.add_alerts` | low, undo | Attach alerts; undo takes out only the ones that were added. |
| `case.remove_alerts` | low, undo | Take alerts out, all or none; undo adds them back. |
| `list.add_entry` | **medium**, undo | Put one value on a list (30 days unless told otherwise); the list's own rules apply (too wide, private, on an allow list). Undo takes it off. |
| `list.remove_entry` | **medium**, undo | Take one value off a list; undo puts it back with its note and exact expiry. |

They call the CS1 service (`src/cases/service.js`), so every rule of cases (a closed case is read-only, an alert is in one case only, tenant checks) still applies and the case timeline shows the change.

## Per tenant: installed means off
A tenant has a row in `action_settings` only after an administrator touched it. **No row means disabled.** The setting is `enabled` and `autonomy` (0 to 4, the levels of `docs/automation.md`), never above the action's own ceiling. Enabling without a level uses the action's default (2).

## The decision (`decide` in `src/actions/model.js`)
| | Level 0 | Level 1 | Level 2 | Level 3 | Level 4 |
|---|---|---|---|---|---|
| **A person** pressing Run | refused (`OBSERVE_ONLY`) | recorded as a recommendation, nothing done | runs now | runs now | runs now |
| **Automation** (a playbook, SR3) | refused | recommendation | **waits for approval** | runs if low-risk, else waits | runs (approved class) |

Not enabled: refused (`ACTION_DISABLED`) for everybody. A person pressing Run *is* the decision, so it is recorded as decided by them. Automation is never a caller of the HTTP API: the routes always use origin `user`, and a body that names an origin is refused. SR3 will call `service.request(..., 'automation')` itself.

**Approval:** a waiting run is approved (`POST /v1/actions/runs/:id/approve`, then it runs with the parameters that were stored, so what was approved is what runs) or rejected. The action must still be enabled: switching it off stops what was already waiting (that approval is recorded as refused). A **high-risk** run cannot be approved by the person who requested it. Two people approving at once: one runs it, the other gets 409 (`FOR UPDATE` on the run).

**Undo:** a run that changed something carries an `undo` ({ action, params }). `POST /v1/actions/runs/:id/undo` runs it as a second run (origin `undo`, linked both ways). Allowed after the action was switched off, because it only reverses something that was allowed; still recorded and audited. A run can be undone once; an undo cannot be undone; setting a value to what it already was has nothing to undo.

**Failure:** the action runs inside a savepoint. A refusal or an error rolls back whatever it changed (`remove_alerts` with one alert not attached puts back the ones it took out), the run is recorded as `failed`, and a database error is never shown in the database's words.

## Audit: every run
`action_runs` has one row per request: who asked, the decision, the parameters, the outcome, the undo, who decided. A **refused** request is a row too (status `refused`). Parameters that do not fit the definition are a 400 and record nothing, because nothing was asked. `audit_events` gets one row per request in the same transaction (`soar:action:run`, resource `<action> run=<id>`, never a parameter value; a run that waited has a second row when it executes), and rows for `soar:action:enable`, `disable`, `autonomy`, `approve`, `reject`.

## Tables (`k8s/12-schema-init.yaml`, idempotent, applied by the schema job on every deploy)
`action_settings` (primary key `(tenant_id, action_id)`, level CHECK 0 to 4) and `action_runs` (CHECKs on origin, status, risk and level; self-references for undo). Both have row-level security like the other tenant tables.

## API (two new permissions)
`soar:actions:read` and `soar:actions:write` are **new**; `scripts/deploy/bootstrap-portal.sh` gives both to `portal-admin` (re-run it to update the role). They are in the manifest `actions` (tier home, requires `cases`).

| Route | Needs | What |
|---|---|---|
| `GET /v1/actions` | read | Every action with this tenant's setting, run count and last run; `levels` (the words). |
| `GET /v1/actions/:id` | read | One action. |
| `GET /v1/actions/runs?status&action&limit&offset` | read | Runs, newest first (`limit` 1-200, default 50). |
| `GET /v1/actions/runs/:id` | read | One run. |
| `PUT /v1/actions/:id/setting` | write | `{ enabled?, autonomy? }`; 400 `AUTONOMY_TOO_HIGH` above the ceiling. |
| `POST /v1/actions/:id/run` | write | `{ parameters? }`. 201 with the run (succeeded, failed, recommended, awaiting approval); 409 with the run when refused. |
| `POST /v1/actions/runs/:id/approve` / `reject` / `undo` | write | As above. 409: `NOT_WAITING`, `SELF_APPROVAL`, `NOT_UNDOABLE`, `ALREADY_UNDONE`. |

## The Actions page
`src/portal/modules/actions/actions.js`, declared by the manifest `ui` block (Settings menu, group Automation, "Actions", needs `soar:actions:read`). **Actions** tab: each action with risk, kind, Enabled/Off and level; Enable/Disable, level choice (up to the ceiling), Details (publisher, source, undo, parameters), and **Run…** with one field per parameter. **Runs** tab: status filter, every run with its words, and Approve and run / Reject / Undo where they apply. Same rules as every module page (`docs/portal-shell.md`).

## Tests
- `tests/actions-model.test.js` (54): the definition check, parameters, settings, the whole decision table, the catalog, the module and its permissions, and that the allowed values match the table constraints.
- `tests/actions-page.test.js` (30): the page, with a fake server.
- **`tests/actions-db.test.js`: against a real PostgreSQL, skipped unless `ASIX_TEST_DB=1`** (same way as `tests/cases-db.test.js`): disabled and refused runs, every level, approval, rejection, undo (and double undo), rollback, a thrown error, a high-risk action through `register()`, two simultaneous approvals and undos, tenant isolation, row-level security with a non-owner role, the constraints, the permission of each route, one audit row per run, module off (403).
  `ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_USER=asix_admin DB_NAME=asix_platform DB_PASSWORD=... node tests/actions-db.test.js`

## Honest limits
- **Not seen in a real browser:** as with Cases and the Marketplace, open Settings > Automation > Actions once after deploying.
- Only case actions exist. **Firewall, endpoint and integration actions are not built** (SR4, SR5, SR1); nothing here can touch a machine or another product.
- **No playbook calls the registry yet** (SR3): `origin: automation` is tested through the service, not through a running playbook.
- Approval is "somebody with `soar:actions:write`"; there is no approver group, expiry of waiting runs or notification yet.
- Undo is one step per run; there is no undo timer (that belongs to SR4/SR5).
- The registry list shows `runs` and `last_run_at` per action but the Runs tab lists at most 100 per filter (it says "Showing x of y").
