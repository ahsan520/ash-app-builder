# Cases

Status: **built 2026-11-08 (task CS1 of `docs/product-plan.md`, "Status of Phase 5").** Cases are the first thing SOAR needs: a playbook opens, enriches and closes a case rather than touching loose alerts (`soar` now requires `cases`).

## What a case is
A case groups alerts under **one owner**, with a **status**, **notes** and a **timeline**. Deliberately small:
- **Status:** `open`, `investigating`, `closed`. Closing sets `closed_at`; reopening clears it.
- **Severity:** `critical`, `high`, `medium`, `low`. When a case is created from alerts it defaults to the worst of them (else `medium`); it can be set by hand and is not changed afterwards when alerts come and go.
- **Number:** `#1, #2, ...` per tenant, with no gaps (a refused create does not use one), handed out under a per-tenant lock so simultaneous creates never share a number.
- **An alert belongs to at most one case** (a unique key on `case_alerts.alert_id`). Adding one that is in another case is refused with 409, naming the case.
- **A closed case is read-only** except to reopen it (a reopen may carry other edits) and to add notes.
- **Timeline:** one entry for every real change (status, owner, severity, title, description), every alert added or removed, and every note, with who and when. Setting a value to what it already is writes nothing. The server sends the words of each entry, so every client shows the same text (`describeEvent` in `src/cases/model.js`).
- **Not in CS1:** deleting a case (close it), closing a case's alerts with it, merging cases, per-case access, SLAs and due dates, attachments, adding a case from the alert list (the Cases page does the adding).

## Tables (`k8s/12-schema-init.yaml`, idempotent, applied by the schema job on every deploy)
`cases` (with CHECK constraints on status and severity and a unique `(tenant_id, case_number)`), `case_alerts` (primary key `(case_id, alert_id)`, unique `alert_id`), `case_events` (the timeline; `created_at` is the statement time so entries of one request keep their order). All three have row-level security like the other tenant tables. **Deleting a case** removes its links and timeline; **deleting an alert** (for example when a content pack is removed with its alerts) drops it from its case without a timeline entry; **deleting a user** only empties the owner.

## API (permissions: the existing `alerts:read` and `alerts:write`, so no role changes)
| Route | Needs | What |
|---|---|---|
| `GET /v1/cases?status=active\|all\|open\|investigating\|closed&owner=me\|unassigned\|<id>&limit&offset` | read | List, most recently changed first; `active` (default) is open + investigating; `limit` 1-200 (default 50). Answer has `total`. |
| `GET /v1/cases/:id` | read | The case, its alerts (worst first) and its timeline (oldest first, up to 1000). |
| `GET /v1/cases/candidates` | read | Up to 50 open or acknowledged alerts that are in no case and not merged, worst first. |
| `GET /v1/alerts/:id/case` | read | The case an alert is in, or `null`. |
| `POST /v1/cases` | write | `{ title, description?, severity?, owner_id?, alert_ids? (up to 50) }`. 201 with the case. |
| `PATCH /v1/cases/:id` | write | Any of `title, description, severity, status, owner_id` (`null` = nobody). Unknown fields are refused. |
| `POST /v1/cases/:id/alerts` | write | `{ alert_ids: [1-50] }`. Alerts already in this case are skipped (`already`); an alert in another case refuses the whole request. |
| `DELETE /v1/cases/:id/alerts/:alertId` | write | Takes the alert out of the case. |
| `POST /v1/cases/:id/notes` | write | `{ body }`, 1-2000 characters. Allowed on a closed case. |

Refusals: 400 for bad input, 404 (case, alert or user not found; another tenant's data is "not found"), 409 `ALERTS_TAKEN`, 409 `CASE_CLOSED`, 403 `MODULE_DISABLED`. The routes need the `cases` module (`src/modules/manifests/cases.js`, tier home, requires `alerts`).

## The Cases page
`src/portal/modules/cases/cases.js`, declared by the manifest's `ui` block (main menu, "Cases", needs `alerts:read`): Active / Closed / All tabs, "Mine only", New case, and a case page with status buttons, an owner choice (the tenant's users, plus "Take it"), severity, edit title and description, the alerts (remove, and "Add alerts" from the free ones), the timeline and a note box. Text typed into a form or the note box is kept when the page redraws. Same rules as every module page: only `ctx.el` and `ctx.api`, no browser dialogs, server text set as text. The existing **Cases & Issues** page (the alert list) is unchanged.

## Where the code is
`src/cases/model.js` (rules, no database), `src/cases/service.js` (SQL; every query filters by tenant, because the API connects as the table owner and bypasses row-level security), `src/gateway/routes/cases.js`. `src/cases/cases-engine.js` is an older placeholder from the first design; nothing uses it.

## Tests
- `tests/cases-model.test.js` (30): the rules, and a check that the allowed values match the table's CHECK constraints.
- `tests/cases-page.test.js` (26): the page, with a fake server.
- **`tests/cases-db.test.js`: against a real PostgreSQL, skipped unless `ASIX_TEST_DB=1`**, in the same way as the other `*-db.test.js` files. It runs the real routes and SQL and covers tenant isolation, numbering (including 12 simultaneous creates and two creates racing for one alert), every refusal, the constraints and cascades, the row-level security policies with a role that does not own the tables, and which permission each route asks for.
  `ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_USER=asix_admin DB_NAME=asix_platform DB_PASSWORD=... node tests/cases-db.test.js`
  A local database for this: install PostgreSQL 16, create the role `asix_admin` and the database `asix_platform`, and apply the schema the way the deploy does (the `schema.sql` inside `k8s/12-schema-init.yaml`, twice, to see it is idempotent).
- The whole path was also run once by hand (not kept in the repo): the real `index.html` in a test DOM, calling the real routes on a real database: create a case, add an alert, add a note, change the owner, investigate, close, reopen, and check the tables.

## Honest limits
- **Not seen in a real browser:** as with the Marketplace, the browser's own `import()` of the page from the running gateway has not been seen; open Cases once after deploying.
- The first database test run found one real flaw (the timeline listed alerts in the database's order, not the order sent); it is fixed and tested.
- The page lists at most 100 cases per tab (it says "Showing x of y" beyond that); there is no paging control yet.
- The timeline shows at most 1000 entries.
