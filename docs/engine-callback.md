# Engine callback (SR3, first half)

Status: **built 2026-11-14, tested against a real PostgreSQL 16 and fakes, NOT yet deployed or run against the lab Tracecat.** It is the half of SR3 that lets the automation engine ask ASIX for an action, as chosen in `docs/soar-spike.md` ("Decision"): **ASIX keeps every tenant's credentials and does every privileged act itself; the workflow only asks.** What is not built: the playbooks themselves (IOC feed import, IOC hit), a page for it, and an encrypted store for the webhook addresses (see "Honest limits").

## Why this shape
The spike showed that Tracecat's `environment` override refuses expressions ("Template expressions are not allowed in `environment` overrides"), so a run cannot choose which tenant's secrets it uses: the environment is fixed in the workflow. Rather than one workflow copy per tenant per playbook, or tenants' credentials in the run's input, the workflow holds **no tenant credential** and calls back to ASIX, which already has the approval gate, the autonomy level, the tenant check and the audit (`docs/actions.md`).

## The flow
1. A person (or service account) calls `POST /v1/engine/runs` with the playbook name, the engine's webhook address, the **actions the run may ask for** and the run's input.
2. ASIX writes the run (status `starting`), makes a **one-run token**, stores only its hash, and POSTs `{ run_id, tenant_id, token, callback_base, playbook, input }` to the webhook. The engine answers; the run becomes `running`. If the engine does not take the call: 502 `ENGINE_START_FAILED`, the run is `failed` and its token is dead.
3. The workflow calls `POST <callback_base>/actions/<action id>` with `Authorization: Bearer <token>` and `{ "parameters": {...} }`. ASIX runs the request through the action registry with **origin `automation`**: not enabled means refused; level 1 means recommended; a medium-risk action (like `list.add_entry`) **waits for a person to approve**; a low-risk one at level 3 or 4 runs at once. Every request is an `action_runs` row and an audit row, as for a person.
4. The answer is the decision in one word, `outcome`: `executed`, `awaiting_approval`, `recommended`, `refused`, `failed`. **A refusal is HTTP 200**, so the workflow can see it and finish.
5. A person approves in ASIX (Settings > Automation > Actions > Runs). **ASIX does the act** with the parameters that were stored. The workflow may read how its own request ended with `GET <callback_base>/action-runs/<id>`, or ignore it.
6. The workflow calls `POST <callback_base>/finish` with `{ "status": "succeeded" | "failed", "summary": "..." }`. The token is cleared. A run whose workflow never finishes stops working at its time limit and reads as `expired`.

## What the token can and cannot do
- It belongs to **one run, one tenant and a list of allowed actions**, all chosen by ASIX when the run is started. The tenant is taken from the run, never from a request: a body that names a tenant or an origin is refused (400 `INVALID_BODY`).
- An action not in the run's list is 403 `ACTION_NOT_ALLOWED` and records nothing. At most `max_calls` recorded requests (default 20, up to 100): then 409 `CALL_LIMIT`. Bad parameters are 400 and are not counted.
- It works until `ttl_seconds` (default 900, from 30 to 86400) or `finish`, whichever comes first. Only its SHA-256 is stored. A token that is wrong, of the wrong shape, expired, finished or never existed gets the **identical** 401 (`ENGINE_AUTH_INVALID`). A token is limited to `ASIX_ENGINE_RATE_PER_MIN` (default 60) requests a minute per API replica (429).
- It can read only its own requests (`GET .../action-runs/<id>` of another run's request is 404). It cannot reach any other API route: the people's API needs a Keycloak sign-in.
- The engine never sees the stored parameters of a request, its undo, or who decided it.

## API
People (same permissions as the registry: `soar:actions:read` and `soar:actions:write`; module `actions`, locked together with it by licensing):

| Route | Needs | What |
|---|---|---|
| `POST /v1/engine/runs` | write | `{ playbook, webhook_url, allowed_actions[], input?, ttl_seconds?, max_calls? }`. 201 with the run. The token is never in an answer. 400 for a bad request or a webhook address in a blocked network (`ENGINE_URL_BLOCKED`); 502 `ENGINE_START_FAILED`; 503 `ENGINE_NOT_CONFIGURED`. |
| `GET /v1/engine/runs?limit&offset` | read | Newest first. Shows `status` (`starting`, `running`, `succeeded`, `failed`, `expired`), `calls` (each with its `action_run_id`), `call_count`, `engine_host`, `engine_ref`, `summary`. |
| `GET /v1/engine/runs/:id` | read | One run. |

Engine (a run token instead of a sign-in; `callback_base` is `<ASIX_ENGINE_CALLBACK_BASE>/v1/engine/callback`):

| Route | What |
|---|---|
| `POST /actions/:actionId` | `{ parameters? }` -> 200 `{ outcome, action_run: { id, action, status, outcome, result, error_code, error_message } }`; 401, 403, 409, 400 as above. |
| `GET /action-runs/:id` | One of this run's own requests, as above. |
| `POST /finish` | `{ status, summary? }` -> 200. The token stops working. |

## Starting a run: the webhook address
The address is the engine's only credential for starting a workflow, so it is treated as a secret: it is **never stored, logged or repeated in an error message**. Today the caller gives it in each `POST /v1/engine/runs` (a lab shortcut). An encrypted address per tenant and playbook (`src/notifications/secret-box.js` is the existing mechanism) is the next step.
Outbound rules (`src/engine/start.js`, its own switch so it does not loosen notifications): https only; loopback, link-local (cloud metadata) and reserved addresses are always refused; private networks only when `ASIX_ENGINE_ALLOW_PRIVATE=true` (then http is allowed too); checked when the run is started and again at connect time. The engine's certificate is checked; for an engine with its own certificate use `ASIX_ENGINE_CA_FILE` (a PEM file), or **lab only** `ASIX_ENGINE_TLS_INSECURE=true`.

## Configuration (`k8s/30-asix-api.yaml`)
| Variable | Default | |
|---|---|---|
| `ASIX_ENGINE_CALLBACK_BASE` | empty | The https address **the engine** uses to reach this API (the API's port, not the portal's if they differ). Empty: falls back to `ASIX_PUBLIC_URL`; neither: starting a run is 503. |
| `ASIX_ENGINE_ALLOW_PRIVATE` | `false` | `true` for an engine on a private network (the lab). |
| `ASIX_ENGINE_TLS_INSECURE` | `false` | Lab only. |
| `ASIX_ENGINE_CA_FILE` | unset | PEM file the engine's certificate is checked against. Not in the manifest: mount the file and add the variable. |
| `ASIX_ENGINE_RATE_PER_MIN` | `60` | Per token, per API replica. |

## Table
`engine_runs` (`k8s/12-schema-init.yaml`, idempotent, row-level security like the other tenant tables): `token_hash` (cleared at the end), `allowed_actions`, `input`, `max_calls`, `call_count`, `calls`, `engine_host` (the host name only), `engine_ref`, `summary`, `error_message`, `expires_at`. Audit actions: `soar:engine:start`, `soar:engine:callback`, `soar:engine:finish` (resource names the playbook or action and the run ids, never a parameter value or the token).

## Trying it on the lab (not done yet)
1. Put the files in the repo and `./sync-and-deploy.sh` (the schema job creates `engine_runs`). Before that, in `k8s/30-asix-api.yaml` set `ASIX_ENGINE_CALLBACK_BASE` to the https address of the API **as the Tracecat VM reaches it**, `ASIX_ENGINE_ALLOW_PRIVATE` to `"true"` and, for Tracecat's self-signed certificate, `ASIX_ENGINE_TLS_INSECURE` to `"true"`.
2. In ASIX: Settings > Automation > Actions: enable **Add an entry to a list** (level 2). Create a block list on the Lists page and copy its id.
3. In Tracecat: import `deploy/soar-spike/callback-request.tracecat.yaml`, save, publish, switch the Trigger's Webhook on, copy the address. If the editor does not accept `verify_ssl`, see the comments at the top of the file.
4. Start a run (`$TOKEN` is a sign-in token of a user with `soar:actions:write`; the address goes in a variable so it stays out of the history):
   `curl -k -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$API/v1/engine/runs" -d "{\"playbook\":\"callback-request\",\"webhook_url\":\"$ENGINE_HOOK\",\"allowed_actions\":[\"list.add_entry\"],\"input\":{\"list_id\":\"<list id>\",\"value\":\"203.0.113.50\",\"note\":\"engine test\"}}"`
5. Expect: 201; in Tracecat a completed run with two green actions; `GET /v1/engine/runs/<id>` shows `succeeded`, one call, and a summary ending in `awaiting_approval`; in Actions > Runs a **waiting** `list.add_entry` requested by "service account". The list is still empty. Approve it: the entry appears on the list and in its feed. Reject another one and nothing is added.
6. Try the refusals: start a run whose `allowed_actions` omits `list.add_entry` and see the workflow fail with 403; switch the action off and see `outcome: refused` and the workflow still finish.

## Tests
- `tests/engine-model.test.js` (8): the token, what a start request may say, what the engine may send, the callback address, what is handed to the engine.
- `tests/engine-start.test.js` (11): where ASIX may call (public https yes; http, private, loopback, metadata, credentials in the address no; the private switch; the notification switch does not open it; DNS rebinding) and the call itself against a local server.
- **`tests/engine-db.test.js`: against a real PostgreSQL, skipped unless `ASIX_TEST_DB=1`** (same way as `tests/actions-db.test.js`): start (nothing secret stored or shown), the registry's decision for each outcome, approval then execution, what the run may not do, the identical 401, tenant isolation, the call limit, finish, expiry, a failed start, bad start requests, paging, and the rate limit.
  `ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_USER=asix_admin DB_NAME=asix_platform DB_PASSWORD=... node tests/engine-db.test.js`
- `tests/licensing.test.js` also checks that the engine routes belong to the `actions` module.

## Honest limits
- **Not run against Tracecat or on the lab cluster.** The DB test used PostgreSQL 16 with the schema from `k8s/12-schema-init.yaml`; the outbound call was tested against a local fake and a stub in the DB test. Whether Tracecat accepts the workflow file, `verify_ssl`, and the `Bearer ${{ TRIGGER.token }}` header is unverified.
- The webhook address is passed per request, not stored; there is no page for engine runs; no playbook (IOC hit, IOC feed import) is built on it yet; no firewall action exists (SR4), so the only blocking action is `list.add_entry`, which a firewall picks up by polling the list.
- The token is in the run's input in Tracecat's run history. It stops at `finish` or its time limit, works for one run and the allowed actions only, and a person who can read Tracecat's history is an ASIX operator by the design.
- There is no callback from ASIX to the engine when a person decides; the workflow can poll `action-runs/<id>` for short waits. A long wait would need a second workflow that ASIX starts on the decision: not built.
- `expired` is worked out when a run is read, not stored; an unfinished run keeps `running` in the table until it is read or never changes.
- The rate limit is per API replica and in memory, like the list feed.
