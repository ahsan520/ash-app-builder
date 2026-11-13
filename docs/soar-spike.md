# SOAR engine spike (task SR0)

**Status 2026-11-13: scenario run and PASSED on Tracecat 1.4.0, idle and one-run-a-minute footprint measured; Shuffle not tried.** Tracecat did the whole scenario on a lab VM (feed, clean-up, approval request, wait for a person, block with a secret-held login) and the stand-in's verdict was **pass**. Idle memory is **5025 MiB over 16 containers** and **5758 MiB** at one run a minute, far over the 2048 MiB budget this spike assumed for Home. So the leaning is: **Tracecat is a candidate for the engine tier (a separate VM), not for Home**. This is not final: the one-hour reading, runs that overlap, tenant isolation, the licence question and the five-minute poll limit are still open (see "Results" and "Findings"). Nothing in ASIX itself changed for this task.

## What is in the kit
| File | What |
|---|---|
| `deploy/soar-spike/stand-in.js` | One small server (no dependency, loopback only) that plays the three things the scenario talks to: an indicator feed, **ASIX's approval gate** and a firewall alias API (OPNsense style). It also judges the run: `GET /_spike/report` says `pass` or `fail` with one sentence per check. |
| `scripts/deploy/soar-spike-measure.sh` | Reads what the engine costs (memory per container or pod, restarts, disk) from Docker or k3s, judges it against the budget, prints a block of Markdown to paste below. Changes nothing. |
| `tests/soar-spike-stand-in.test.js` (11), `tests/soar-spike-measure-script.test.js` (8) | Real HTTP for the stand-in; stubs on `PATH` for docker, kubectl, free, nproc. One test found a real bug (kubectl writes `Gi`, not `GiB`). |

## The scenario (the same for every engine)
1. **Pull the feed** (`GET /feed.txt`: three public addresses, one with a note after it, and one private address `10.0.0.5`).
2. **Normalise**: drop the notes, drop the private address (a block list must never take it, `docs/lists.md`).
3. **Ask for approval** for each address (`POST /asix/approvals {address}`), **then wait** (poll `GET /asix/approvals/:id`, or a callback if the engine does it natively).
4. A person decides in the stand-in: grant one address, reject another (`POST /asix/approvals/:id/grant` or `/reject`).
5. **Block** only the granted one: `POST /api/firewall/alias_util/add/asix_block` with `{"address": "..."}` and basic auth (`spike-key` / `spike-secret`). The firewall stand-in refuses a block that has no granted approval, and the verdict records it.
6. **The credentials are a secret of the engine**, not typed into the workflow text.

`GET /_spike/report` must say **pass**: fetched, asked, every block after its grant, no block without approval, no private address sent, only approved addresses in the alias, a rejected one stays out, no wrong-credential request, at least one blocked.

Why the approval is a stand-in: in ASIX the approval gate is **ASIX's own** (`docs/actions.md`: levels, a waiting run, approve, reject, undo, audit). The engine only asks and waits. So the engine's own approval feature (Tracecat lists human-in-the-loop under its paid edition) does not matter to the choice. What the real engine will need from ASIX, and what is **not built** (it is part of SR3): a way for the engine to call `service.request(..., 'automation')` under a key of its own, scoped to one tenant. Today the HTTP API only ever acts as a person.

## Running it on the lab
Use a **separate VM** for the engine (4 vCPU / 8 GB, the Home profile), not asix1: the point is to learn whether the engine fits next to ASIX, and what it costs by itself.
1. On the engine VM, start the stand-in: `node deploy/soar-spike/stand-in.js --host 0.0.0.0 --port 8099` (lab only: it has no login on `/asix` and `/_spike`). If the engine runs on another machine, use that VM's address.
2. Install Tracecat with its own Docker Compose instructions (`docs.tracecat.com`, self-hosting, Docker Compose), **pinned to a release tag**, not `main`. Do not use its Helm chart for the spike: it is source-available (PolyForm Shield, internal use) and the docs say it is a private OCI artifact (see "Sources").
3. `./scripts/deploy/soar-spike-measure.sh --runtime docker --match tracecat --label idle --out idle.md`
4. Build the scenario as a Tracecat workflow (HTTP request, a loop, the engine's wait for an external answer, then the firewall call with the credentials in the engine's secrets). Run it. Then `curl http://<stand-in>:8099/_spike/report`. Run it again 20 times in a loop and measure with `--label busy --stand-in http://<stand-in>:8099`. Measure again after an hour with `--label settled`.
5. Answer each row of the table. If a step needed a workaround, write it down: that is the "how well it maps" answer.
6. If the budget is exceeded or the scenario cannot be done, repeat with Shuffle (same stand-in, same table) before choosing.

## What we know before running (sources, 2026-11-12; licences must be re-read on the day of use)
| | Tracecat | Shuffle | Own engine |
|---|---|---|---|
| Licence | AGPL-3.0 core; `packages/tracecat-ee` paid; Helm chart and EKS templates PolyForm Shield (internal use) | Backend AGPLv3; workflows, docs, app spec, SDK and apps MIT | ours |
| Needs | PostgreSQL, Redis, S3-compatible store (MinIO works), Temporal, nsjail sandbox. Several containers | OpenSearch (its own `.env` defaults to it), Orborus and workers that start app containers through Docker; the release notes mention Kubernetes as a scaling option | nothing new |
| Workflows as files | YAML templates (data, which suits a pack that carries data only) | JSON workflows in a GUI; apps are OpenAPI specs (MIT, importable) | our format |
| Connectors | 100+ | 200+ apps, the broader catalogue | few, by hand |
| Approval | human-in-the-loop is listed under the paid edition; not needed (ASIX gate) | has its own | ours exists (`docs/actions.md`) |
| Tenants | one deployment per tenant or one shared with ASIX's tenant check in front: **to be measured** | built with MSSPs in mind (sub-organisations): **to be measured** | ours |
| Why it matters | Postgres and Temporal are known quantities; but the free tier's feature split is disputed between sources | OpenSearch beside ClickHouse and the Wazuh indexer is a third search engine on a small box; a GitHub discussion asks about execution limits in the self-hosted edition (**unverified**) | most work, no new moving parts |

**Why Tracecat first:** its workflows are plain files (they fit the pack format, `docs/content-packs.md`), it keeps its state in PostgreSQL, and it does not need a Docker socket or a third search engine. **Against it:** Temporal and Redis and a store are several containers; its Helm chart is not for us; its integration catalogue is smaller. **Not a verdict:** every number in "Results" is still empty.

## Decision rule (outcome so far in the last paragraph)
- **Adopt Tracecat** if the scenario passes, the idle total stays within the budget (**2048 MiB, an assumption** of this spike: it is what we decided the engine may take on a Home machine that also runs ASIX; change it here first) and the busy total stays within 1.5 times it.
- **Try Shuffle** if either fails, then choose the one that passes.
- **Home without an engine** (open decision in `docs/product-plan.md`) if neither fits: a minimal runner inside ASIX for Home only; Enterprise keeps the engine.
- Either way: the engine is a **separate service**, ASIX talks to it over HTTP and keeps approval, autonomy, tenant and audit in front of every action. Any AGPL tool is used unmodified and over its API; a lawyer's read is still open.

## Results (Tracecat 1.4.0 on a lab VM, 2026-11-13; Shuffle not run)
Lab VM: Ubuntu, **ARM64** (all images have arm64 builds and pull cleanly), 8 vCPU, 9209 MiB, no swap, Docker 29.9.3, Compose 5.7.1, HTTPS at the VM's LAN address with a self-signed certificate, executor backend `direct` (no sandbox).

| Question | Tracecat | Shuffle |
|---|---|---|
| Scenario verdict (`/_spike/report`) | **pass** (2026-11-13), by hand and then 23 scheduled runs: blocked exactly the granted addresses; the rejected one stayed out; no private address, no wrong credentials | not run |
| Idle memory (MiB, highest of 3 readings, about 14 minutes after start) | **5025** over **16 containers** (largest: litellm 1272, api 637, executor 393, temporal 351, background worker 349, mcp 342); CPU idle under 6% per container | not measured |
| Busy memory, one run a minute for 20 minutes (a Tracecat schedule `*/1 * * * *`; a background script decided each approval) | **5758** MiB, 10 minutes in, 6 readings: **+733 MiB (+15%) over idle**; executor 393 to 701 MiB and a **peak of 194% CPU** (about two cores, in a burst of a few seconds per run), Temporal 351 to 517, Temporal's PostgreSQL 155 to 277, api 637 to 697; the rest within 30 MiB. Host: 5941 MiB used, 3228 MiB available of 9209. **Result over the whole window: 23 runs, 69 approvals, 46 blocks (3 and 2 per run), verdict `pass`, no failed check, no run failed, Temporal restarts unchanged at 3, no container exited** | not measured |
| After one hour | **not measured yet** (`soar-spike-measure.sh --label settled`). Right after the load stopped: 5778 MiB used against 5135 MiB used at idle, about 640 MiB still held; whether it falls back or grows is what this reading is for | not measured |
| Containers or pods | 16 running, plus 2 one-shot jobs (migrations, minio-init) | not measured |
| Starts after a reboot by itself | not tried (containers are `restart: unless-stopped`) | not tried |
| Tenant isolation (can one tenant's workflow read another's secrets or runs?) | not tried | not tried |
| Fits k3s | not tried; the vendor's Helm chart is not self-serve (see Findings) | not tried |
| Pack mapping: which parts of a workflow can be a data file | not tried: the workflow was built in the UI; export to YAML not yet looked at | not tried |
| Free edition has what ASIX needs | **partly known**: image label says AGPL-3.0; the Platform admin pages (Organizations, Tiers, Managed Workspaces) show with `TRACECAT__EE_MULTI_TENANT=false` and the Tiers page says its settings will be gated behind a licence key in a future release; the `.env` says the Enterprise flags need an Enterprise licence. Which features are free is **not established**: ask Tracecat in writing | not checked |
| Who patches it, and how often it releases | not checked (the version seen is 1.4.0; `temporalio/ui` is unpinned `latest` in the shipped compose file; `postgres:13` backs Temporal) | not checked |

## Findings (what building the scenario taught us)
- **The workflow that passed:** manual trigger, then `core.http_request` (feed), `core.script.run_python` (split lines, strip notes, drop private and duplicate addresses), `core.http_request` with **For each** (one approval request per address), `core.http_poll` with **For each** (`poll_retry_codes: [202]`, `poll_interval: 5`), `core.script.run_python` (keep the granted addresses), `core.http_request` with **For each** (the block call, `Authorization` header from a secret).
- **A script action exists and is enough for clean-up.** `core.script.run_python` ran `re` and `ipaddress`. Its inputs are a separate `inputs:` key (a mistake that put `inputs:` inside the script text caused an `IndentationError`).
- **The HTTP action can reach a private address** with no allow-list setting (a plain GET and POST to the lab LAN address worked). Tracecat's FAQ mentions an allow-list for LLM and MCP endpoints only.
- **Loop order is not stable.** Requests in a loop ran in parallel and the stand-in numbered approvals in arrival order, not feed order. Carry the address in every answer (a real ASIX approval carries its action) and never rely on position.
- **`core.http_poll` ends a poll on any status code you did not list**, so a 404 gave a green "Action completed". The step after it must check for the status it wants. Polling on a `202` while waiting and `200` once decided worked. `poll_condition` (a Python lambda over `headers`, `data`, `status_code`) exists and was not used.
- **The poll was killed at 300 seconds** ("Action execution timed out after 300s") although `timeout: 600` was set. Cause not established (an executor limit, or the field not applying). **A person who takes longer than five minutes cannot be waited for inside one poll action**, so an ASIX approval that may take hours needs a different design: ASIX calls a Tracecat webhook when a person decides, and a second workflow does the block. Not built, not tried.
- **Secrets are checked when a workflow is saved** (`Found 0 secrets matching 'firewall' in the 'default' environment`). `SECRETS.<name>.<KEY>` is the syntax.
- **HTTPS is needed for the MCP service** (it exits with `Issuer URL must be HTTPS`). With a bare IP address Caddy also needs `default_sni <ip>` or browsers and curl fail the handshake; a mounted single-file Caddyfile needs `docker compose up -d --force-recreate caddy` after `sed -i` (a new file is not seen by the running container).
- **Temporal restarted 3 times** in its first minutes and not again over about 35 minutes. No out-of-memory kills. Cause not established.
- **The Kubernetes route is gated.** The vendor's Helm chart is source-available (PolyForm Shield, internal use) and a private OCI artifact (contact their customer success to evaluate). Its defaults ask for roughly 78 GiB and 46 vCPU of requests; the nsjail sandbox needs privileged pods (`SYS_ADMIN`, unconfined seccomp); autoscaling uses KEDA on Temporal queue depth. None of this was tried.
- **A schedule works and runs the published version.** A Tracecat schedule (`*/1 * * * *`) started a run every minute; scheduled runs carry no Draft badge and manual runs from the editor do. The schedule's start and end are shown in the **browser's local time zone** while the VM and the stand-in log UTC: a first schedule set from the VM's clock ran five hours late. Check a schedule against the stand-in's request count, not the clock on screen.
- **Overlapping runs were not tested.** One run takes about 5 seconds and one starts every minute, so two never ran together. The executor's 194% CPU burst suggests several at once would be heavier; test with several runs started together before sizing for more than a trickle.
- **`core.http_paginate`** exists and the scenario did not need it. A real feed or firewall list that pages would.

## Outcome so far (2026-11-13), by the rule above
- Scenario: **passed**, by hand and 23 times on a schedule. Idle memory **5025 MiB** and busy **5758 MiB** (1.15 times idle, within the rule's 1.5 times): **both over the 2048 MiB budget**, so the budget half of the rule fails. By the rule, the next step is Shuffle, and for Home a minimal runner inside ASIX is the fallback.
- **Leaning, not a decision:** Tracecat is the candidate for the **engine tier** (its own VM of at least the vendor's Small size, 8 cores and 16 GB), and **Home gets no engine** (a minimal runner inside ASIX). Shuffle's footprint (OpenSearch, Docker-started apps) is unmeasured and is likely not lighter, but that is a guess. Run the Shuffle spike only if Tracecat's licence answer or its tenant isolation turns out wrong for ASIX.
- **Still to do before this closes:** the one-hour reading (`--label settled`), runs that overlap, tenant isolation, the written licence question to Tracecat, the five-minute poll limit (test `timeout`, then decide on the webhook design), and export the workflow to YAML for the pack mapping.

## Sources (2026-11-12)
Tracecat repository and documentation (`github.com/TracecatHQ/tracecat`, `docs.tracecat.com` self-hosting pages: licence exceptions, dependencies, Helm chart as a private OCI artifact), two third-party summaries of it (dev.co, openapps.pro: they list RBAC, version control and MCP servers as paid; the repository's older text says SSO and audit logs stay free: **the sources disagree**), Shuffle repository (`.env` with OpenSearch settings, licence note in its README, release notes) and one community discussion about self-hosted limits. The OPNsense paths in the stand-in are from our memory of its alias API and **were not checked against a real OPNsense**.

## Honest limits
- One engine was installed and run (Tracecat 1.4.0, one lab VM, ARM64, direct executor backend): only the idle footprint exists; no busy, one-hour, isolation or k3s figure yet. Shuffle was not run.
- The stand-in judges order and safety rules; it does not judge how pleasant the engine is to build with.
- The approval, the feed and the firewall are stand-ins (`deploy/soar-spike/stand-in.js`); the real call from an engine into ASIX is not built, and the OPNsense paths are from memory.
- The stand-in has two things a real ASIX approval would answer differently: the address in every answer, and a `/decision` endpoint that answers 202 while waiting.
