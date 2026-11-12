# SOAR engine spike (task SR0)

**Status 2026-11-12: kit built, engine NOT yet run.** Decision so far: **Tracecat is the engine to try first** (a provisional choice from reading, not from running anything). The spike is finished only when the table in "Results" is filled in on the lab and the decision below is confirmed or reversed. Nothing in ASIX itself changed for this task.

## What is in the kit
| File | What |
|---|---|
| `deploy/soar-spike/stand-in.js` | One small server (no dependency, loopback only) that plays the three things the scenario talks to: an indicator feed, **ASIX's approval gate** and a firewall alias API (OPNsense style). It also judges the run: `GET /_spike/report` says `pass` or `fail` with one sentence per check. |
| `scripts/deploy/soar-spike-measure.sh` | Reads what the engine costs (memory per container or pod, restarts, disk) from Docker or k3s, judges it against the budget, prints a block of Markdown to paste below. Changes nothing. |
| `tests/soar-spike-stand-in.test.js` (9), `tests/soar-spike-measure-script.test.js` (8) | Real HTTP for the stand-in; stubs on `PATH` for docker, kubectl, free, nproc. One test found a real bug (kubectl writes `Gi`, not `GiB`). |

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

## Decision rule
- **Adopt Tracecat** if the scenario passes, the idle total stays within the budget (**2048 MiB, an assumption** of this spike: it is what we decided the engine may take on a Home machine that also runs ASIX; change it here first) and the busy total stays within 1.5 times it.
- **Try Shuffle** if either fails, then choose the one that passes.
- **Home without an engine** (open decision in `docs/product-plan.md`) if neither fits: a minimal runner inside ASIX for Home only; Enterprise keeps the engine.
- Either way: the engine is a **separate service**, ASIX talks to it over HTTP and keeps approval, autonomy, tenant and audit in front of every action. Any AGPL tool is used unmodified and over its API; a lawyer's read is still open.

## Results (fill in; paste the measure script's blocks)
| Question | Tracecat | Shuffle |
|---|---|---|
| Scenario verdict (`/_spike/report`) | not run | not run |
| Idle memory (MiB, highest) | not measured | not measured |
| Busy memory, 20 runs in a loop | not measured | not measured |
| After one hour | not measured | not measured |
| Containers or pods | not measured | not measured |
| Starts after a reboot by itself | not tried | not tried |
| Tenant isolation (can one tenant's workflow read another's secrets or runs?) | not tried | not tried |
| Fits k3s (if a later step needs it) | not tried | not tried |
| Pack mapping: which parts of a workflow can be a data file | not tried | not tried |
| Free edition has what ASIX needs (SSO not needed; audit export; secrets) | not checked | not checked |
| Who patches it, and how often it releases | not checked | not checked |

## Sources (2026-11-12)
Tracecat repository and documentation (`github.com/TracecatHQ/tracecat`, `docs.tracecat.com` self-hosting pages: licence exceptions, dependencies, Helm chart as a private OCI artifact), two third-party summaries of it (dev.co, openapps.pro: they list RBAC, version control and MCP servers as paid; the repository's older text says SSO and audit logs stay free: **the sources disagree**), Shuffle repository (`.env` with OpenSearch settings, licence note in its README, release notes) and one community discussion about self-hosted limits. The OPNsense paths in the stand-in are from our memory of its alias API and **were not checked against a real OPNsense**.

## Honest limits
- Nothing was installed or run when this was written: no footprint, isolation or k3s figure exists yet.
- The stand-in judges order and safety rules; it does not judge how pleasant the engine is to build with.
- The approval is a stand-in; the real call from an engine into ASIX is not built.
