# IOC feeds: scheduled import of an indicator feed

**Built 2026-11-12.** A feed brings indicators (addresses, domain names, URLs, file hashes, e-mail addresses) into the IOC store (`threat_indicators`) on a schedule, so the IOC matcher can alert on them. It is the "IOC feed import" first playbook of the SR3 task (`docs/product-plan.md`), built as **an ASIX job rather than a playbook**, because SR3 waits for the engine decision (SR0) and this part needs no engine. When SR3 exists, a playbook calls `runFeed` (`src/feeds/service.js`) or an action wrapping it; nothing here has to be redone.

**Not deployed or tried on the k3s box yet, and no real feed has been fetched.** Checked here against a real PostgreSQL 16 and real local HTTP servers.

## How it fits

A feed uses a **Threat feed (HTTP)** integration (`docs/integrations.md`): its address (`feed_url`), format (`plain-text`, `csv`, `json`) and optional token (a bearer token, kept as a write-only credential). The feed adds the schedule and the rules for what is imported. Page: Threat Management, group **Feeds**, "IOC feeds". Module `ioc-feeds` (requires `threat-intel` and `integrations`; in the residential bundle).

| Setting | Choices |
| --- | --- |
| Severity | low, medium, high, critical: given to every indicator of the feed |
| Keep for (days) | 1 to 365: an indicator expires this long after it was last listed |
| Import | every 1, 6, 12 or 24 hours (a run by hand also restarts the clock) |
| Switched off | keeps everything, runs nothing |

A tenant can have 20 feeds. Several feeds may share one integration.

## What a run does, in order

1. **One run per feed at a time.** `running_since` is a lease taken in the database (works across API replicas); a lease older than 15 minutes is taken over. Another run answers `BUSY` (409).
2. **Gets the account** through `useCredentials` (`docs/integrations.md`), which refuses a disabled or not configured integration and writes an audit row with the purpose `ioc.feed:<feed name>`.
3. **Fetches** (`src/feeds/fetcher.js`) and **reads** (`src/feeds/parser.js`) with no database transaction open.
4. **Refuses what looks broken** and changes nothing: no valid indicator at all (`NO_VALID_INDICATORS`, even when forced); a feed that now lists under a fifth of what it listed last time, when that was 20 or more (`FEED_SHRANK`, unless a person runs it with force). A broken feed (an error page, an empty file) must not wipe the store.
5. **Writes** each indicator with source `feed:<feed id>`, the feed's severity and an expiry of now plus the feed's days. Rules that protect people's work:
   - an indicator that already exists from **another source** (typed by a person, or from another feed) is **never touched** (counted as "owned by another source");
   - an indicator a person **switched off stays switched off** (`enabled` is never written on update);
   - an indicator the feed lists again after it expired is active again.
6. **Expires** the feed's indicators that the feed no longer lists (`expires_at` = now; the matcher ignores expired indicators). **Nothing is deleted.**
7. **Records** the run: items, added, refreshed, expired, not recognised, owned by another source, or the error code and a message safe to show. The last 100 runs per feed are kept. One audit row per run (counts, never values).

Runs that never finished (the API restarted) are closed as `INTERRUPTED` by the next schedule tick.

## Reading a feed

An indicator is accepted only when the existing classifier (`src/threat-intel/indicators.js`) recognises it, written in its normal form (lower case; `hxxp://evil[.]com` becomes `http://evil.com`). Everything else is counted as "not recognised" and never stored. Duplicates are removed.

- `plain-text`: one per line; blank lines and lines starting `#`, `;` or `//` are skipped; a note after the value (`1.2.3.4 ; SBL123`, `evil.com # seen`) is dropped.
- `csv`: the first cell of each line that is an indicator (commas, semicolons or tabs; quotes allowed); a first line with none is the header.
- `json`: an array, or an object holding one of `indicators`, `iocs`, `data`, `items`, `results`, `values`, `observables`; each element a string or an object with one of `value`, `indicator`, `ioc`, `observable`, `ip`, `ip_address`, `domain`, `hostname`, `url`, `hash`, `sha256`, `sha1`, `md5`, `email`.
- More than **50,000** indicators (or 400,000 lines): the run fails (`TOO_MANY_ITEMS`) rather than importing a cut list, which would expire the wrong things.
- Networks (`8.8.8.0/24`) are not accepted: the IOC store holds single addresses.

## The fetcher: why it is strict

The address comes from a tenant, so this is where a server-side request forgery would happen. Rules (all tested with real servers):

- `http` and `https` only; no user name or password in the address.
- The name is resolved by ASIX and the **connection goes to the address that was checked** (no second lookup, so DNS rebinding does not work); a name with **any** internal answer is refused.
- Refused: loopback, private (10/8, 172.16/12, 192.168/16), link-local (169.254/16, which includes the cloud metadata address), shared (100.64/10), multicast, reserved, and the IPv6 equivalents (an IPv4 address written as IPv6 is judged as IPv4). This holds for the first request **and every redirect**.
- At most 3 redirects. **The token is never sent to another host** than the one asked for.
- 20 seconds for the whole request, 5 MB for the body (a declared size over it is refused without reading; an endless body is cut).
- **Errors never contain the query string**: a feed address can carry a key in it (`?apikey=…`), and run messages, logs and the audit trail name only the host and path. Put keys in the token, not in the address: the address is a setting, shown on the Integrations page.
- `ASIX_FEED_ALLOW_PRIVATE=1` lets feeds reach internal addresses (a feed server inside the network). **Off by default**; it is a deployment decision, not a tenant setting.

## API (new permissions `threatintel:feeds:read`, `threatintel:feeds:write`)

`bootstrap-portal.sh` gives both to `portal-admin`. Behind the module (`403 MODULE_DISABLED`) and the licensing gate (`/v1/ioc-feeds`).

| Route | Permission | What |
| --- | --- | --- |
| `GET /v1/ioc-feeds` | read | feeds with their last run, the Threat feed integrations a feed can use, the choices |
| `POST /v1/ioc-feeds` | write | `{ integration_id, name, severity?, ttl_days?, interval_hours? }` (defaults: medium, 30, 24) |
| `GET /v1/ioc-feeds/:id` | read | the feed and its last 20 runs |
| `PUT /v1/ioc-feeds/:id` | write | `{ name?, severity?, ttl_days?, interval_hours?, enabled? }`; the integration never changes |
| `DELETE /v1/ioc-feeds/:id` | write | the indicators stay and expire on their own; `?remove_indicators=true` also deletes them |
| `GET /v1/ioc-feeds/:id/runs` | read | `limit` 1 to 100 |
| `POST /v1/ioc-feeds/:id/run` | write | runs now and answers when done (up to about 20 seconds). A failed run is still a 200 with `run.status` "failed" and its code. `{ "force": true }` lets a shrunk feed through |

Deleting the integration deletes the feeds that use it (their indicators stay and expire).

## The schedule

`src/feeds/runner.js`, started by `src/server.js` beside the IOC matcher. Every 60 seconds (`FEED_INTERVAL_SECONDS`, at least 15) it runs up to 5 feeds that are due, across tenants. A feed is due when it is switched on and its last run started more than its interval ago; **a failed run also waits for the next interval** (no hammering a broken feed). A lapsed license pauses it (`src/licensing/worker-gate.js`), as for the IOC matcher; `FEEDS_ENABLED=false` switches it off.

## Tables (`k8s/12-schema-init.yaml`, idempotent)

`ioc_feeds` (the lease column, last status, last error, last item count) and `ioc_feed_runs`. Tenant policy and grants as the other tables.

## Tests

`tests/feeds-fetch.test.js` (16: real local servers; every refusal, redirects re-checked, token not forwarded, limits, no query string in any error), `tests/feeds-parser.test.js` (10), `tests/feeds-page.test.js` (15), and `tests/feeds-db.test.js` (real PostgreSQL and a real local feed server: the first import and its counts, other sources untouched, a person's switch-off kept, expiry and return, the shrink guard and force, bad feeds, the lease and a stale lease, the schedule across tenants, history trimmed to 100, deleting with and without the indicators, no token anywhere, every use audited, permissions per route, module switch). That test found one real SQL typing bug before release.

## Honest limits

- No real feed has been fetched, from asix1 or anywhere: the formats are what feeds commonly use, not what a given feed returns. The first real one will probably need a format adjustment.
- No networks (CIDR) and no per-indicator scores or descriptions: severity is one value for the whole feed.
- The fetcher does not unpack gzip or zip; it asks for the plain answer. A feed that is only served compressed will fail with "no valid indicator".
- No authentication other than a bearer token (no basic auth, no custom header, no API key header).
- A first run of a very large feed reads it into memory (up to 5 MB) and writes it in one statement; fine for the 50,000 limit, not for more.
- Not a playbook: no approval step and no undo; indicators only change detection (alerts), they block nothing. Blocking is what lists and the firewall integrations are for (SR3 and SR4).
