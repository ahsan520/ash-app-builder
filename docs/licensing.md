# Licensing (tasks E15 and E16)

Status: **built 2026-11-07 (E15) and 2026-11-08 (E16), made an independent module the same day. Tested with generated keys and stand-ins (`tests/licensing.test.js`, `tests/license-page.test.js`, `tests/portal-license.test.js`), NOT on a real cluster.** **Licensing is OFF by default on a development build**, so nothing here changes how any other module is built or behaves until you switch it on. Read "An independent module" and "Before you deploy" first.

## An independent module (agreed 2026-11-08)
Licensing must not get in the way of building other modules, and other modules must not know about it. So:
- **All of it lives in `src/licensing/`** (license check, vendor keys, installation id, stored licenses, the gate, the License API, the notices, the worker guard), with a manifest `src/modules/manifests/licensing.js` and **its own page** `src/portal/modules/licensing/license.js` (a native module page of the portal shell, `docs/portal-shell.md`). `src/portal/index.html` is not touched.
- **It can be OFF.** On a development build it is off until an admin switches it on (License page, or `ASIX_LICENSE_MODE=open` for tests); a release build is always on. **While off, no module is locked for want of a license, no route is refused, no worker is paused, no notice is sent**: the platform behaves exactly as it did before licensing existed. If the database cannot be read, a development build stays off and a release build stays on.
- **Modules do not name license features.** Which module a license feature unlocks is one table in `src/licensing/bundles.js` (`FEATURE_OF`); the home-tier manifests carry no `entitlement` (the enterprise ones already did and keep it). Build, rename or remove a module without touching licensing; a module not in the table is baseline.
- **The contact points are a fixed list**, enforced by `tests/licensing-independence.test.js`: `src/modules/index.js` (state, entitled, featureFor, describe), `src/gateway/index.js` (the gate and the License API), `src/server.js` (the notices) and the two detection workers (the worker guard). A new one fails a test until someone decides it is fine.
- **Turning it on later is a switch, not a project:** License page, Switch licensing on. Until then the stored licenses wait in the database (`license_files`).
- Not done to keep the shell and `index.html` untouched: greying the Endpoints menu entry when it is locked (it is refused by the server with `MODULE_LOCKED`; greying needs one line in the portal's menu map, to add when licensing is switched on for real), and a banner on every page when a license has lapsed (the notices go to every notification channel, and the License page shows the state; an every-page banner needs a small shell feature).

## What it does
- **When licensing is on, the default install = baseline only.** With no usable license the platform runs: **core, ingestion (collection, brokers, parsing, keys), retention and capacity.** Everything else, including **search**, is locked until a license unlocks it.
- **Licensed by feature**, sold as two products (`src/licensing/bundles.js`; `@residential` and `@enterprise` in the tool expand to these):

| Feature (license name) | Module | Residential | Enterprise |
| --- | --- | --- | --- |
| `search`, `detections`, `alerts`, `cases`, `actions`, `lists`, `integrations`, `ioc-feeds`, `content-packs`, `dashboards` (reports), `notifications`, `threat-intel` | the twelve residential modules | yes | yes |
| `endpoints` | Endpoints (agents, alerts, vulnerabilities, group settings) | no | yes |
| `xdr`, `soar`, `posture`, `compliance`, `ai`, `multi-tenant` | planned or not yet built enterprise modules | no | yes (they switch on when built) |

  A feature also needs what it depends on (alerts needs detections; cases needs alerts; actions needs cases; lists and integrations stand alone; ioc-feeds needs threat-intel and integrations; all are in the bundle). `cases` and `actions` are residential because their manifests are home tier; to make the action registry an enterprise feature, change its tier in its manifest and move `actions` to `ENTERPRISE_ONLY` in `src/licensing/bundles.js` (the tests tell you what else to update). Enterprise modules also need `ASIX_PROFILE=enterprise`.
- **Enforced on the server**, not only in the menu: `src/licensing/gate.js` refuses a locked module's routes with `403 MODULE_LOCKED`, and the **rule runner and IOC matcher stop** for real (`src/licensing/worker-gate.js`). The data plane (events in, heartbeats, broker config), health, the Modules page and the License page are never gated. A test fails if a new route file's prefix is neither gated nor listed as baseline.
- **Bound to one installation.** The schema job makes one random installation id (table `installation`), shown on the License page. A license names that id, so a copy on another installation, or on a reinstall with a fresh database, unlocks nothing. A restore from backup keeps the id. A license signed with `*` works anywhere (use sparingly).
- **Only built-in keys.** Licenses are verified against `src/licensing/vendor-keys.js`, never a key from the environment or a file on the server. The signing key stays offline.
- **Clock.** A clock set more than a day behind the last time the platform ran is refused (`clock_error`).

## Expiry: warning, grace, lapse (agreed 2026-11-08, like Splunk: search stops, ingestion continues)
| State | When | What works |
| --- | --- | --- |
| Valid | until expiry | everything the license includes |
| Expiring | last 14 days | everything, plus a banner and a notice |
| Grace | 0 to 30 days after expiry | everything still works; red banner; weekly notice; a last notice 1 day before the end |
| Lapsed | after the grace | **search, reports, detections and alerts stop.** Ingestion, retention, capacity and backup continue; **nothing is deleted**; renewing switches everything back on at once |

- **The grace period is a signed claim** (`grace_days`, default 30, at most 90). Sign a trial with grace 0 and it ends on its date. Changing the value breaks the signature.
- **Notices are loud.** One message per stage and expiry date goes through **every notification channel of every tenant** (Slack, e-mail, webhook), sent directly (`src/licensing/notices.js`), so it still goes out when the notifications feature is locked. A stage is recorded only when at least one channel took it (or there are no channels); a renewal with a new expiry date starts the series again. Hourly check.
- Events that arrive while lapsed are stored and searchable after renewal. Detections do not run on that gap (no catch-up is built).

## The License page (Settings, General, License)
- Shows the **installation id** (with Copy), the status in plain words, the active license (customer, kind, expiry, features), the version and build channel.
- **Stored licenses:** paste or choose a license file and **Store license**: it is checked (signature, this installation, not past its grace) and kept **but not activated**. You can store several (trial, residential, enterprise). **Activate** makes one the only active one (checked again first), **Deactivate** switches it off, **Remove** deletes one that is not active. They live in the database (`license_files`), so a deploy never touches them and a backup keeps them.
- Reading needs `license:read`, every change needs `license:write` and is audited (the standard request audit). `scripts/deploy/bootstrap-portal.sh` gives both to the portal admin of the Default Tenant: **re-run it on the ASIX node once** (`sudo scripts/deploy/bootstrap-portal.sh <username>`) or the page answers "forbidden".
- The command line still works: `scripts/deploy/install-license.sh license.jwt` (a license from the `asix-license` Secret or `ASIX_LICENSE` is used only when no license is active on the page).

## Staging and release (the build channel)
- **Dev build (the default, your staged builds):** the License page has a **Licensing on/off** switch, **off by default**. Off = licensing does nothing and every module of the edition is on. Switch it on to see exactly what a customer sees; switch it off again. `ASIX_LICENSE_MODE=open` also works on a dev build (tests).
- **Release build (what customers get):** licensing is **always enforced**, there is no switch, the setting in the database is ignored, `ASIX_LICENSE_MODE=open` does nothing.
- The channel is written into the image when it is built (`Dockerfile`: `--build-arg ASIX_BUILD_CHANNEL=release --build-arg ASIX_VERSION=26.4.0` writes `src/licensing/build-channel.json`); it is **not** read from the environment, so a customer cannot set it. The release pipeline (not built yet) must pass `release`.
- The Modules and License pages show the version and channel (`GET /v1/modules` returns `build`).

## Before you deploy
1. **Make the vendor key, once, on your own machine:** `node scripts/license-tool.js keygen ./keys asix-2026-1`. Paste the printed line into `KEYS` in `src/licensing/vendor-keys.js` and commit it. Keep `keys/license-private.pem` off every server and out of Git (password manager + encrypted offline backup; if lost you cannot sign new licenses).
2. Re-run `sudo scripts/deploy/bootstrap-portal.sh <username>` once for the new permissions (above).
3. Set `ASIX_PROFILE` to `enterprise` in `k8s/30-asix-api.yaml` if this installation uses Endpoints (the deployment defaults to `home`).
4. Deploy (`./sync-and-deploy.sh`). **Your own build is a dev build with licensing off, so nothing locks.** The schema job creates the installation id, the license tables and the switch.
5. When you want to test licensing: sign a license for the installation id shown on the License page, store it there, activate it, switch licensing on:
   ```
   node scripts/license-tool.js sign keys/license-private.pem asix-2026-1 "Your Company" 365 <installation-id> @enterprise unlimited unlimited
   ```
   (`@residential` for a home customer; or a list such as `search,detections,alerts`; the last two arguments are tenants and retention days; for a trial with no grace add `unlimited unlimited 0` at the end: tenants, retention, then `grace_days` 0). Check a license with `node scripts/license-tool.js inspect <license>`.

## Selling it
- **Residential customer:** release build, default profile, sends you the installation id (License page), you sign `@residential` for 365 days with `tenants` 1 and the retention you sell, they store and activate it on the License page.
- **Enterprise customer:** profile `enterprise`, `@enterprise` or a custom feature list, tenants and retention as sold.
- **Trial:** sign a 30-day license for their installation id on request, with grace 0. No automatic trial: a reinstall would restart it; a reinstall gets a new installation id and needs a new license.
- **Renewal:** sign a new license for the same installation id; they store and activate it (the old one can be removed). Licenses of 90 to 365 days limit what a leaked one is worth.
- **Rotating the vendor key:** add the new key (new `kid`) to `KEYS`, sign new licenses with it, remove the old key when its last license has expired.

## The limits of this protection (be honest with yourself)
Anyone who has the whole source can edit the checks out; a check in the same code cannot prevent that. What this gives you: a stock copy does nothing useful, a copied license does not work elsewhere, nobody can mint a license without your private key, a customer cannot flip an environment variable to unlock, and the contract plus a private repo do the rest. **Strongest next step: ship only signed release images to customers and keep the source private** (see the quarterly release plan in `docs/product-plan.md`).

## Not built
The release pipeline that builds `release` images and signs them; an online activation or trial server; hardware fingerprint beyond the database-bound id; per-tenant module toggles; a catch-up run of detections after renewal; 
