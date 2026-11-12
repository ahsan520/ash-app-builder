# Integrations and credentials (task SR1)

**Built 2026-11-11.** An integration is a tenant's **account for another product**: a firewall, a threat feed, a lookup service. It holds settings that are not secret (an address, a format) and **credentials** (keys, tokens) that go in and never come out. Its status is **Not configured** until every required credential is set.

**Not deployed or tried on the k3s box yet.** Checked here against a real PostgreSQL 16 (the platform schema applied twice).

**What SR1 does not do.** It records and protects accounts. **Nothing connects to any product yet**: there is no "test connection", and no action uses an account. SR3 (feeds, playbooks) and SR4 (firewalls) find an account through `useCredentials` below. "Configured" means "the credentials are filled in", not "they work".

## Definitions (in code, like actions)

`src/integrations/catalog.js`. A definition says what an account for a product needs: `config` fields (`string`, `url`, `enum`, `boolean`; required or not) and `credentials` (always text, secret, required or not), plus `category` (`firewall`, `threat-intel`, `enrichment`, `ticketing`, `messaging`, `identity`, `endpoint`, `other`), `publisher` and a description. A tenant cannot create or change a definition. `kind` is `builtin`; a definition carried by a content pack (MK1 `integrations`) stays refused until a pack installer exists.

Shipped (what SR3 and SR4 will need; the field names follow what each product documents for API access, **none tried against a real product**):

| Id | Category | Settings | Credentials |
| --- | --- | --- | --- |
| `opnsense` | firewall | `base_url` | `api_key`, `api_secret` (both required) |
| `pfsense` | firewall | `base_url` | `api_key` (needs the REST API package) |
| `fortigate` | firewall | `base_url` | `api_token` |
| `threat-feed` | threat-intel | `feed_url`, `format` (plain-text, csv, json) | `token` (optional) |
| `virustotal` | enrichment | none | `api_key` |

## Credentials: the secrets abstraction (`docs/plan.md` H.7)

Everything that keeps a secret goes through `src/secrets/provider.js` (`seal`, `open`, `configured`), so a Vault or cloud provider can replace the local one without touching callers. Built: `local`, which is AES-256-GCM with **the key ASIX already uses for notification secrets** (`NOTIFY_ENCRYPTION_KEY`, k8s secret `asix-notify-secret`). One key to back up, and losing it loses both. `ASIX_SECRETS_PROVIDER` other than `local` is refused (not built).

- Stored as **one sealed JSON object per integration** (`credential_enc`), beside the **names** of the fields that are set (`credential_fields`), so the list and the status need no key.
- **No route returns a credential**, not even to the person who typed it; the page shows only *Set* / *Not set*. Typed values are sent once and dropped from the page.
- Setting some credentials keeps the others; `clear` removes named ones; `DELETE .../credentials` removes all (it works even when the stored ones can no longer be read). A refused request changes nothing, and an error never contains the value that came with it.
- **Audit (`audit_events`, `soar:integration:*`): names and counts, never values**: `credentials-set` lists the field names set and cleared; **every use** by the code that talks to the product is a `credentials-use` row with its purpose (for example `firewall.block`).
- No key on the deployment: the page warns, saving answers 503 `SECRETS_NOT_CONFIGURED`. Key changed: the old secrets answer 409 `SECRET_UNREADABLE`; clear them and enter them again.

`useCredentials(client, tenantId, id, purpose)` in `src/integrations/service.js` is **for the code that talks to the product, never for a route**. It returns `{ definition_id, config, credentials }` only for an integration that is enabled and has every required credential (otherwise `NOT_FOUND`, `DISABLED`, `NOT_CONFIGURED`, `SECRET_UNREADABLE`), and audits the use.

## Tables (`k8s/12-schema-init.yaml`, idempotent)

`integration_instances`: tenant, `definition_id`, `name` (unique per tenant ignoring capitals), `config` (jsonb), `enabled`, `credential_enc`, `credential_fields`, who and when the credentials were last changed, tenant policy and grants as the other tables. A tenant can have 50. A definition that ASIX no longer ships leaves its instances listed, never configured, and deletable; nothing can be saved to them.

## API (new permissions `soar:integrations:read`, `soar:integrations:write`)

`bootstrap-portal.sh` gives both to `portal-admin`. Behind the Integrations module (`403 MODULE_DISABLED`) and the licensing gate (`/v1/integrations`, feature `integrations`, now in the residential bundle).

| Route | Permission | What |
| --- | --- | --- |
| `GET /v1/integrations/definitions` | read | the definitions, and whether the key is configured |
| `GET /v1/integrations`, `GET /v1/integrations/:id` | read | instances: settings, status, and for each credential only `set` |
| `POST /v1/integrations` | write | `{ definition_id, name, config }` (every required setting) |
| `PUT /v1/integrations/:id` | write | `{ name?, config?: { setting: value or null }, enabled? }`; the product never changes; a required setting cannot be removed |
| `DELETE /v1/integrations/:id` | write | removes it and its credentials |
| `PUT /v1/integrations/:id/credentials` | write | `{ values: { field: "…" }, clear?: [field] }`; one line of text each, up to 4096 characters |
| `DELETE /v1/integrations/:id/credentials` | write | clears them all |

Status: `not_configured`, `configured`, `disabled` (switched off; wins over the others).

## The Integrations page

Settings, group **Integrations** (`src/portal/modules/integrations/integrations.js`, a module page; `index.html` is not touched). Integrations grouped by category with a status pill; Add (choose the product, name it, fill its settings); an integration opens to its settings, its credentials (a password input per credential, always empty, "Type to set / replace"), Switch off and Delete. Clearing all credentials and deleting take two presses; viewers without `soar:integrations:write` see no input or button that changes anything.

## Tests

`tests/integrations-model.test.js` (13), `tests/integrations-page.test.js` (21) and `tests/integrations-db.test.js` (real PostgreSQL, `ASIX_TEST_DB=1`). The DB test's main check: four distinct secrets are typed through the real routes, rotated, cleared and re-entered under a changed key, and afterwards **none is found in any response, any table in plain text, the audit trail or a log line**. It also covers the 50 limit, tenant isolation, the missing and the changed key, a removed definition, every route's permission and the module switch.

## Honest limits

- No connector, no "test connection", no health check: "Configured" only means the credentials are filled in.
- The definitions have not been tried against real OPNsense, pfSense, FortiGate, a feed or VirusTotal.
- Same key as notifications. No rotation tool: changing the key makes stored secrets unreadable and they must be entered again.
- A credential is one line of text. A multi-line value (a PEM certificate or key) is not supported yet.
- Settings are checked for shape (an address starts with http:// or https://, no password in it) but not for where they point; the code that connects (SR3, SR4) must apply its own limits on which hosts ASIX may call.
- No per-integration permission: anyone with `soar:integrations:write` can replace any credential of the tenant.
