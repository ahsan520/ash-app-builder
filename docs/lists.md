# Lists (task L1)

**Built 2026-11-11.** A list is a tenant object that holds values of one type for one purpose, and can be published at a secret address that a firewall polls. This is the low-risk way to push indicators to a firewall (see `docs/xsiam-reference.md`, "Lists and an external dynamic list"): ASIX never logs in to the firewall; the firewall comes and reads a text file.

**Not deployed or tried on the k3s box yet.** Checked here against a real PostgreSQL 16 (the platform schema applied twice), not against asix1.

## What a list is

| | Choices |
| --- | --- |
| **Purpose** (`kind`) | `block` (a firewall should drop these), `allow` (never block these), `watch` (only look out for these) |
| **Holds** (`item_type`) | `ip` (an address or a network such as `198.51.100.0/24`, IPv4 or IPv6), `domain`, `url`, `hash` (MD5, SHA-1 or SHA-256) |

The purpose and the type cannot be changed after creation, because every entry was checked against them. The name (unique per tenant, any capitals), the description and, for address lists, "allow private addresses" can be changed. A tenant can have 100 lists; a list holds 50,000 entries. An entry has a note (200 characters), where it came from (`manual` or `action`), who added it, when, and when it expires (never, 1 hour, 24 hours, 7 days, 30 days or 90 days).

Every value is written in one normal form: addresses and names in lower case, `10.0.0.5/24` becomes `10.0.0.0/24`, `/32` becomes the plain address, IPv6 is compressed, a URL loses its `#fragment`. A value already on the list is left as it is and reported as "already on the list".

## What a block list refuses

A block list reaches a firewall, so it refuses what could cut a network off. Each refused value is reported with its reason while the rest of the request still goes in.

| Refused | Code | Why |
| --- | --- | --- |
| A network wider than `/8` (IPv4) or `/32` (IPv6), such as `0.0.0.0/0` | `TOO_WIDE` | one wrong line must never reach a firewall |
| Loopback, unspecified, multicast and reserved addresses (all list types of addresses) | `NOT_LISTABLE` | nothing can be meant by blocking them |
| Private addresses (10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, fc00::/7, fe80::/10) | `PRIVATE_ADDRESS` | blocking your own network. Turn on **allow private addresses** on that list when it is meant (a home network blocking a hacked device) |
| Anything an **allow list** of the same tenant covers | `ON_ALLOW_LIST` | allow wins. For addresses the two ranges overlap (either one inside the other); an allowed domain covers its subdomains, and a blocked parent would include an allowed subdomain; URLs and hashes match exactly. Expired allow entries protect nothing |

Allow and watch lists are not checked against anything except the "never listable" addresses. Domain names must be full names (`example.com`, not `com`, not `*.example.com`; whether subdomains are blocked depends on the firewall, so ASIX publishes the name as written). A URL with a user name or password is refused.

## The address a firewall polls

`POST /v1/lists/:id/feed` makes (or replaces) the address `/v1/list-feed/asix_lt_<43 characters>`, and answers once with the path and, when the server can tell how it was reached, the full `feed_url`. Only a SHA-256 hash of the secret is stored (like ingestion keys), with its last four characters as a hint; it is not in the audit log either. **The secret is shown once.** Making a new one stops the old at once; `DELETE /v1/lists/:id/feed` turns it off.

`GET /v1/list-feed/<token>` (`src/lists/feed.js`) needs no sign-in: a firewall cannot sign in, so the secret in the address is the credential. It answers `text/plain`, one value per line, sorted, with no comments, no name and no notes; expired entries are left out; an empty list is an empty 200 (so a firewall does drop what was removed). It carries an `ETag` and answers 304 to `If-None-Match`, and `X-ASIX-List-Count`. A wrong, replaced or turned-off address, and a token of the wrong shape (which never reaches the database), get the same plain 404. A token is limited to 120 requests a minute per API replica (`ASIX_LIST_FEED_RATE_PER_MIN`). The time and address of the last fetch are written at most once a minute, so the page can show that the firewall really picked the list up.

It is mounted before the JSON parser and the sign-in chain, beside the ingestion lane, and **not behind the licensing gate**: a firewall must not lose its block list because a subscription ran out. Deleting the list or turning the address off stops it. *This choice should be confirmed with Ash.*

Firewalls that take this kind of address: OPNsense and pfSense (URL table alias), FortiGate (external connector, threat feed), Palo Alto (external dynamic list), and most others. Use an address list for `ip`, a domain list for `domain`, a URL list for `url`.

## The two actions (with SR2, `docs/actions.md`)

Registered when the Lists routes load (`src/lists/actions.js`), off until an administrator enables them for the tenant, medium risk, reversible, never above level 3 (so automation asking for one waits for a person):

- `list.add_entry` (`list_id`, `value`, `note`, `expires`, `expires_at`): adds one value through the same rules as the page. **Expires after 30 days unless told otherwise** (what automation blocks should come off by itself). Undo takes it off. A refusal (too wide, private, on an allow list, list full, list not found) is a failed run with the reason and nothing added. A value already there is a successful run with nothing to undo.
- `list.remove_entry` (`list_id`, `value`): takes one value off. Undo puts it back **with its note and its exact expiry time** (`expires_at` is the text the database wrote, so no time zone can move it).

They are what SR3's playbooks use for "add this IOC to the firewall block list".

## Tables (`k8s/12-schema-init.yaml`, idempotent)

`lists` (name unique per tenant ignoring capitals, kind and item type checked, the feed token hash with a unique index, hint, creation and last-fetch time and address) and `list_entries` (`UNIQUE (list_id, value)`, `ON DELETE CASCADE`, source checked, expiry). Both have the tenant policy and the same grants as the other tables. Times use the database clock (`localtimestamp`). Expired entries are not counted or served; one that has been expired for over a day is deleted by the next change to its list.

## API (two new permissions: `soar:lists:read`, `soar:lists:write`)

`bootstrap-portal.sh` gives both to `portal-admin`. All routes are behind the Lists module (`403 MODULE_DISABLED` when off) and the licensing gate (`/v1/lists`, feature `lists`, now in the residential bundle).

| Route | Permission | What |
| --- | --- | --- |
| `GET /v1/lists` | read | the lists with entry counts and feed state, plus the choices the page needs |
| `POST /v1/lists` | write | `{ name, kind, item_type, description?, allow_private? }` |
| `GET / PUT / DELETE /v1/lists/:id` | read / write | read; change name, description, allow_private; delete (entries go with it, the address stops) |
| `GET /v1/lists/:id/entries` | read | `q` (plain substring), `limit` (1 to 200), `offset`, `expired=true` |
| `POST /v1/lists/:id/entries` | write | `{ values: [...] }` or `{ text: "one per line" }` (up to 1000; `#` and `;` lines dropped), `note`, `expires` or `expires_at`. 200 with `added`, `existing`, `refused` (value, code, message) |
| `POST /v1/lists/:id/entries/remove` | write | `{ values }` (a POST, because some proxies drop a DELETE body). Any way of writing a value finds it |
| `POST / DELETE /v1/lists/:id/feed` | write | make or replace the address (secret shown once); turn it off |

Whole-request refusals: `NOT_FOUND` 404, `NAME_TAKEN`, `TOO_MANY_LISTS`, `LIST_FULL`, `ALLOW_SET_TOO_LARGE` 409, `ALREADY_EXPIRED` 400. The audit log (`audit_events`, `soar:list:*`) gets one row per change with the list name and counts, never a value.

## The Lists page

Threat Management, group **Lists** (`src/portal/modules/lists/lists.js`, a page the module brings itself; `index.html` is not touched). A card per list; a list opens to its address card, an Add box (paste values, note, how long), the entries (search, paging, Remove) and Delete. Removing an entry, replacing or turning off the address, and deleting a list take two presses. The secret address is shown once and is gone when the person leaves the list. Without `soar:lists:write` no button that changes anything is drawn.

## Tests

`tests/lists-model.test.js` (23: normal forms, every refusal, the allow matcher, bodies, the text, tokens, the two action definitions), `tests/lists-feed.test.js` (12: the real router on a real socket with a fake database: no sign-in, hash-only lookup, 304, rate limit, fetch record, no token in any log, where it is mounted), `tests/lists-page.test.js` (21), and `tests/lists-db.test.js` (real PostgreSQL, `ASIX_TEST_DB=1`: all of the above through the real routes and SQL, tenant isolation, allow-list protection, the size limit, expiry by the database clock, the public address made, replaced and turned off, both actions run, undone, refused and approved, audit rows without values, permissions per route, module off). The licensing and module tests were updated for the new module.

## Honest limits

- Not deployed or tried on asix1, and no firewall has fetched a list yet. Which firewall Ash will use decides the last details (some want a `.txt` ending or basic authentication; neither is built).
- The allow check loads the tenant's active allow entries of that type (at most 200,000) into memory for each add. Fine for the expected sizes; a very large allow list would need an index.
- Adding to an allow list a value that is already on a block list does not remove it from the block list.
- Entries are not yet written by anything but a person or the two actions: IOC feed import and IOC hit (SR3) will use `list.add_entry`.
- Domain names are ASCII only (write an international name in its `xn--` form).
- One address per list; no second reader can be given its own revocable address.
