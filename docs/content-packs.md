# Content packs: manifest v2 and the Marketplace page

Status: **built 2026-11-08 (tasks MK1 and MK2 of `docs/product-plan.md`, "Status of Phase 5").** Signed delivery of packs from outside the ASIX image (MK3) is not built: every pack today ships inside the image.

## What a pack is today
One file per pack in `src/packs/catalog/<pack id>.js` (file name = pack id). Only **detection rules** can be installed. An installed rule is an ordinary `detection_rules` row with `builtin_key = pack:<pack id>:<rule key>`, so installing twice never duplicates. `src/packs/index.js` validates every pack when it loads; a bad pack fails the tests, and in production it is skipped with a log line.

## Manifest v2 (all new fields are optional, so the first three packs work unchanged)
| Field | Meaning | Default |
|---|---|---|
| `publisher` | `{ name, url? }`; the url must be https | `{ name: 'ASIX' }` |
| `certification` | `certified` or `community` | `certified` |
| `supported_by` | `asix`, `community` or `none` | `asix` (certified) or `community` |
| `core` | shown with a "Core" tag | `false` |
| `deprecated`, `deprecation`, `replaced_by` | a deprecated pack needs a reason; a replacement is optional; a reason without `deprecated: true` is refused | not deprecated |
| `tags` | up to 10 lowercase words | `[]` |
| `license` | text, up to 60 characters | none |
| `requires` | `{ modules: [ids], packs: [ids] }` | nothing |
| `history` | newest first: `{ version, released?, notes }`; the first entry must be the current version; `released` must be a real date | `[]` |

Checks beyond the fields: an **unknown field is an error** (a typo cannot pass silently). Content of kind `parsers`, `dashboards`, `playbooks`, `actions` or `integrations` is **refused**, naming the task that will make it installable (SR1 integrations, SR2 actions, SR3 playbooks; parsers and dashboards have no task yet): a kind of content is allowed together with the code that installs it. Packs carry **data only, never portal code** (`docs/portal-shell.md`). `checkCatalog()` finds problems across packs (unknown module or pack, a loop, a pack that requires a deprecated one) and runs in `tests/packs-v2.test.js` against the real module ids.

## What the API does now
- `GET /v1/packs` and the new `GET /v1/packs/:id` answer with every v2 field, `contents` (counts per kind, rules only for now) and the installed state. Rule definitions are never sent.
- `POST /v1/packs/:id/install` is refused with **409** when the pack is deprecated (`PACK_DEPRECATED`; `allow_deprecated: true` overrides), when a module it needs is off (`MODULE_REQUIRED`), or when a pack it needs is not fully installed (`PACK_REQUIRED`).
- `DELETE /v1/packs/:id` is refused with **409** `REQUIRED_BY` while another installed pack depends on it, besides the existing `HAS_ALERTS` rule.
- The decisions are pure functions in `src/packs/index.js` (`installBlockers`, `removeBlockers`, `describe`, `stateOf`) and are tested without a database. **The HTTP routes themselves are not covered by a test** (they need the database); they only call those functions.

## The Marketplace page (the first module page)
`src/portal/modules/content-packs/marketplace.js`, declared by a `ui` block in `src/modules/manifests/content-packs.js` (menu: Main, "Marketplace"; needs `detections:rules:read`; installing and removing need `detections:rules:write`, so a read-only role sees no buttons).
- **Browse** and **Installed (n)** tabs, a search box (name, description, publisher, tags), a "Show deprecated packs" switch (installed deprecated packs always show under Installed).
- A card per pack: name, version, state, Certified or Community, Deprecated, Core, description, publisher, rule count, tags, a quick **Install**, and **Details**.
- The pack page: **Details**, **Content**, **Dependencies** (what it needs with their state, and what needs it), **Version history**. Actions: Install, Add missing rules, Restore shipped rules, Remove.
- Confirmations are drawn **inside the page** (a question, then Confirm or Cancel), not as browser dialogs. A removal that would delete alerts asks a second time. A deprecated pack is refused first, then installed on request.
- Our own layout, simple on purpose (`docs/xsiam-reference.md`).
- The page draws only through `ctx.el`, calls only `/v1/packs...` through `ctx.api`, and sets server text as text; tests enforce this (`tests/marketplace-page.test.js`, `tests/branding-modules.test.js`).
- **The older "Content packs" page stays in the main menu** until the Marketplace has been seen working in a real browser; then it can be removed.

## Not built yet
Signed delivery and updates (MK3), per-tenant update notices, staged rollout, version ranges in `requires` (only ids today), install of any content other than rules.
