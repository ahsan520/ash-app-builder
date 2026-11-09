# Portal shell and module UI contract

Status: **DESIGN, agreed with Ash 2026-11-08. S1 (the manifest `ui` block), S3 (gateway headers and module file serving) and S2 (the shell loader in `index.html`) are built; the embedded host `/app/<id>/` (S4) is not, and no real module declares a page yet.** Tasks: `docs/product-plan.md`, "Status of Phase 5".

## Why

`src/portal/index.html` is one file with no build step. Every new page (and every fix) edits it, so two sessions collide, and one bad page can stop the whole portal from loading. The backend already solved this: one route file per feature, one manifest file per module. The portal gets the same rule.

**Decision:** the portal index becomes a **shell**. It draws the frame (header, side menu, tenant, theme, sign-in) and, for each module, **calls that module's own page**. A new module adds its own files and one manifest; it does not edit `index.html`. A module whose page fails to load shows an error card; the shell and every other module keep working.

Two further decisions that shape this contract:

1. **Adopt before build.** Most modules will run an open-source tool behind ASIX (see `docs/open-source-stack.md`, "Adopt before build"). The shell must be able to show such a tool under the ASIX frame, not only pages written by us.
2. **Simplified GUI, as many features as possible.** We do not copy any other product's screens (see `docs/xsiam-reference.md`). A module page is one page per job, with defaults, and the advanced options behind an "Advanced" fold.

## Three kinds of module page

| `ui.kind` | What loads | Used for |
|---|---|---|
| `builtin` | A `pgXxx` function that is still inside `index.html` | Every page that exists today. Nothing moves until someone touches it. |
| `native` | An ES module file we ship, `src/portal/modules/<id>/<page>.js`, loaded on demand | New ASIX-written pages (Marketplace, Cases, Lists, Integrations, Actions). |
| `embedded` | An open-source tool's own web UI, shown in an iframe from `/app/<id>/` on the gateway | Tools we adopt (the SOAR engine, if one is chosen). |

## Manifest: the `ui` block

`src/modules/manifests/<id>.js` gains an optional `ui` block. A module without one behaves as today.

```js
ui: {
  kind: 'native',                       // 'builtin' | 'native' | 'embedded'
  entries: [
    {
      id: 'browse',                     // unique inside the module; letters, digits, dashes
      label: 'Marketplace',             // the words in the menu
      area: 'Settings',                 // which menu: 'Main' (the left menu), 'Settings' or 'Threat Management' (their side menus)
      group: 'Content',                 // optional heading inside that menu
      page: 'marketplace.js',           // native: a file name in src/portal/modules/<module id>/ (no folders)
      // path: 'settings/retention',    // builtin: the menu path of a page still inside index.html
      // url: '/app/shuffle/',          // embedded: must start with /app/<module id>/
      permission: 'detections:rules:read', // optional; one of the module's own permissions. The shell hides the entry without it; the server still decides
      order: 20,                        // optional, 0 to 9999, default 100
    },
  ],
},
// embedded modules also declare where the tool listens, as the NAME of an environment variable:
proxy: { env: 'ASIX_SHUFFLE_URL' },    // the address itself is set by the installer; the name is never sent to the browser
```

Rules the registry checks at load (`src/modules/registry.js`; a bad manifest stops the gateway at start and fails `tests/modules-ui.test.js`, never a request):
- `kind` is one of the three; `entries` is a non-empty list; entry ids are lowercase letters, digits and dashes and are unique inside the module; `label` is required; `area` must be `Main`, `Settings` or `Threat Management` (the three menus the shell draws).
- `native` entries name a `page` that is a plain file name ending in `.js` and the file must exist at `src/portal/modules/<module id>/<page>`; they take no `url`.
- `embedded` entries name a `url` that starts with `/app/<module id>/` (no `..`, spaces, `?` or `#`); the module must declare `proxy: { env: 'ASIX_<NAME>_URL' }`; `proxy` is refused on any other kind.
- `builtin` entries name the `path` of a page still in `index.html`; two modules cannot claim the same builtin path.
- `permission`, when given, must be one of the module's own `permissions`.
- The menu path of a `native` or `embedded` entry is computed as `mod/<module id>/<entry id>`, so it cannot collide with a builtin path.

`GET /v1/modules` already feeds the portal's menu state. **Built in S1:** each row now has a `ui` field (the normalised entries, or `null`), next to `state` (enabled, locked, planned) as before. The `proxy` variable name is never included. The row is sent for every module, as today; hiding an entry for a caller who lacks its `permission` is the shell's job (S2), and the server checks the permission again on every call. **The shell builds the menu from that answer.** The old `NAV`, `SETTINGS` and `THREAT` arrays in `index.html` stay as the fallback for `builtin` entries and for when `/v1/modules` cannot be read (the menu-state code already tolerates that: nothing is greyed out).

## Native module pages

```js
// src/portal/modules/<id>/<page>.js
export async function mount(host, ctx) { /* draw into host */ }
export function unmount() { /* optional: stop timers, listeners */ }
```

`ctx` is a small, stable object the shell hands in, so a page never reaches into `index.html`:
`api(path, opts)` (same sign-in, same error shape), `el(tag, props, ...children)`, `tenant`, `can(permission)`, `navigate(path)` (a menu path such as `mod/market/browse` or `dashboard`), `toast(text, kind)` (`kind` `'error'` for the red one), `theme` (the CSS variables are already on the document). A test pins this list, so adding to it is a deliberate change.

**Permissions in the portal (built in S2):** `GET /v1/auth/me` now also returns `permissions`, the caller's own permission names (sorted, no duplicates; `src/gateway/identity-body.js`). `can(p)` is true when no permission is asked for, **or when the list is not known** (the call failed): then nothing is hidden and the server's 403 is the answer. A menu entry whose `permission` the caller lacks is left out of the menu, and opening its address shows a permission message without loading the page. This is a convenience only; the server checks every call.

How the shell loads a page (built in S2; the code is the marked `module-shell` block in `src/portal/index.html`):
1. `import('/portal/modules/<id>/<page>')` with a **10 second limit on loading the file**. A Retry adds `?r=<n>` so the browser fetches a fresh copy (a failed import can be remembered).
2. Clears the host and calls `mount(host, ctx)` inside `try/catch`. **The 10 seconds do not apply to mount itself**: a page may legitimately wait longer for its data, and a mount that never finishes simply leaves the host as the page drew it.
3. On any failure (missing file, syntax error, no `mount()`, thrown or rejected error, 10 second timeout, a page name or address that is not a plain name) it replaces the host's content with an **error card**: the module name, one line of cause (set as text, never as markup), **Retry**, and a link to Modules. The menu and every other page keep working. The failure is also written to the browser console.
4. When the person leaves the page the shell calls `unmount()` if there is one (an `unmount` that throws is ignored). A page that finishes loading *after* the person has moved on is unmounted at once and never becomes the current page.

Page files are shipped inside the ASIX image, same origin, so the portal's existing CSP (`script-src 'self'`) allows them. **Served only as `/portal/modules/<module id>/<name>.js` or `.css` (S3):** the match is on the raw path, so anything encoded (`%2e%2e`, `%2f`), nested deeper, hidden (`.env`), upper-case, a source map, a note (`.md`) or an HTML file is a 404 and never falls through to the general portal folder; only GET and HEAD are answered. Like the shell itself these files are not behind a token (they are code, not data); every data call a page makes is. **Marketplace packs cannot ship portal code.** A pack can add data (rules, parsers, playbooks, action and integration definitions, dashboards); a page file only arrives with an ASIX release. This keeps signed-pack delivery from becoming a way to run script in an analyst's browser.

## Embedded open-source tools

The tool runs as its own service inside the cluster. It is never exposed outside it; the only way in is the gateway.

- **Route:** `/app/<module id>/*` on the gateway, one reverse-proxy file per tool under `src/gateway/routes/`. The route checks, in order: sign-in, the module is enabled (profile, license, dependencies), the caller holds the entry's `permission`, the tenant. Only then does it forward.
- **Sign-in to the tool:** single sign-on through Keycloak where the tool supports it; otherwise a per-tenant service identity set up by the module's installer. The browser never receives the tool's own admin credentials.
- **Tenant mapping:** the tool must keep tenants apart (its own organisations or workspaces). This is **unverified for every candidate** and is one of the spike's pass or fail checks.
- **Sandbox (built in S2):** the iframe gets `sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-downloads"`, set as an **attribute** (assigning the property did not set it in a test DOM; if it cannot be set, no frame is drawn and the error card appears instead). There is no `allow-top-navigation`, so the tool cannot send the portal elsewhere. **Honest limit:** a tool that is both scripted and same-origin can remove its own sandbox, so the sandbox is not a defence against a hostile tool; only tools we choose are embedded, and the S4 proxy is the real boundary.
- **Framing (built in S3, `src/gateway/portal-headers.js`):** everything under `/portal` is sent with `frame-src 'self'` and still `frame-ancestors 'none'` (the portal may frame only its own origin; nothing may frame the portal). Everything under `/app/*` is sent with only `frame-ancestors 'self'` plus `X-Frame-Options: SAMEORIGIN`; deliberately no `default-src` or `script-src` there, so the tool can run its own scripts. **S4 must remove any `frame-ancestors` or `X-Frame-Options` the tool sends itself**, because the browser enforces every policy it receives and a tool that sends `frame-ancestors 'none'` would stay unframeable. The shell puts the tool in an iframe with a `sandbox` attribute, and offers **Open in a new tab** for tools that refuse to be framed. An unknown `/app/...` path is a plain 404 (Express's own answer, which nothing can frame).
- **Network:** a NetworkPolicy lets only the gateway pods reach the tool's pods.
- **Licence:** a tool under AGPL runs as a separate program that ASIX talks to over HTTP. ASIX does not link to it or copy its code. If we ever modify and re-brand a tool and offer it to customers, its own licence terms apply to that modified copy: get a lawyer's read first (open decision in `docs/product-plan.md`).
- **When the tool is down:** the iframe area shows the same error card as a failed native page. ASIX's own pages are unaffected.

## Keeping ASIX from breaking

- A module's files are separate from `index.html`, so a change to one module cannot change another.
- The shell has no module-specific code; it only reads manifests.
- A broken or slow module page is contained by the error card and the timeout.
- A broken `ui` block is caught at load by the registry and by `tests/modules-ui.test.js`.
- `index.html` shrinks over time: when a `builtin` page is next changed, move it to a `native` page file first, in its own change, with its tests.

## Tests this needs

- Registry (**done in S1**, `tests/modules-ui.test.js`): every rule above, each with a deliberate break that fails with a message naming the problem, plus a check that `proxy` never reaches the browser.
- Shell (**done in S2**, `tests/portal-shell.test.js`, 40 tests): the `menu-state` and `module-shell` blocks are cut out of `index.html` and run without a DOM, with a fake `el()` and a fake page loader. It covers which entries are listed and in what order, malformed rows from the server, permissions, a module page greying like any other, every failure above showing the card, the 10 second limit, Retry, unmount and late results, the embedded frame, and wiring checks that `route()` and the menu use the shell while the old arrays and pages are unchanged. `tests/identity-body.test.js` covers the `permissions` field.
- **Also checked once by hand, not kept in the repo:** the real `index.html` was run in jsdom (a test DOM) with a fake sign-in and fake API answers: old menus unchanged when no module declares a page; embedded, Settings and Threat pages; the error card; permission gating; and `/v1/modules` down. jsdom cannot load an ES module, so **a native page that loads successfully has not been seen in a real browser**: that needs the first real native page (MK2) and a look in the browser.
- Gateway headers and module files (**done in S3**, `tests/gateway-csp.test.js`, 18 tests): the policies as written, headers on the real app, `appHeaders` mounted before any route, what is and is not served from the modules folder, and attempts to climb out of it. Still to do in S4: `/app/<id>/` refuses a caller without the permission, a disabled module, and another tenant.
- Branding test (`tests/branding.test.js`) keeps scanning `index.html`, and also the new `src/portal/modules/**` files.

## Not decided
- Whether a page's `mount` should get a time limit after all (today only loading the file is limited).

- Whether native pages use a small shared stylesheet or a shadow root per page. Start with the shared CSS variables and revisit if pages interfere.
- Whether `embedded` tools share one Keycloak realm with ASIX or get their own client.
- How an embedded tool's own menu is hidden so only the part we want shows.
