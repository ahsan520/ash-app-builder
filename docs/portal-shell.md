# Portal shell and module UI contract

Status: **DESIGN, agreed with Ash 2026-11-08. S1 (the manifest `ui` block, its checks and `GET /v1/modules`) is built; the shell loader (S2), the gateway CSP (S3) and the embedded host (S4) are not.** Tasks: `docs/product-plan.md`, "Status of Phase 5".

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
      area: 'Configuration',            // which side menu: a main-menu id or 'Settings'
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
- `kind` is one of the three; `entries` is a non-empty list; entry ids are lowercase letters, digits and dashes and are unique inside the module; `label` and `area` are required.
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
`api(path, opts)` (same sign-in, same error shape), `el(tag, props, ...children)`, `tenant`, `can(permission)`, `navigate(path)`, `toast(text, kind)`, `theme` (the CSS variables are already on the document).

How the shell loads a page:
1. `import('/portal/modules/<id>/<page>.js')` with a 10 second limit.
2. Calls `mount(host, ctx)` inside `try/catch`.
3. On any failure (missing file, syntax error, thrown error, timeout) it draws an **error card** in `host`: the module name, one line of cause, **Retry**, and a link to Settings, Modules. The menu and every other page keep working. The failure is written to the browser console.
4. When the person leaves the page, the shell calls `unmount()` if it exists and empties `host`.

Page files are shipped inside the ASIX image, same origin, so the portal's existing CSP (`script-src 'self'`) allows them. **Served only as `/portal/modules/<module id>/<name>.js` or `.css` (S3):** the match is on the raw path, so anything encoded (`%2e%2e`, `%2f`), nested deeper, hidden (`.env`), upper-case, a source map, a note (`.md`) or an HTML file is a 404 and never falls through to the general portal folder; only GET and HEAD are answered. Like the shell itself these files are not behind a token (they are code, not data); every data call a page makes is. **Marketplace packs cannot ship portal code.** A pack can add data (rules, parsers, playbooks, action and integration definitions, dashboards); a page file only arrives with an ASIX release. This keeps signed-pack delivery from becoming a way to run script in an analyst's browser.

## Embedded open-source tools

The tool runs as its own service inside the cluster. It is never exposed outside it; the only way in is the gateway.

- **Route:** `/app/<module id>/*` on the gateway, one reverse-proxy file per tool under `src/gateway/routes/`. The route checks, in order: sign-in, the module is enabled (profile, license, dependencies), the caller holds the entry's `permission`, the tenant. Only then does it forward.
- **Sign-in to the tool:** single sign-on through Keycloak where the tool supports it; otherwise a per-tenant service identity set up by the module's installer. The browser never receives the tool's own admin credentials.
- **Tenant mapping:** the tool must keep tenants apart (its own organisations or workspaces). This is **unverified for every candidate** and is one of the spike's pass or fail checks.
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
- Shell: a module that throws, one that never finishes, one whose file is missing; each shows the card, and the next page still opens. (Follows `tests/portal-menu.test.js`: cut the marked block out of `index.html` and run it without a DOM.)
- Gateway headers and module files (**done in S3**, `tests/gateway-csp.test.js`, 18 tests): the policies as written, headers on the real app, `appHeaders` mounted before any route, what is and is not served from the modules folder, and attempts to climb out of it. Still to do in S4: `/app/<id>/` refuses a caller without the permission, a disabled module, and another tenant.
- Branding test (`tests/branding.test.js`) keeps scanning `index.html`, and also the new `src/portal/modules/**` files.

## Not decided

- Whether native pages use a small shared stylesheet or a shadow root per page. Start with the shared CSS variables and revisit if pages interfere.
- Whether `embedded` tools share one Keycloak realm with ASIX or get their own client.
- How an embedded tool's own menu is hidden so only the part we want shows.
