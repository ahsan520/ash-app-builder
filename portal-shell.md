# Portal shell and module UI contract

Status: **DESIGN, agreed with Ash 2026-11-08. Nothing here is built yet.** First task: S1 in `docs/product-plan.md`, "Status of Phase 5".

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
      page: 'marketplace.js',           // native: file in src/portal/modules/<id>/
      // url: '/app/shuffle/',          // embedded: path on the gateway (set by the module, never by a request)
      permission: 'packs:read',         // the menu entry is hidden without it; the server still decides
      order: 20,
    },
  ],
}
```

Rules the registry checks at load (a bad manifest fails `tests/modules.test.js`, never production):
- `kind` is one of the three; `entries` is non-empty; entry ids are unique inside the module and across all modules for the same `area`.
- `native` entries name a `page` file that exists; the name has no path separators.
- `embedded` entries name a `url` that starts with `/app/<module id>/`, and the module must also declare `proxy` (below).
- `permission` is a string from the module's own `permissions` list.
- Menu paths are `<area>/<module id>/<entry id>` and cannot collide with a `builtin` path.

`GET /v1/modules` already feeds the portal's menu state. It returns the `ui` entries of every module the caller may see, with `state` (enabled, locked, planned) as today. **The shell builds the menu from that answer.** The old `NAV`, `SETTINGS` and `THREAT` arrays in `index.html` stay as the fallback for `builtin` entries and for when `/v1/modules` cannot be read (the menu-state code already tolerates that: nothing is greyed out).

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

Page files are shipped inside the ASIX image, same origin, so the portal's existing CSP (`script-src 'self'`) already allows them. **Marketplace packs cannot ship portal code.** A pack can add data (rules, parsers, playbooks, action and integration definitions, dashboards); a page file only arrives with an ASIX release. This keeps signed-pack delivery from becoming a way to run script in an analyst's browser.

## Embedded open-source tools

The tool runs as its own service inside the cluster. It is never exposed outside it; the only way in is the gateway.

- **Route:** `/app/<module id>/*` on the gateway, one reverse-proxy file per tool under `src/gateway/routes/`. The route checks, in order: sign-in, the module is enabled (profile, license, dependencies), the caller holds the entry's `permission`, the tenant. Only then does it forward.
- **Sign-in to the tool:** single sign-on through Keycloak where the tool supports it; otherwise a per-tenant service identity set up by the module's installer. The browser never receives the tool's own admin credentials.
- **Tenant mapping:** the tool must keep tenants apart (its own organisations or workspaces). This is **unverified for every candidate** and is one of the spike's pass or fail checks.
- **Framing:** the portal's CSP gets `frame-src 'self'`. Only `/app/*` responses carry `frame-ancestors 'self'`; everything else under `/portal` keeps `frame-ancestors 'none'`. The shell puts the tool in an iframe with a `sandbox` attribute, and offers **Open in a new tab** for tools that refuse to be framed.
- **Network:** a NetworkPolicy lets only the gateway pods reach the tool's pods.
- **Licence:** a tool under AGPL runs as a separate program that ASIX talks to over HTTP. ASIX does not link to it or copy its code. If we ever modify and re-brand a tool and offer it to customers, its own licence terms apply to that modified copy: get a lawyer's read first (open decision in `docs/product-plan.md`).
- **When the tool is down:** the iframe area shows the same error card as a failed native page. ASIX's own pages are unaffected.

## Keeping ASIX from breaking

- A module's files are separate from `index.html`, so a change to one module cannot change another.
- The shell has no module-specific code; it only reads manifests.
- A broken or slow module page is contained by the error card and the timeout.
- A broken `ui` block is caught at load by the registry and by `tests/modules.test.js`.
- `index.html` shrinks over time: when a `builtin` page is next changed, move it to a `native` page file first, in its own change, with its tests.

## Tests this needs

- Registry: every rule above, each with a deliberate break that fails one test.
- Shell: a module that throws, one that never finishes, one whose file is missing; each shows the card, and the next page still opens. (Follows `tests/portal-menu.test.js`: cut the marked block out of `index.html` and run it without a DOM.)
- Gateway: `/app/<id>/` refuses a caller without the permission, a disabled module, and another tenant; CSP headers differ between `/portal` and `/app`.
- Branding test (`tests/branding.test.js`) keeps scanning `index.html`, and also the new `src/portal/modules/**` files.

## Not decided

- Whether native pages use a small shared stylesheet or a shadow root per page. Start with the shared CSS variables and revisit if pages interfere.
- Whether `embedded` tools share one Keycloak realm with ASIX or get their own client.
- How an embedded tool's own menu is hidden so only the part we want shows.
