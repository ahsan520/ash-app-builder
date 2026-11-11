# Design reference: what we take from the XSIAM screenshots

Status: **DESIGN, 2026-11-08.** Ash shared six screenshots of Cortex XSIAM (Marketplace, Autonomous Playbooks / integrations, Agentic Assistant Hub actions, Endpoint Policy Management, Posture menu, Modules). They are a reference for **what a SIEM like this needs to do**, not a layout to copy.

## Rules

1. **We do not copy the GUI.** No copied screens, names, wording, icons or colours. We take the ideas (what objects exist and how they relate) and draw our own, simpler pages. This also keeps to `docs/branding.md`.
2. **As many features as possible, with a simple GUI.** Each page does one job. Sensible defaults. Advanced options behind an "Advanced" fold. Setup as a short wizard, not a form with forty boxes. No more than two clicks from the menu to the main action.
3. **Adopt before build.** A feature we can get from a good open-source tool is shown under our portal (see `docs/portal-shell.md`), not rewritten. What stays ours is the thin layer that makes it safe: sign-in, tenant, approval, audit, undo.
4. **A page only exists when its backend exists** (unchanged from `docs/ui-architecture.md`).

## Ideas worth taking

| Idea seen | What it means for ASIX | Task |
|---|---|---|
| A marketplace pack is a **bundle with a page of its own**: publisher, version, certified or not, who supports it, first created, last release, "Update to x.y.z", dependencies, version history, a "show deprecated content" switch, and a count of what is inside (actions, scripts) | Pack manifest v2 with typed items and dependencies; Browse and Installed views; a pack page. Our own words and layout. | MK1, MK2 |
| **Installing a pack does not configure it.** Integrations sit in a list as "Not configured" until credentials are added | Separate Integrations (instances and status) and Credentials (through the secrets abstraction in `docs/plan.md` H.7). A pack brings the definition; a person adds the account. | SR1 |
| An **action registry**: each action has a name, publisher, description, kind (script or command) and a source; many are shown **Disabled** | Same idea, with the safe default: **an installed action starts disabled**; an admin turns it on, per tenant. This is the allow-list for firewall blocks and endpoint actions. | SR2 |
| **Integrations by category**: Investigation, Remediation, Data collection, Mail sender | Tag every integration with what it can do; a playbook only offers actions of the right kind. | SR1 |
| **Lists** and an **external dynamic list** integration | A tenant's lists (block, allow, watch) as a first-class object, and a read-only URL a firewall can poll. This is the low-risk way to push IOCs to a firewall. | L1 (built, `docs/lists.md`) |
| **Cases** group **issues** (alerts) | Today "Cases & Issues" is the alert list. A minimal case record that alerts attach to is the first step SOAR needs. | CS1 |
| **Policy rules**: grouped by platform, ordered, aimed at a group or machine, tied to named profiles, with a risk warning and a stale-target message | Group settings (E10, E11, E13) becomes **Profiles** (what to monitor) plus **Rules** (platform, target group, order). Wazuh merges settings when a machine is in several groups and has no per-rule order, so ASIX must work out and show the merged result. | PM1 |
| A banner saying **staged content** was not enabled | Pack and rule updates can go to a few machines first, then everyone. | MK3 |
| Menu grouped by purpose: Data Management, Automation, Integrations, Object Setup, Access | Regroup Settings by purpose when the shell lands (the groups can change in the manifests, not in code). | S5 |
| Posture area: Vulnerability Management, Compliance, Rules & Policies | Our Vulnerabilities (E6e) and Configuration checks (E6d) tabs already are this. Show them under **Posture Management**, which is "soon" today. | S5 |
| Menu: Tenant Navigator and a notifications count | Tenant switcher in the header; a notifications count from the existing delivery log. | later |

## Ideas we leave out (for now)

- AI agents and an assistant hub (module `ai-assistant` stays planned; the action registry comes first and is what an assistant would call).
- Cloud-specific security areas (code-to-cloud, AI security, Kubernetes security): not endpoint or log work, no backend.
- A shopping-cart style install flow, billing and partner programme (`docs/marketplace.md` Phases 5 and 6).

## How it fits the rest

- Menu and page loading: `docs/portal-shell.md`.
- Which tools we adopt, and why: `docs/open-source-stack.md`.
- Tasks, order and open decisions: `docs/product-plan.md`, "Status of Phase 5".
- `docs/marketplace.md` is a separate, generic marketplace project plan. We use only its ideas for package review and signing; its web store, SDK, community and revenue phases are not part of Phase 5.
