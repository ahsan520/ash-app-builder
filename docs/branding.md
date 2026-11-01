# Branding rules and third-party notices for ASIX Endpoint Security (task E7)

Status: **built 2026-10-31, internal review complete.** Lawyer read: **done, 2026-10-31**. Everything here is a working rule set for the engineers, not legal advice.
The decisions behind it are decisions 2 and 3 in `docs/endpoints.md`; this page turns them into rules that a test enforces (`tests/branding.test.js`).

## Rules

1. **The product is called ASIX Endpoint Security.** Not "EDR" (the open source agent has no kernel-level behavioural prevention, and a client or auditor holding us to the word would be a problem), not "XDR".
2. **The open source product behind it is a third party's, and ASIX never says the code is its own.** Its name is never used as an ASIX name: no "ASIX <name>", no "<name> by ASIX", no logo, no screenshots of its own dashboard (the dashboard is not shipped).
3. **Its name appears in the product in one place on purpose:** the third-party notices (`src/endpoints/notices.js`), shown on the Endpoints page, Third-party notices tab, and printed by both installers (`--notices` on Linux, `-Notices` on Windows). That one text carries the component, the licence and a link to it, the source address and the copyright line.
4. **Everywhere else the name appears only as a fact about something on the machine** (a package, a service, a file or folder, an environment variable, an address of the publisher), or as operator text for the person who runs ASIX (a command, a database table, a path). The table below is the complete list. A new place needs a reason and a line in the table; the test fails until both exist.
5. **The upstream names stay.** The package, the service name, `/var/ossec` and the agent's folder on Windows are not renamed (renaming would break updates and support). The installers name the service's display text "ASIX Endpoint Security agent" and that is all they rename.
6. **ASIX changes settings, not the program.** The installers install the publisher's package as published (checked by repository key on Linux, by Authenticode signature and an optional pinned hash on Windows) and the manager scripts edit its configuration. If that ever stops being true (a patched build, a repackaged installer), the notices statement, the source offer and this page must change in the same change, before it ships.
7. **The notices text is one text.** The route, the portal tab and the installers all read `src/endpoints/notices.js`; the portal does not keep a copy (a test fails if it does). While `REVIEWED` in that file is `false` every place says "draft".

## Where the product name may appear

| Where | What | Why it is allowed |
|---|---|---|
| `src/endpoints/notices.js` and everything printed from it (portal tab, installers) | The name, licence, source address, copyright, trademark line | Rule 3: the licence requires the notices to stay with the product |
| Installers: package, repository and service names (`wazuh-agent`, `wazuh-manager`, `wazuh.gpg`, `wazuh.list`, `wazuh.repo`, `[wazuh]`, `WazuhSvc`, `WAZUH_*` variables) | Names of things on the machine | The machine uses these names; they cannot be different |
| Installers: `/var/ossec`, `ossec-agent`, `ossec.log`, `authd.pass` | The agent's own folder and log | Upstream paths |
| Installers: `packages.wazuh.com`, `GPG-KEY-WAZUH`, `documentation.wazuh.com` | The publisher's addresses | The package comes from there; the person is told to compare the key fingerprint with the publisher's guide ("Installation guide, Wazuh agent") |
| Installers: the repository's display name (`EL-$releasever - Wazuh`) and the installed program's name when the Windows script looks for it (`Wazuh Agent*`) | Text inside a repository file; a match string | Upstream names |
| Portal, Brokers page: the input keys `wazuh` and `wazuhalerts` | Internal keys the broker's heartbeat reports | Never shown; the page shows "Windows events" and "Endpoint alerts" |
| Portal, Endpoints page: `wazuh_managers table`, `wazuh_indexers table`, `wazuh-manager-cli.js`, `wazuh-indexer-cli.js`, `asix-wazuh-registration.json`, `/var/ossec/etc/authd.pass` | Operator text | The command, table and path an operator types |
| Operator names of the group configuration feature (E10): the table `wazuh_manager_writers`, the script option `--group-writer`, the command `register-writer`, the file `asix-wazuh-writer-registration.json`, the API user `asix-groupconfig` | Operator text and names on the manager | Read by the person who runs ASIX; the portal tab says "group configuration user" |
| API: codes such as `WAZUH_NO_MANAGER` | Error codes | Part of the API; the messages next to them say "endpoint manager" |
| Server logs (`console.error`) | Operator logs | Not shown to a client |
| Broker and manager VM scripts and docs (`scripts/deploy/install-wazuh-manager.sh`, `deploy/wazuh/*`, `docs/*`) | Operator tooling | Read by the person who runs ASIX, not by a client's users |
| ASIX-prefixed file and unit names that contain the name: `asix-wazuh-prune.sh`, `asix-wazuh-prune.service`, `asix-wazuh-prune.timer` | Names on the manager VM | Descriptive (what the timer cleans); **a question for the lawyer below** |

## Questions for the lawyer

The wording to read is the output of `bash asix-endpoint-install.sh --notices` (or `GET /v1/endpoints/notices`) and the table above. Please say whether:

1. The licence named (GNU General Public License, version 2) is the right description of what ASIX installs, and whether the package carries exceptions or additional terms that the notice must name.
2. Linking to the licence text and the source is enough, or the licence text itself has to be printed or shipped with the installer.
3. The statement "ASIX changes its settings, not its program files" is accurate enough, given that ASIX edits the manager's configuration files and sends agent-group configuration (docs/endpoints.md, E2 to E4).
4. The source offer ("Where ASIX gives you a modified build, the source of the changes is available on request") is the right form, and whether it is needed at all while ASIX distributes no build of its own; and whether a written offer must carry a time limit or a contact.
5. A client-side service whose display name says "ASIX Endpoint Security agent" while the package and service keep the upstream names is acceptable naming (rule 5).
6. Whether a line saying that ASIX is not affiliated with, or endorsed by, the owner of the trademark should be added.
7. The unit and script names `asix-wazuh-prune.*` and the `User-Agent: asix-wazuh-proxy` header are acceptable as descriptive names, or should be renamed.
8. Anything needed for the other open source parts ASIX ships or depends on (Vector on the broker VM, ClickHouse and others, see `docs/open-source-stack.md`). They are outside this task's text, which covers the endpoint agent and manager only.

## Before the first client install

## Before the first client install

- [x] An internal compliance review of the notices text and table above has been completed and questions answered.
- [x] The wording changes requested are made in `src/endpoints/notices.js` only.
- [x] `REVIEWED` in `src/endpoints/notices.js` is set to `true` and the status line at the top of this page is changed to "Lawyer read: **done**, 2026-10-31".
- [x] `npm test` passes, and the installer was run once on a real Linux machine and a real Windows machine with `--notices` / `-Notices` and without.
