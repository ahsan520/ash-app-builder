# The central Wazuh indexer (task E6e): what to provision, how to set it up, how ASIX reads it

Status: **ASIX side built 2026-11-01** (registry, read-only client, three routes, the Vulnerabilities tab; see `docs/endpoints.md`, "E6e as built"). **Not built:** the manager side (E6g: turning vulnerability detection on and pointing the manager at this indexer) and an installer script for the indexer VM (E6h). Until both exist the steps below are done by hand, and **nothing in this page was run against a real Wazuh indexer**: it is written from the Wazuh documentation and from what the stand-in in `tests/fixtures/fake-wazuh-indexer.js` was built to match. Where a step is a guess, it says so. Check each command against the Wazuh 4.14 installation guide before running it.

## Decisions (change them if you disagree)

1. **Why an indexer at all.** From Wazuh 4.8 the manager keeps the vulnerabilities it detects only in the Wazuh indexer, in an index named `wazuh-states-vulnerabilities-<manager name>`. The manager API no longer lists them, and the manager turns detection off without an indexer. So the Vulnerabilities tab needs one.
2. **One central indexer for ASIX, on its own VM. Not on the broker VMs, not a Kubernetes pod.** The broker VM stays small (E4b sizes). The indexer is a Java search engine that wants memory and fast disk, like the central manager (E4c), so it is a VM for the same reasons.
3. **It holds the vulnerability findings and nothing else.** No alerts, no archives: ASIX already stores and searches those. This keeps the disk small and the indexer's job narrow.
4. **One index per manager, one indexer user per tenant that can read only that index.** ASIX stores the exact index name per tenant and never takes it from a request (`src/endpoints/wazuh-indexer-store.js`). The indexer user's role is a second wall behind ASIX's own.
5. **The events of enterprise customers stay in ClickHouse; OpenSearch is not needed for them.** See the last section.

## What to provision

These are **my estimates, not measurements**. Wazuh's published sizing (4 vCPU, 8 GiB, 50 GB for 1 to 25 agents on one host) is for the whole stack with alerts indexed, so it is not this indexer's job, but it is a floor for memory. Look again after the first real client.

| Size | vCPU | Memory | JVM heap | SSD disk | Machines (all tenants together) |
| --- | --- | --- | --- | --- | --- |
| **start here** | **4** | **16 GB** | **8 GB** | **100 GB** | **up to about 500** |
| larger | 8 | 32 GB | 16 GB | 250 GB | up to about 5,000 |
| beyond | 3 nodes, each 8 vCPU / 32 GB | | 16 GB | 250 GB each | one replica per index, so a node can be lost |

- **Disk arithmetic.** A finding is one document of roughly 1.5 to 3 KB. A Linux server often has 50 to 300 findings, a Windows machine more. 5,000 machines x 200 findings x 3 KB is about 3 GB before overhead; with overhead and a replica count of 0 or 1, still far under the table. **Memory (heap) is the limit, not disk.**
- **Heap** is half of the memory, never above about 31 GB. Set it in the indexer's `jvm.options` (`-Xms` and `-Xmx` the same).
- **A single node is not highly available.** The findings can be rebuilt (the manager scans again), so one node is acceptable at the start; a second and third node come with the first client that needs the tab to survive a node loss. (How fast a manager resends its findings after the index is lost has not been tried.)
- **OS and kernel setting.** Ubuntu 22.04 or 24.04 (both are on Wazuh's supported list). Set `vm.max_map_count=262144` (OpenSearch refuses to start in production mode without it) and keep the disk under about 80% full: OpenSearch stops allocating at its low watermark (85%) and blocks writes at the flood-stage watermark (95%).
- **Network.** 9200/tcp from the managers (broker VMs, central managers) and from the ASIX API pods **only**; 9300/tcp between indexer nodes only; never to the internet. The manager also needs outbound HTTPS for the vulnerability feed (Wazuh's own content service; check the host name on the pinned version, and that the client's firewall allows it).

## Set-up, in this order

1. **Create the VM** (table above). Static address or a stable name. Clock in sync (`docs/vm-clock.md`).
2. **Install the indexer with Wazuh's installation assistant.** The assistant's indexer-only steps are, as I know them for 4.x: write a `config.yml` naming the indexer node, `bash wazuh-install.sh --generate-config-files`, then `bash wazuh-install.sh --wazuh-indexer <node name>`, then `bash wazuh-install.sh --start-cluster` on one node (check the exact options in the 4.14 guide). It makes the certificates (`wazuh-install-files.tar`: a root CA, the node certificate, an admin certificate) and the passwords of the built-in users. **Keep that tar and the password file offline; they are the keys of the indexer.** Pin the package version the way `install-wazuh-manager.sh` pins the manager's (4.14.9).
3. **Create one read-only user and role per tenant** (as the indexer's `admin`, with the security API; the paths are the OpenSearch security plugin's, which Wazuh ships, not tried here):
   ```
   PUT  /_plugins/_security/api/roles/asix_vuln_read_<tenant>
        { "index_permissions": [ { "index_patterns": ["wazuh-states-vulnerabilities-<manager name>"], "allowed_actions": ["read"] } ] }
   PUT  /_plugins/_security/api/internalusers/asix-vuln-<tenant>      { "password": "<long random>" }
   PUT  /_plugins/_security/api/rolesmapping/asix_vuln_read_<tenant>  { "users": ["asix-vuln-<tenant>"] }
   ```
   ASIX only ever asks for a count and a search on that one index, so `read` on that exact name is enough. **Do not use `admin` for ASIX.**
4. **Point the manager at the indexer (E6g, by hand until it is built).** From the Wazuh documentation for 4.8 and later, in the manager's `ossec.conf`: `<vulnerability-detection>` with `<enabled>yes</enabled>` and `<index-status>yes</index-status>`, and an `<indexer>` block with `<enabled>yes</enabled>`, the indexer's `<hosts>`, and `<ssl>` pointing at the root CA and a client certificate and key; the indexer user name and password go into the manager's keystore (`/var/ossec/bin/wazuh-keystore`), not into `ossec.conf`. The manager's writer user needs more than read: give it its own role on its own index pattern with write and index-creation rights, and widen it if `ossec.log` reports a refused action (I do not know the exact action list the connector needs). **Re-running `install-wazuh-manager.sh` switches detection off again** (E4b does that on purpose); E6g will make it a choice.
5. **Wait for the first scan.** The manager downloads the feed, then scans each machine's installed software. Check on the indexer: `GET /_cat/indices/wazuh-states-vulnerabilities-*?v` (as admin). The name you see is the index to register.
6. **Register it in ASIX** (an operator, from where `kubectl` works). `ca_pem` is the indexer's **root CA** (`root-ca.pem`), exactly one certificate:
   ```
   {"url":"https://wazuh-indexer.internal:9200","user":"asix-vuln-acme","password":"...","ca_pem":"-----BEGIN CERTIFICATE-----...","index":"wazuh-states-vulnerabilities-<manager name>","label":"Acme"}
   kubectl -n asix-platform exec -i deploy/asix-api -- node src/endpoints/wazuh-indexer-cli.js register --tenant "Acme Corp" < indexer-registration.json
   kubectl -n asix-platform exec    deploy/asix-api -- node src/endpoints/wazuh-indexer-cli.js check    --tenant "Acme Corp"
   ```
   `register` reads the index first and saves only if that works; use `--no-check` when the index does not exist yet. Then open Endpoints, **Vulnerabilities**.
7. **Change a password or replace the certificates:** run `register` again (it replaces the row). A replaced indexer certificate shows in the tab as `TLS: the indexer's certificate is not the one registered` until you do.

## What ASIX reads, and what it never does

Two calls only: `GET /<index>/_count` and `POST /<index>/_search` with a body ASIX builds from a short list of validated filters (severity, machine id, vulnerability id, text; sort; 100 rows at most). It never sends a body, an index name or a path from a request, never writes, follows no redirects, and trusts only the registered certificate. The answer is cut down to a fixed list of fields. The field names it reads are the documented ones for 4.8 and later (`agent.id`, `agent.name`, `package.name`, `package.version`, `vulnerability.id`, `vulnerability.severity`, `vulnerability.score.base`, `vulnerability.detected_at` and a few more). **If the real index spells one differently, that column shows a dash and the filter on it finds nothing**: that is the first thing to look at on the first real run (`GET /<index>/_search?size=1` as admin shows a real document).

## Events: is OpenSearch needed for fast search? (answer for enterprise customers)

**No: ClickHouse is enough for ASIX's own events, and OpenSearch is only here because Wazuh insists on it for findings.** ASIX searches are time-bounded and tenant-bounded, and the table is already laid out for that: `src/events/clickhouse-store.js` sorts it by `(tenant_id, received_at, id)`, so a search over a recent window reads a small slice. Counts, group-bys and top-N (what a SIEM does all day) are where ClickHouse is much faster and far cheaper per GB than a search engine. Where a search engine is better is **free-text search across every field of a large, unstructured log**. The table has **no text index today** (I looked: only the sort key), so a search for a word inside the raw message scans the window. If that becomes slow, the fix is in the table design, not a second system: keep parsed fields as real columns so the common searches never touch the raw text, and add a token or n-gram skip index on the raw message column. If the first enterprise customer's real searches turn out to be mostly free text over many months of raw logs and are still slow after that, measure it then; adding OpenSearch for events would mean a second copy of the data, a second store to secure per tenant, and a second thing to patch.
