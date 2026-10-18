# Broker VM (Vector)

A broker VM is a small Linux machine that sits close to your log sources, receives their syslog, and forwards
it to the ASIX data node. It holds no database credentials: it only knows one URL and one ingestion key, so a
stolen or exposed broker can be cut off by revoking that key.

```
devices ──syslog UDP/TCP 514──────────> Vector (broker VM) ──HTTPS + ingestion key──> /v1/ingest/http (ASIX)
devices ──syslog over TLS 6514 (opt.)─┘
                                   │ disk buffer (1 GiB)                              │
                                   └─ heartbeat every 60 s ────────────────────> /v1/ingest/heartbeat
```

## What you get
- **Syslog in:** UDP and TCP on one port (default 514), RFC 3164 and RFC 5424. **Optionally syslog over TLS** (RFC 5425) on its own port (default 6514), see below.
- **No server change for parsing:** Vector rewrites each event as `ISO-time host app[pid]: message`, which the
  HTTP lane already parses into host, app name, pid and event time, so existing parsing rules and the data
  model apply unchanged.
- **Survives outages:** events wait in a 1 GiB on-disk buffer when ASIX is down or rebooting, and the sources
  slow down instead of dropping when it is full. Retries back off to once a minute.
- **Per-broker identity:** one ingestion key per broker (revocable, shown with its name on the Collectors page).
  This replaces the shared `BROKER_INGEST_TOKEN` for brokers outside the cluster.
- **Heartbeat:** a one-minute timer tells ASIX the broker is alive, so a quiet broker stays **Connected**. It
  sends nothing when Vector is not healthy, so a broken broker turns Disconnected (after 15 minutes, or the threshold set for that collector on the Collectors page).

## Install
1. In the portal: **Settings > Collectors > Installers**, create an installer (platform `linux`), name it like the
   broker (for example `broker-1`), and copy the key. It is shown once.
2. Get the repo's `deploy/broker/` and `scripts/deploy/bootstrap-broker.sh` onto the broker VM (Debian or Ubuntu). The repo is public, so no login is needed.
   The script finds the files next to it, so keep the `scripts/` and `deploy/` folders side by side.

   **Option A, clone the repo** (simplest; `git pull` updates it later):
   ```bash
   sudo apt-get update && sudo apt-get install -y git
   git clone https://github.com/ahsan520/ash-app-builder.git
   cd ash-app-builder
   ```

   **Option B, download only the broker files** (no git, no full clone):
   ```bash
   mkdir -p ~/asix-broker/scripts/deploy ~/asix-broker/deploy/broker && cd ~/asix-broker
   B=https://raw.githubusercontent.com/ahsan520/ash-app-builder/main
   curl -fsSL --output-dir scripts/deploy -O $B/scripts/deploy/bootstrap-broker.sh
   for f in vector.yaml vector-tls.yaml vector-asix.conf broker.env.example \
            asix-broker-heartbeat.sh asix-broker-heartbeat.service asix-broker-heartbeat.timer; do
     curl -fsSL --output-dir deploy/broker -O $B/deploy/broker/$f
   done
   ```

   **Option C, copy from your own machine** (a private fork, or a VM with no internet):
   ```bash
   # run on your machine, from the repo folder; the VM needs scripts/ and deploy/ side by side
   ssh user@broker-vm 'mkdir -p ~/asix-broker/scripts ~/asix-broker/deploy'
   scp -r scripts/deploy user@broker-vm:~/asix-broker/scripts/
   scp -r deploy/broker  user@broker-vm:~/asix-broker/deploy/
   ```

   Then, as root, in the folder that holds `scripts/` and `deploy/` (for the CA option, copy the nginx certificate to the VM first, see below):
   ```bash
   bash scripts/deploy/bootstrap-broker.sh --url https://asix1:30443/v1/ingest/http --key asix_ik_... --name broker-1
   ```
   Run it with `bash`, so it works even if the file lost its executable bit.
   For the self-signed nginx certificate add `--ca /path/to/that-certificate.pem`; fetch it from the VM with
   `echo | openssl s_client -connect <asix-host>:30443 2>/dev/null | openssl x509 > /root/asix-cert.pem`. If Vector is already
   installed (offline or pinned version) add `--no-install`.
3. Open port 514 (UDP and TCP) on the broker VM's firewall for the devices that send syslog, and point those
   devices at the broker VM.
4. Check: `logger -n 127.0.0.1 -P 514 -T 'asix broker test'`, then **Settings > Collectors** should show
   `broker-1` as Connected, and the line appears under search.

The script validates the Vector config before restarting, and is safe to re-run (for example to change the key).

**The URL needs the port.** The platform's nginx listens on **30443** (the same port as the portal); plain 443 on the k3s box is k3s's own Traefik, which
answers every request with `404 page not found`. The ASIX certificate also lists the box's addresses, so an IP works in the URL as well as `asix1`. Test the path
before the bootstrap: `curl -sk -X POST -H 'Authorization: Bearer asix_ik_fake' https://<asix-host>:30443/v1/ingest/http` must answer `401 INGEST_AUTH_INVALID`.

**Vector versions.** The broker config is checked with Vector 0.47 and 0.59.0 (`vector validate` on the shipped files, `vector test` on `vector-tests.yaml`, and a real start
that listens on UDP and TCP). Vector 0.59 stopped substituting `${VAR}` in its config unless `VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true` is set, so the bootstrap
writes that line into `broker.env` (the service reads it through the systemd drop-in; older Vector ignores it). Without it, validation fails with
`sources.syslog_udp: Must be a valid IPv4/IPv6 address with port`. On a broker set up before this, add that line to `/etc/asix-broker/broker.env` and re-run the bootstrap
with `--no-install`. The heartbeat's health check (`http://127.0.0.1:8686/health`) still answers on 0.59.

**The IP column.** It shows the address ASIX sees the broker connect from. The platform's two NodePort Services (`nginx-control`, `asix-syslog-collector`) use
`externalTrafficPolicy: Local` so that is the broker's real address; with the Kubernetes default (`Cluster`) it was the cluster gateway, `10.42.0.1`, for every collector.
`Local` needs the pod on the node that receives the traffic, which is true on the single-node k3s box. To apply it without redeploying:
`kubectl -n asix-platform patch svc nginx-control asix-syslog-collector -p '{"spec":{"externalTrafficPolicy":"Local"}}'` (back: `Cluster`). The column updates at the broker's next heartbeat.

## Syslog over TLS (optional)
Plain syslog is readable and forgeable by anyone on the path. For sources that cross a network you do not control, add the TLS listener:
```bash
./scripts/deploy/bootstrap-broker.sh --url https://asix1:30443/v1/ingest/http --key asix_ik_... --name broker-1 \
    --tls-cert /path/server.crt --tls-key /path/server.key [--tls-port 6514] [--tls-client-ca /path/client-ca.pem]
```
- The certificate is the broker's own. Devices must trust whoever issued it, and its name or IP must match what they connect to. The
  script checks that certificate and key belong together before changing anything.
- **Without `--tls-client-ca`** any device can connect and the traffic is encrypted. **With it** (mutual TLS) every sender must present a
  certificate issued by that CA; a sender with none, or with one from another CA, is refused at the handshake.
- UDP and plain TCP stay as they were on `--port`. To turn TLS off, re-run the script without the `--tls-*` options: it removes the listener
  and its copy of the key. Open the TLS port (default 6514/tcp) on the VM's firewall.
- Both framings are accepted: newline-delimited and RFC 5425 octet-counted (`<length> <message>`). Events then take the same line rewrite,
  disk buffer and HTTPS sink as every other syslog source; nothing changes on the ASIX side and there is no schema change.
- How it is wired: `deploy/broker/vector-tls.yaml` is a second Vector config file with one source, `syslog_tls`; the transform in `vector.yaml`
  reads `syslog_*`. The script sets `VECTOR_CONFIG=/etc/vector/vector.yaml,/etc/vector/vector-tls.yaml` in `broker.env`, which the Vector
  package's service picks up (its unit runs plain `/usr/bin/vector`). The key is stored `640 root:vector` in `/etc/asix-broker/tls/`.
- Check on the broker: `openssl s_client -connect 127.0.0.1:6514 -CAfile <issuing CA>`, then send one line, for example
  `printf '<34>1 2026-10-17T10:00:00Z host app 1 - - tls test\n' | openssl s_client -connect 127.0.0.1:6514 -CAfile <CA> -quiet`
  (add `-cert`/`-key` with mutual TLS). The line shows in search with source `syslog` and the broker's name.
- A device configured for TLS syslog that the broker refuses (wrong CA, expired certificate, no client certificate) only fails on the device
  side; look at `journalctl -u vector` on the broker. Certificates are not renewed for you: replace the files and re-run the script.
- **Checked** with Vector 0.47.0: both config files validate; with a test CA, newline-framed and octet-counted lines over TLS arrived at the
  HTTP sink in the expected `ISO-time host app[pid]: message` form; with mutual TLS on, the sender with a certificate from the CA got through
  and a sender with no certificate and one with an untrusted certificate did not; the bootstrap script ran for real (only `systemctl`
  stubbed) with and without TLS, refused a key that does not match, a certificate without a key and a TLS port equal to the plain port, and
  removed the listener when re-run without TLS. `tests/broker-tls-config.test.js` (in `npm test`) keeps the three files in step. **Not yet
  tried:** on a real broker VM under systemd, and with real devices (rsyslog, syslog-ng, network gear). Vector is still not in CI.
- Not covered: the in-cluster Node collector (`src/ingestion/syslog-server.js`) has no TLS listener; use a broker VM for TLS sources.

## Files
| File | Purpose |
|---|---|
| `deploy/broker/vector.yaml` | Vector config: syslog sources, line rewrite, HTTP sink with disk buffer |
| `deploy/broker/vector-tests.yaml` | Vector unit tests for the line format: `vector test deploy/broker/vector.yaml deploy/broker/vector-tests.yaml` |
| `deploy/broker/vector-tls.yaml` | Optional second Vector config: the syslog-over-TLS source (installed only with `--tls-cert`) |
| `deploy/broker/broker.env.example` | Settings (`/etc/asix-broker/broker.env` on the VM, mode 640) |
| `deploy/broker/vector-asix.conf` | systemd drop-in: loads the env file, lets Vector bind port 514 |
| `deploy/broker/asix-broker-heartbeat.{sh,service,timer}` | The one-minute heartbeat |
| `scripts/deploy/bootstrap-broker.sh` | Installs and starts everything |
| `src/ingest/heartbeat.js` | Server side: `POST /v1/ingest/heartbeat` (ingestion key) |

## Heartbeat API
- `POST /v1/ingest/heartbeat` with `Authorization: Bearer asix_ik_...`. Optional JSON
  `{"collector":{"name","platform","os","version"}}` or the `X-ASIX-*` headers used by the HTTP lane; the name
  defaults to the key's name. Creates or refreshes the collector row (`last_seen`), writes no event and no audit
  row. Limit: 30 per minute per key (`HEARTBEAT_RATE_PER_MIN`).
- `POST /v1/ingest/heartbeat/broker` with the shared `BROKER_INGEST_TOKEN` and
  `{"tenant_id" | "tenant_name", "collector_id", "version"}`. Used by the in-cluster syslog collector
  (`src/ingestion/syslog-server.js` sends it every 60 s; `SYSLOG_HEARTBEAT_SECONDS=0` turns it off,
  `INGEST_HEARTBEAT_URL` overrides the address). The row is key-less, which the Collectors page shows as
  **built-in**, merged with the event counts it already derived from events.

## Limits and not built yet
- One syslog port for UDP and TCP, plus the optional TLS port. No non-syslog sources (files, Windows events, Kafka) on the broker yet.
  TLS certificates are not renewed or reloaded for you (re-run the script after replacing them).
- The portal has a read-only **Brokers** page (Settings, Brokers: status, Vector version, events in 24 hours, installer key state, what needs attention, and the
  command to add a broker). It cannot change a broker: there is no remote config push, upgrade or capacity view. A broker is recognised by its heartbeat's
  version text (`vector-<version>`), so a broker that has never sent a heartbeat does not appear. `src/brokers/broker-framework.js` is still the Phase 3 placeholder.
- A 4xx other than 408/429 from ASIX (for example a revoked key) is not retried by Vector, so those events are
  dropped; fix the key and re-run the bootstrap script.
- The connected/disconnected threshold is 15 minutes unless you set one for that collector (Collectors page, **Threshold**; 1 to 10080 minutes). A broker
  with a long quiet spell does not need it: the heartbeat keeps it Connected. It is for slow senders such as a nightly job.

## Getting an alert when a broker goes quiet
A broker that stops (Vector down, VM off, network cut) shows as Disconnected on the Collectors and Brokers pages, but nothing tells you unless you look. On the
Collectors page, press **Alert if down** on the broker's row: ASIX then raises a `Collector disconnected: <broker name>` alert (severity high) once the broker has
been silent longer than its connected threshold, and closes it when the broker's heartbeat returns. Add a notification channel (Settings, Notifications) to be told
by email, Slack or webhook. It is off until you press the button; a slow or rarely used broker should get a longer threshold first (**Threshold** button). Details:
`docs/product-plan.md`, "Collector disconnect alerts".

## Replacing a broker's key
If a key leaked, or the old one was revoked, press **Rotate key** on the broker's row on the Brokers page. ASIX makes a new key and shows it once with the bootstrap command for
that broker. Run that command on the broker VM, as root, with the same `--ca` or `--tls-*` options as the first install. The broker keeps working on the old key until you
revoke it, so do the revoke last: when the broker shows Connected again, press **Revoke old key** in the same dialog, or revoke it on the Installers page.
