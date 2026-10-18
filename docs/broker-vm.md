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
| `deploy/broker/asix-broker-config.{sh,service,timer}` | Optional (`--accept-config`): asks ASIX every 5 minutes for the syslog port and applies it after its own checks |
| `scripts/deploy/bootstrap-broker.sh` | Installs and starts everything |
| `src/ingest/heartbeat.js` | Server side: `POST /v1/ingest/heartbeat` (ingestion key) |
| `src/ingest/broker-config.js`, `src/brokers/config.js` | Server side of the config pull: `GET /v1/ingest/broker-config` (ingestion key) |

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
  command to add a broker). It cannot push a change to a broker: the only config is the syslog port brokers can pull (see "Config from ASIX" below; a broker can be set to accept it only with ASIX's signature, see "Signed config"), there is no remote upgrade (it shows which brokers are behind a target Vector version and gives the command, see "Upgrading Vector" below) and no capacity view. A broker is recognised by its heartbeat's
  version text (`vector-<version>`), so a broker that has never sent a heartbeat does not appear. `src/brokers/broker-framework.js` is still the Phase 3 placeholder.
- A 4xx other than 408/429 from ASIX (for example a revoked key) is not retried by Vector, so those events are
  dropped; fix the key and re-run the bootstrap script.
- The connected/disconnected threshold is 15 minutes unless you set one for that collector (Collectors page, **Threshold**; 1 to 10080 minutes). A broker
  with a long quiet spell does not need it: the heartbeat keeps it Connected. It is for slow senders such as a nightly job.

## Config from ASIX (optional, syslog port only)
ASIX never connects to a broker. A broker that was installed with `--accept-config` asks ASIX for its config instead, and only that kind of broker:
```bash
sudo ./scripts/deploy/bootstrap-broker.sh --url https://asix1:30443/v1/ingest/http --key asix_ik_... --name broker-1 --accept-config
```
This writes `ASIX_ACCEPT_CONFIG=true` to `broker.env` and installs `asix-broker-config.timer`, which runs `asix-broker-config.sh` as root two minutes after boot and then every 5 minutes. Re-running the bootstrap script **without** `--accept-config` turns it off again
(and, as always, rewrites `broker.env` from the flags you give it, so give `--port` again if the broker was told to use another one, and `--config-pubkey` again if it was set up to require signed config, see "Signed config" below).
A broker installed before this existed can be switched on by re-running the bootstrap script with the same options plus `--accept-config`.

**Setting it:** Brokers page, **Syslog port for brokers** card (`GET` and `PUT /v1/broker-config`, body `{ "syslog_port": 1514 | null }`; `collectors:read` / `collectors:write`, no role change). One value for the whole tenant; empty means "no opinion": brokers keep what they have.
The broker asks with `GET /v1/ingest/broker-config` and its own ingestion key and gets `{ "config": { "syslog_port": 1514 | null }, "interval_seconds": 300 }` (read only, no audit row, same rate limit and key rules as the heartbeat; a revoked key gets nothing).
After every pull the broker also tells ASIX what it is listening on: `POST /v1/ingest/broker-config/report` with `{ "collector": "broker-1", "syslog_port": 1514, "rejected_port": null }` and the same key (see "What the Brokers page shows" below). That is information only; it changes no setting.

**Updating a broker after an ASIX deploy (the commands used on broker-1):** on the broker VM, pull the repo, make the scripts executable, then re-run the bootstrap with the broker's own settings read back from `broker.env`. The bootstrap rewrites `broker.env` from the flags you give it, so the port and CA are passed again; **add `--tls-cert`, `--tls-key` (and `--tls-port`, `--tls-client-ca`) as well if the broker takes syslog over TLS, or the TLS listener is removed.** Run the bootstrap as root (`sudo`).
```bash
cd /home/ash/ash-app-builder
git pull && find . -name '*.sh' -not -path './node_modules/*' -exec chmod +x {} +

. /etc/asix-broker/broker.env
cp /etc/asix-broker/ca.pem /tmp/asix-ca.pem 2>/dev/null

./scripts/deploy/bootstrap-broker.sh \
  --url "$ASIX_INGEST_URL" --key "$ASIX_INGEST_KEY" --name "$ASIX_BROKER_NAME" \
  --port "${ASIX_SYSLOG_PORT:-514}" ${ASIX_CA_FILE:+--ca /tmp/asix-ca.pem} \
  --no-install --accept-config
```
(`--no-install` because Vector is already there; `--accept-config` keeps the config pull on.) It validates the Vector config before restarting and ends with "ASIX may now change this broker's syslog port".

**Changing a port and checking it at once:** in the ASIX GUI, Brokers page, set the tenant-wide port on the card or press **Port** on one broker's row. The broker asks every 5 minutes; to not wait, on the broker VM:
```bash
sudo systemctl start asix-broker-config.service
sudo journalctl -u asix-broker-config -n 15 --no-pager
ss -lunt | grep <port>
logger -n 127.0.0.1 -P <port> -T 'port test'
```
The journal shows "ASIX asks for syslog port N (now M). Applying." then "Done: syslog port M -> N, Vector healthy". No journal lines at all means ASIX asked for no port or the one already in use. Open the port (UDP and TCP) on the VM's firewall for real devices; the script never does.

**A port for one broker (done 2026-10-18):** the tenant-wide port is one value for every broker that opted in. To give ONE broker a different port, press **Port** on its row on the Brokers page (`PUT /v1/brokers/:id/syslog-port`, body `{ "syslog_port": 2514 | null }`; `collectors:write`, no role change; empty or `null` puts the broker back on the tenant-wide port). It is stored on that broker's own row (`collectors.syslog_port_override`, a new nullable column with a 1 to 65535 CHECK, added by the normal schema job and safe to re-run) and **wins over the tenant-wide port for that broker only**; it works with no tenant-wide port set. The same port rules apply (22, 443, 8686 and 30443 are refused with a reason).
The broker now asks with its name, `GET /v1/ingest/broker-config?collector=broker-1`, and gets its effective port in the same `{ "config": { "syslog_port": ... } }` shape (the row is found by the sending key AND the name, so one key cannot read another broker's port; a name with no row, or no name, gets the tenant-wide port). **The script on the broker must be the current `asix-broker-config.sh`**: re-run `bootstrap-broker.sh` from the updated checkout with the broker's usual options plus `--accept-config`. A broker still on the older script sends no name, is told the tenant-wide port, and its row will show **Pending** for the port it was given. The Syslog port column judges each broker against the port it is asked for and shows `(own)` next to one set for that broker alone.
**Run on broker-1 (vm1, 2026-10-18):** the bootstrap re-run installed the new script; after the port was set in the GUI one pull logged "ASIX asks for syslog port 2514 (now 1514). Applying." and "Done: syslog port 1514 -> 2514, Vector healthy", and `ss` showed Vector listening on 2514 UDP and TCP. Not yet confirmed: the test line arriving in Events, the column showing Applied (own), and clearing the port to go back.

**Leaving one broker out of the tenant-wide port (done 2026-10-18):** the tenant-wide port is for every broker that opted in; a broker that must keep the port it has (a device class that cannot move, a port that is taken on that VM) can be left out of it. Press **Leave out** on its row on the Brokers page (`PUT /v1/brokers/:id/syslog-port-exclude`, body `{ "exclude": true | false }`; `collectors:write`, no role change; **Follow port** puts it back). It is stored on that broker's own row (`collectors.syslog_port_exclude`, a new `BOOLEAN NOT NULL DEFAULT false` column added by the normal schema job and safe to re-run; only a broker, meaning a collector whose version reads `vector-<version>`, of the caller's own tenant can be set, otherwise 404).
- **What the broker is told:** `GET /v1/ingest/broker-config?collector=<name>` answers `{ "config": { "syslog_port": null } }` for a left-out broker, which the broker script already treats as "no opinion, leave everything as it is", so **no change to the broker script is needed**. Nothing is pushed and nothing on the broker changes when the flag is set: it keeps the port it listens on now, whatever that is. **A port set for that broker alone (the Port button) still applies**, because it was chosen for that broker; the flag then does nothing until that port is cleared.
- **Needs the broker to send its name**, like the per-broker port: the flag is found by the sending key AND the name, so one key cannot read another broker's flag. A broker still on a script that sends no name (older than 2026-10-18) is told the tenant-wide port whatever the flag says; re-run `bootstrap-broker.sh` from the updated checkout with the broker's usual options plus `--accept-config` to replace the script.
- **Without a tenant-wide port** the flag is kept but has nothing to hold back (the page shows **Left out** with a note saying so).
- **What the Brokers page shows:** a **Left out** pill in the Syslog port column (with the port the broker reports, if it has reported), a **Leave out** / **Follow port** button, and a "N left out" note on the port card. A left-out broker is asked for nothing, so it is counted neither as applied nor as not applied: the card's pill now reads "N of M applied" with M = the brokers that are asked for a port (before this it used all brokers as M).
- **If you leave a broker out after it already applied the tenant-wide port,** it keeps listening on that port; leaving out does not send it back. To move it, give it its own port with the **Port** button, or change `ASIX_SYSLOG_PORT` in `broker.env` on the VM and restart Vector.

**What the broker does with it, in order, stopping at the first failure:**
1. Does nothing for `null`, or when the port is already the one in use.
2. Checks the port itself, whatever ASIX sent: 1 to 65535, not 22, 443, 8686 (Vector's health API) or 30443, and not this broker's own syslog-over-TLS port.
3. Edits only the `ASIX_SYSLOG_PORT` line of `broker.env` (the previous file is kept as `broker.env.before-config`), runs `vector validate` on the result, restarts Vector and waits up to 30 seconds for its health check.
4. If validation, the restart or the health check fails, it puts the old `broker.env` back, restarts Vector on it, and remembers the rejected port in `/var/lib/asix-broker/config-rejected`, so it does not retry every 5 minutes. A different port from ASIX is tried again.

**It does not open the firewall and does not move your devices:** after a change, open the new port (UDP and TCP) on the broker VM and point the senders at it; until they are changed they send to a port nobody listens on. Check what happened with `journalctl -u asix-broker-config -n 20`.
Seen working on broker-1 (vm1, Ubuntu aarch64, Vector 0.59.0, 2026-10-18): after the port was set to 1514 one pull applied it, Vector was healthy, and it listened on 1514 UDP and TCP with nothing on 514; with no port set the pull changes nothing. The way back (setting 514 again) and the failure paths have only run against stubs. Under systemd the service runs as root with `StateDirectory=asix-broker`; the journal shows its lines under `asix-broker-config.sh`.
The TLS port, the key, the certificates and the ASIX URL are never changed this way.

**What the Brokers page shows (done 2026-10-18):** a **Syslog port** column, and an "N of M applied" line on the port card. The broker's script sends a report at the end of **every** run that asked ASIX, whatever happened (an `EXIT` trap, best effort: if the report cannot be sent nothing else changes, and the exit status stays the script's own). The report carries the port read from `broker.env` after any change or put-back, and the port in `/var/lib/asix-broker/config-rejected` if there is one. ASIX keeps it on that broker's own row (`collectors.config_syslog_port`, `config_rejected_port`, `config_reported_at`; the row is found by the sending key AND the name, so one key cannot write another broker's row, and a report never creates a row). The column compares it with the port ASIX asks for:

| Shows | Meaning |
|---|---|
| (the port, or `-`) | ASIX asks for no port; the number is what the broker reported, if it did |
| **Applied 1514** | the broker reports it is listening on the port ASIX asks for |
| **Pending 1514** (now 514) | it reported a different port, has not rejected this one, and its report is under 15 minutes old: it has not picked the change up yet (it asks every 5 minutes) |
| **Rejected 1514** (now 514) | it tried this port and put its old settings back; `journalctl -u asix-broker-config` on the broker says why. It will not try that port again until ASIX asks for a different one |
| **Not asking** (now 514) | its last report is over 15 minutes old and it is not on the port: the timer, Vector or the VM is down |
| **Not reporting** | a port is set but the broker never reported: it was not installed with `--accept-config`, or its `asix-broker-config.sh` is older than reporting. Copy the new script and re-run the bootstrap script with `--accept-config` |

None of these is a "needs attention" problem and none raises an alert. **Applied** means the broker says it is listening, not that devices send to it: that is still on you (firewall and senders), and the test line from `logger -n <broker> -P 1514 -T test` arriving in Events is the real proof.

## Signed config (optional)
Without this, the only protection on the config a broker pulls is the HTTPS connection and the broker's ingestion key. With it, ASIX **signs** what it tells a broker, and a broker that has been given ASIX's public key acts only on a valid signature. An answer from something that is not ASIX, one edited on the way, one made for another broker and an old one that is replayed are all refused (nothing changes, the reason is in `journalctl -u asix-broker-config`).

**What it protects against, and what it does not.** It protects against a spoofed ASIX address, an answer changed in transit, and anything that can write ASIX's database but cannot read the signing Secret. It does **not** protect against someone who can read that Secret: the private key lives on ASIX (an offline signing key, where a person signs each change, is not built). It does not change what a broker accepts: the broker still checks the port itself (never 22, 443, 8686, 30443 or its TLS port) and still validates, restarts and puts the old settings back on failure.

**1. Make the key pair, once, on the ASIX VM** (needs only openssl and k3s):
```bash
sudo scripts/deploy/make-config-signing-key.sh --dir /root/asix-config-signing --apply
```
This writes `config-signing.key` (private, owner only) and `config-signing.pub`, prints the **key id**, stores the private key as the Secret `asix-platform/asix-config-signing` and restarts `asix-api`. Without `--apply` it only makes the files and prints the two `k3s kubectl` commands. It never overwrites an existing key file or Secret. **Keep a copy of `config-signing.key` somewhere safe.** The Brokers page then shows **Answers signed (key ...)** with a **Copy public key** button; the key id must match the one the script printed.

**2. Give a broker the public key**, by re-running its bootstrap with the usual options plus `--config-pubkey`:
```bash
sudo ./scripts/deploy/bootstrap-broker.sh --url https://asix1:30443/v1/ingest/http --key asix_ik_... --name broker-1 --accept-config --config-pubkey config-signing.pub
```
It checks that every key in the file is an EC P-256 public key, installs it as `/etc/asix-broker/config-signing.pub`, writes `ASIX_CONFIG_PUBKEY_FILE` to `broker.env` and prints the key id it now trusts (compare it with the portal's). Needs `openssl` on the broker. `--config-pubkey` needs `--accept-config`. **Re-running the bootstrap without `--config-pubkey` goes back to accepting unsigned config**, so keep the flag on every re-run (as with `--port`).

**What the broker checks, in order** (`asix-broker-config.sh`): the answer has a signed part (else: "ASIX did not sign this answer"); the ECDSA P-256 / SHA-256 signature matches one of the keys in the file; the signed text is version 1 and was made for **this broker's name** (or for none, if the broker has no usable name); and it was issued within `ASIX_CONFIG_MAX_SKEW_S` (default 600) seconds of the broker's own clock. Only then it reads the port, **from the signed text**; the unsigned `config` part of the answer is ignored in this mode. A broker whose clock is badly wrong refuses everything: fix the clock (`timedatectl`).

**Replacing the signing key** (a broker pins the public key, so a new key means every broker needs it): put both public keys in one file (`cat old.pub new.pub > both.pub`), re-run each broker's bootstrap with `--config-pubkey both.pub`, then make the new pair under a new `--dir`, replace the Secret by hand (`k3s kubectl -n asix-platform delete secret asix-config-signing`, create it again from the new key file, `rollout restart deployment/asix-api`), and when every broker has been given the file with both keys, re-run them once more with `--config-pubkey new.pub` alone. The script refuses to replace an existing Secret so this is never done by accident. Until the Secret is replaced the brokers go on with the settings they have.

**Checking it works:** on the broker, with the portal's port set to something new, `journalctl -u asix-broker-config -n 20` says "Done: syslog port ... Vector healthy"; with the signing Secret deleted (and `asix-api` restarted) the same journal says "ASIX did not sign this answer" and nothing changes. The Brokers page cannot tell which brokers verify signatures (a broker does not report that yet): the broker's `broker.env` having `ASIX_CONFIG_PUBKEY_FILE` is the proof.

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

## Upgrading Vector
ASIX never runs anything on a broker, so an upgrade is a command you run on the VM. The Brokers page helps with the rest:
1. Set a **Vector version target** on the Brokers page (for example `0.60.0`; empty clears it). Each broker row then shows **Behind 0.60.0**, **Up to date** or **Newer than target**
   (a version that is not a plain `x.y.z`, such as a nightly build, shows nothing). Being behind is not a "needs attention" problem and raises no alert. The target is stored per tenant (`broker_settings`).
2. On each broker VM, as root, from the ASIX repo checkout: `sudo ./scripts/deploy/upgrade-broker.sh --version 0.60.0` (the card shows the exact command; without `--version` it takes
   the newest version the package repository offers). `--dry-run` says what it would do and changes nothing.
3. The script installs the package, then checks **this broker's own config** (including `vector-tls.yaml` if present) against the new binary with `vector validate` **before** restarting. If that
   check fails, Vector is not restarted and keeps forwarding on the old binary, and the script prints the `apt-get install --allow-downgrades vector=<old version>` command to go back (this
   matters: Vector 0.59 stopped accepting the old config until `VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true` was set). After the restart it waits up to 30 seconds for Vector's health
   check, then sends one heartbeat so the page shows the new version at once.
4. It refuses a version older than the one installed, and a version the repository does not have. It does not touch `broker.env`, the keys, the certificates or the disk buffer.

Upgrade one broker first and watch it on the Brokers page before doing the rest. Debian and Ubuntu only (it uses `apt`).

If `apt-get update` fails with "Release file ... is not valid yet", the broker's clock is behind (found on vm1 2026-10-18: `chronyc tracking` showed the system clock 35006 seconds slow although
`timedatectl` said the NTP service was active, because chrony only steps a big error in its first updates after start). Fix it with `sudo chronyc makestep`, then `sudo hwclock --systohc`; to make it
self-correct, add the line `makestep 1 -1` to `/etc/chrony/chrony.conf` (`/etc/chrony/conf.d/` is not read on every install: check with `grep -n 'confdir\|conf.d' /etc/chrony/chrony.conf`) and restart chrony.
A wrong clock also puts wrong times on what the broker sends, so check `date -u` against another machine first. The package repository can lag behind a Vector release for one architecture
(`apt-cache madison vector` lists what this machine can install; arm64 had only 0.58.0 and 0.59.0 when this was written), and the script refuses a `--version` that is not in that list.
