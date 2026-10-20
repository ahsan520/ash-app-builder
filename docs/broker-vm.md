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

## Broker setup commands (cheat sheet)
Everything needed to set up or update a broker that takes syslog over TLS and requires signed config, in the order it is used. Details for each step are in the sections named. Replace `asix1`, `broker-1` and the paths with yours.

**1. Make the ASIX CA file, `asix-ca.pem` (once, on the ASIX VM, then copy it to the broker).** The broker trusts ASIX's self-signed nginx certificate, so the "CA" is that certificate:
```bash
# on the ASIX VM (asix1): the public copy that make-nginx-tls.sh already saved ...
sudo cp /root/asix-nginx-tls.crt /root/asix-ca.pem
# ... or fetch it from the running nginx
echo | openssl s_client -connect asix1:30443 2>/dev/null | openssl x509 > /root/asix-ca.pem
scp /root/asix-ca.pem ash@192.168.68.54:/tmp/asix-ca.pem        # to the broker
```
Re-making the nginx certificate (`ASIX_TLS_REGENERATE=1 scripts/deploy/make-nginx-tls.sh`) means a new `asix-ca.pem` on every broker.

**2. Make the signing key pair, and copy `config-signing.pub` to the broker (once).** Only the public file goes to the broker; keep a copy of `config-signing.key` somewhere safe (see "Signed config"):
```bash
# on the ASIX VM
sudo scripts/deploy/make-config-signing-key.sh --dir /root/asix-config-signing --apply
scp /root/asix-config-signing/config-signing.pub ash@192.168.68.54:/tmp/config-signing.pub   # to the broker
```
The Brokers page, Syslog port card, **Copy public key** gives the same text. On the broker keep a copy outside `/etc/asix-broker/` (for example `/root/config-signing.pub`): the bootstrap installs it as `/etc/asix-broker/config-signing.pub` and cannot copy a file onto itself.

**3. Make the broker's own TLS certificate (once, on the broker).** The certificate is the broker's own; devices must trust it and its name or IP must match what they connect to. `-addext` adds the broker's address, which newer TLS clients require:
```bash
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=broker-1" \
  -addext "subjectAltName=DNS:broker-1,IP:192.168.68.54" \
  -keyout /root/tls.key -out /root/tls.crt
sudo chmod 600 /root/tls.key
sudo mv /tmp/asix-ca.pem /root/asix-ca.pem; sudo mv /tmp/config-signing.pub /root/config-signing.pub   # the files from steps 1 and 2
```
Certificates are not renewed for you: after 365 days make a new one and re-run step 4.

**4. Download the repo and set the broker up (or update it after an ASIX deploy).** The bootstrap rewrites `broker.env` from the flags you give it, so every option the broker uses must be passed again: the port and the TLS port (read back from `broker.env`, so a port set from the Brokers page is not reset), the CA, the TLS files, the signing key and the time zone (`--timezone`, see "Syslog times from senders in another time zone").
```bash
cd /home/ash/ash-app-builder
git pull && find . -name '*.sh' -not -path './node_modules/*' -exec chmod +x {} +

. /etc/asix-broker/broker.env
sudo ./scripts/deploy/bootstrap-broker.sh \
  --url "$ASIX_INGEST_URL" --key "$ASIX_INGEST_KEY" --name "$ASIX_BROKER_NAME" \
  --port "${ASIX_SYSLOG_PORT:-514}" --ca /root/asix-ca.pem \
  --no-install --accept-config --config-pubkey /root/config-signing.pub \
  --tls-cert /root/tls.crt --tls-key /root/tls.key --tls-port "${ASIX_SYSLOG_TLS_PORT:-6514}" \\
  --timezone "${ASIX_SYSLOG_TIMEZONE:-UTC}"
```
`--no-install` because Vector is already there (leave it out on a new VM; on a new VM `broker.env` does not exist yet, so give `--url`, `--key`, `--name`, `--port` by hand as in "Install"). If the CA was kept from the first install, `cp /etc/asix-broker/ca.pem /root/asix-ca.pem` instead of step 1. It validates the Vector config before restarting and ends with the key id it now trusts: compare it with the one on the Brokers page.

**5. Check the ports on the broker:**
```bash
ss -tln | grep 6514          # the TLS port in use (6514 by default; the Brokers page shows the one in use)
ss -lunt | grep -E ':514|:1514'   # the syslog port, UDP and TCP
```
Open the same ports (TCP, and UDP for the plain syslog port) on the VM's firewall. See "Syslog over TLS" for a test line over TLS.

**6. The clock.** A signed answer is refused when it is more than 10 minutes from the broker's own clock (`ASIX_CONFIG_MAX_SKEW_S`, default 600), which the Brokers page shows as **Refused: clock skew**. A VirtualBox VM often drifts after the Mac sleeps or the VM is paused. On the broker:
```bash
sudo chronyc makestep                       # step the clock now
date -u                                     # compare with another machine
chronyc tracking                            # "System time ... seconds slow/fast of NTP time" should be tiny
timedatectl status                          # "System clock synchronized: yes"
```
Then retry the signed update without waiting for the timer:
```bash
sudo systemctl start asix-broker-config.service
sudo journalctl -u asix-broker-config -n 15 --no-pager -o cat
```
The page should move to **Checks** within a pull. **Do the same on the ASIX VM**, because it stamps every answer and a wrong clock there refuses every broker:
```bash
date -u
chronyc tracking
chronyc sources -v                          # at least one source marked ^* (selected) or ^+
```
If chrony keeps drifting, make it step big errors by itself (add `makestep 1 -1` to `/etc/chrony/chrony.conf` and restart chrony, see "Upgrading Vector"). Prefer fixing the clock to raising `ASIX_CONFIG_MAX_SKEW_S`, which weakens the protection against a replayed answer.

## Files
| File | Purpose |
|---|---|
| `deploy/broker/vector.yaml` | Vector config: syslog sources, line rewrite, HTTP sink with disk buffer |
| `deploy/broker/vector-tests-timezone.yaml` | Vector unit tests for `ASIX_SYSLOG_TIMEZONE`: run with the zone set, see "Syslog times from senders in another time zone" |
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

## Config from ASIX (optional: the syslog port and the syslog-over-TLS port)
ASIX never connects to a broker. A broker that was installed with `--accept-config` asks ASIX for its config instead, and only that kind of broker:
```bash
sudo ./scripts/deploy/bootstrap-broker.sh --url https://asix1:30443/v1/ingest/http --key asix_ik_... --name broker-1 --accept-config
```
This writes `ASIX_ACCEPT_CONFIG=true` to `broker.env` and installs `asix-broker-config.timer`, which runs `asix-broker-config.sh` as root two minutes after boot and then every 5 minutes. Re-running the bootstrap script **without** `--accept-config` turns it off again
(and, as always, rewrites `broker.env` from the flags you give it, so give `--port` again if the broker was told to use another one, and `--config-pubkey` again if it was set up to require signed config, see "Signed config" below).
A broker installed before this existed can be switched on by re-running the bootstrap script with the same options plus `--accept-config`.

**Setting it:** Brokers page, **Syslog port for brokers** card (`GET` and `PUT /v1/broker-config`, body `{ "syslog_port": 1514 | null }`; `collectors:read` / `collectors:write`, no role change). One value for the whole tenant; empty means "no opinion": brokers keep what they have.
The broker asks with `GET /v1/ingest/broker-config` and its own ingestion key and gets `{ "config": { "syslog_port": 1514 | null }, "interval_seconds": 300 }` (read only, no audit row, same rate limit and key rules as the heartbeat; a revoked key gets nothing).
After every pull the broker also tells ASIX what it is listening on: `POST /v1/ingest/broker-config/report` with `{ "collector": "broker-1", "syslog_port": 1514, "rejected_port": null, "signature": "off" }` and the same key (see "What the Brokers page shows" below, and "Which brokers check the signature" for `signature`). That is information only; it changes no setting.

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
The key, the certificates, the ASIX URL and whether a TLS listener exists at all are never changed this way; the port of a TLS listener a broker already has can be (next section).

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

## The syslog-over-TLS port (done 2026-10-18)
**What it does:** moves the port of the syslog-over-TLS listener on brokers that already have one (installed with `--tls-cert` and `--tls-key`, see "Syslog over TLS" above), the same way the syslog port is moved. It does **not** turn TLS on or off: that needs a certificate and key on the broker, which ASIX never sends. A broker without a TLS listener ignores the value with a note in its journal and exits 0.

**Setting it:** Brokers page, **Syslog port for brokers** card, the **Syslog-over-TLS port** row (`PUT /v1/broker-config` with `{ "tls_port": 6514 | null }` on its own, or together with `syslog_port`; a key that is left out is not touched; `GET /v1/broker-config` returns `tls_port`; `collectors:write`, no role change). One value for the whole tenant, stored in `broker_settings.tls_port` (new nullable column with a 1 to 65535 CHECK, added by the schema job on deploy, safe to re-run). It follows the syslog port's rules (not 22, 443, 8686, 30443) and must differ from the tenant-wide syslog port; the save is refused with 400 `INVALID_TLS_PORT` (or `INVALID_SYSLOG_PORT` when the syslog port is the one that now clashes). A broker's own syslog port can still be changed to equal it: the broker refuses that itself.

**What the broker is told:** `GET /v1/ingest/broker-config` answers `{ "config": { "syslog_port": ..., "tls_port": 6514 | null } }`, and the signed copy carries `"tls_port"` after `"syslog_port"` as the last field of the signed text (so a script from before this reads the same fields it always read and simply never looks at the new one). A broker **left out** of the tenant-wide port is told `null` for both tenant-wide ports (a TLS port set for that broker alone still applies, see "A TLS port for one broker" below). An answer signed before the field existed reads as `null`.

**What the broker does with it** (`asix-broker-config.sh`; the two settings are applied one after the other, the syslog port first, each with its own backup, validate, restart, health check and way back):
1. `null`, no field, or the port already in use: nothing. A value that is neither a number nor `null`: exit 1, nothing changed.
2. Its own checks, whatever ASIX sent: 1 to 65535, not 22, 443, 8686 or 30443, not the syslog port the broker uses **now** (after step 1 of the same run), and the broker must have a TLS listener (`ASIX_SYSLOG_TLS_PORT` in `broker.env` and `/etc/vector/vector-tls.yaml` present), else it logs "has no TLS listener" and stops.
3. Edits only the `ASIX_SYSLOG_TLS_PORT` line of `broker.env` (previous file kept as `broker.env.before-config`), runs `vector validate` **with the TLS file**, restarts Vector, waits for its health check.
4. Any failure puts the old file back (restarting Vector on it if it had been restarted) and remembers the port in `/var/lib/asix-broker/config-tls-rejected`, so it is not retried until ASIX asks for another one. A rejected TLS port never undoes a syslog port applied in the same run; the run exits 1.

**Needs the new `asix-broker-config.sh` on each broker** (re-run the bootstrap from the updated checkout, see "Updating a broker after an ASIX deploy" above); an older script ignores the field.

**It does not open the firewall and does not move your devices:** open the new port (TCP) on the VM and point the senders at it. Check on the broker: `sudo systemctl start asix-broker-config.service; sudo journalctl -u asix-broker-config -n 15 --no-pager; ss -tln | grep <port>; openssl s_client -connect 127.0.0.1:<port> </dev/null`.

**Not built:** turning TLS on from ASIX. A TLS port for one broker is built: see "A TLS port for one broker" below. Whether each broker applied the TLS port is shown on the Brokers page now: see "Which brokers applied the TLS port" below.

**Checked:** unit and route tests (`tests/broker-config.test.js`, `tests/config-signing.test.js`), the real script against stubbed `id`, `vector`, `systemctl`, `curl` and, for signed answers, the real signer and real openssl (`tests/broker-config-tls-script.test.js`, 14 tests; the existing script tests still pass), and real PostgreSQL 16 with the schema applied twice (`tests/broker-config-db.test.js`: saved alone and with the syslog port, answered next to it, refused clashes, the CHECK, another tenant, a left-out broker; the left-out check fails with the rule removed). **Run on broker-1 (Vector 0.59.0, Ubuntu 26.04.1 LTS, 192.168.68.54) on 2026-10-19: the Brokers page of the deployed install, seen in a browser, shows it Connected with **Syslog port Applied 1514**, **TLS port Applied 6515** and **Config check Checks** (12 events in 24 hours). So a tenant-wide syslog-over-TLS port set from the portal was pulled, applied and reported back on a real broker. **Still not seen:** the way back (6515 to 6514), a rejected TLS port on a real broker, a broker without a TLS listener saying so, a test line arriving over TLS in Events.** To try the rest: deploy; on a broker with TLS re-run the bootstrap with its usual options plus `--accept-config`; set a TLS port on the card (say 6515); run the service by hand and see "Done: syslog-over-TLS port 6514 -> 6515"; `ss -tln` shows it listening; set it back to 6514 (the first real try of the way back); then on a broker without TLS see "has no TLS listener".

## A TLS port for one broker (done 2026-10-19)
**The gap it closes:** the syslog-over-TLS port was one value for the whole tenant. A broker whose TLS listener has to sit on another port (a port already used on that VM, a different class of devices) could not be given its own, although its plain syslog port could.

**Setting it:** Brokers page, **TLS port** button on the broker's row (empty goes back to following the tenant-wide TLS port), or `PUT /v1/brokers/:id/tls-port` with `{ "tls_port": 6515 | null }` (`collectors:write`, no role change). Stored in `collectors.tls_port_override` (new nullable column with a 1 to 65535 CHECK, added by the schema job on deploy, safe to re-run). Only a broker of your own tenant can be set (a collector whose version reads `vector-<version>`); anything else is a 404 and nothing is written.

**Rules:** the TLS port's rules (a whole number from 1 to 65535, not 22, 443, 8686 or 30443) and it must differ from the syslog port **this broker is asked for**: its own syslog port if it has one, else the tenant-wide one. A broker that is left out of the tenant-wide ports and has no own syslog port is asked for no syslog port, so there is nothing to clash with. A refusal is 400 `INVALID_TLS_PORT` with the reason. The check runs the other way too: an own **syslog** port equal to the TLS port that broker is asked for is refused (400 `INVALID_SYSLOG_PORT`), and a tenant-wide syslog or TLS port save is refused, naming the brokers, when it equals the own port of the other kind of a broker that would follow it (a broker left out, or with its own port of the same kind, does not follow). What is not caught is a clash that appears later, for example clearing an own port so the broker starts following a tenant-wide port equal to its other port; the broker refuses that itself and the column stays **Pending**.

**What the broker is told:** `GET /v1/ingest/broker-config?collector=<name>` answers the effective TLS port next to the syslog port, and the signed copy carries the same value. Own port first; else `null` if the broker is left out of the tenant-wide ports; else the tenant-wide port. **An own TLS port still applies to a broker that is left out**, because it was chosen for that broker alone (the same as an own syslog port). The row is found by the sending key AND the name, so one key cannot read another broker's port, and a missing or odd name, or a database without the new column, gets the tenant-wide answer.

**On the broker:** nothing changes. It applies the TLS port exactly as before (its own checks, `vector validate` with the TLS file, restart, health check, way back, remembered rejection) and only moves the port of a TLS listener it already has: ASIX still never turns TLS on. A broker with no TLS listener says so and ignores it. **No new script to copy** if the broker already sends its name (the per-broker syslog port script) and has the TLS report script; an older script is told the tenant-wide port.

**What the Brokers page shows:** the **TLS port** column judges the broker against its own TLS port when it has one and adds **(own)** after the pill. `GET /v1/brokers` returns per broker `tls.source` (`broker` = its own, `tenant` = follows it, `excluded` = a tenant-wide TLS port is set but the broker is left out of it, `none` = nothing asked) and `tls.override_port`; the summary has `tls_port_overrides`. Information only: not a problem, no alert.

**Checked:** real PostgreSQL 16 with the schema applied twice (`tests/broker-tls-override-db.test.js`, CI `postgres` job), unit and route tests (`tests/broker-tls-override.test.js`) and the portal button and cell (`tests/portal-broker-tls-own.test.js`); the DB test fails with the key condition dropped from the read and with the broker-only condition dropped from the write. **Not yet tried on a real broker:** no own TLS port has been set on broker-1, and the button has not been seen in a browser. To try it: deploy (the schema job adds the column); on the Brokers page press **TLS port** on broker-1, enter 6516; wait up to 5 minutes (or `sudo systemctl start asix-broker-config.service`) and see **Applied 6516 (own)**; `ss -tln | grep 6516`; clear it and see it return to 6515 (the way back).

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

**Checking it works:** on the broker, with the portal's port set to something new, `journalctl -u asix-broker-config -n 20` says "Done: syslog port ... Vector healthy"; with the signing Secret deleted (and `asix-api` restarted) the same journal says "ASIX did not sign this answer" and nothing changes. The Brokers page also shows which brokers check the signature: see "Which brokers check the signature" below. That is what each broker says about itself; the proof is still `ASIX_CONFIG_PUBKEY_FILE` in its `broker.env`.

## Which brokers applied the TLS port (done 2026-10-18)
The gap it closes: after setting a syslog-over-TLS port, the Brokers page could not say whether any broker had picked it up. A broker that had nothing to do (no TLS port set, no TLS listener, an older script) printed nothing in its journal either, so "nothing in `journalctl -u asix-broker-config`" and "it worked" looked the same. The broker's script now adds two fields to the report it already sends after every run: `tls_port` (the port its TLS listener uses, read from `broker.env` **after** any change or put-back, or `null` when it has no TLS listener, meaning no `ASIX_SYSLOG_TLS_PORT` or no `/etc/vector/vector-tls.yaml`) and `rejected_tls_port` (the TLS port it put back, from `/var/lib/asix-broker/config-tls-rejected`, or `null`). ASIX stores them on the broker's own collector row (`collectors.config_tls_port`, where **0 means no TLS listener** and NULL means never said, and `config_rejected_tls_port`; both added by the schema job, safe to re-run; found by key AND name like the rest of the report). Both fields are optional: an older script leaves them out, which clears an older claim and reads as **Not reporting**. Anything that is not a port or `null` is a 400 and writes nothing, not even the syslog port.

The Brokers page has a **TLS port** column, and the TLS row on the card says "N of M applied":

| Shows | Meaning |
|---|---|
| **Applied 6515** | the broker says its TLS listener is on the port ASIX asks for |
| **Pending 6515 (now 6514)** | its listener is on another port and it has not rejected this one yet; it asks every 5 minutes |
| **Rejected 6515 (now 6514)** | it tried that port and put its old settings back; `journalctl -u asix-broker-config` on the broker says why, and it will not retry until ASIX asks for a different port |
| **Not asking** | its last report is over 15 minutes old: the timer, Vector or the VM is down |
| **No TLS listener** | it says it has none, so it ignores the setting. Counted on its own, never as a failure. ASIX cannot turn TLS on: that needs a certificate and key on the broker (`--tls-cert` and `--tls-key`) |
| **Not reporting** | a TLS port is asked for but the broker said nothing about TLS: not installed with `--accept-config`, or its script is older than this report. Copy the new `asix-broker-config.sh` and re-run the bootstrap with `--accept-config` |
| (the port it listens on, or `-`) | nothing is asked: no TLS port is set, or the broker is left out of the tenant-wide ports (it keeps what it has) |

The state is judged against the TLS port this broker is asked for: its own if one was set (see "A TLS port for one broker" below), else the tenant-wide one (an own syslog port does not change it); an own TLS port shows **(own)** after the pill. `GET /v1/brokers` returns `tls_port` and, per broker, `tls` = `{ state, configured_port, reported_port, has_listener, rejected_port, reported_at }` with `state` one of `none | unknown | no_listener | applied | rejected | pending | stale` (rules in `tlsState()` in `src/brokers/config.js`), and the summary has `tls_applied`, `tls_not_applied` (unknown, rejected, pending, stale) and `tls_no_listener`. None of it is a "needs attention" problem and none raises an alert. If the TLS port is asked for but the broker's own syslog port was set to the same number, the broker refuses it itself (exit 1) and the column stays **Pending**: change one of the two.

**Reading the journal after this:** an empty journal run means one of: no TLS port is set on ASIX, the port is already the one in use, or the broker has no TLS listener. The column tells you which (**-** / port, **Applied**, **No TLS listener**).

**Needs the new `asix-broker-config.sh` on each broker** (copy it from the updated checkout and re-run the bootstrap with the broker's usual options plus `--accept-config`, see "Updating a broker after an ASIX deploy" above) **and the schema job on deploy** (two new columns on `collectors`; `sync-and-deploy.sh` runs it). Until then the page shows **Not reporting** for a broker that was asked for a TLS port.

**Checked:** real PostgreSQL 16 with the schema applied twice (`tests/broker-tls-report-db.test.js`, CI `postgres` job: unknown, pending, applied, rejected, a moved port no longer rejected, no listener stored as 0, an older script's report stored as NULL and clearing an old claim, the summary, left-out broker shows none, cleared port, a key cannot write another broker's row (same tenant, another tenant, no row), stale and applied-stays-applied, another tenant's page, the CHECKs; the test fails with the key condition dropped and fails with the TLS columns never written; `broker-config-db`, `brokers-db`, `broker-signature-report-db`, `broker-port-override-db`, `broker-port-exclude-db`, `broker-upgrade-db`, `broker-rotate-key-db`, `heartbeat-db`, `collector-watch-all-db`, `broker-key-watch-db`, `core-reads-db` still pass), unit tests (`tests/broker-tls-report.test.js`: the body rules, `recordReport`, every state and the 15 minute edge, the broker row and the summary), the real script with stubs (`tests/broker-tls-report-script.test.js`: the port read after a change, put-back reported as the old port with the rejected one, no listener, garbled values, and that every body the script can send passes the server's rules), the portal cell and summary cut out of `index.html` and run (`tests/portal-broker-tls.test.js`), and **once end to end in the sandbox: the REAL script with REAL `curl` against the real routes and real PostgreSQL** (only `vector` and `systemctl` stubbed): nothing asked (page: the port the listener uses), asked 6515 (applied), 6516 with a failing validate (rejected, still listening on 6515), the next run not retrying, 6517 (applied), the listener removed (no listener). Existing report assertions in `tests/broker-config*.test.js` and `tests/broker-signature.test.js` now include the two new fields. **The TLS port column was seen in a browser on broker-1 showing Applied 6515 (2026-10-19); the new CI line has not run on GitHub.** To try the rest: deploy; copy the script and re-run the bootstrap on broker-1 (with `--accept-config --config-pubkey ... --tls-cert ... --tls-key ... --tls-port 6514`); wait for the next timer run (or `sudo systemctl start asix-broker-config.service`) and see the **TLS port** column show `6514` while no TLS port is set; set 6515 on the card and see **Pending** then **Applied 6515** within 5 minutes and "All 1 applied"; `ss -tln | grep 6515`; set 6514 again (the first real try of the way back).

## Which brokers check the signature (done 2026-10-18)
The gap it closes: with a signing key on ASIX, nothing showed which brokers had been given the public key. A broker that was never re-run with `--config-pubkey` kept acting on unsigned answers, and the only way to know was to read its `broker.env`. Now the broker's script says it, in the report it already sends after every run (the `signature` field, one value from a fixed list; ASIX refuses anything else with a 400). The Brokers page has a **Config check** column, and the signing line on the port card says how many brokers check (**N of M brokers check it**, in the bad colour while ASIX signs and some do not) and how many are refusing.

| Shows | The broker reports | Meaning |
|---|---|---|
| **Checks** | `ok` | it has a public key and the last answer passed all three checks: signature, broker name, age |
| **Refused: ...** | one of the reasons below | it has a public key and refused the last answer, so it **changed nothing**; the tooltip says what to fix |
| **Waiting** | `unchecked` | it has a public key but has not fetched an answer to check yet (ASIX could not be reached) |
| **Not checking** | `off` | no public key (`--config-pubkey` was not given): it acts on unsigned answers. Reads **(ASIX signs)** next to it when ASIX has a signing key: that is the gap this column is for |
| **Not asking** | (any, but over 15 minutes old) | its last report is old: the timer, Vector or the VM is down. A refusal it was reporting is named in the tooltip |
| **Not reporting** | nothing | it never said: not installed with `--accept-config`, or its `asix-broker-config.sh` is older than this report. Copy the new script and re-run the bootstrap script, keeping `--accept-config` and `--config-pubkey` |

Reasons for **Refused** (all of them leave `broker.env` and Vector alone): `unsigned` (ASIX did not sign: is the Secret `asix-config-signing` set and `asix-api` restarted?), `bad signature` (wrong key on the broker, or the answer was changed on the way: compare the key id the bootstrap printed with the portal's), `wrong broker` (the answer was made for another name: check `ASIX_BROKER_NAME`), `clock skew` (the answer is further from the broker's clock than `ASIX_CONFIG_MAX_SKEW_S`: check time sync), `bad format` (the signed part could not be read), `no key file` (the file named by `ASIX_CONFIG_PUBKEY_FILE` is missing: re-run the bootstrap with `--config-pubkey`), `no openssl` (install it on the broker).

**Limits, stated plainly.** This is the broker describing itself, not ASIX proving it: a broker running an old or edited script, or one that has been taken over, can say anything. It is information for the operator. It does not change what a broker accepts, is not a "needs attention" problem on the page. The separate alert for a watched broker that does not check while ASIX signs is described in the next section. A report is only as fresh as the broker's last pull (every 5 minutes), and only brokers installed with `--accept-config` report at all. Not built: an alert for a broker that does not check while ASIX signs, a way to require signatures from the ASIX side (ASIX cannot refuse to serve an unchecked broker, because it cannot tell whether a pull comes from one), showing the key id each broker trusts.

## Getting an alert when a broker does not check the signature (done 2026-10-19)

When ASIX signs its config answers (see "Signed config"), a watched broker that has no public key, or that refuses ASIX's answer, raises the alert **Broker not checking config signature** (severity `high`, through your notification channels). "Watched" is the same as for the other broker alerts: **Alert if down** on the broker, or **Watch everything** on the Collectors page.

| The broker says | Alert? | What to do |
|---|---|---|
| Not checking (`off`: no public key) | Yes | Copy the public key from the Syslog port card on the Brokers page, then re-run `bootstrap-broker.sh` with the broker's usual options plus `--accept-config --config-pubkey <file>` |
| Refused (`bad_signature`, `wrong_broker`, `clock_skew`, ...) | Yes | The alert text and the Brokers page give the fix for each reason (see "Which brokers check the signature") |
| Checks (`ok`), waiting, never reported, or a refusal report older than 15 minutes | No | Nothing; a broker that stopped reporting is the disconnect alert's job |

Nothing is raised while ASIX does not sign, and an open alert closes (with an "ASIX" note) when it stops. It closes by itself when the broker checks again. If you close it while the same problem is still there it is not raised again for that problem. It is the broker describing itself: an old or edited script can say anything.

## Syslog times from senders in another time zone (done 2026-10-20)

**The problem.** A classic (RFC 3164) syslog line looks like `Oct 19 18:44:27 laptop sshd[9]: ...` and carries **no time zone**. Vector reads that clock as UTC, whatever zone the broker VM or the sender is in (Vector's own `timezone` setting does not apply to the syslog source; checked on Vector 0.59.0). A sender in Toronto (UTC-4 in summer) therefore shows up four hours early: events stored a second ago say they happened hours ago, search and the time picker look wrong, and a detection rule that looks at "the last 15 minutes by event time" never sees them. RFC 5424 lines carry their own offset and are right. Found on broker-1 2026-10-20: 26 events received minutes earlier were 4 hours old by their own time.

**The fix.** Tell the broker which zone its RFC 3164 senders write in:
```bash
# on the broker, as part of the usual bootstrap command (see "Broker setup commands", step 4)
sudo ./scripts/deploy/bootstrap-broker.sh ... --timezone America/Toronto
# or by hand: add this line to /etc/asix-broker/broker.env and restart Vector
ASIX_SYSLOG_TIMEZONE=America/Toronto
sudo systemctl restart vector
```
The same wall-clock time is then read in that zone (summer and winter time are handled: 18:44:27 in Toronto is 22:44:27Z in October and 23:44:27Z in January). Unset, empty or `UTC` changes nothing. `bootstrap-broker.sh` checks the name against `/usr/share/zoneinfo` and, like every option, keeps it only if you give it again on a re-run (the config pull from ASIX edits only the port lines of `broker.env`, so it keeps it).

**Check it worked.** Send a line and look at its time in Log search:
```bash
logger -n 192.168.68.54 -P 1514 -T "asix time test"
```
The event time should be the sender's real time converted to UTC, close to the received time (`filter _raw contains "asix time test" | fields _time, _insert_time`).

**Limits, stated plainly.**
- **One zone per broker** for RFC 3164 lines. Senders in several zones behind one broker cannot all be right: put the ones in another zone behind another broker, or set those devices to send RFC 5424 or to use UTC.
- **Events already stored keep the time they were stored with.** Nothing rewrites them.
- A name Vector cannot use, or a local time that does not exist (the hour clocks skip in spring), keeps the UTC reading for that line; the broker still runs.
- Checked on real Vector 0.59.0: `vector test` on both test files, `vector validate`, and a real syslog UDP packet through the real source and HTTP sink (RFC 3164 `Oct 19 18:44:27` came out `18:44:27Z` before and `22:44:27Z` with `America/Toronto`; the RFC 5424 line was `22:44:27Z` in both). **Not yet applied on broker-1.**

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
