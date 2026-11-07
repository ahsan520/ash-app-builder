# Installing a new VM from asix1 over ssh (task E12)

Status: **built 2026-11-06. Tested only with a stand-in for `ssh` (`tests/remote-install.test.js`, 35 tests, deliberate breaks each fail a test), NOT against a real VM or sshd.** Expect to read the audit log on the first real run.

Two scripts, run **on asix1** (or any machine with this repo and OpenSSH 8.4 or newer), that do by ssh what `docs/broker-vm.md` and `docs/wazuh-indexer.md` say to do by hand on the VM:

| Script | What it sets up | Runs on the VM, as root |
| --- | --- | --- |
| `scripts/deploy/remote-install-broker-vm.sh` | a broker VM: Vector and the Wazuh manager | `bootstrap-broker.sh --wazuh-manager [--wazuh-alerts] ...`, then (with `--indexer-file`) `install-wazuh-manager.sh --indexer-file ...` |
| `scripts/deploy/remote-install-indexer-vm.sh` | a central Wazuh indexer VM, and optionally a tenant's users | `install-wazuh-indexer.sh --address ...`, then (with `--tenant-name`) `wazuh-indexer-tenant.sh` and `--writer` |

Both ask for **the VM's address, the ssh user and the password** (the password is also used for `sudo`), sign in, become root with `sudo`, copy `scripts/` and `deploy/` to `~/asix-remote-install` on the VM, run the installer there, and remove that folder again (also when the run fails: it may hold copied key files).

## Use

```
# look first (changes nothing): signs in, checks sudo, runs the installer's own --check
./scripts/deploy/remote-install-broker-vm.sh  --check --host 10.0.0.60 --user ash
./scripts/deploy/remote-install-indexer-vm.sh --check --host 10.0.0.61 --user ash --address idx.internal

# a new indexer VM, with the tenant's read-only user and the manager's write user (files come back to this machine)
./scripts/deploy/remote-install-indexer-vm.sh --host 10.0.0.61 --user ash --address idx.internal \
    --tenant-name "Acme Corp" --manager-name acme-mgr --writer --writer-address 10.0.0.60

# a new broker VM with its manager, pointed at that indexer
./scripts/deploy/remote-install-broker-vm.sh --host 10.0.0.60 --user ash --url https://asix1:30443/v1/ingest/http --name broker-2 \
    --timezone America/Toronto --ca /root/asix-ca.pem --tls-cert server.crt --tls-key server.key --accept-config --config-pubkey config-signing.pub \
    --indexer-file remote-install-out/10.0.0.61-<time>/asix-manager-indexer-acme-mgr.json
```
Anything not given is asked for on the terminal. `--help` on either script lists every option. Options after `--` are passed to the installer on the VM (letters, digits and `. _ : / = @ + , % * ? [ ] -` only; each is quoted for the VM).

**Secrets.** The ssh password: `--password-file` (mode 600 or 400), or `ASIX_SSH_PASSWORD`, or typed (hidden). The ingest key: `--key-file`, `ASIX_INGEST_KEY`, or typed. Neither is an option on the command line, so `ps` on asix1 never shows them. The password lives in a mode-600 file in a private temporary folder that is deleted when the script ends; ssh gets it through `SSH_ASKPASS` (or `sshpass -f` when installed), `sudo` on its standard input. The ingest key is copied to a file on the VM and read there inside the command (the existing `bootstrap-broker.sh --key` still shows it in `ps` on the VM for the moments it runs; that is how that script has always taken it). Files you name (`--ca`, `--tls-*`, `--config-pubkey`, `--indexer-file`) are copied the same way.

**The host key.** First contact accepts the VM's key and records it in `remote-install-out/<host>-<time>/known_hosts` (not in your own `~/.ssh`). Compare it with the VM's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the VM) if the network is not yours.

## When it stops: the audit files

- **On asix1:** `remote-install-out/<host>-<time>/audit-broker-vm.log` or `audit-indexer-vm.log` (mode 600, folder 700): everything the script printed and everything the installers printed, with the password filtered out. The last line of a failed run names it.
- **On the VM:** `/var/log/asix-remote-install-<time>.log`: the same installer output, written there as root. It stays when the run ends.
- The installers' own logs and the checks they print (`docs/broker-vm.md`, `docs/wazuh-indexer.md`) are unchanged. Re-run after fixing the cause: every step of the installers is safe to repeat.
- Files fetched back (`asix-indexer-registration-<slug>.json`, `asix-manager-indexer-<slug>.json`) hold passwords: they are mode 600 in that folder; delete them once used.

## Things to know

- **A re-run of `bootstrap-broker.sh` forgets any option not given again.** On a VM that is already set up give every option again and add `--no-install` (docs/broker-vm.md says the same).
- `--writer-address` is what the manager will use to reach the indexer: `127.0.0.1` when both run on one machine (the lab), else the indexer's address.
- It does **not** open any firewall: 1514/tcp and 1515/tcp on the broker VM for the agents, the syslog ports for the senders; 9200/tcp on the indexer VM from the managers and the ASIX API node only.
- ssh is forced to password sign-in (`PubkeyAuthentication=no`), as asked. A user with passwordless `sudo` works too (the password line is simply not used).
- The installers are the ones already in the repo and keep their own checks (resources, ports, the repository fingerprint, a pinned version).
- **Not built:** key-based sign-in, one command that does both VMs, reading the broker's key and the registration through the ASIX API, the firewall.
