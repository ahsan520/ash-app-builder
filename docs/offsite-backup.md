# Off-VM copy of the backups

The nightly backup (`asix-backup`, 02:17) writes encrypted files to `/var/backups/asix/scheduled` on the k3s VM. Those protect against a deleted pod, a bad upgrade or a
mistake, but not against losing the VM or its disk. `scripts/offsite-backup.sh` copies them to another machine every night and tells the Data safety page whether it worked.

## What you need
1. Another machine you control (a second VM, a NAS, a PC that is always on) with `rsync` and an SSH server, and a folder for the copies.
2. An SSH key for root on the k3s VM that the other machine accepts:
   ```bash
   sudo ssh-keygen -t ed25519 -N '' -f /root/.ssh/asix-offsite
   sudo cat /root/.ssh/asix-offsite.pub        # add this line to ~/.ssh/authorized_keys of the user on the other machine
   ```
   Use a user that can only write to its own home folder; the copy never needs more. (A restricted key is possible with `command=` and `from=` options in `authorized_keys`; not required.)
3. `rsync` on the k3s VM: `sudo apt-get install -y rsync`.

## Set it up
```bash
cd ash-app-builder
sudo bash scripts/offsite-backup.sh --check --target user@other-host:/home/user/asix-backups --key /root/.ssh/asix-offsite
sudo bash scripts/offsite-backup.sh --install-timer --target user@other-host:/home/user/asix-backups --key /root/.ssh/asix-offsite
```
`--check` only tests the connection and the folder. `--install-timer` saves the settings in `/etc/asix-offsite.env` (mode 600), installs `asix-offsite-backup.timer` (every night at 03:30,
an hour after the backup; `Persistent=true`, so a missed run happens at the next boot), and copies once straight away. A local folder works as a target too (a mounted disk or share): `--target /mnt/usb/asix-backups`.
The first connection trusts the other machine's host key (`StrictHostKeyChecking=accept-new`).

Copy now at any time: `sudo bash scripts/offsite-backup.sh` (uses the saved settings). Last runs: `journalctl -u asix-offsite-backup -n 30`, `systemctl list-timers | grep offsite`.

## What it does and what it checks
- Copies the `asix-*` files (PostgreSQL dumps, ClickHouse day files, manifests) with rsync: only new or changed files travel. Files are owner-only (`0600`) on the other machine.
- Then runs rsync again in dry-run mode: it must find nothing left to send (same names and sizes). Anything else is a failed copy.
- Records one row in `backup_runs` (`kind = 'offsite'`) through the PostgreSQL pod. The Data safety page shows **Copy on another machine**, and:
  - no copy yet, or none in the last 36 hours: the info finding "Backups are stored on this VM" stays, with the command to set it up;
  - the latest copy failed: a warning with rsync's error;
  - the last good copy is over 36 hours old: a warning; over 72 hours: critical (which makes the verdict critical).
- It never deletes anything on the other machine, so that copy keeps files this VM has already pruned (`BACKUP_KEEP` days). Clean it yourself now and then, for example `find /home/user/asix-backups -type f -mtime +60 -delete`.

## The passphrase
The files are AES-256-GCM encrypted (`src/backup/crypto.js`), so the other machine learns nothing from them, and they cannot be read without the passphrase (Kubernetes secret `asix-backup-secret`,
also saved by the installer in `/root/asix-backup-key.txt` on the VM). **Keep a copy of the passphrase somewhere that is not the k3s VM** (a password manager); a copy of the files without it is useless.

## Restoring from the other machine
Copy the files back to `/var/backups/asix/scheduled` on a rebuilt VM (same names), then use `sudo scripts/restore-backup.sh list` and the restore commands in the Data safety page.
For a whole-VM loss you also need the passphrase and, for the Postgres roles, `restore-backup.sh globals <set>`.

## Checked
- `scripts/offsite-backup.sh` against a local folder and over real SSH (OpenSSH server on this machine, a second user, key login, a folder that did not exist yet): copy, repeat run, a changed file repaired, only `asix-*` files sent, owner-only files, a wrong key and an unwritable folder fail with exit 1 and a `failed` row, a bad target or a missing key file is refused before anything runs, nothing to copy is refused, a recording failure still exits 0 with a warning.
- Real PostgreSQL 16: the script's row and the real Data safety report (`tests/offsite-backup-db.test.js`, CI `postgres` job): not configured, fresh copy clears the finding, a failed later copy is reported while last night's copy still counts, the row does not show up in the PostgreSQL backup history.
- Unit tests: `tests/safety-offsite.test.js` (the findings and their thresholds), `tests/offsite-backup-script.test.js` (the script against a local folder; skipped when rsync is missing).
- **Not run on the k3s box yet** (the `k3s kubectl exec` recording and the systemd timer); the SSH path is not in CI.

## Not built
Pruning the other machine, S3 or other object storage, a restricted-key setup script, a portal button, an alert when the timer itself is missing (the stale finding catches it after 36 hours, but only once at least one copy has been recorded).
