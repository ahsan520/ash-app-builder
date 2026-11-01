# PostgreSQL stuck at 100% CPU after a kernel update (gosu), and the fix

**What happened (asix1, 2026-11-01).** After `apt update && apt upgrade` and a reboot onto kernel `7.0.0-42-generic` (arm64, k3s v1.36.4), `postgresql-0` never became ready. The portal showed 502, both `asix-api` pods sat in CrashLoopBackOff (no database), Keycloak was `Unknown`, and `sync-and-deploy.sh` failed its health check. The pod's log was empty and `pg_isready` said "no response".

**What it looked like.** Inside the pod the only process was `gosu postgres /usr/local/bin/docker-entrypoint.sh postgres`, at about 99% CPU with a tiny memory use. Its kernel stack was `do_sched_yield` (a Go program looping on `sched_yield`). The open-file limit was a normal 1,048,576, so that was not it. PostgreSQL itself never started, so the data was never opened: the log of the last start before the reboot showed a clean shutdown, and the next start printed "Skipping initialization" and "ready to accept connections".

**Cause, as far as it is known.** The `postgres` image starts as root and its entrypoint drops privileges with `gosu`. `gosu` is a Go program; on this kernel it spun. **This is a hypothesis, not proven:** the previous kernel (`-38`) was never booted to compare. What is proven is that starting the container directly as the `postgres` user (no `gosu`) works.

**The fix.** `k8s/10-postgresql.yaml` now has, on the pod:
```yaml
securityContext:
  runAsUser: 70
  runAsGroup: 70
```
70 is the `postgres` user of `postgres:16-alpine`. The existing `pgdata` folder already belonged to uid 70, so nothing on the volume was changed. `tests/k8s-postgres-user.test.js` fails if the setting is removed.

**Things to know**
- **A new volume** (a fresh install) relies on the storage class giving the pod a writable directory. On k3s's `local-path` it does (mode 0777). With another storage class that does not hand out a writable directory, PostgreSQL would fail to create its data directory; adding `fsGroup: 70` to the same block is the usual fix. Not tried.
- **If the image changes** (a different base such as `postgres:16` on Debian, where the user is uid 999), change both numbers to match, or PostgreSQL will refuse to start on the existing data.
- **Other containers that use `gosu`** (ClickHouse and the Wazuh containers use their own entrypoints) started fine on the same kernel, but check them after any kernel update.
- **Keep the previous kernel installed** after an upgrade until `kubectl get pods -A` is clean; it is the way back if a kernel is the cause.

**If it happens again**
1. `kubectl get pods -n asix-platform` and `kubectl logs postgresql-0 -n asix-platform`. Empty log plus a `gosu` process at 100% CPU (`pgrep -af 'gosu postgres'`, `ps -o pcpu -p <pid>`) is this problem.
2. Do **not** delete the volume. The pod can be deleted safely (its data volume is kept).
3. Apply the fix live without a deploy:
   `kubectl patch statefulset postgresql -n asix-platform --type merge -p '{"spec":{"template":{"spec":{"securityContext":{"runAsUser":70,"runAsGroup":70}}}}}'` then `kubectl delete pod postgresql-0 -n asix-platform`.
4. Restart the API: `kubectl rollout restart deployment/asix-api -n asix-platform`.

**Before any reboot of the k3s box:** take a backup (`Back up now` on the Backup control card) and afterwards check `kubectl get pods -A`.
