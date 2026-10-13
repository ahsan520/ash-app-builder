#!/usr/bin/env bash
#
# Restore from an encrypted backup made by the nightly job (k8s/32-backup.yaml).
#
#   sudo scripts/restore-backup.sh list
#   sudo scripts/restore-backup.sh verify  <set>                              restore into scratch databases and compare, change nothing
#   sudo scripts/restore-backup.sh restore <set> <database> --as <new-name>   restore a COPY under another name, change nothing else
#   sudo scripts/restore-backup.sh restore <set> <database> [--yes]           REPLACE the live database (stops the apps that use it first)
#   sudo scripts/restore-backup.sh globals <set>                              recreate roles (only when rebuilding a fresh cluster)
#
# <database> is asix_platform (events, rules, alerts, ...) or keycloak (users, passwords, clients).
# Everything runs in a one-off Kubernetes Job from the API image; the passphrase never leaves the cluster.
set -euo pipefail
NS="${NAMESPACE:-asix-platform}"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
K=(k3s kubectl -n "$NS")
cmd="${1:-}"; set_name="${2:-}"; db="${3:-}"; shift $(( $# > 3 ? 3 : $# )) || true
as=""; yes=""
while (( $# )); do case "$1" in --as) as="${2:-}"; shift 2 ;; --yes) yes=1; shift ;; *) echo "unknown option: $1" >&2; exit 1 ;; esac; done

die() { echo "$*" >&2; exit 1; }
SET_RE='^asix-[0-9]{8}T[0-9]{6}Z$'; DB_RE='^[A-Za-z0-9_]{1,63}$'
case "$cmd" in
  list) args=(list) ;;
  verify)  [[ "$set_name" =~ $SET_RE ]] || die "usage: $0 verify <set>   (see: $0 list)"; args=(verify "$set_name") ;;
  globals) [[ "$set_name" =~ $SET_RE ]] || die "usage: $0 globals <set>"; args=(globals "$set_name") ;;
  restore)
    [[ "$set_name" =~ $SET_RE && "$db" =~ $DB_RE ]] || die "usage: $0 restore <set> <database> [--as <new-name>] [--yes]"
    args=(restore "$set_name" "$db")
    if [[ -n "$as" ]]; then [[ "$as" =~ $DB_RE ]] || die "invalid --as name"; args+=(--as "$as")
    else args+=(--yes); fi ;;
  *) die "usage: $0 list | verify <set> | restore <set> <database> [--as <name>] [--yes] | globals <set>" ;;
esac

# --- replacing a live database: confirm, then stop everything that uses it -------------------
scaled=()
restore_apps() {
  for entry in "${scaled[@]:-}"; do [[ -n "$entry" ]] && "${K[@]}" scale "deploy/${entry%%=*}" --replicas="${entry##*=}" >/dev/null || true; done
}
if [[ "$cmd" == "restore" && -z "$as" ]]; then
  if [[ -z "$yes" ]]; then
    [[ -t 0 ]] || die "refusing to replace '$db' without --yes (no terminal to confirm on)"
    echo "This REPLACES the live database '$db' with $set_name. Everything written after that backup is lost."
    read -r -p "Type the database name to continue: " typed; [[ "$typed" == "$db" ]] || die "cancelled"
  fi
  trap restore_apps EXIT
  deployments=(asix-api); [[ "$db" == "keycloak" ]] && deployments+=(keycloak)
  for d in "${deployments[@]}"; do
    n="$("${K[@]}" get deploy "$d" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo 1)"
    "${K[@]}" scale "deploy/$d" --replicas=0 >/dev/null; scaled+=("$d=${n:-1}")
    "${K[@]}" wait --for=delete pod -l "app=$d" --timeout=120s >/dev/null 2>&1 || true
  done
fi

# --- run the restore tool as a one-off Job ----------------------------------------------------
IMAGE="$("${K[@]}" get deploy asix-api -o jsonpath='{.spec.template.spec.containers[0].image}')"
job="asix-restore-$(date +%s)"
cmdjson="$(printf '"%s",' node src/backup/restore.js "${args[@]}")"; cmdjson="[${cmdjson%,}]"
"${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: batch/v1
kind: Job
metadata:
  name: $job
  namespace: $NS
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 3600
  template:
    spec:
      restartPolicy: Never
      securityContext: { runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000 }
      containers:
        - name: restore
          image: $IMAGE
          imagePullPolicy: IfNotPresent
          command: $cmdjson
          env:
            - { name: PGHOST, value: "postgresql.$NS.svc.cluster.local" }
            - { name: PGPORT, value: "5432" }
            - { name: PGUSER, value: "asix_admin" }
            - name: PGPASSWORD
              valueFrom: { secretKeyRef: { name: postgresql-secret, key: POSTGRES_PASSWORD } }
            - name: BACKUP_PASSPHRASE
              valueFrom: { secretKeyRef: { name: asix-backup-secret, key: BACKUP_PASSPHRASE } }
            - { name: BACKUP_DIR, value: "/backups" }
            - { name: BACKUP_TMP, value: "/scratch" }
          volumeMounts:
            - { name: backups, mountPath: /backups, readOnly: true }
            - { name: scratch, mountPath: /scratch }
      volumes:
        - name: backups
          hostPath: { path: /var/backups/asix/scheduled, type: Directory }
        - name: scratch
          emptyDir: { sizeLimit: 20Gi }
YAML
status=0
"${K[@]}" wait --for=condition=complete "job/$job" --timeout=3600s >/dev/null 2>&1 || status=$?
"${K[@]}" logs "job/$job" 2>&1 || true
"${K[@]}" delete "job/$job" --ignore-not-found >/dev/null 2>&1 || true
if (( status != 0 )); then echo "RESTORE FAILED (see the log above). The applications will be started again." >&2; exit 1; fi
if [[ "$cmd" == "restore" && -z "$as" ]]; then
  echo "Restored $db from $set_name. Starting the applications again..."
  [[ "$db" == "asix_platform" ]] && echo "NOTE: run deploy.sh afterwards if the code is newer than this backup, so any schema changes are applied."
fi
