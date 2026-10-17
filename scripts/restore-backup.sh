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
# The events held in ClickHouse have their own backup (one encrypted file per day, see docs/clickhouse-backup.md):
#   sudo scripts/restore-backup.sh ch-list                                    days in the ClickHouse backup, rows, sizes
#   sudo scripts/restore-backup.sh ch-verify                                  load all of it into a scratch table and compare with the manifest, change nothing
#   sudo scripts/restore-backup.sh ch-restore --as <new_table> [--from D] [--to D]   restore into a NEW table to look at it, change nothing else
#   sudo scripts/restore-backup.sh ch-restore --yes [--from D] [--to D]       ADD the backed-up events to the live events table (never deletes)
#
# <database> is asix_platform (events, rules, alerts, ...) or keycloak (users, passwords, clients).
# Everything runs in a one-off Kubernetes Job from the API image; the passphrase never leaves the cluster.
set -euo pipefail
NS="${NAMESPACE:-asix-platform}"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
K=(k3s kubectl -n "$NS")
die() { echo "$*" >&2; exit 1; }
cmd="${1:-}"; set_name=""; db=""; as=""; yes=""
if [[ "$cmd" == ch-* ]]; then
  # ClickHouse events: no backup set name, no applications to stop (the restore only adds events)
  shift
  [[ "$cmd" =~ ^ch-(list|verify|restore)$ ]] || die "usage: $0 ch-list | ch-verify | ch-restore [--as <new_table>] [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--yes]"
  args=("$cmd")
  while (( $# )); do case "$1" in
    --as) [[ "${2:-}" =~ ^[A-Za-z_][A-Za-z0-9_]{0,63}$ && "${2:-}" != "events" ]] || die "--as must be a NEW table name (letters, digits, underscore), not 'events'"; as="$2"; args+=(--as "$2"); shift 2 ;;
    --from|--to) [[ "${2:-}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "$1 needs a day like 2026-10-17"; args+=("$1" "$2"); shift 2 ;;
    --yes) args+=(--yes); shift ;;
    *) die "unknown option: $1" ;;
  esac; done
  [[ "$cmd" != "ch-restore" || -n "$as" || " ${args[*]} " == *" --yes "* ]] || die "ch-restore adds the backed-up events to the live events table (nothing is deleted): pass --yes, or --as <new_table> for a separate copy"
else
  set_name="${2:-}"; db="${3:-}"; shift $(( $# > 3 ? 3 : $# )) || true
  while (( $# )); do case "$1" in --as) as="${2:-}"; shift 2 ;; --yes) yes=1; shift ;; *) die "unknown option: $1" ;; esac; done
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
    *) die "usage: $0 list | verify <set> | restore <set> <database> [--as <name>] [--yes] | globals <set> | ch-list | ch-verify | ch-restore [--as <table>] [--yes]" ;;
  esac
fi

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
            - name: CLICKHOUSE_PASSWORD
              valueFrom: { secretKeyRef: { name: clickhouse-secret, key: CLICKHOUSE_PASSWORD, optional: true } }
            - { name: ASIX_CLICKHOUSE_URL, value: "http://asix:\$(CLICKHOUSE_PASSWORD)@clickhouse:8123/asix" }
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
