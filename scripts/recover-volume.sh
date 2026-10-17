#!/usr/bin/env bash
#
# Re-attach a retained data volume after its claim was deleted (accidental `kubectl delete pvc`,
# `kubectl delete ns`, or a re-install). Works because scripts/deploy/protect-volumes.sh set the volumes
# to Retain: the data folder is still on the VM, the PV just sits in state "Released".
#
#   sudo scripts/recover-volume.sh list
#   sudo scripts/recover-volume.sh rebind <pv-name> <claim-name>           show what would be done
#   sudo scripts/recover-volume.sh rebind <pv-name> <claim-name> --apply   do it
#
# The PostgreSQL claim is called  postgresql-data-postgresql-0 . Recreate the namespace and the
# StatefulSet (deploy.sh) AFTER the claim is back, and PostgreSQL starts on the old data.
set -euo pipefail
NS="${NAMESPACE:-asix-platform}"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
K=(k3s kubectl)
ID='^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$'

case "${1:-}" in
  list)
    echo "Released volumes that used to belong to $NS (data is still on disk):"
    "${K[@]}" get pv -o jsonpath='{range .items[?(@.status.phase=="Released")]}{.metadata.name}{"\t"}{.spec.claimRef.namespace}/{.spec.claimRef.name}{"\t"}{.spec.capacity.storage}{"\n"}{end}' \
      | awk -F'\t' -v ns="$NS" '$2 ~ "^"ns"/" {printf "  %-48s was %-40s %s\n", $1, $2, $3; n++} END {if (!n) print "  (none)"}'
    ;;
  rebind)
    pv="${2:-}"; claim="${3:-}"; apply="${4:-}"
    [[ "$pv" =~ $ID && "$claim" =~ $ID ]] || { echo "usage: $0 rebind <pv-name> <claim-name> [--apply]" >&2; exit 1; }
    size="$("${K[@]}" get pv "$pv" -o jsonpath='{.spec.capacity.storage}')"
    sc="$("${K[@]}" get pv "$pv" -o jsonpath='{.spec.storageClassName}')"
    manifest="apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $claim
  namespace: $NS
spec:
  accessModes: [\"ReadWriteOnce\"]
  storageClassName: \"$sc\"
  volumeName: $pv
  resources:
    requests:
      storage: $size"
    echo "1. Clear the old claim reference so the volume becomes Available:"
    echo "     k3s kubectl patch pv $pv --type=json -p '[{\"op\":\"remove\",\"path\":\"/spec/claimRef\"}]'"
    echo "2. Create the claim that points at it:"
    echo "$manifest" | sed 's/^/     /'
    if [[ "$apply" == "--apply" ]]; then
      "${K[@]}" get ns "$NS" >/dev/null 2>&1 || "${K[@]}" create namespace "$NS"
      "${K[@]}" patch pv "$pv" --type=json -p '[{"op":"remove","path":"/spec/claimRef"}]' >/dev/null
      echo "$manifest" | "${K[@]}" apply -f -
      echo "done. Now run deploy.sh (or sync-and-deploy.sh) so PostgreSQL starts on this volume."
    else
      echo "(nothing changed - add --apply to do it)"
    fi
    ;;
  *) echo "usage: $0 list | rebind <pv-name> <claim-name> [--apply]" >&2; exit 1 ;;
esac
