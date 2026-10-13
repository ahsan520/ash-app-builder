#!/usr/bin/env bash
#
# Make the platform's data volumes survive an accidental delete.
#
# k3s's default "local-path" storage class has reclaimPolicy=Delete: deleting a PersistentVolumeClaim
# (or the whole namespace) also deletes the data folder on the VM. Switching every volume that belongs
# to the platform namespace to Retain means the data stays on disk and can be re-attached with
# scripts/recover-volume.sh. Deleting or recreating PODS never touched the data; this protects
# against the bigger mistakes. Safe to run repeatedly (deploy.sh does).
#
#   sudo scripts/deploy/protect-volumes.sh [namespace]
set -euo pipefail
NS="${1:-asix-platform}"
[[ "$NS" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || { echo "invalid namespace: $NS" >&2; exit 1; }
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
K=(k3s kubectl)

changed=0; seen=0
while IFS=$'\t' read -r pv claim policy; do
  [[ -z "$pv" ]] && continue
  seen=$((seen + 1))
  if [[ "$policy" == "Retain" ]]; then
    echo "ok         $pv ($claim): data is kept if the claim is deleted"
  else
    "${K[@]}" patch pv "$pv" -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}' >/dev/null
    echo "protected  $pv ($claim): reclaim policy $policy -> Retain"
    changed=$((changed + 1))
  fi
done < <("${K[@]}" get pv -o jsonpath='{range .items[?(@.spec.claimRef.namespace=="'"$NS"'")]}{.metadata.name}{"\t"}{.spec.claimRef.name}{"\t"}{.spec.persistentVolumeReclaimPolicy}{"\n"}{end}')

echo "volumes in $NS: $seen, newly protected: $changed"
