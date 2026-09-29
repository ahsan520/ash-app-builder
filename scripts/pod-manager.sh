#!/usr/bin/env bash
#
# Pod manager for the asix-platform namespace: clean up broken pods, and
# optionally restart healthy ones. Called by sync-and-deploy.sh after every
# deploy (even a failed one), or on its own via:
#
#     ./sync-and-deploy.sh --pods-only        # fast break/fix, no rebuild
#     bash scripts/pod-manager.sh [options]
#
# What it does, in order:
#   1. CLEAN  - pods that are failing (CrashLoopBackOff, ImagePullBackOff,
#               Error/Evicted/Failed, or Running-but-never-Ready with
#               restarts) get their diagnostics saved + printed, then are
#               deleted so their Deployment recreates them.
#               Pods left over from an OLD revision are deleted only if the
#               new revision is fully rolled out. If the new revision is NOT
#               healthy, the old pods are the only ones serving traffic, so
#               they are kept.
#   2. MENU   - healthy pods are listed; you pick which to restart:
#               [r] rolling restart of the owning workload (no downtime)
#               [d] delete just the selected pod(s)
#   Job pods (Completed) are ignored. StatefulSet pods (PostgreSQL) always
#   ask for confirmation.
#
# Options:
#   -n, --namespace NS   namespace (default: asix-platform)
#   --no-clean           skip step 1
#   --no-menu            skip step 2 (also skipped automatically when stdin
#                        is not a terminal)
#   --restart-all        non-interactive: rolling-restart every Deployment
#                        (StatefulSets like PostgreSQL are never touched)
#   --dry-run            print what would be deleted/restarted, change nothing
#   --yes                assume "yes" to confirmations
#   -h, --help
#
# Deleting a failing pod does NOT fix why it fails: the Deployment recreates
# it and it fails again. Read the saved diagnostics for the cause.
#
set -uo pipefail

NS="asix-platform"
DO_CLEAN=1
DO_MENU=1
RESTART_ALL=0
DRY_RUN=0
ASSUME_YES=0

usage() { sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace) NS="${2:?--namespace needs a value}"; shift ;;
    --no-clean)     DO_CLEAN=0 ;;
    --no-menu)      DO_MENU=0 ;;
    --restart-all)  RESTART_ALL=1; DO_MENU=0 ;;
    --dry-run)      DRY_RUN=1 ;;
    --yes|-y)       ASSUME_YES=1 ;;
    -h|--help)      usage; exit 0 ;;
    *) echo "pod-manager: unknown option '$1'" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
# KUBECTL can be overridden (e.g. for testing); default is the k3s bundled one.
read -r -a KC <<< "${KUBECTL:-k3s kubectl}"

command -v jq >/dev/null || { echo "pod-manager: jq is required (apt-get install -y jq)" >&2; exit 1; }
"${KC[@]}" version --client >/dev/null 2>&1 || { echo "pod-manager: cannot run '${KC[*]}'" >&2; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

DIAG_DIR="/var/log/asix"
{ mkdir -p "$DIAG_DIR" 2>/dev/null && [[ -w "$DIAG_DIR" ]]; } || DIAG_DIR="/tmp"
DIAG_FILE="$DIAG_DIR/pod-diagnostics-$(date -u +%Y%m%dT%H%M%SZ).log"

interactive=0
[[ -t 0 || "${POD_MANAGER_ASSUME_TTY:-0}" == "1" ]] && interactive=1

run() { # run a mutating command, or just print it in --dry-run
  if [[ $DRY_RUN -eq 1 ]]; then echo "  [dry-run] $*"; else "$@"; fi
}

confirm() { # confirm "question"  -> 0 if yes
  [[ $ASSUME_YES -eq 1 ]] && return 0
  local a; read -r -p "$1 [y/N]: " a || return 1
  [[ "$a" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# ---------------------------------------------------------------------------
# Classify every pod. Output (tab separated, no empty fields):
#   name  class  workload  ready  restarts  age_s  detail  rollout_complete
# class: failing | old | healthy   (Job/Succeeded/terminating pods omitted)
# ---------------------------------------------------------------------------
JQ_CLASSIFY='
def bad: ["CrashLoopBackOff","ImagePullBackOff","ErrImagePull","CreateContainerConfigError",
          "CreateContainerError","InvalidImageName","RunContainerError"];
($rs[0].items // []) as $rsItems
| ($deps[0].items // []) as $depItems
| ($rsItems | map({key: .metadata.name,
     value: (((.metadata.ownerReferences // []) | map(select(.kind=="Deployment")) | .[0].name) // "")}) | from_entries) as $rsOwner
| ($rsItems | map({key: .metadata.name,
     value: ((.metadata.annotations // {})["deployment.kubernetes.io/revision"] // "")}) | from_entries) as $rsRev
| ($depItems | map({key: .metadata.name, value: {
     rev: ((.metadata.annotations // {})["deployment.kubernetes.io/revision"] // ""),
     complete: (((.status.updatedReplicas // 0) >= (.spec.replicas // 1))
                and ((.status.readyReplicas // 0) >= (.spec.replicas // 1))
                and ((.status.replicas // 0) == (.status.updatedReplicas // 0)))}}) | from_entries) as $dep
| $pods[0].items[]
| select(.metadata.deletionTimestamp == null)
| . as $p
| (($p.metadata.ownerReferences // [])[0]) as $o
| ($o.kind // "none") as $ok
| ($o.name // "") as $on
| (if $ok == "ReplicaSet" then ($rsOwner[$on] // "") else "" end) as $depName
| ($p.status.containerStatuses // []) as $cs
| ([$cs[].restartCount] | add // 0) as $restarts
| ([$cs[] | (.state.waiting.reason // empty)]) as $waiting
| (($p.status.phase == "Running") and ($cs | length > 0) and ($cs | all(.ready))) as $ready
| (if $ok == "Job" or $p.status.phase == "Succeeded" then "skip"
   elif $p.status.phase == "Failed" or $p.status.phase == "Unknown" then "failing"
   elif ($waiting | any(. as $w | (bad | index($w)) != null)) then "failing"
   elif ($p.status.phase == "Running" and ($ready | not) and $restarts > 0) then "failing"
   elif ($depName != "" and ($rsRev[$on] != ($dep[$depName].rev // ""))) then "old"
   else "healthy" end) as $class
| select($class != "skip")
| (if $depName != "" then "deployment/" + $depName
   elif $ok == "StatefulSet" then "statefulset/" + $on
   elif $ok == "DaemonSet" then "daemonset/" + $on
   else "pod/" + $p.metadata.name end) as $wl
| (if ($waiting | length) > 0 then $waiting[0]
   elif $p.status.phase == "Failed" then ($p.status.reason // "Failed")
   elif ($p.status.phase == "Running" and ($ready | not)) then "NotReady"
   else ($p.status.phase // "-") end) as $detail
| [ $p.metadata.name, $class, $wl, ($ready | tostring), ($restarts | tostring),
    ((now - ($p.metadata.creationTimestamp | fromdateiso8601)) | floor | tostring),
    $detail,
    (if $depName != "" then ($dep[$depName].complete | tostring) else "-" end)
  ] | @tsv
'

echo "== Pod check (namespace: $NS) =="
for kind in pods rs deploy; do
  "${KC[@]}" -n "$NS" get "$kind" -o json > "$TMP/$kind.json" 2>"$TMP/err" || {
    echo "pod-manager: 'get $kind' failed: $(cat "$TMP/err")" >&2; exit 1; }
done

mapfile -t ROWS < <(jq -r --slurpfile pods "$TMP/pods.json" --slurpfile rs "$TMP/rs.json" \
                       --slurpfile deps "$TMP/deploy.json" -n "$JQ_CLASSIFY")

fmt_age() {
  local s=$1
  if   (( s >= 86400 )); then echo "$((s/86400))d"
  elif (( s >= 3600 ));  then echo "$((s/3600))h"
  elif (( s >= 60 ));    then echo "$((s/60))m"
  else echo "${s}s"; fi
}

FAILING=(); OLD_DEL=(); OLD_KEEP=(); HEALTHY=()
declare -A WL_COUNT=()
for row in "${ROWS[@]}"; do
  IFS=$'\t' read -r name class wl ready restarts age detail complete <<< "$row"
  case "$class" in
    failing) FAILING+=("$row") ;;
    old)     if [[ "$complete" == "true" ]]; then OLD_DEL+=("$row"); else OLD_KEEP+=("$row"); fi ;;
    healthy) HEALTHY+=("$row")
             # count only healthy pods per workload: used to warn when a selection
             # would remove every pod that is currently serving traffic
             WL_COUNT[$wl]=$(( ${WL_COUNT[$wl]:-0} + 1 )) ;;
  esac
done

if [[ ${#ROWS[@]} -eq 0 ]]; then echo "No pods found in namespace $NS."; exit 0; fi
printf '  %d healthy, %d failing, %d old-revision (%d safe to delete)\n' \
  "${#HEALTHY[@]}" "${#FAILING[@]}" "$(( ${#OLD_DEL[@]} + ${#OLD_KEEP[@]} ))" "${#OLD_DEL[@]}"

diagnose() { # diagnose <pod> - print + save why a pod is failing, BEFORE deleting it
  local pod=$1
  {
    echo "----- $pod  ($(date -u +%FT%TZ)) -----"
    "${KC[@]}" -n "$NS" describe pod "$pod" 2>&1 \
      | grep -E '^\s+(State|Last State|Reason|Exit Code|Restart Count|Liveness|Readiness|Image):' | sed 's/^/  /'
    echo "  --- Events ---"
    "${KC[@]}" -n "$NS" describe pod "$pod" 2>&1 | sed -n '/^Events:/,$p' | tail -12 | sed 's/^/  /'
    echo "  --- logs (current, last 30) ---"
    "${KC[@]}" -n "$NS" logs "$pod" --all-containers --tail=30 2>&1 | sed 's/^/  /'
    echo "  --- logs (previous crash, last 30) ---"
    "${KC[@]}" -n "$NS" logs "$pod" --all-containers --previous --tail=30 2>&1 | sed 's/^/  /'
  } | tee -a "$DIAG_FILE"
}

rolling_restart() { # rolling_restart <kind/name>
  local wl=$1
  echo "Rolling restart: $wl"
  run "${KC[@]}" -n "$NS" rollout restart "$wl" || return 1
  [[ $DRY_RUN -eq 1 ]] || "${KC[@]}" -n "$NS" rollout status "$wl" --timeout=180s
}

# ---------------------------------------------------------------------------
# 1. CLEAN
# ---------------------------------------------------------------------------
if [[ $DO_CLEAN -eq 1 ]]; then
  if [[ ${#FAILING[@]} -gt 0 ]]; then
    echo
    echo "== Failing pods =="
    for row in "${FAILING[@]}"; do
      IFS=$'\t' read -r name class wl ready restarts age detail complete <<< "$row"
      echo "* $name  [$wl]  $detail, ready=$ready, restarts=$restarts, age=$(fmt_age "$age")"
    done
    echo
    echo "Saving diagnostics (before the pods are deleted) -> $DIAG_FILE"
    for row in "${FAILING[@]}"; do
      IFS=$'\t' read -r name _ <<< "$row"
      diagnose "$name"
    done
    echo
    for row in "${FAILING[@]}"; do
      IFS=$'\t' read -r name class wl ready restarts age detail complete <<< "$row"
      if [[ "$wl" == statefulset/* ]]; then
        if [[ $interactive -eq 1 || $ASSUME_YES -eq 1 ]]; then
          confirm "Delete failing STATEFUL pod $name ($wl)? Its data volume is kept." || { echo "  kept $name"; continue; }
        else
          echo "  kept $name ($wl is stateful; re-run interactively or with --yes to delete it)"; continue
        fi
      fi
      echo "Deleting failing pod $name ..."
      run "${KC[@]}" -n "$NS" delete pod "$name" --wait=false
    done
    echo "NOTE: the controller recreates these pods. If the cause is in the code/config"
    echo "      (see diagnostics above), the new pod fails the same way until that is fixed."
  else
    echo "No failing pods."
  fi

  if [[ ${#OLD_DEL[@]} -gt 0 ]]; then
    echo
    echo "== Old-revision pods (new revision is fully rolled out) =="
    for row in "${OLD_DEL[@]}"; do
      IFS=$'\t' read -r name _ <<< "$row"
      echo "Deleting old pod $name ..."
      run "${KC[@]}" -n "$NS" delete pod "$name" --wait=false
    done
  fi
  if [[ ${#OLD_KEEP[@]} -gt 0 ]]; then
    echo
    echo "== Old-revision pods KEPT (new revision is NOT healthy yet) =="
    for row in "${OLD_KEEP[@]}"; do
      IFS=$'\t' read -r name class wl ready restarts age detail complete <<< "$row"
      echo "* $name [$wl] ready=$ready - still serving traffic; deleting it would cause downtime"
    done
    echo "  Fix the failing new pod (see diagnostics), or undo the rollout:"
    echo "    ./rollback.sh --quick"
  fi
fi

# ---------------------------------------------------------------------------
# --restart-all (non-interactive)
# ---------------------------------------------------------------------------
if [[ $RESTART_ALL -eq 1 ]]; then
  echo
  echo "== Rolling restart of all Deployments (StatefulSets untouched) =="
  mapfile -t DEPS < <(jq -r '.items[].metadata.name | "deployment/" + .' "$TMP/deploy.json")
  for d in "${DEPS[@]}"; do rolling_restart "$d" || echo "  WARN: $d did not finish rolling out"; done
fi

# ---------------------------------------------------------------------------
# 2. MENU for healthy pods
# ---------------------------------------------------------------------------
if [[ $DO_MENU -eq 1 ]]; then
  if [[ ${#HEALTHY[@]} -eq 0 ]]; then
    echo; echo "No healthy pods to offer."
  elif [[ $interactive -eq 0 ]]; then
    echo; echo "(non-interactive: skipping the healthy-pod restart menu; run ./sync-and-deploy.sh --pods-only in a terminal)"
  else
    echo
    echo "== Healthy pods - restart any? =="
    i=0
    for row in "${HEALTHY[@]}"; do
      i=$((i+1))
      IFS=$'\t' read -r name class wl ready restarts age detail complete <<< "$row"
      printf '  %2d) %-42s %-32s restarts=%s age=%s\n' "$i" "$name" "$wl" "$restarts" "$(fmt_age "$age")"
    done
    read -r -p "Select numbers (e.g. 1,3), 'a' = all, Enter = none: " sel || sel=""
    sel="${sel//,/ }"
    PICK=()
    if [[ "$sel" =~ ^[[:space:]]*[Aa]([Ll][Ll])?[[:space:]]*$ ]]; then
      for ((n=0; n<${#HEALTHY[@]}; n++)); do PICK+=("$n"); done
    else
      for tok in $sel; do
        if [[ "$tok" =~ ^[0-9]+$ ]] && (( tok >= 1 && tok <= ${#HEALTHY[@]} )); then PICK+=("$((tok-1))")
        else echo "  ignoring invalid selection '$tok'"; fi
      done
    fi

    if [[ ${#PICK[@]} -eq 0 ]]; then
      echo "Nothing selected."
    else
      SEL_NAMES=(); declare -A SEL_WL=(); declare -A SEL_PER_WL=()
      for idx in "${PICK[@]}"; do
        IFS=$'\t' read -r name class wl _ <<< "${HEALTHY[$idx]}"
        SEL_NAMES+=("$name"); SEL_WL[$wl]=1; SEL_PER_WL[$wl]=$(( ${SEL_PER_WL[$wl]:-0} + 1 ))
      done
      echo "Selected: ${SEL_NAMES[*]}"
      read -r -p "Action: [r] rolling restart of owning workload (no downtime)  [d] delete selected pod(s)  [Enter] cancel: " act || act=""
      case "$act" in
        r|R)
          for wl in "${!SEL_WL[@]}"; do
            if [[ "$wl" == pod/* ]]; then
              echo "  $wl has no controller (bare pod) - rolling restart not possible; use [d] instead"; continue
            fi
            if [[ "$wl" == statefulset/* ]]; then
              confirm "  $wl is STATEFUL (database). Restarting it interrupts service briefly. Continue?" || { echo "  skipped $wl"; continue; }
            fi
            rolling_restart "$wl" || echo "  WARN: $wl did not finish rolling out"
          done ;;
        d|D)
          for wl in "${!SEL_WL[@]}"; do
            if (( ${SEL_PER_WL[$wl]} >= ${WL_COUNT[$wl]:-1} )); then
              echo "  WARNING: this deletes ALL running pods of $wl -> brief downtime until they are recreated."
              confirm "  Continue for $wl?" || { echo "  skipped $wl"; continue; }
            fi
            for idx in "${PICK[@]}"; do
              IFS=$'\t' read -r name _ wl2 _ <<< "${HEALTHY[$idx]}"
              [[ "$wl2" == "$wl" ]] || continue
              if [[ "$wl" == statefulset/* ]]; then confirm "  $name is STATEFUL. Delete it?" || { echo "  skipped $name"; continue; }; fi
              echo "Deleting $name ..."
              run "${KC[@]}" -n "$NS" delete pod "$name" --wait=false
            done
          done ;;
        *) echo "Cancelled." ;;
      esac
    fi
  fi
fi

echo
echo "== Current pods =="
[[ $DRY_RUN -eq 1 ]] || sleep 3
"${KC[@]}" -n "$NS" get pods 2>&1 | grep -v -E ' Completed ' || true
if [[ -s "$DIAG_FILE" ]]; then echo; echo "Diagnostics saved: $DIAG_FILE"; fi
exit 0
