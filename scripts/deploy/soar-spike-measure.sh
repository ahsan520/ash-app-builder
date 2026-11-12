#!/bin/bash
# SOAR engine spike (task SR0, docs/soar-spike.md): measures what an engine costs on the machine it runs on, and prints the result as a block of Markdown to paste into
# docs/soar-spike.md. It changes nothing. Run it on the engine's host, three times: right after the engine is up and idle (--label idle), while the scenario runs in a loop
# (--label busy), and after an hour of idling (--label settled). Numbers from one run say little; the three together say what the box has to carry.
#   ./scripts/deploy/soar-spike-measure.sh --runtime docker --match tracecat --label idle
#   ./scripts/deploy/soar-spike-measure.sh --runtime k3s --namespace tracecat --label idle --stand-in http://127.0.0.1:8099
# Options:
#   --runtime docker|k3s   how the engine runs (default: docker if `docker` answers, else k3s)
#   --match TEXT           docker: only containers whose name contains TEXT (default: all running containers, which on a dedicated spike VM is the engine)
#   --namespace NS         k3s: the namespace of the engine (default: tracecat)
#   --label TEXT           idle | busy | settled | anything short (default: idle)
#   --samples N            how many readings (default 3), --interval S seconds apart (default 10); the figures printed are the highest seen, not the average
#   --budget-mb N          what the engine may take on the Home machine (default 2048). An ASSUMPTION of the spike, written in docs/soar-spike.md: change it there first.
#   --stand-in URL         also read the verdict of the stand-in server (deploy/soar-spike/stand-in.js) and print it
#   --out FILE             also write the block to FILE
# Exit: 0 printed, 1 nothing could be read (the reason on stderr), 2 a wrong option.
set -uo pipefail

RUNTIME=""; MATCH=""; NS="tracecat"; LABEL="idle"; SAMPLES=3; INTERVAL=10; BUDGET=2048; STAND=""; OUT=""
die() { echo "soar-spike-measure: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --runtime) RUNTIME="${2:-}"; shift 2;; --match) MATCH="${2:-}"; shift 2;; --namespace) NS="${2:-}"; shift 2;;
    --label) LABEL="${2:-}"; shift 2;; --samples) SAMPLES="${2:-}"; shift 2;; --interval) INTERVAL="${2:-}"; shift 2;;
    --budget-mb) BUDGET="${2:-}"; shift 2;; --stand-in) STAND="${2:-}"; shift 2;; --out) OUT="${2:-}"; shift 2;;
    *) die "unknown option $1";;
  esac
done
case "$RUNTIME" in ""|docker|k3s) ;; *) die "--runtime must be docker or k3s";; esac
[[ "$SAMPLES" =~ ^[0-9]+$ ]] && [ "$SAMPLES" -ge 1 ] && [ "$SAMPLES" -le 60 ] || die "--samples must be 1 to 60"
[[ "$INTERVAL" =~ ^[0-9]+$ ]] && [ "$INTERVAL" -le 600 ] || die "--interval must be 0 to 600"
[[ "$BUDGET" =~ ^[0-9]+$ ]] && [ "$BUDGET" -ge 1 ] || die "--budget-mb must be a whole number"
[[ "$LABEL" =~ ^[A-Za-z0-9._-]{1,24}$ ]] || die "--label: letters, digits . _ - only, up to 24"
[[ "$NS" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || die "--namespace is not a valid namespace name"
[[ "$MATCH" =~ ^[A-Za-z0-9._-]*$ ]] || die "--match: letters, digits . _ - only"
if [ -z "$RUNTIME" ]; then if docker ps >/dev/null 2>&1; then RUNTIME=docker; else RUNTIME=k3s; fi; fi

# "512.3MiB" "1.2GiB" "900kB" "12B" -> whole MiB (rounded up)
to_mib() { awk -v s="$1" 'BEGIN{ if (match(s,/^[0-9.]+/)==0) {print 0; exit} n=substr(s,RSTART,RLENGTH)+0; u=substr(s,RLENGTH+1); gsub(/[ \t]/,"",u); u=tolower(u);
  if (u=="gib"||u=="gb"||u=="g"||u=="gi") n=n*1024; else if (u=="mib"||u=="mb"||u=="m"||u=="mi") n=n; else if (u=="kib"||u=="kb"||u=="k"||u=="ki") n=n/1024; else if (u=="b"||u=="") n=n/1048576; else if (u=="tib"||u=="tb"||u=="ti") n=n*1048576;
  printf "%d\n", (n==int(n))?n:int(n)+1 }'; }

# One reading -> lines "name<TAB>mib<TAB>cpu" on stdout, nonzero when nothing could be read.
reading() {
  if [ "$RUNTIME" = docker ]; then
    local out; out=$(docker stats --no-stream --format '{{.Name}}|{{.MemUsage}}|{{.CPUPerc}}' 2>/dev/null) || return 1
    [ -n "$out" ] || return 1
    while IFS='|' read -r name mem cpu; do
      [ -n "$name" ] || continue
      [ -z "$MATCH" ] || case "$name" in *"$MATCH"*) ;; *) continue;; esac
      printf '%s\t%s\t%s\n' "$name" "$(to_mib "${mem%% /*}")" "${cpu%\%}"
    done <<<"$out"
  else
    local out; out=$(kubectl -n "$NS" top pods --no-headers 2>/dev/null) || return 1
    [ -n "$out" ] || return 1
    while read -r name cpu mem _; do
      [ -n "$name" ] || continue
      printf '%s\t%s\t%s\n' "$name" "$(to_mib "$mem")" "$(awk -v c="$cpu" 'BEGIN{ if (c ~ /m$/) { sub(/m$/,"",c); printf "%.1f", c/10 } else printf "%.1f", c*100 }')"
    done <<<"$out"
  fi
}

tmp=$(mktemp -d) || exit 1; trap 'rm -rf "$tmp"' EXIT
i=0; ok=0
while [ "$i" -lt "$SAMPLES" ]; do
  i=$((i+1))
  if reading > "$tmp/r$i" 2>/dev/null && [ -s "$tmp/r$i" ]; then ok=$((ok+1)); else rm -f "$tmp/r$i"; fi
  [ "$i" -lt "$SAMPLES" ] && [ "$INTERVAL" -gt 0 ] && sleep "$INTERVAL"
done
[ "$ok" -ge 1 ] || { echo "soar-spike-measure: nothing could be read from ${RUNTIME}${MATCH:+ (match '$MATCH')}. Is the engine running, and (k3s) is the metrics API up?" >&2; exit 1; }

# The highest total seen across the readings, and the highest of each container.
total_max=$(for f in "$tmp"/r*; do awk -F'\t' '{s+=$2} END{print s+0}' "$f"; done | sort -n | tail -1)
per=$(cat "$tmp"/r* | awk -F'\t' '{ if (!($1 in m) || $2>m[$1]) m[$1]=$2; if (!($1 in c) || $3+0>c[$1]+0) c[$1]=$3 } END{ for (k in m) printf "%s\t%d\t%s\n", k, m[k], c[k] }' | sort -t$'\t' -k2,2nr)
count=$(printf '%s\n' "$per" | grep -c .)
cpus=$(nproc 2>/dev/null || echo "?"); memtot=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}'); memavail=$(free -m 2>/dev/null | awk '/^Mem:/{print $7}')
disk=$( { [ "$RUNTIME" = docker ] && docker system df --format '{{.Type}}: {{.Size}}' 2>/dev/null | tr '\n' ';' ; } || true)
restarts=""
if [ "$RUNTIME" = k3s ]; then restarts=$(kubectl -n "$NS" get pods --no-headers 2>/dev/null | awk '{r+=$4} END{print r+0}'); fi
verdict="within the budget"; [ "$total_max" -gt "$BUDGET" ] && verdict="OVER the budget"

block=$(
  echo "#### Footprint: ${LABEL} ($(date -u +%Y-%m-%d\ %H:%M) UTC, ${RUNTIME}, ${ok} reading(s))"
  echo
  echo "- Host: ${cpus} CPUs, ${memtot:-?} MiB memory, ${memavail:-?} MiB available now."
  echo "- Engine: ${count} container(s) or pod(s), highest total resident memory **${total_max} MiB** against a budget of ${BUDGET} MiB: **${verdict}**."
  [ -n "$restarts" ] && echo "- Pod restarts so far: ${restarts}."
  [ -n "$disk" ] && echo "- Docker disk: ${disk}"
  echo
  echo "| Container or pod | MiB (highest) | CPU % (highest) |"
  echo "|---|---|---|"
  printf '%s\n' "$per" | awk -F'\t' 'NF>=3 {printf "| %s | %s | %s |\n", $1, $2, $3}'
  if [ -n "$STAND" ]; then
    echo
    rep=$(curl -fsS --max-time 10 "${STAND%/}/_spike/report" 2>/dev/null) || rep=""
    if [ -n "$rep" ]; then
      printf '%s' "$rep" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const r=JSON.parse(s);console.log("- Scenario verdict from the stand-in: **"+r.verdict+"**; blocked: "+(r.blocked.join(", ")||"none")+".");for(const c of r.checks)if(!c.ok)console.log("  - FAILED: "+c.text)}catch(e){console.log("- The stand-in answered, but not in a form this script reads.")}})'
    else
      echo "- The stand-in at ${STAND} did not answer."
    fi
  fi
)
printf '%s\n' "$block"
[ -n "$OUT" ] && printf '%s\n' "$block" > "$OUT"
exit 0
