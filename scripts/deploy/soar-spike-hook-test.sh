#!/bin/bash
# SOAR engine spike (task SR0, docs/soar-spike.md, "Webhook and environment tests"): two small helpers for the two open tests that decide whether the one-shared-Tracecat design stands.
# It changes nothing on the engine. It only calls the webhook you give it and reads the stand-in server (deploy/soar-spike/stand-in.js).
#   ./scripts/deploy/soar-spike-hook-test.sh webhook --url 'https://<engine>/<the webhook URL from the Trigger panel>' [--insecure]
#   ./scripts/deploy/soar-spike-hook-test.sh verdict [--decide 120] [--reset]
#   ./scripts/deploy/soar-spike-hook-test.sh reset
# webhook  POSTs to the webhook, then waits for the probe workflow (deploy/soar-spike/webhook-probe.tracecat.yaml) to call the stand-in, and says whether a run started and whether the
#          JSON body reached it. If the webhook asks for a key, it says so: that is the answer the design needs. The URL carries a secret: it is printed with its last part hidden.
#   --url URL            the webhook URL (or set SOAR_HOOK_URL, which keeps it out of the shell history)
#   --header-env NAME    send the header line held in the environment variable NAME (for example NAME='X-API-Key: abc'); use it only to test a webhook that asked for a key
#   --no-body            send a bare POST with no body (what `curl -X POST <url>` does); then only "a run started" can be judged
#   --insecure           accept a self-signed certificate (curl -k): the lab engine uses one
#   --stand-in URL       the stand-in (default http://127.0.0.1:8099)   --wait S  how long to wait for the run to show (default 30)
# verdict  prints the stand-in's verdict, the checks that failed, what was blocked, and WHICH credentials reached the firewall (a short fingerprint, never the value), so the
#          environment test reads "wrong ones reached it" or "only the right ones did".
#   --decide S           for S seconds, grant every approval that is waiting (stands in for the person who decides), so a run does not sit waiting
#   --reset              clear the stand-in first
# Exit: webhook 0 = a run started, 1 = no run started; verdict 0 = pass, 1 = fail; 2 = a wrong option or the stand-in cannot be reached.
set -uo pipefail

die() { echo "soar-spike-hook-test: $*" >&2; exit 2; }
CMD="${1:-}"; [ $# -gt 0 ] && shift
URL="${SOAR_HOOK_URL:-}"; HDR_ENV=""; NOBODY=0; INSECURE=0; STAND="http://127.0.0.1:8099"; WAIT=30; DECIDE=0; RESET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="${2:-}"; shift 2;; --header-env) HDR_ENV="${2:-}"; shift 2;; --no-body) NOBODY=1; shift;; --insecure) INSECURE=1; shift;;
    --stand-in) STAND="${2:-}"; shift 2;; --wait) WAIT="${2:-}"; shift 2;; --decide) DECIDE="${2:-}"; shift 2;; --reset) RESET=1; shift;;
    *) die "unknown option $1";;
  esac
done
case "$CMD" in webhook|verdict|reset) ;; *) die "first word must be webhook, verdict or reset (see the top of this file)";; esac
[[ "$WAIT" =~ ^[0-9]+$ ]] && [ "$WAIT" -le 600 ] || die "--wait must be 0 to 600"
[[ "$DECIDE" =~ ^[0-9]+$ ]] && [ "$DECIDE" -le 3600 ] || die "--decide must be 0 to 3600"
command -v curl >/dev/null 2>&1 || die "curl is needed"
command -v node >/dev/null 2>&1 || die "node is needed (it reads the stand-in's JSON)"
STAND="${STAND%/}"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# jget FILE EXPR: evaluate a JavaScript expression over the parsed JSON file as `j` and print the result (arrays one per line).
jget() { node -e 'let j;try{j=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))}catch(e){process.exit(3)};const r=eval(process.argv[2]);if(Array.isArray(r))r.forEach(x=>console.log(x));else if(r!==undefined&&r!==null)console.log(r)' "$1" "$2"; }
standget() { curl -sS --max-time 10 -o "$TMP/$2" -w '%{http_code}' "$STAND$1" 2>"$TMP/err" ; }
need_stand() { local c; c="$(standget /_spike/pings pings.json)"; [ "$c" = "200" ] || die "the stand-in does not answer at $STAND (status $c: $(head -c 200 "$TMP/err")). Start it: node deploy/soar-spike/stand-in.js --host 0.0.0.0 --port 8099"; }

mask_url() { echo "$1" | sed -E 's/\?.*$/?<hidden>/; s#/[^/?]+(\?<hidden>)?$#/<hidden>\1#'; }

if [ "$CMD" = "reset" ]; then
  need_stand; curl -sS --max-time 10 -X POST "$STAND/_spike/reset" >/dev/null || die "reset failed"; echo "stand-in cleared"; exit 0
fi

if [ "$CMD" = "webhook" ]; then
  [ -n "$URL" ] || die "give the webhook URL with --url (or SOAR_HOOK_URL)"
  case "$URL" in http://*|https://*) ;; *) die "the URL must start with http:// or https://";; esac
  need_stand; before="$(jget "$TMP/pings.json" 'j.pings.length')"
  note="hook-test-$(date +%s)"; ARGS=(-sS --max-time 30 -o "$TMP/body" -w '%{http_code}' -X POST)
  [ "$INSECURE" = 1 ] && ARGS+=(-k)
  if [ -n "$HDR_ENV" ]; then
    line="${!HDR_ENV:-}"; [ -n "$line" ] || die "--header-env $HDR_ENV: that variable is empty"
    case "$line" in *:*) ;; *) die "--header-env $HDR_ENV must hold a header line like 'Name: value'";; esac
    ( umask 077; printf '%s\n' "$line" > "$TMP/hdr" ); ARGS+=(-H "@$TMP/hdr")
  fi
  if [ "$NOBODY" = 0 ]; then ARGS+=(-H 'Content-Type: application/json' --data "{\"tenant\":\"probe-1\",\"note\":\"$note\"}"); fi
  echo "calling $(mask_url "$URL")"
  code="$(curl "${ARGS[@]}" "$URL" 2>"$TMP/err")"; rc=$?
  echo "HTTP status: $code"
  if [ $rc -ne 0 ]; then echo "curl said: $(head -c 300 "$TMP/err")"; [ $rc -eq 60 ] && echo "hint: a self-signed certificate; run again with --insecure"; fi
  [ -s "$TMP/body" ] && echo "answer: $(head -c 300 "$TMP/body" | tr '\n' ' ')"
  # wait for the probe workflow to call the stand-in: one ping when the run started, a second one (with the tenant) when the body reached it
  want=1; waited=0; started=0; inputok=0
  while :; do
    standget /_spike/pings pings.json >/dev/null
    now="$(jget "$TMP/pings.json" 'j.pings.length' 2>/dev/null || echo "$before")"
    [ "$now" -gt "$before" ] && started=1
    if [ "$NOBODY" = 0 ] && [ "$(jget "$TMP/pings.json" "j.pings.filter(p=>p.note==='$note'&&p.tenant==='probe-1').length")" -ge 1 ]; then inputok=1; fi
    if [ "$started" = 1 ] && { [ "$NOBODY" = 1 ] || [ "$inputok" = 1 ]; }; then break; fi
    [ "$waited" -ge "$WAIT" ] && break
    sleep 2; waited=$((waited + 2))
  done
  echo "---"
  if [ "$started" = 1 ]; then echo "run started: YES (the probe workflow called the stand-in)"; else echo "run started: NO (nothing reached the stand-in within ${WAIT}s)"; fi
  if [ "$NOBODY" = 1 ]; then echo "JSON body reached the run: not tested (--no-body)"; elif [ "$inputok" = 1 ]; then echo "JSON body reached the run: YES (tenant and note arrived through TRIGGER)"; else echo "JSON body reached the run: NO"; fi
  case "$code" in
    2??) [ "$started" = 1 ] || echo "note: the webhook accepted the call but nothing arrived. Open the run in Tracecat (Runs): the HTTP action may have failed, or the stand-in address in the workflow is wrong.";;
    401|403) echo "NEEDS A KEY: the webhook refused a call with no credentials. Tell me what the Webhook panel offers (an API key or a secret header). If the only way in is an API key that the free tier does not have, the design breaks and the fallback is one Tracecat per customer.";;
    404) echo "note: not found. The URL is wrong, or the Webhook switch on the Trigger node is off, or the workflow is not published.";;
    405) echo "note: the webhook does not accept POST. Look at the allowed methods in the Webhook panel.";;
    000) echo "note: no answer at all (address, firewall or certificate).";;
  esac
  [ "$started" = 1 ] && exit 0 || exit 1
fi

# verdict
need_stand
[ "$RESET" = 1 ] && { curl -sS --max-time 10 -X POST "$STAND/_spike/reset" >/dev/null || die "reset failed"; echo "stand-in cleared"; }
if [ "$DECIDE" -gt 0 ]; then
  echo "granting every waiting approval for ${DECIDE}s (start the run now) ..."
  end=$(( $(date +%s) + DECIDE ))
  while [ "$(date +%s)" -lt "$end" ]; do
    standget /_spike/report report.json >/dev/null
    for id in $(jget "$TMP/report.json" "j.approvals.filter(a=>a.status==='waiting').map(a=>a.id)" 2>/dev/null); do
      curl -sS --max-time 10 -X POST "$STAND/asix/approvals/$id/grant" >/dev/null && echo "  granted $id"
    done
    sleep 2
  done
fi
c="$(standget /_spike/report report.json)"; [ "$c" = "200" ] || die "could not read the report (status $c)"
verdict="$(jget "$TMP/report.json" 'j.verdict')"
echo "verdict: $(echo "$verdict" | tr a-z A-Z)"
bad="$(jget "$TMP/report.json" "j.checks.filter(c=>!c.ok).map(c=>'  '+c.id+': '+c.text)")"
[ -n "$bad" ] && { echo "failed checks:"; echo "$bad"; }
echo "blocked: $(jget "$TMP/report.json" "j.blocked.join(', ')||'(none)'")"
exp="$(jget "$TMP/report.json" 'j.expected_fp')"
echo "credentials that reached the firewall (the right ones have fingerprint $exp):"
rows="$(jget "$TMP/report.json" "j.credentials_seen.map(r=>'  fp '+r.fp+'  user '+(r.user||'-')+'  '+(r.fp===j.expected_fp?'RIGHT':'WRONG')+'  x'+r.count)")"
if [ -n "$rows" ]; then echo "$rows"; else echo "  (none yet)"; fi
wrong="$(jget "$TMP/report.json" "j.credentials_seen.filter(r=>r.fp!==j.expected_fp).length")"
if [ "${wrong:-0}" -gt 0 ]; then echo "reading: a WRONG credential reached the firewall, so the environment override picked the secret that was set wrong."
elif [ "$verdict" = "pass" ]; then echo "reading: only the right credentials reached the firewall and the verdict passes."; fi
[ "$verdict" = "pass" ] && exit 0 || exit 1
