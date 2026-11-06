#!/bin/bash
# One pass of every layer on the current code: the check after a hard reset.
#
#   scripts/test-run.sh --plan          # print the steps, run nothing
#   scripts/test-run.sh                 # run them (hours; see below)
#
# Steps, each logged to <data root>/test-run/<stamp>/<step>.log with its exit code and
# time in summary.txt. A failed step is recorded and the run goes on where the next
# step does not depend on it.
#   1. preflight: quarry doctor, Ollama and the deep models, Docker
#   2. quarry db sync (skip with --skip-sync)
#   3. quarry deep-replay: the planted-bug set through Layer 2 (about 10 minutes)
#   4. every target: ingest, scan (--timeout 3600), funnel, status
#   5. a bounded deep review of one target (--deep-hours, default 2)
#   6. quarry validate on VulnLookup, the one target shown to boot under Layer 3
#      (build about 30 minutes; seeds two users for the cross-user probe)
#   7. quarry report and quarry status --json for every run
#
# Options: --skip-sync, --deep-hours N, --deep-target SLUG, --no-validate,
#          --targets "SLUG SLUG ..."
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
Q="${QUARRY_HOME:-$HOME/Library/Application Support/Quarry}"
QB="${QUARRY_BIN:-$REPO/.venv/bin/quarry}"
PY="${QUARRY_PY:-$REPO/.venv/bin/python}"
TARGETS="CVEProject/cve-services vulnerability-lookup/ML-Gateway vulnerability-lookup/vulnerability-lookup"
DEEP_TARGET="vulnerability-lookup/ML-Gateway"
DEEP_HOURS=2
VALIDATE_TARGET="vulnerability-lookup/vulnerability-lookup"
SYNC=1; PLAN=0; VALIDATE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --plan) PLAN=1 ;;
    --skip-sync) SYNC=0 ;;
    --no-validate) VALIDATE=0 ;;
    --deep-hours) DEEP_HOURS="$2"; shift ;;
    --deep-target) DEEP_TARGET="$2"; shift ;;
    --targets) TARGETS="$2"; shift ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
  shift
done

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$Q/test-run/$STAMP"
SUMMARY="$OUT/summary.txt"
export LC_ALL=en_US.UTF-8 COLUMNS=160

note() { echo "$*"; [ "$PLAN" = 1 ] || echo "$*" >> "$SUMMARY"; }

# step NAME CMD...: run, log, record exit code and seconds
step() {
  local name="$1"; shift
  if [ "$PLAN" = 1 ]; then echo "  [$name] $*"; return 0; fi
  local t0=$SECONDS
  echo "=== $(date '+%H:%M:%S') $name: $*"
  "$@" >"$OUT/$name.log" 2>&1
  local rc=$?
  printf '%-28s rc=%-3s %6ss  %s\n' "$name" "$rc" "$((SECONDS - t0))" "$*" >> "$SUMMARY"
  tail -3 "$OUT/$name.log" | sed 's/^/    /'
  return $rc
}

run_id() {   # newest run of a target, or empty
  "$PY" - "$1" <<'PY'
import sys
from quarry.cli import _open
_, con = _open()
r = con.execute("SELECT MAX(id) FROM runs WHERE target=?", (sys.argv[1],)).fetchone()[0]
print(r or "")
PY
}

slug() { echo "$1" | tr '/' '_'; }

if [ "$PLAN" = 0 ]; then
  mkdir -p "$OUT"
  note "Quarry test run $STAMP on $(git -C "$REPO" rev-parse --short HEAD) ($(git -C "$REPO" status --porcelain -- quarry | wc -l | tr -d ' ') uncommitted file(s) under quarry/)"
  note "data root $Q"
else
  echo "Quarry test run, plan only. Logs would go to $OUT"
fi

# 1. preflight
step preflight-doctor "$QB" doctor
step preflight-ollama /bin/bash -c "curl -s --max-time 5 http://127.0.0.1:11434/api/tags | \
  '$PY' -c 'import json,sys; from quarry.cli import DEFAULT_DEEP_MODELS as D; have={m[\"name\"] for m in json.load(sys.stdin)[\"models\"]}; need=D.split(\",\"); miss=[m for m in need if m not in have]; print(\"models:\", need, \"missing:\", miss); sys.exit(1 if miss else 0)'"
[ "$VALIDATE" = 1 ] && step preflight-docker docker info --format '{{.ServerVersion}} {{.NCPU}} cpu {{.MemTotal}} bytes'

# 2. vulnerability databases
[ "$SYNC" = 1 ] && step db-sync "$QB" db sync

# 3. Layer 2 against the planted set
step deep-replay "$QB" deep-replay --out "$OUT/replay.json"

# 4. Layer 1 and the funnel, every target
RIDS=""
for t in $TARGETS; do
  s="$(slug "$t")"
  step "ingest-$s" "$QB" ingest "$t" || continue
  if [ "$PLAN" = 1 ]; then rid="<$s>"; else rid="$(run_id "$t")"; fi
  note "run $rid = $t"
  RIDS="$RIDS $rid"
  step "scan-$s" "$QB" scan "$rid" --timeout 3600
  step "funnel-$s" "$QB" funnel "$rid"
done

# 5. a bounded deep review
if [ "$PLAN" = 1 ]; then drid="<run of $DEEP_TARGET>"; else drid="$(run_id "$DEEP_TARGET")"; fi
[ -n "$drid" ] && step "deep-$(slug "$DEEP_TARGET")" caffeinate -is "$QB" deep "$drid" --hours "$DEEP_HOURS"

# 6. Layer 3 on the target that boots
if [ "$VALIDATE" = 1 ]; then
  if [ "$PLAN" = 1 ]; then vrid="<run of $VALIDATE_TARGET>"; else vrid="$(run_id "$VALIDATE_TARGET")"; fi
  uuid="$(uuidgen | tr 'A-Z' 'a-z')"
  [ -n "$vrid" ] && step "validate-$(slug "$VALIDATE_TARGET")" caffeinate -is "$QB" validate "$vrid" \
    --build-network --memory 6g --env "INSTANCE_UUID=$uuid" --seed vulnlookup
fi

# 7. reports and the final state of every run
for rid in $RIDS; do
  step "report-run$rid" "$QB" report "$rid"
  step "status-run$rid" /bin/bash -c "'$QB' status '$rid' --json > '$OUT/status-run$rid.json'"
done
[ "$PLAN" = 1 ] || { echo; cat "$SUMMARY"; echo "logs: $OUT"; }
