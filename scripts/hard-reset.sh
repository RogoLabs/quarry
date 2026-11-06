#!/bin/bash
# Start Quarry over from an empty database, keeping everything that came before.
#
# Nothing is deleted. The database, run images, blobs, reports, logs, backups and
# replay results move to <data root>/archive/<stamp>/, so a reset is undone by moving
# them back. Kept in place: the vulnerability databases (vulndb/), the rule packs
# (rules/), the nightly job's runtime (runtime/) and its script (nightly-deep.sh).
#
#   scripts/hard-reset.sh          # dry run: checks, then prints every step
#   scripts/hard-reset.sh --go     # does it
#
# Refuses while anything could be writing: a `quarry deep` worker, the 21:00 launchd
# job loaded, or the dashboard (`quarry serve`) holding the database open.
set -uo pipefail

Q="${QUARRY_HOME:-$HOME/Library/Application Support/Quarry}"
STAMP="$(date +%Y%m%d-%H%M%S)"
A="$Q/archive/$STAMP"
JOB="net.rogolabs.quarry-deep"
GO=0
[ "${1:-}" = "--go" ] && GO=1

step() {                       # print, and run only with --go
  echo "  + $*"
  if [ "$GO" = 1 ]; then "$@" || { echo "FAILED: $*"; exit 1; }; fi
}
refuse() { echo "refusing: $*"; exit 2; }

echo "Quarry hard reset ($([ $GO = 1 ] && echo LIVE || echo 'dry run'))"
echo "  data root: $Q"
echo "  archive:   $A"
[ -d "$Q" ] || refuse "no data root at $Q"

# QUARRY_RESET_TEST=1 rehearses on a scratch root: it needs QUARRY_HOME set to something
# other than the real data root, and skips the machine-wide checks below (processes,
# the launchd job, mounted run volumes), which are about the real root only.
TEST=0
if [ "${QUARRY_RESET_TEST:-}" = 1 ]; then
  [ -n "${QUARRY_HOME:-}" ] && [ "$Q" != "$HOME/Library/Application Support/Quarry" ] \
    || refuse "QUARRY_RESET_TEST needs QUARRY_HOME set to a scratch root"
  TEST=1
  echo "  rehearsal on a scratch root: process, job and volume checks skipped"
fi

# -- preconditions ------------------------------------------------------------------
# The patterns are bracketed so they cannot match this script's own command line.
if [ "$TEST" != 1 ]; then
  if pgrep -fl "[q]uarry(\.cli)? deep" >/dev/null; then
    refuse "a deep review is running: $(pgrep -fl '[q]uarry(\.cli)? deep' | head -1)"
  fi
  if pgrep -fl "[q]uarry(\.cli)? serve" >/dev/null; then
    refuse "the dashboard holds the database open; stop it first: $(pgrep -fl '[q]uarry(\.cli)? serve' | head -1)"
  fi
  if launchctl print "gui/$(id -u)/$JOB" >/dev/null 2>&1; then
    refuse "the nightly job $JOB is loaded; unload it first: launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/$JOB.plist"
  fi
fi
command -v sqlite3 >/dev/null || refuse "sqlite3 not found"

# -- what moves ---------------------------------------------------------------------
MOVE=()
for d in quarry.db quarry.db-wal quarry.db-shm runs run blobs reports logs deep-logs backups replay test-run; do
  [ -e "$Q/$d" ] && MOVE+=("$d")
done
echo "  moves:     ${MOVE[*]:-(nothing)}"
for d in "${MOVE[@]}"; do
  printf '             %-14s %s\n' "$d" "$(du -sh "$Q/$d" 2>/dev/null | cut -f1)"
done
echo "  keeps:     vulndb rules runtime nightly-deep.sh"

# -- run volumes --------------------------------------------------------------------
# Each ingested run's clone is a sparse image mounted at /private/tmp/quarry/run-<id>.
# Its image is about to move, so detach it first; a mount point left empty is removed
# with rmdir, which refuses anything that is not an empty directory.
for m in /private/tmp/quarry/run-*; do
  [ "$TEST" = 1 ] && break
  [ -e "$m" ] || continue
  if mount | grep -q " on $m "; then
    step /usr/bin/hdiutil detach "$m" -quiet
  fi
  [ "$GO" = 1 ] && rmdir "$m" 2>/dev/null
done

# -- database: fold the WAL into the main file so the archived copy stands alone -----
if [ -e "$Q/quarry.db" ]; then
  step sqlite3 "$Q/quarry.db" "PRAGMA wal_checkpoint(TRUNCATE);"
  step sqlite3 "$Q/quarry.db" "PRAGMA quick_check;"
fi

# -- move ---------------------------------------------------------------------------
step mkdir -p "$A"
for d in "${MOVE[@]}"; do
  step mv "$Q/$d" "$A/$d"
done
if [ "$GO" = 1 ]; then
  {
    echo "Quarry data archived by scripts/hard-reset.sh on $(date)."
    echo "Restore: stop Quarry, then move every entry here back to $Q"
    echo "(the fresh quarry.db created after the reset must be moved aside first)."
  } > "$A/README.txt"
fi

# -- fresh database -----------------------------------------------------------------
# Opening the database creates it and applies every migration.
PY="$Q/runtime/venv/bin/python"
[ -x "$PY" ] || PY="$(dirname "$0")/../.venv/bin/python"
step "$PY" -c "from quarry.cli import _open; p, c = _open(); print('  fresh database, schema version', c.execute('PRAGMA user_version').fetchone()[0])"

echo
if [ "$GO" = 1 ]; then
  echo "Done. Archived to $A"
  echo "The nightly job's script still names its old run (RUN= in $Q/nightly-deep.sh); set it to a new run before loading the job."
else
  echo "Dry run only. Run again with --go to do it."
fi
