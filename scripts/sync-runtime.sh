#!/bin/bash
# Resync Quarry's self-contained nightly runtime with this editable repo.
#
# The launchd nightly deep-review job (net.rogolabs.quarry-deep) runs from a copy of
# quarry installed under ~/Library/Application Support/Quarry/runtime/venv, OUTSIDE
# ~/Documents, so macOS TCC does not block it. Run this after code changes you want
# the next overnight run to use. Safe to run anytime; pip is fast when deps are met.
#
# Wire it as a post-commit hook if you want it automatic:
#   ln -s ../../scripts/sync-runtime.sh .git/hooks/post-commit
set -euo pipefail
RT="$HOME/Library/Application Support/Quarry/runtime/venv"
REPO="$(git rev-parse --show-toplevel)"
if [ ! -x "$RT/bin/pip" ]; then
  echo "runtime venv missing; creating it at $RT"
  PYBIN="/opt/homebrew/opt/python@3.13/bin/python3.13"; [ -x "$PYBIN" ] || PYBIN="$(command -v python3.13)"
  mkdir -p "$(dirname "$RT")"; "$PYBIN" -m venv "$RT"
  PIP_USER=0 "$RT/bin/pip" install --upgrade pip -q
fi
cd "$REPO"
PIP_USER=0 "$RT/bin/pip" install . -q
echo "runtime synced to $(git rev-parse --short HEAD) at $RT"
