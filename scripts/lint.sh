#!/usr/bin/env bash
# Lint the module: ruby syntax + patched msftidy (structural). Runs against the
# deployed modules/post path so msftidy infers the module type correctly.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOYED="$HOME/.msf4/modules/post/windows/gather/bluehammer_defender_audit.rb"
SRC="$REPO/modules/post/windows/gather/bluehammer_defender_audit.rb"
echo "[*] ruby -c"; ruby -c "$SRC" || exit 1
echo "[*] msftidy (patched)"
# 2>/dev/null hides git's stderr from msftidy's out-of-tree rubocop-gate probe.
ruby "$REPO/scripts/msftidy_patched.rb" "$DEPLOYED" 2>/dev/null
echo "[+] lint done (exit $?)"
