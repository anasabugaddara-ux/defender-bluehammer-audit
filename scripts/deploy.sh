#!/usr/bin/env bash
# Deploy the defensive audit module into the MSF user module tree for loading.
# Uses a symlink so edits in the repo are picked up by `reload_all`.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$HOME/.msf4/modules/post/windows/gather"
SRC="$REPO/modules/post/windows/gather/bluehammer_defender_audit.rb"
mkdir -p "$DEST"
ln -sf "$SRC" "$DEST/bluehammer_defender_audit.rb"
echo "[+] Linked: $DEST/bluehammer_defender_audit.rb -> $SRC"
echo "[i] In msfconsole:  reload_all ; use post/windows/gather/bluehammer_defender_audit"
