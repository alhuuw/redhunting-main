#!/usr/bin/env bash
# install-preset.sh: wire the openchamber preset into opencode. Symlinks the
# redhunter agent + commands into ~/.config/opencode and the rh launcher into
# ~/.local/bin. Symlinks by default so edits in the repo take effect live.
#
#   ./install-preset.sh            symlink (default)
#   ./install-preset.sh --copy     copy instead of symlink
#   ./install-preset.sh --uninstall remove the preset (skill + env untouched)
#   ./install-preset.sh --list     show targets, no changes
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OC="$HOME/.config/opencode"
BIN="$HOME/.local/bin"
MODE="link"; ACTION="install"
for a in "$@"; do case "$a" in
  --copy) MODE="copy" ;; --uninstall) ACTION="uninstall" ;; --list) ACTION="list" ;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac; done

link_one() { # src dst
  mkdir -p "$(dirname "$2")"
  if [ -e "$2" ] || [ -L "$2" ]; then rm -rf "$2"; fi
  if [ "$MODE" = copy ]; then cp "$1" "$2"; else ln -s "$1" "$2"; fi
  echo "[ok]   ${2/#$HOME/~}"
}

case "$ACTION" in
  list)
    echo "agent   -> ~/.config/opencode/agent/redhunter.md"
    for f in "$HERE"/command/*.md; do echo "command -> ~/.config/opencode/command/$(basename "$f")"; done
    echo "launcher-> ~/.local/bin/rh"
    exit 0 ;;
  uninstall)
    rm -f "$OC/agent/redhunter.md" "$BIN/rh"
    for f in "$HERE"/command/*.md; do rm -f "$OC/command/$(basename "$f")"; done
    echo "[done] preset removed (skill at ~/.config/opencode/skill and ~/.rh-tools env untouched)"
    exit 0 ;;
esac

link_one "$HERE/agent/redhunter.md" "$OC/agent/redhunter.md"
for f in "$HERE"/command/*.md; do link_one "$f" "$OC/command/$(basename "$f")"; done
chmod +x "$HERE/rh"
link_one "$HERE/rh" "$BIN/rh"

echo "[next] restart opencode so it loads the agent + commands"
echo "[next] start hunting:  rh            (or: opencode --agent redhunter)"
echo "[next] verify skill:   rh dev"
