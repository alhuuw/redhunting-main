#!/usr/bin/env bash
# redhunting installer: links or copies the skill into any agent harness.
# Pure bash + coreutils, no machine-specific paths (resolved from this file's location).
#
# Usage:
#   ./install.sh                          install for every detected harness (symlink mode)
#   ./install.sh --agent opencode         one harness: opencode | claude | codex | cursor | agents | all
#   ./install.sh --copy                   copy files instead of symlinking
#   ./install.sh --uninstall              remove the skill from every harness
#   ./install.sh --list                   show detected harnesses and target paths, no changes
#
# Any MCP-capable CLI agent works with this skill (any model); the harness list below is
# just where skill folders are conventionally read from.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_NAME="redhunting"
MODE="link"
AGENT="all"
ACTION="install"

while [ $# -gt 0 ]; do
  case "$1" in
    --agent) AGENT="${2:-all}"; shift 2 ;;
    --copy) MODE="copy"; shift ;;
    --uninstall) ACTION="uninstall"; shift ;;
    --list) ACTION="list"; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $1 (try --help)" >&2; exit 2 ;;
  esac
done

detect_harnesses() {
  local -a found=()
  [ -d "$HOME/.config/opencode" ] || command -v opencode >/dev/null 2>&1 && found+=("opencode")
  [ -d "$HOME/.claude" ] || command -v claude >/dev/null 2>&1 && found+=("claude")
  [ -d "$HOME/.codex" ] || command -v codex >/dev/null 2>&1 && found+=("codex")
  [ -d "$HOME/.cursor" ] || command -v cursor >/dev/null 2>&1 && found+=("cursor")
  [ -d "$HOME/.agents" ] && found+=("agents")
  [ ${#found[@]} -eq 0 ] && found+=("agents")
  printf '%s\n' "${found[@]}"
}

skill_path_for() {
  case "$1" in
    opencode) # ~/.config/opencode/skill is used when it exists, else the cross-agent ~/.agents/skills
      if [ -d "$HOME/.config/opencode/skill" ]; then
        printf '%s\n' "$HOME/.config/opencode/skill"
      else
        printf '%s\n' "$HOME/.agents/skills"
      fi
      ;;
    claude)   printf '%s\n' "$HOME/.claude/skills" ;;
    codex)   printf '%s\n' "$HOME/.codex/skills" ;;
    cursor)   printf '%s\n' "$HOME/.cursor/skills" ;;
    agents)   printf '%s\n' "$HOME/.agents/skills" ;;
  esac
}

is_selected() {
  [ "$AGENT" = "all" ] || [ "$AGENT" = "$1" ]
}

install_into() {
  local harness="$1" dir target
  dir="$(skill_path_for "$harness")"
  target="$dir/$SKILL_NAME"
  mkdir -p "$dir"
  if [ -e "$target" ] || [ -L "$target" ]; then
    if [ "$MODE" = "copy" ] && [ -d "$target" ]; then
      echo "[skip] $target exists (copy mode; remove it first to refresh)"
      return 0
    fi
    rm -rf "$target"
  fi
  if [ "$MODE" = "copy" ]; then
    cp -R "$HERE" "$target"
    rm -rf "$target/__pycache__" "$target/bin/__pycache__" 2>/dev/null || true
    echo "[ok]   $harness: copied -> $target"
  else
    ln -s "$HERE" "$target"
    echo "[ok]   $harness: linked -> $target"
  fi
}

uninstall_from() {
  local harness="$1" target
  target="$(skill_path_for "$harness")/$SKILL_NAME"
  if [ -L "$target" ]; then
    rm "$target"
    echo "[ok]   $harness: removed $target"
  elif [ -d "$target" ]; then
    rm -rf "$target"
    echo "[ok]   $harness: removed $target (was a copy)"
  else
    echo "[skip] $harness: nothing at $target"
  fi
}

case "$ACTION" in
  list)
    echo "harnesses detected on this machine:"
    for h in $(detect_harnesses); do
      printf '  %-9s -> %s/%s\n' "$h" "$(skill_path_for "$h")" "$SKILL_NAME"
    done
    exit 0
    ;;
  uninstall)
    for h in $(detect_harnesses); do
      is_selected "$h" && uninstall_from "$h" || true
    done
    echo "[done] uninstall complete (workspace at ~/redhunting is NEVER touched)"
    exit 0
    ;;
esac

sanity=0
python3 -c "import ast, glob; [ast.parse(open(f).read()) for f in glob.glob('$HERE/bin/*.py')]" && sanity=1 || echo "[warn] bin/ scripts failed to parse, continuing install anyway"
[ -f "$HERE/SKILL.md" ] || { echo "[fatal] SKILL.md missing at $HERE"; exit 1; }

installed_any=0
for h in $(detect_harnesses); do
  if is_selected "$h"; then
    install_into "$h"
    installed_any=1
  fi
done
[ $installed_any -eq 1 ] || { echo "[fatal] unknown agent: $AGENT (opencode|claude|codex|cursor|agents|all)"; exit 2; }

echo "[note] MCP server registration snippets: knowledge/mcp-tools.md"
echo "[note] the workspace root (~/redhunting) is created by rh_init on first use; nothing is auto-cleaned"
echo "[next] python3 $HERE/bin/rh_doctor.py"
echo "[next] python3 -m unittest discover -s $HERE/tests -v   (regression suite)"
