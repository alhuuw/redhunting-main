#!/usr/bin/env bash
# redhunting optional-tool installer: the external CLIs + python deps that the
# core loop treats as skip-not-fail. Nothing here is required to run the skill;
# each tool only un-degrades one phase. Mirrors bin/rh_doctor.py.
#
# Usage:
#   ./install-tools.sh            install everything available for this OS
#   ./install-tools.sh --python   python deps only (androguard, curl_cffi, pycryptodome, frida-tools)
#   ./install-tools.sh --go       ProjectDiscovery / go recon tools only
#   ./install-tools.sh --system   OS packages only (jdk, apktool, mitmproxy, adb, jadx, semgrep)
#   ./install-tools.sh --dry-run  print what would run, change nothing
#
# Safe to re-run. System packages use the detected manager (apt/dnf/pacman/brew)
# and call sudo only for that step. Go tools need `go`; python deps need pip3.

set -uo pipefail

DRY=0; DO_PY=1; DO_GO=1; DO_SYS=1
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --python) DO_PY=1; DO_GO=0; DO_SYS=0; shift ;;
    --go)     DO_PY=0; DO_GO=1; DO_SYS=0; shift ;;
    --system) DO_PY=0; DO_GO=0; DO_SYS=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $1 (try --help)" >&2; exit 2 ;;
  esac
done

run() { if [ "$DRY" = 1 ]; then echo "  [dry] $*"; else echo "  [run] $*"; "$@"; fi; }
have() { command -v "$1" >/dev/null 2>&1; }

OS="$(uname -s)"
PKG=""
if   have apt-get; then PKG=apt
elif have dnf;     then PKG=dnf
elif have pacman;  then PKG=pacman
elif have brew;    then PKG=brew
fi
echo "[env] OS=$OS  pkg-manager=${PKG:-none}  go=$(have go && echo yes || echo no)  pip3=$(have pip3 && echo yes || echo no)"
[ "$DRY" = 1 ] && echo "[env] DRY RUN: nothing will be installed"

# ---- python deps ---------------------------------------------------------
if [ "$DO_PY" = 1 ]; then
  echo "[python] vendored-tool deps"
  if have pip3; then
    run pip3 install --user androguard curl_cffi pycryptodome frida-tools
  else
    echo "  [skip] pip3 not found; install Python 3 + pip first"
  fi
fi

# ---- go recon tools ------------------------------------------------------
if [ "$DO_GO" = 1 ]; then
  echo "[go] ProjectDiscovery + recon (output enters as LEADS only, never findings)"
  if have go; then
    run go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    run go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    run go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    run go install github.com/ffuf/ffuf@latest
    run go install github.com/projectdiscovery/katana/cmd/katana@latest
    run go install github.com/lc/gau/v2/cmd/gau@latest
    run go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
    echo "  [note] ensure \$(go env GOPATH)/bin is on your PATH"
  else
    echo "  [skip] go not found; install Go first (https://go.dev/dl), then re-run --go"
  fi
fi

# ---- system packages -----------------------------------------------------
if [ "$DO_SYS" = 1 ]; then
  echo "[system] mobile decode + traffic capture"
  case "$PKG" in
    apt)
      run sudo apt-get update
      run sudo apt-get install -y default-jdk apktool android-tools-adb mitmproxy semgrep
      have jadx || echo "  [note] jadx: no apt package on Debian/Ubuntu; grab a release from github.com/skylot/jadx and put it on PATH"
      ;;
    dnf)
      run sudo dnf install -y java-latest-openjdk apktool android-tools mitmproxy
      echo "  [note] jadx/semgrep: install via release/pip if your repos lack them"
      ;;
    pacman)
      run sudo pacman -S --needed --noconfirm jdk-openjdk apktool android-tools mitmproxy jadx
      ;;
    brew)
      run brew install --cask temurin
      run brew install jadx apktool mitmproxy semgrep
      run brew install --cask android-platform-tools
      ;;
    *)
      echo "  [skip] no supported package manager detected; install jdk/apktool/adb/mitmproxy/jadx manually"
      ;;
  esac
fi

echo "[done] re-run the doctor to confirm:  python3 bin/rh_doctor.py"
