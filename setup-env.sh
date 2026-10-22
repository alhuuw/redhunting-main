#!/usr/bin/env bash
# redhunting full-env setup (no-sudo, $HOME-local). Installs the external
# toolchain the loop uses into ~/.rh-tools + ~/.local/bin and wires PATH via
# ~/.rh-tools/env.sh. Idempotent: re-run to resume; present tools are skipped.
# Nothing here needs root. The ONLY sudo step (compilers for blutter's build)
# is printed at the end, never executed.
#
# Order (also the manual setup order):
#   1 pip + python deps      androguard curl_cffi pycryptodome frida-tools mitmproxy
#   2 Java (Temurin 21)      needed by jadx + apktool
#   3 jadx                   APK decompile
#   4 apktool                APK resource decode
#   5 adb (platform-tools)   on-device execution
#   6 Go + recon suite       subfinder httpx nuclei ffuf katana gau interactsh
#   7 blutter (clone)        Flutter/Dart RE  (build needs the sudo step below)
#
# Usage: ./setup-env.sh [--skip-go] [--skip-mobile] [--skip-blutter]
set -uo pipefail

SKIP_GO=0; SKIP_MOBILE=0; SKIP_BLUTTER=0
for a in "$@"; do case "$a" in
  --skip-go) SKIP_GO=1 ;; --skip-mobile) SKIP_MOBILE=1 ;; --skip-blutter) SKIP_BLUTTER=1 ;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac; done

TOOLS="$HOME/.rh-tools"; BIN="$HOME/.local/bin"; ENVF="$TOOLS/env.sh"
mkdir -p "$TOOLS" "$BIN"
: > "$ENVF.tmp"
have(){ command -v "$1" >/dev/null 2>&1; }
say(){ printf '\n\033[1m[setup] %s\033[0m\n' "$*"; }
dl(){ curl -fL --retry 3 --retry-delay 2 -o "$2" "$1"; }

case "$(uname -m)" in
  x86_64)  GOARCH=amd64; JARCH=x64;   ADBOK=1 ;;
  aarch64) GOARCH=arm64; JARCH=aarch64; ADBOK=1 ;;
  *)       GOARCH=amd64; JARCH=x64;   ADBOK=1 ;;
esac
echo "export PATH=\"$BIN:\$PATH\"" >> "$ENVF.tmp"

# ---- 1 pip + python deps -------------------------------------------------
say "1/7 pip + python deps"
if ! python3 -m pip --version >/dev/null 2>&1; then
  # ensurepip is disabled on Debian/Ubuntu; bootstrap via get-pip.py (no sudo)
  python3 -m ensurepip --user >/dev/null 2>&1 \
    || { dl "https://bootstrap.pypa.io/get-pip.py" "$TOOLS/get-pip.py" \
         && python3 "$TOOLS/get-pip.py" --user --break-system-packages >/dev/null 2>&1; }
fi
PIP="python3 -m pip install --user --break-system-packages"
if python3 -m pip --version >/dev/null 2>&1; then
  $PIP androguard curl_cffi pycryptodome frida-tools mitmproxy || echo "[warn] some pip deps failed (continuing)"
  echo "export PATH=\"$HOME/.local/bin:\$PATH\"" >> "$ENVF.tmp"
else
  echo "[warn] pip unavailable; skipping python deps (apt: python3-pip)"
fi

# ---- 2 Java (Temurin 21) -------------------------------------------------
if [ "$SKIP_MOBILE" = 0 ]; then
  say "2/7 Java (Temurin 21, needed by jadx + apktool)"
  if have java; then echo "[skip] java present: $(java -version 2>&1 | head -1)"
  else
    JDKDIR="$TOOLS/jdk"
    if [ ! -x "$JDKDIR/bin/java" ]; then
      dl "https://api.adoptium.net/v3/binary/latest/21/ga/linux/${JARCH}/jdk/hotspot/normal/eclipse" "$TOOLS/jdk.tar.gz" \
        && mkdir -p "$JDKDIR" && tar -xzf "$TOOLS/jdk.tar.gz" -C "$JDKDIR" --strip-components=1 && rm -f "$TOOLS/jdk.tar.gz" \
        && echo "[ok] java -> $JDKDIR" || echo "[warn] java install failed"
    fi
    echo "export JAVA_HOME=\"$JDKDIR\"" >> "$ENVF.tmp"
    echo "export PATH=\"$JDKDIR/bin:\$PATH\"" >> "$ENVF.tmp"
    export JAVA_HOME="$JDKDIR"; export PATH="$JDKDIR/bin:$PATH"
  fi

  # ---- 3 jadx ------------------------------------------------------------
  say "3/7 jadx"
  if have jadx; then echo "[skip] jadx present"
  else
    JV=$(curl -fsSL https://api.github.com/repos/skylot/jadx/releases/latest | grep -oE '"tag_name": *"v[^"]+"' | head -1 | grep -oE '[0-9.]+')
    if [ -n "${JV:-}" ]; then
      dl "https://github.com/skylot/jadx/releases/download/v${JV}/jadx-${JV}.zip" "$TOOLS/jadx.zip" \
        && rm -rf "$TOOLS/jadx" && mkdir -p "$TOOLS/jadx" && unzip -q -o "$TOOLS/jadx.zip" -d "$TOOLS/jadx" && rm -f "$TOOLS/jadx.zip" \
        && ln -sf "$TOOLS/jadx/bin/jadx" "$BIN/jadx" && ln -sf "$TOOLS/jadx/bin/jadx-gui" "$BIN/jadx-gui" \
        && echo "[ok] jadx $JV -> $TOOLS/jadx" || echo "[warn] jadx install failed"
    else echo "[warn] could not resolve jadx version"; fi
  fi

  # ---- 4 apktool ---------------------------------------------------------
  say "4/7 apktool"
  if have apktool; then echo "[skip] apktool present"
  else
    AV=$(curl -fsSL https://api.github.com/repos/iBotPeaches/Apktool/releases/latest | grep -oE '"tag_name": *"v[^"]+"' | head -1 | grep -oE '[0-9.]+')
    if [ -n "${AV:-}" ]; then
      dl "https://github.com/iBotPeaches/Apktool/releases/download/v${AV}/apktool_${AV}.jar" "$TOOLS/apktool.jar" \
        && printf '#!/usr/bin/env bash\nexec java -jar "%s" "$@"\n' "$TOOLS/apktool.jar" > "$BIN/apktool" \
        && chmod +x "$BIN/apktool" && echo "[ok] apktool $AV -> $BIN/apktool" || echo "[warn] apktool install failed"
    else echo "[warn] could not resolve apktool version"; fi
  fi

  # ---- 5 adb -------------------------------------------------------------
  say "5/7 adb (platform-tools)"
  if have adb; then echo "[skip] adb present"
  else
    dl "https://dl.google.com/android/repository/platform-tools-latest-linux.zip" "$TOOLS/pt.zip" \
      && rm -rf "$TOOLS/platform-tools" && unzip -q -o "$TOOLS/pt.zip" -d "$TOOLS" && rm -f "$TOOLS/pt.zip" \
      && ln -sf "$TOOLS/platform-tools/adb" "$BIN/adb" && echo "[ok] adb -> $TOOLS/platform-tools" || echo "[warn] adb install failed"
  fi
fi

# ---- 6 Go + recon suite --------------------------------------------------
if [ "$SKIP_GO" = 0 ]; then
  say "6/7 Go + recon suite"
  if ! have go; then
    GV=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -1)
    if [ -n "${GV:-}" ]; then
      dl "https://go.dev/dl/${GV}.linux-${GOARCH}.tar.gz" "$TOOLS/go.tar.gz" \
        && rm -rf "$TOOLS/go" && tar -xzf "$TOOLS/go.tar.gz" -C "$TOOLS" && rm -f "$TOOLS/go.tar.gz" \
        && echo "[ok] $GV -> $TOOLS/go" || echo "[warn] go install failed"
    fi
    echo "export PATH=\"$TOOLS/go/bin:\$PATH\"" >> "$ENVF.tmp"
    export PATH="$TOOLS/go/bin:$PATH"
  fi
  echo "export PATH=\"$HOME/go/bin:\$PATH\"" >> "$ENVF.tmp"
  export PATH="$HOME/go/bin:$PATH"
  if have go; then
    for pkg in \
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
      github.com/projectdiscovery/httpx/cmd/httpx@latest \
      github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
      github.com/ffuf/ffuf@latest \
      github.com/projectdiscovery/katana/cmd/katana@latest \
      github.com/lc/gau/v2/cmd/gau@latest \
      github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest ; do
      name=$(basename "${pkg%@*}")
      if have "$name"; then echo "[skip] $name present"; else echo "[go] install $name"; go install "$pkg" || echo "[warn] $name failed"; fi
    done
  else echo "[warn] go unavailable; skipped recon suite"; fi
fi

# ---- 7 blutter (clone; build needs sudo compilers) -----------------------
if [ "$SKIP_BLUTTER" = 0 ]; then
  say "7/7 blutter (Flutter/Dart RE)"
  BDIR="$TOOLS/blutter"
  if [ -d "$BDIR/.git" ]; then (cd "$BDIR" && git pull --ff-only -q || true); echo "[ok] blutter clone present: $BDIR"
  else git clone --depth 1 https://github.com/worawit/blutter "$BDIR" && echo "[ok] cloned -> $BDIR" || echo "[warn] blutter clone failed"; fi
  echo "export BLUTTER_HOME=\"$BDIR\"" >> "$ENVF.tmp"
fi

# ---- finalize env --------------------------------------------------------
# de-dupe while preserving order, write env.sh, wire ~/.bashrc once
awk '!seen[$0]++' "$ENVF.tmp" > "$ENVF"; rm -f "$ENVF.tmp"
if ! grep -q 'rh-tools/env.sh' "$HOME/.bashrc" 2>/dev/null; then
  printf '\n# redhunting toolchain\n[ -f "%s" ] && . "%s"\n' "$ENVF" "$ENVF" >> "$HOME/.bashrc"
fi

say "DONE (no-sudo phase)"
echo "env wired in: $ENVF  (sourced from ~/.bashrc)"
echo "activate now:  source \"$ENVF\""
echo
echo "REMAINING sudo step (only if you will BUILD blutter for Flutter targets):"
echo "  sudo apt-get update && sudo apt-get install -y build-essential cmake ninja-build pkg-config"
echo "  then: source \"$ENVF\" && cd \"$TOOLS/blutter\" && python3 blutter.py --help"
echo
echo "verify:  source \"$ENVF\" && python3 $(cd "$(dirname "$0")" && pwd)/bin/rh_doctor.py"
