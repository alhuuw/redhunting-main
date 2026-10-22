#!/usr/bin/env python3
"""rh_doctor: environment checklist. Missing tools are skipped, never fatal
(the loop degrades); a broken skill structure or unwritable workspace is fatal.
"""
import json
import shutil
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent

CORE_SCRIPTS = [
    "rh_init", "rh_scope", "rh_kickoff", "rh_clock", "rh_guard", "rh_device", "rh_doctor", "rh_leadboard", "rh_ledger",
    "rh_validate", "rh_materials", "rh_verify", "rh_capture", "rh_differential",
    "rh_impact", "rh_recall", "rh_apkrecon",
]

KNOWLEDGE = ("kickoff", "workflow", "playbook", "chains", "verification", "identity",
             "target-intel", "materials", "workspace", "web", "mobile", "js-reverse",
             "mcp-tools", "push-notifications", "journal")

TEMPLATES = ("WORKSPACE-README.md", "TARGET-README.md", "FINDING-README.md",
             "FINDING-SUMMARY.md", "VERIFICATION.md", "MATERIALS.md")

VENDORED = [
    ("tools/apkpure/apkpure_dl/cli.py", "APK mirror downloader with provenance"),
    ("tools/play_store/play_meta.py", "Play Store metadata (authoritative version)"),
    ("tools/device_pull/get_app_from_device.py", "device APK puller"),
    ("tools/paranoid/paranoid_decode.py", "io.michaelrocks.paranoid string decoder"),
    ("tools/mcp/cvss/server.py", "cvss MCP"),
    ("tools/mcp/tempmail/server.py", "tempmail MCP (account registration)"),
    ("tools/mcp/shodan/server.py", "shodan MCP (SHODAN_API_KEY)"),
    ("tools/mcp/hacktricks/server.py", "hacktricks MCP"),
    ("tools/mcp/jadx/server.py", "jadx MCP (needs jadx on PATH)"),
    ("tools/mcp/burp/server.py", "burp MCP bridge (needs Burp running)"),
]

OPTIONAL_TOOLS = [
    ("subfinder", "subdomain enumeration", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("httpx", "live host probing (ProjectDiscovery)", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("nuclei", "template scanner (LEADS ONLY, never findings)", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("ffuf", "content discovery", "go install github.com/ffuf/ffuf@latest"),
    ("katana", "crawler", "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    ("gau", "URL archive fetch", "go install github.com/lc/gau/v2/cmd/gau@latest"),
    ("interactsh-client", "OOB listener (blind SSRF/XXE proofs)", "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    ("java", "jadx mobile decode", "brew install --cask temurin"),
    ("jadx", "APK decompile", "brew install jadx"),
    ("apktool", "APK resource decode", "brew install apktool"),
    ("mitmdump", "traffic capture", "brew install mitmproxy"),
    ("frida", "dynamic instrumentation", "pip3 install frida-tools"),
    ("adb", "on-device execution (deeplink/push classes)", "brew install --cask android-platform-tools"),
    ("semgrep", "SAST leads", "brew install semgrep"),
]

PYTHON_DEPS = [("requests", "apkpure downloader"), ("androguard", "signing cert extraction"),
               ("curl_cffi", "TLS-impersonation WAF bypass"), ("Crypto", "pycryptodome, crypto replica work")]

# Install hints default to macOS/brew (OPTIONAL_TOOLS); these override per-command on Linux.
LINUX_HINTS = {
    "java": "sudo apt install -y default-jdk  (or your distro's JDK package)",
    "jadx": "sudo apt install -y jadx  (Debian/Ubuntu: grab a release from github.com/skylot/jadx)",
    "apktool": "sudo apt install -y apktool",
    "mitmdump": "sudo apt install -y mitmproxy  (or: pipx install mitmproxy)",
    "adb": "sudo apt install -y android-tools-adb  (or your distro's android platform tools)",
    "semgrep": "pip3 install semgrep",
}


def hint_for(cmd: str, default: str) -> str:
    """Pick an install hint matching the host OS (brew default, apt/pip on Linux)."""
    if sys.platform.startswith("linux"):
        return LINUX_HINTS.get(cmd, default)
    return default


def collect_capabilities() -> dict:
    """Machine-readable readiness query (REA capabilities pattern): what is
    available, what is missing, and what each miss degrades. Missing optional
    capability is informational, never blocking."""
    caps = {"core": {}, "vendored": {}, "external_tools": {}, "python_deps": {}, "knowledge": {}}
    for name in ("SKILL.md", "AGENTS.md", "README.md"):
        caps["core"][name] = (SKILL_DIR / name).exists()
    for rel, what in VENDORED:
        caps["vendored"][what] = {"path": rel, "present": (SKILL_DIR / rel).exists()}
    for cmd, what, _hint in OPTIONAL_TOOLS:
        caps["external_tools"][cmd] = {"present": bool(shutil.which(cmd)), "purpose": what}
    for mod, why in PYTHON_DEPS:
        try:
            __import__(mod)
            caps["python_deps"][mod] = {"present": True, "purpose": why}
        except ImportError:
            caps["python_deps"][mod] = {"present": False, "purpose": why}
    caps["knowledge"]["cheatsheets"] = len(list((SKILL_DIR / "knowledge" / "cheatsheets").glob("*.md"))) if (SKILL_DIR / "knowledge" / "cheatsheets").is_dir() else 0
    caps["knowledge"]["classes"] = len(list((SKILL_DIR / "knowledge" / "classes").glob("*/SKILL.md"))) if (SKILL_DIR / "knowledge" / "classes").is_dir() else 0
    return caps


def main() -> int:
    if "--json" in sys.argv:
        caps = collect_capabilities()
        missing = [cmd for cmd, info in caps["external_tools"].items() if not info["present"]]
        result = {
            "capabilities": caps,
            "missing_optional": missing,
            "note": "missing optional tools degrade the loop (skip-not-fail) and never block setup",
            "ready_core": all(caps["core"].values())
            and caps["knowledge"]["cheatsheets"] >= 13
            and caps["knowledge"]["classes"] == 26,
        }
        print(json.dumps(result, indent=2))
        return 0 if result["ready_core"] else 1

    ok = True
    print("redhunting doctor")
    print("=" * 64)

    try:
        cfg = json.loads((SKILL_DIR / "config.json").read_text())
        print(f"[ok]     config.json ({len(cfg)} sections)")
    except Exception as e:
        print(f"[fatal]  config.json unreadable: {e}")
        return 2

    import os
    env_key = cfg.get("workspace", {}).get("env_override", "RH_HOME")
    root = (os.environ.get(env_key) if env_key else None) or cfg.get("workspace", {}).get("root", "./")
    root = Path(os.path.expanduser(root))
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".rh_probe"
        probe.write_text("ok")
        probe.unlink()
        print(f"[ok]     workspace root writable: {root} (env override: {'yes' if os.environ.get(env_key or '') else 'no'})")
    except Exception as e:
        print(f"[fatal]  workspace root not writable: {root} ({e})")
        ok = False

    for name in ("SKILL.md", "AGENTS.md", "README.md"):
        if (SKILL_DIR / name).exists():
            print(f"[ok]     {name}")
        else:
            print(f"[fatal]  missing {name}")
            ok = False

    missing_t = [n for n in TEMPLATES if not (SKILL_DIR / "templates" / n).exists()]
    if missing_t:
        print(f"[fatal]  missing templates: {', '.join(missing_t)}")
        ok = False
    else:
        print(f"[ok]     templates/: {len(TEMPLATES)} files")

    missing_k = [n for n in KNOWLEDGE if not (SKILL_DIR / "knowledge" / f"{n}.md").exists()]
    if missing_k:
        print(f"[fatal]  missing knowledge files: {', '.join(missing_k)}")
        ok = False
    else:
        total = sum(len((SKILL_DIR / "knowledge" / f"{n}.md").read_text().splitlines()) for n in KNOWLEDGE)
        print(f"[ok]     knowledge/: {len(KNOWLEDGE)} files, {total} lines")

    cheats = SKILL_DIR / "knowledge" / "cheatsheets"
    cheat_files = sorted(cheats.glob("*.md")) if cheats.is_dir() else []
    if len(cheat_files) < 13:
        print(f"[fatal]  cheatsheet library incomplete: {len(cheat_files)}/13 files")
        ok = False
    else:
        total_c = sum(len(f.read_text().splitlines()) for f in cheat_files)
        print(f"[ok]     knowledge/cheatsheets/: {len(cheat_files)} files, {total_c} lines")

    missing_s = [n for n in CORE_SCRIPTS if not (SKILL_DIR / "bin" / f"{n}.py").exists()]
    if missing_s:
        print(f"[fatal]  missing bin scripts: {', '.join(missing_s)}")
        ok = False
    else:
        print(f"[ok]     bin/: {len(CORE_SCRIPTS)} scripts (stdlib-only core)")

    classes_dir = SKILL_DIR / "knowledge" / "classes"
    class_files = sorted(classes_dir.glob("*/SKILL.md")) if classes_dir.is_dir() else []
    if len(class_files) != 26:
        print(f"[fatal]  class library incomplete: {len(class_files)}/26 files")
        ok = False
    else:
        total_cls = sum(len(f.read_text().splitlines()) for f in class_files)
        print(f"[ok]     knowledge/classes/: 26 class files, {total_cls} lines (unit-load, one per vuln class)")

    for extra in ("demo/serve.py", "tests/test_core.py", "tests/test_e2e.py", "tests/test_guard.py", "tests/test_device.py", "tests/test_classes.py", "install.sh"):
        if (SKILL_DIR / extra).exists():
            print(f"[ok]     {extra}")
        else:
            print(f"[fatal]  missing {extra}")
            ok = False

    print("-" * 64)
    print("vendored tools (self-contained, ship with the repo):")
    for rel, what in VENDORED:
        if (SKILL_DIR / rel).exists():
            print(f"[ok]     {what}")
        else:
            print(f"[miss]   {what} - {rel}")

    print("-" * 64)
    print("optional external tools (skip-not-fail; missing ones degrade the loop; --json for machine-readable):")
    have_any = False
    for cmd, what, hint in OPTIONAL_TOOLS:
        if shutil.which(cmd):
            print(f"[ok]     {cmd:20} {what}")
            have_any = True
        else:
            print(f"[miss]   {cmd:20} {what} - {hint_for(cmd, hint)}")
    if not have_any:
        print("[note]   none present: the loop degrades to pure-MCP + capture-tool; still operational")

    print("-" * 64)
    print("python deps for the vendored tools:")
    for mod, why in PYTHON_DEPS:
        try:
            __import__(mod)
            print(f"[ok]     {mod:12} {why}")
        except ImportError:
            install = "pycryptodome" if mod == "Crypto" else mod
            print(f"[miss]   {mod:12} {why} - pip3 install {install}")

    print("-" * 64)
    print("MCP registration snippets: knowledge/mcp-tools.md (any MCP-capable agent, any model)")

    print("=" * 64)
    print("[doctor] " + ("environment READY" if ok else "environment BROKEN (fix fatal items)"))
    print("[doctor] setup first on every hunt: bin/rh_kickoff.py <target>")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
