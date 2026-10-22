#!/usr/bin/env python3
"""rh_device: the device profile and hunt planner.

The skill should know the machine it hunts from: how much memory is free, which tools
exist, what the process baseline looks like, and what the target surface holds. From
that state it PROPOSES a plan; the operator reads it, adjusts, and runs.

Commands:
  init              capture the device profile -> ~/redhunting/device.json (specs,
                    memory, disk, tool census, vendored deps, process baseline)
  check             drift report vs the saved profile (memory, processes, tools),
                    exit 1 when the machine budget is blown
  plan <target>     write targets/<slug>/plan.md: sprint sequence proposal built from
                    the lead board + device capacity + scope + mode. A PROPOSAL for
                    the operator, never an auto-executed schedule.

Stdlib only. macOS and Linux (memory via sysctl or /proc/meminfo; disk via statvfs).
"""
import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent

OPTIONAL_TOOLS = [
    "subfinder", "httpx", "nuclei", "ffuf", "katana", "gau", "interactsh-client",
    "java", "jadx", "apktool", "mitmdump", "frida", "adb", "semgrep",
]

PYTHON_DEPS = [("requests", "requests"), ("androguard", "androguard"),
               ("curl_cffi", "curl_cffi"), ("Crypto", "pycryptodome")]

VENDORED_MARKERS = ["tools/apkpure/apkpure_dl/cli.py", "tools/mcp/tempmail/server.py",
                    "tools/paranoid/paranoid_decode.py", "tools/mcp/jadx/server.py"]

# planning heuristics: one parallel HTTP worker is cheap, but the capture tool and
# any scanner stack cost real memory; the ceiling scales with free RAM at plan time.
MB_PER_WORKER = 40
MIN_FREE_MB_FOR_HUNT = 2048


def load_config() -> dict:
    return json.loads((SKILL_DIR / "config.json").read_text())


def workspace_root(cfg: dict) -> Path:
    env_key = cfg.get("workspace", {}).get("env_override", "RH_HOME")
    root = (os.environ.get(env_key) if env_key else None) or cfg.get("workspace", {}).get("root", "./")
    base = Path.cwd() if root in (".", "./") else Path(os.path.expanduser(root))
    return base


def sh(cmd, timeout=15):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception:
        return ""


def machine_memory():
    total_mb = free_mb = None
    if sys.platform == "darwin":
        out = sh(["sysctl", "-n", "hw.memsize"])
        if out.isdigit():
            total_mb = int(out) // (1024 * 1024)
        mp = sh(["memory_pressure", "-Q"])
        m = re.search(r"free percentage: (\d+)%", mp)
        if m and total_mb:
            free_mb = round(total_mb * int(m.group(1)) / 100)
    else:
        try:
            meminfo = Path("/proc/meminfo").read_text()
            total_kb = int(re.search(r"MemTotal:\s+(\d+)", meminfo).group(1))
            avail_kb = int(re.search(r"MemAvailable:\s+(\d+)", meminfo).group(1))
            total_mb, free_mb = total_kb // 1024, avail_kb // 1024
        except Exception:
            pass
    return total_mb, free_mb


def disk_free_mb():
    try:
        if sys.platform == "darwin":
            out = sh(["df", "-m", str(Path.home())]).splitlines()[-1].split()
            return int(out[3])
        import statvfs
        st = os.statvfs(str(Path.home()))
        return st.f_bavail * st.f_frsize // (1024 * 1024)
    except Exception:
        return None


def tool_census():
    return {t: bool(shutil.which(t)) for t in OPTIONAL_TOOLS}


def python_deps():
    present = {}
    for mod, name in PYTHON_DEPS:
        try:
            __import__(mod)
            present[name] = True
        except ImportError:
            present[name] = False
    return present


def vendored_ok():
    return {m.split("/")[-2] if "/" in m else m: (SKILL_DIR / m).exists() for m in VENDORED_MARKERS}


def guard_census():
    here = SKILL_DIR / "bin"
    r = subprocess.run([sys.executable, str(here / "rh_guard.py"), "status"],
                       capture_output=True, text=True, timeout=90)
    watched = free_hint = None
    m = re.search(r"processes: (\d+) holding (\d+)MB \((\d+) orphan, (\d+) duplicate, (\d+) live\)", r.stdout)
    if m:
        watched = {"count": int(m.group(1)), "mb": int(m.group(2)),
                   "orphan": int(m.group(3)), "duplicate": int(m.group(4)), "live": int(m.group(5))}
    fm = re.search(r"machine: (\d+)MB total, (\d+)MB free", r.stdout)
    if fm:
        free_hint = {"total_mb": int(fm.group(1)), "free_mb": int(fm.group(2))}
    return {"watched": watched, "machine": free_hint, "budget_ok": "[budget] OK" in r.stdout}


def snapshot():
    total_mb, free_mb = machine_memory()
    cores = os.cpu_count()
    return {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "python": platform.python_version(),
        "cores": cores,
        "memory_total_mb": total_mb,
        "memory_free_mb": free_mb,
        "disk_free_mb": disk_free_mb(),
        "tools": tool_census(),
        "python_deps": python_deps(),
        "vendored": vendored_ok(),
        "guard": guard_census(),
    }


def cmd_init(args) -> int:
    cfg = load_config()
    root = workspace_root(cfg)
    root.mkdir(parents=True, exist_ok=True)
    snap = snapshot()
    state = SKILL_DIR / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "device.json").write_text(json.dumps(snap, indent=2) + "\n")
    print(f"[device] profile written -> {SKILL_DIR / 'state' / 'device.json'}")
    print(f"  {snap['os']} {snap['arch']}, {snap['cores']} cores, "
          f"{snap['memory_total_mb']}MB RAM ({snap['memory_free_mb']}MB free), "
          f"{snap['disk_free_mb']}MB disk free")
    tools_present = [t for t, ok in snap["tools"].items() if ok]
    tools_missing = [t for t, ok in snap["tools"].items() if not ok]
    print(f"  tools present: {', '.join(tools_present) or '(none)'}")
    print(f"  tools missing: {', '.join(tools_missing) or '(none)'} (skip-not-fail)")
    print(f"  python deps: {sum(snap['python_deps'].values())}/{len(snap['python_deps'])}")
    print(f"  guard baseline: {snap['guard']['watched']}, budget "
          f"{'OK' if snap['guard']['budget_ok'] else 'NOT OK (run rh_guard reap)'}")
    print("[device] rerun after attaching devices, installing tools, or when memory feels wrong (rh_device check)")
    return 0


def cmd_check(args) -> int:
    cfg = load_config()
    prof_path = SKILL_DIR / "state" / "device.json"
    if not prof_path.exists():
        print("[check] no device profile (run: rh_device init)")
        return 1
    prof = json.loads(prof_path.read_text())
    now = snapshot()
    problems = []
    if now["memory_free_mb"] is not None and prof["memory_free_mb"] is not None:
        delta = now["memory_free_mb"] - prof["memory_free_mb"]
        print(f"[check] memory free: {now['memory_free_mb']}MB (baseline {prof['memory_free_mb']}MB, delta {delta:+d}MB)")
        if now["memory_free_mb"] < MIN_FREE_MB_FOR_HUNT:
            problems.append(f"free memory {now['memory_free_mb']}MB below the {MIN_FREE_MB_FOR_HUNT}MB hunt floor")
    new_tools = [t for t in prof["tools"] if not prof["tools"][t] and now["tools"].get(t)]
    lost_tools = [t for t in prof["tools"] if prof["tools"][t] and not now["tools"].get(t)]
    if new_tools:
        print(f"[check] new tools since baseline: {', '.join(new_tools)} (rerun rh_device init to adopt)")
    if lost_tools:
        print(f"[check] tools gone: {', '.join(lost_tools)}")
    if now["guard"]["watched"] and prof["guard"]["watched"]:
        grew = now["guard"]["watched"]["count"] - prof["guard"]["watched"]["count"]
        if grew > 2:
            problems.append(f"hunt process count grew by {grew} since baseline (leak pattern: rh_guard reap)")
    if not now["guard"]["budget_ok"]:
        problems.append("guard budget FAIL (rh_guard reap, or --dedupe)")
    if problems:
        print("[check] DRIFT:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("[check] within baseline")
    return 0


def load_board(slug, root):
    leads = []
    p = root / slug / "leads.jsonl"
    if p.exists():
        for line in p.read_text().splitlines():
            if line.strip():
                leads.append(json.loads(line))
    return leads


def load_scope(slug, root):
    p = root / slug / "target.json"
    return json.loads(p.read_text()) if p.exists() else {}


def has_artifact(slug, root):
    for round_dir in sorted((root / slug / "assets").glob("round-*"), reverse=True):
        for pat in ("*.apk", "*.xapk", "*.ipa"):
            if list(round_dir.glob(pat)):
                return True
        if (round_dir / "app").is_dir() and any((round_dir / "app").glob("*.apk")):
            return True
    return False


def cmd_plan(args) -> int:
    cfg = load_config()
    root = workspace_root(cfg)
    tdir = root / args.target
    if not tdir.exists():
        print(f"[fatal] target workspace not found: {tdir}")
        return 1
    snap = snapshot()
    scope = load_scope(args.target, root)
    leads = load_board(args.target, root)
    new_leads = [l for l in leads if l.get("status") == "new"]

    free_mb = snap["memory_free_mb"] or MIN_FREE_MB_FOR_HUNT
    hunt_budget_mb = max(0, free_mb - MIN_FREE_MB_FOR_HUNT)
    parallel = max(1, min(cfg.get("pacing", {}).get("max_parallel", 5),
                          hunt_budget_mb // (MB_PER_WORKER * 8)))
    mode = "static" if has_artifact(args.target, root) else "dynamic"
    sprint_min = cfg.get("hunt", {}).get("sprint_default_minutes", 60)

    rank = {"high": 0, "med": 1, "low": 2}
    top = sorted(new_leads, key=lambda l: rank.get(l.get("priority"), 3))[:12]
    by_class = {}
    for l in top:
        by_class.setdefault(l.get("skill", "manual"), []).append(l)
    sprints = []
    idx = 0
    for cls, group in sorted(by_class.items(), key=lambda kv: rank.get(next((g.get("priority") for g in kv[1]), "low"), 3)):
        for i in range(0, len(group), 4):
            sprints.append((f"sprint-{idx + 1}", cls, [g["id"] for g in group[i:i + 4]]))
            idx += 1

    lines = [f"# Hunt plan (proposal): {args.target}", "",
             f"Generated {snap['captured_at']} from the lead board ({len(new_leads)} new leads), "
             f"scope law, and the device profile. A PROPOSAL: the operator adjusts and executes; "
             f"nothing runs on its own.", "",
             "## Device capacity",
             "",
             f"- {snap['os']} {snap['arch']}, {snap['cores']} cores, "
             f"{snap['memory_free_mb']}MB free of {snap['memory_total_mb']}MB",
             f"- parallel probe ceiling: {parallel} (memory-derived; config pacing caps at "
             f"{cfg.get('pacing', {}).get('max_parallel', 5)})",
             f"- guard budget: {'OK' if snap['guard']['budget_ok'] else 'FAIL: run rh_guard reap first'}",
             f"- tools present: {', '.join(t for t, ok in snap['tools'].items() if ok) or '(none: pure-MCP + capture tool)'}",
             "",
             "## Scope (the law, fail-closed)",
             ""]
    for e in scope.get("scope", [])[:8]:
        lines.append(f"- [{e.get('type')}] {e.get('value')}")
    if scope.get("exclusions"):
        lines.append(f"- exclusions: {', '.join(scope['exclusions'][:6])}")
    lines += ["", f"## Mode: {mode}",
              "",
              ("artifact present: decode and map first (rh_apkrecon), the static map drives dynamic probes"
               if mode == "static" else
               "no artifact: live surface mapping first, grow the static side from captured traffic"), "",
              "## Proposed sprints (top leads by priority, 4 per sprint)",
              ""]
    if sprints:
        for name, cls, ids in sprints[:10]:
            lines.append(f"- {name} ({sprint_min} min, focus {cls}): leads {', '.join(ids)}")
    else:
        lines.append("- (board empty: run recon and ingest before planning, knowledge/target-intel.md)")
    lines += ["", "## Every sprint follows the loop",
              "",
              "clock start -> work one focus -> every probe through rh_capture.py -> "
              "VERIFICATION.md rows closed -> rh_clock wrap (mandatory, guard runs at wrap)", "",
              "## Stalls this plan expects",
              "",
              "- registration wall: park the lead with a revisit condition, pivot to unauth surfaces",
              "- WAF challenge: curl_cffi ladder, low concurrency, rotate vantage",
              "- device needed for mobile classes but absent: static+API first, on-device proofs stay leads"]
    out = tdir / "plan.md"
    out.write_text("\n".join(lines) + "\n")
    print(f"[plan] proposal written -> {out} ({len(sprints)} sprint(s), mode {mode}, parallel ceiling {parallel})")
    print("[plan] the operator reads, adjusts, and executes; nothing auto-runs")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Device profile and hunt planner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("check")
    sp_plan = sub.add_parser("plan")
    sp_plan.add_argument("target")
    args = ap.parse_args()
    if args.cmd == "init":
        return cmd_init(args)
    if args.cmd == "check":
        return cmd_check(args)
    return cmd_plan(args)


if __name__ == "__main__":
    sys.exit(main())
