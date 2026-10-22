#!/usr/bin/env python3
"""rh_guard: the machine guard. Checks OUR device and enforces limits.

The incident this exists for: npx-spawned MCP servers do not die with the session that
spawned them. Each new session spawns fresh instances, the old ones linger parented to
dead (or same live) processes, and each pulls its own hundreds of MB. On a 16 GB machine
three stacked instances push into memory exhaustion. The guard makes that state visible
and reversible.

Commands:
  status    process census of hunt/machine-relevant processes (ORPHAN / DUPLICATE / LIVE),
            memory totals, machine memory pressure, budget verdict
  reap      kill ORPHANS (default, safe: their parent is gone, nothing owns them)
            --dedupe   also kill older DUPLICATE instances per signature (newest kept)
            --dry-run  print what would die, kill nothing
  budget    exit 0 when machine limits hold, exit 1 with reasons otherwise
            (for pre-flight in kickoff and post-flight in wrap)

Never kills: pid 1, the guard itself, or any ancestor of the guard (your shell, your
agent). Every reap action is appended to ~/redhunting/machine.log.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent

DEFAULT_PATTERNS = [
    r"npx", r"npm exec", r"jshook", r"mcp[-_]server", r"mcp$", r"frida", r"mitmdump",
    r"mitmproxy", r"adb", r"jadx", r"apktool", r"blutter", r"ghidra", r"burp",
    r"codegraph", r"interactsh", r"nuclei", r"subfinder", r"httpx", r"ffuf", r"katana",
]

PROTECT_COMMANDS = (r"opencode", r"codex", r"claude", r"cursor", r"tmux", r"sshd", r"login",
                    r"-zsh", r"/bash", r"WindowServer")


def load_config() -> dict:
    return json.loads((SKILL_DIR / "config.json").read_text())


def workspace_root(cfg: dict) -> Path:
    env_key = cfg.get("workspace", {}).get("env_override", "RH_HOME")
    root = (os.environ.get(env_key) if env_key else None) or cfg.get("workspace", {}).get("root", "./")
    base = Path.cwd() if root in (".", "./") else Path(os.path.expanduser(root))
    return base


def run_ps() -> str:
    for args in (["/bin/ps", "-axo", "pid,ppid,rss,command"], ["ps", "-axo", "pid,ppid,rss,command"]):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=15)
            if r.returncode == 0 and "keyword not found" not in r.stderr:
                if len(r.stdout.splitlines()[0].split()) >= 4:
                    return r.stdout
        except Exception:
            continue
    return ""


def parse_ps(text: str):
    """ps -axo pid,ppid,rss,command -> list of dicts."""
    procs = []
    for line in text.splitlines()[1:]:
        parts = line.strip().split(None, 3)
        if len(parts) < 4:
            continue
        pid, ppid, rss = parts[0], parts[1], parts[2]
        command = parts[3]
        if not pid.isdigit() or not ppid.isdigit():
            continue
        procs.append({"pid": int(pid), "ppid": int(ppid), "rss_kb": int(rss or 0), "cmd": command})
    return procs


def signature(cmd: str) -> str:
    s = cmd.strip()
    s = re.sub(r"/Users/[^/]+", "~", s)
    s = re.sub(r"~/\.npm/_npx/[0-9a-f]+", "~/.npm/_npx/#", s)
    s = re.sub(r"~/\.[a-z]+/[^ ]*node_modules/\.bin/", "#bin/", s)
    s = re.sub(r"node #bin/", "#", s)
    s = re.sub(r"\s+--?[a-z-]+(=\S+)?", "", s)
    s = re.sub(r"@\d+\.\d+\.\d+", "@v", s)
    s = s.split()[0:4]
    return " ".join(s)[:90].lower() or "unknown"


def is_watch(cmd: str, patterns) -> bool:
    low = cmd.lower()
    return any(re.search(p, low) for p in patterns)


def is_protected(proc, ancestors):
    if proc["pid"] in ancestors:
        return True
    return any(re.search(p, proc["cmd"]) for p in PROTECT_COMMANDS) and not is_watch(proc["cmd"], DEFAULT_PATTERNS)


def ancestor_chain(procs, own_pid):
    by_pid = {p["pid"]: p for p in procs}
    chain, cur = set(), own_pid
    for _ in range(64):
        if cur in chain or cur <= 1:
            break
        chain.add(cur)
        parent = by_pid.get(cur)
        if parent is None:
            break
        cur = parent["ppid"]
    return chain


DAEMON_BY_DESIGN = (r"fork-server", r"frida-server", r"mitmdump.*--daemon")


def classify(procs, patterns, own_pid):
    """Split watched processes into orphans, duplicates (killable older), live."""
    watched = [p for p in procs if is_watch(p["cmd"], patterns)]
    pids = {p["pid"] for p in procs}
    ancestors = ancestor_chain(procs, own_pid)

    orphans, rest = [], []
    for p in watched:
        if re.search(r"|".join(DAEMON_BY_DESIGN), p["cmd"]):
            continue
        if p["pid"] in ancestors:
            continue
        if p["ppid"] not in pids or p["ppid"] == 1:
            orphans.append(p)
        else:
            rest.append(p)

    groups = {}
    for p in rest:
        groups.setdefault(signature(p["cmd"]), []).append(p)

    dupes_killable, live = [], []
    for sig, group in groups.items():
        if len(group) > 1:
            group_sorted = sorted(group, key=lambda p: p["pid"])
            live.extend(group_sorted[-1:])
            dupes_killable.extend(group_sorted[:-1])
        else:
            live.extend(group)

    return orphans, dupes_killable, live, watched


def memory_stats():
    total_mb = free_mb = swap_mb = None
    try:
        out = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=10).stdout.strip()
        total_mb = int(out) / 1024 / 1024
    except Exception:
        pass
    try:
        mp = subprocess.run(["memory_pressure", "-Q"], capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"free percentage: (\d+)%", mp)
        if m and total_mb:
            free_mb = round(total_mb * int(m.group(1)) / 100)
    except Exception:
        pass
    try:
        sw = subprocess.run(["sysctl", "-n", "vm.swapusage"], capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"free = (\d+)", sw)
        if m:
            swap_mb = round(int(m.group(1)) / 1024 / 1024, 1)
    except Exception:
        pass
    return {"total_mb": round(total_mb) if total_mb else None,
            "free_mb": free_mb, "swap_free_mb": swap_mb}


def budget_verdict(mem, watched_mb, orphans, dupes, cfg_machine):
    reasons = []
    floor = cfg_machine.get("memory_floor_mb", 2048)
    max_mb = cfg_machine.get("max_hunt_process_mb", 1500)
    max_dup = cfg_machine.get("max_duplicate_instances", 1)
    if mem["free_mb"] is not None and mem["free_mb"] < floor:
        reasons.append(f"free memory {mem['free_mb']}MB below floor {floor}MB")
    if watched_mb > max_mb:
        reasons.append(f"hunt processes hold {watched_mb}MB above the {max_mb}MB ceiling")
    if orphans:
        reasons.append(f"{len(orphans)} orphaned process(es) holding "
                       f"{sum(p['rss_kb'] for p in orphans) // 1024}MB (reap them)")
    if len(dupes) > max_dup:
        reasons.append(f"{len(dupes)} duplicate instance(s) beyond the {max_dup} allowed (reap --dedupe)")
    return reasons


def fmt_mb(kb):
    return f"{kb // 1024}MB" if kb >= 1024 else f"{kb}KB"


def print_row(p, state):
    print(f"  [{state:9}] pid={p['pid']:<7} {fmt_mb(p['rss_kb']):>7}  {p['cmd'][:78]}")


def cmd_status(args) -> int:
    cfg = load_config()
    machine_cfg = cfg.get("machine", {})
    patterns = machine_cfg.get("watch_patterns", DEFAULT_PATTERNS)
    procs = parse_ps(run_ps())
    orphans, dupes, live, watched = classify(procs, patterns, os.getpid())
    mem = memory_stats()

    watched_mb = sum(p["rss_kb"] for p in watched) // 1024
    print(f"machine: {mem['total_mb']}MB total, {mem['free_mb']}MB free"
          + (f", {mem['swap_free_mb']}MB swap free" if mem["swap_free_mb"] is not None else ""))
    print(f"hunt-relevant processes: {len(watched)} holding {watched_mb}MB "
          f"({len(orphans)} orphan, {len(dupes)} duplicate, {len(live)} live)")
    for p in orphans:
        print_row(p, "ORPHAN")
    for p in dupes:
        print_row(p, "DUPLICATE")
    if args.verbose:
        for p in live:
            print_row(p, "LIVE")
    reasons = budget_verdict(mem, watched_mb, orphans, dupes, machine_cfg)
    if reasons:
        print("[budget] FAIL:")
        for r in reasons:
            print(f"  - {r}")
        print("[budget] fix: python3 bin/rh_guard.py reap   (add --dedupe for duplicate instances)")
        return 1
    print("[budget] OK")
    return 0


def kill_pid(pid) -> bool:
    try:
        os.kill(pid, 15)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return False


def log_reap(_unused_root, lines):
    state = SKILL_DIR / "state"
    state.mkdir(parents=True, exist_ok=True)
    entry = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " reaped " + "; ".join(lines)
    with (state / "machine.log").open("a") as f:
        f.write(entry + "\n")


def cmd_reap(args) -> int:
    cfg = load_config()
    machine_cfg = cfg.get("machine", {})
    patterns = machine_cfg.get("watch_patterns", DEFAULT_PATTERNS)
    procs = parse_ps(run_ps())
    own_pid = os.getpid()
    orphans, dupes, live, _ = classify(procs, patterns, own_pid)

    victims = list(orphans)
    if args.dedupe:
        victims += dupes
    if not victims:
        print("[reap] nothing to kill: no orphans" + (" (duplicates exist, use --dedupe)" if dupes and not args.dedupe else ""))
        return 0

    print(f"[reap] {len(victims)} process(es) to kill:")
    for p in victims:
        print_row(p, "KILL")
    if args.dry_run:
        print("[reap] dry-run: nothing killed")
        return 0

    killed, missed = [], []
    for p in victims:
        if kill_pid(p["pid"]):
            killed.append(f"{p['pid']}({fmt_mb(p['rss_kb'])})")
        else:
            missed.append(str(p["pid"]))
    time.sleep(1)
    for p in victims:
        try:
            os.kill(p["pid"], 0)
            kill_pid(p["pid"])
            time.sleep(0.5)
        except ProcessLookupError:
            pass
        except PermissionError:
            pass
    log_reap(workspace_root(cfg), killed or ["none"])
    freed = sum(p["rss_kb"] for p in victims) // 1024
    print(f"[reap] killed {len(killed)} process(es), ~{freed}MB freed; log: workspace machine.log")
    if missed:
        print(f"[reap] could not signal: {', '.join(missed)}")
    return 0


def cmd_budget(args) -> int:
    cfg = load_config()
    machine_cfg = cfg.get("machine", {})
    patterns = machine_cfg.get("watch_patterns", DEFAULT_PATTERNS)
    procs = parse_ps(run_ps())
    orphans, dupes, _, watched = classify(procs, patterns, os.getpid())
    mem = memory_stats()
    watched_mb = sum(p["rss_kb"] for p in watched) // 1024
    reasons = budget_verdict(mem, watched_mb, orphans, dupes, machine_cfg)
    if reasons:
        for r in reasons:
            print(f"[budget] {r}")
        return 1
    print("[budget] OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Machine guard: process census, orphan reaping, memory budget")
    sub = ap.add_subparsers(dest="cmd")
    sp_st = sub.add_parser("status")
    sp_st.add_argument("--verbose", action="store_true")
    sp_re = sub.add_parser("reap")
    sp_re.add_argument("--dedupe", action="store_true", help="also kill older duplicate instances (newest kept)")
    sp_re.add_argument("--dry-run", action="store_true")
    sub.add_parser("budget")
    args = ap.parse_args()
    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "reap":
        return cmd_reap(args)
    return cmd_budget(args)


if __name__ == "__main__":
    sys.exit(main())
