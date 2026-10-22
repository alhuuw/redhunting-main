#!/usr/bin/env python3
"""rh_kickoff: the pre-hunt setup. Writes targets/<slug>/hunt.json.

Three questions only (sprint, mode, adb). Everything else is decided by the
system, not the operator: identities are random per engagement, accounts are
self-registered via tempmail (A and B, always), pacing auto-derives from target
behavior, and the whole app/system surface is in scope of analysis because
nobody knows where the bug lives until the surface is mapped.

Interactive when run bare; flag-driven with --yes for agent mode.
"""
import argparse
import datetime
import json
import random
import re
import shutil
import string
import subprocess
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent

WORDS = ("swift", "quiet", "amber", "north", "vex", "lunar", "cobalt", "ridge",
         "silent", "delta", "onyx", "harbor", "ember", "atlas", "quartz", "fjord",
         "nimbus", "vector", "gravel", "solace", "iron", "basalt", "cipher", "delta")


def load_config() -> dict:
    return json.loads((SKILL_DIR / "config.json").read_text())


def target_root(cfg: dict) -> Path:
    import os
    env_key = cfg.get("workspace", {}).get("env_override", "RH_HOME")
    root = (os.environ.get(env_key) if env_key else None) or cfg.get("workspace", {}).get("root", "./")
    base = Path.cwd() if root in (".", "./") else Path(os.path.expanduser(root))
    return base


def random_identity() -> dict:
    word = random.choice(WORDS)
    digits = "".join(random.choices(string.digits, k=random.randint(2, 4)))
    letters = "".join(random.choices(string.ascii_lowercase, k=2))
    return {
        "handle": f"{word}.{letters}{digits}",
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def adb_state():
    if not shutil.which("adb"):
        return "off", "adb not on PATH (static + API work only; on-device classes become hypotheses until a device exists)"
    try:
        out = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=10).stdout
        devices = [l.split("\t")[0] for l in out.splitlines()[1:] if l.strip() and "offline" not in l]
    except Exception:
        devices = []
    if not devices:
        return "detect", "adb present, no device attached (re-run kickoff after attaching emulator or physical device)"
    serial = devices[0]
    abi = ""
    try:
        abi = subprocess.run(["adb", "-s", serial, "shell", "getprop", "ro.product.cpu.abi"],
                             capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        pass
    return f"on:{serial}", f"device {serial} ({abi or 'abi?'}) attached"


def ask(prompt, default):
    raw = input(f"{prompt} [{default}]: ").strip()
    return raw or default


def guard_preflight() -> str:
    """Run the machine guard pre-flight: reap orphans, report budget state."""
    here = Path(__file__).resolve().parent
    r = subprocess.run([sys.executable, str(here / "rh_guard.py"), "reap"],
                       capture_output=True, text=True, timeout=60)
    tail = [l for l in (r.stdout or "").strip().splitlines() if l.startswith("[reap]")][-1:]
    b = subprocess.run([sys.executable, str(here / "rh_guard.py"), "budget"],
                       capture_output=True, text=True, timeout=60)
    return (tail[0] if tail else "") + " | " + (b.stdout.strip().splitlines()[-1] if b.stdout.strip() else "")


def main() -> int:
    ap = argparse.ArgumentParser(description="Pre-hunt setup -> hunt.json")
    ap.add_argument("target")
    ap.add_argument("--sprint", type=int, default=None, help="sprint length in minutes")
    ap.add_argument("--mode", choices=["static", "dynamic", "mixed"], default=None)
    ap.add_argument("--adb", choices=["on", "off", "detect"], default=None)
    ap.add_argument("--yes", action="store_true", help="non-interactive: accept flags/defaults")
    ap.add_argument("--refresh", action="store_true", help="re-run the interview even though hunt.json exists")
    args = ap.parse_args()

    cfg = load_config()
    tdir = target_root(cfg) / args.target
    if not tdir.exists():
        print(f"[fatal] target workspace not found: {tdir} (run rh_init.py {args.target} --scope-file ... first)")
        return 1

    existing = tdir / "hunt.json"
    if existing.exists() and not args.refresh:
        hunt = json.loads(existing.read_text())
        print(f"[kickoff] hunt.json already exists for {args.target} (setup is asked ONCE; config lives in the target folder)")
        print(f"  started: {hunt.get('started')}  sprint: {hunt.get('sprint_minutes')} min  mode: {hunt.get('mode')}  adb: {hunt.get('adb')}")
        print(f"  identity: {hunt.get('identity')}  accounts: {hunt.get('accounts')}")
        print("[kickoff] re-read this file at every session start instead of re-asking. Force a re-setup only with --refresh.")
        return 0

    adb_value, adb_note = adb_state()
    if args.adb:
        adb_value = "on" if args.adb == "on" else ("off" if args.adb == "off" else adb_value.split(":")[0])

    sprint_min = cfg.get("hunt", {}).get("sprint_min_minutes", 30)
    if args.yes:
        sprint = args.sprint or cfg.get("hunt", {}).get("sprint_default_minutes", 60)
        mode = args.mode or cfg.get("hunt", {}).get("mode_default", "static")
    else:
        print(f"kickoff: {args.target} (enter accepts the default)")
        sprint = int(ask("sprint minutes", str(args.sprint or cfg.get("hunt", {}).get("sprint_default_minutes", 60))))
        mode = ask("mode (static | dynamic | mixed)", args.mode or cfg.get("hunt", {}).get("mode_default", "static"))
    if sprint < sprint_min:
        print(f"[fatal] sprint {sprint} min is below the floor ({sprint_min} min): sprints may run longer, never shorter")
        return 1

    identity = random_identity()
    hunt = {
        "target": args.target,
        "started": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sprint_minutes": sprint,
        "mode": mode,
        "adb": adb_value,
        "adb_note": adb_note,
        "frida": "available" if shutil.which("frida") else "missing (static-only for protected apps)",
        "identity": identity["handle"],
        "identity_note": "random per engagement; the operator's real identity never appears anywhere",
        "accounts": "A and B self-registered via tempmail MCP at sprint start",
        "rate": "auto: start at config pacing.delay_ms, back off on 429/5xx, never push through",
        "surface": "the whole target estate (app, api, web, infra) is mapped before hunting; nobody pre-decides where the bug lives",
    }
    (tdir / "hunt.json").write_text(json.dumps(hunt, indent=2) + "\n")

    print(f"[kickoff] hunt.json written -> {tdir / 'hunt.json'}")
    print(f"  sprint:   {sprint} min  (start: rh_clock.py {args.target} start --minutes {sprint})")
    print(f"  mode:     {mode}")
    print(f"  adb:      {adb_value} - {adb_note}")
    print(f"  frida:    {hunt['frida']}")
    print(f"  identity: {identity['handle']} (random, this engagement only)")
    print(f"  accounts: A and B via tempmail, register them at sprint start")
    print(f"  rate:     auto-derived from target behavior")
    guard_note = ""
    try:
        guard_note = guard_preflight()
    except Exception as e:
        guard_note = f"guard pre-flight failed: {e}"
    print(f"  machine:  {guard_note}")
    dev_note = ""
    try:
        root_dir = target_root(load_config())
        prof = SKILL_DIR / "state" / "device.json"
        dev_note = "profile present (rh_device check for drift)" if prof.exists() else "no profile yet (rh_device init)"
    except Exception:
        dev_note = "device state unknown (rh_device init)"
    print(f"  device:   {dev_note} | plan: rh_device.py <target> plan after the board fills")
    print("[kickoff] the sprint cannot be abandoned: wrap it (rh_clock wrap) before any session end.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
