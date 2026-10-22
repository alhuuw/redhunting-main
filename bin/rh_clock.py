#!/usr/bin/env python3
"""rh_clock: sprint clock. No clock, no sprint (workflow.md sprint protocol).

start    begin a sprint (default minutes from config, --minutes overrides)
status   elapsed / remaining (exit 1 when expired)
wrap     close the sprint: append the wrap log to notes.md, clear state
list     show all recorded sprints for the target

The clock state is targets/<slug>/sprint.json; history is sprints.jsonl.
"""
import argparse
import datetime
import json
import subprocess
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent


def target_dir(slug: str) -> Path:
    cfg = json.loads((SKILL_DIR / "config.json").read_text())
    import os
    env_key = cfg.get("workspace", {}).get("env_override", "RH_HOME")
    root = (os.environ.get(env_key) if env_key else None) or cfg.get("workspace", {}).get("root", "./")
    base = Path.cwd() if root in (".", "./") else Path(os.path.expanduser(root))
    return base / slug


def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def fmt(sec: float) -> str:
    sec = max(0, int(sec))
    return f"{sec // 60:02d}:{sec % 60:02d}"


def load_state(p: Path):
    if p.exists():
        return json.loads(p.read_text())
    return None


_PRANK = {"high": 0, "med": 1, "low": 2}


def _next_action(d: Path) -> str:
    """Surface the next move so a live sprint never has to think about idling:
    the top unworked lead, or - when the board has none - the explicit
    no-idle fallback. Waiting is never a move (workflow.md sprint protocol)."""
    leads_path = d / "leads.jsonl"
    leads = []
    if leads_path.exists():
        for line in leads_path.read_text().splitlines():
            if line.strip():
                try:
                    leads.append(json.loads(line))
                except ValueError:
                    pass
    fresh = [l for l in leads if l.get("status") == "new"]
    fresh.sort(key=lambda l: (_PRANK.get(l.get("priority"), 2), l.get("id", "")))
    if fresh:
        l = fresh[0]
        return (f"[clock] next -> {l.get('id','-')} [{l.get('priority','-')}] {l.get('skill','-')}: {l.get('signal','-')}\n"
                f"[clock] work it: rh_leadboard.py <target> touch {l.get('id','-')} --status investigating")
    if leads:
        return ("[clock] board has no FRESH lead but the floor still holds. No-idle fallback: deepen a "
                "verification ladder on an open finding, widen recon (new leads -> ingest), or APK version-diff. Waiting is never a move.")
    return ("[clock] board empty and the floor still holds. No-idle fallback: run recon and ingest "
            "(rh_leadboard.py <target> ingest), or deepen an open finding. Waiting is never a move.")


def _next_sprint_no(d: Path) -> int:
    hist = d / "sprints.jsonl"
    if not hist.exists():
        return 1
    lines = [json.loads(l) for l in hist.read_text().splitlines() if l.strip()]
    return (lines[-1]["sprint_no"] + 1) if lines else 1


def cmd_start(args) -> int:
    d = target_dir(args.target)
    cfg = json.loads((SKILL_DIR / "config.json").read_text())
    state_path = d / "sprint.json"
    existing = load_state(state_path)
    if existing:
        print(f"[clock] a sprint is already running (started {existing['started_at']}) - status:")
        return cmd_status(args)
    minutes = args.minutes or cfg.get("hunt", {}).get("sprint_default_minutes", 60)
    state = {
        "sprint_no": _next_sprint_no(d),
        "started_at": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "minutes": minutes,
        "focus": args.focus,
    }
    state_path.write_text(json.dumps(state, indent=2) + "\n")
    print(f"[clock] sprint #{state['sprint_no']} START {minutes} min - deadline {state['started_at']} + {minutes}m" + (f" - focus: {args.focus}" if args.focus else ""))
    print(f"[clock] one focus per sprint. Clock visible every turn. The sprint cannot be abandoned: wrap it (rh_clock.py {args.target} wrap) before session end.")
    return 0


def cmd_status(args) -> int:
    d = target_dir(args.target)
    state = load_state(d / "sprint.json")
    if not state:
        print("[clock] no sprint running (start: rh_clock.py <target> start)")
        return 0
    started = datetime.datetime.strptime(state["started_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    elapsed = (now_utc() - started).total_seconds()
    remaining = state["minutes"] * 60 - elapsed
    mark = "TIME LEFT" if remaining > 0 else "EXPIRED"
    print(f"[clock] sprint #{state['sprint_no']} {mark}: {fmt(remaining)}  (elapsed {fmt(elapsed)} / {state['minutes']} min) - focus: {state.get('focus') or 'unset'}")
    if remaining <= 0:
        print("[clock] expired: wrap the sprint before starting the next")
        return 1
    print(_next_action(d))
    return 0


def cmd_wrap(args) -> int:
    d = target_dir(args.target)
    state = load_state(d / "sprint.json")
    if not state:
        print("[clock] no sprint running")
        return 1
    started = datetime.datetime.strptime(state["started_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    elapsed = (now_utc() - started).total_seconds()
    remaining = state["minutes"] * 60 - elapsed
    if remaining > 0 and not args.force:
        print(f"[clock] sprint #{state['sprint_no']} still has {fmt(remaining)} left: a sprint may run longer, never shorter.")
        print("[clock] the sprint cannot be abandoned. Finish the focus, or let it expire, then wrap.")
        print("[clock] (only a deliberate --force with a recorded reason breaks this rule)")
        return 1
    entry = {
        "sprint_no": state["sprint_no"],
        "started_at": state["started_at"],
        "minutes": state["minutes"],
        "actual_minutes": round(elapsed / 60, 1),
        "focus": state.get("focus") or "",
        "findings": args.findings,
        "negatives": args.negatives,
        "note": (args.note + " [forced: sprint floor broken]") if args.force else args.note,
        "wrapped_at": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with (d / "sprints.jsonl").open("a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    with (d / "notes.md").open("a") as f:
        f.write(f"\n## Sprint wrap #{entry['sprint_no']} ({entry['wrapped_at']})\n"
                f"- focus: {entry['focus'] or '(unset)'} - {entry['actual_minutes']} min actual / {entry['minutes']} planned\n"
                f"- findings: {entry['findings']}  negatives/leads killed: {entry['negatives']}\n"
                f"- {entry['note'] or '(no note)'}\n")
    (d / "sprint.json").unlink()
    guard_note = ""
    try:
        here = Path(__file__).resolve().parent
        r = subprocess.run([sys.executable, str(here / "rh_guard.py"), "reap"],
                           capture_output=True, text=True, timeout=60)
        lines = (r.stdout or "").strip().splitlines()
        guard_note = next((l for l in lines if l.startswith("[reap]")), "")
    except Exception as e:
        guard_note = f"guard post-flight failed: {e}"
    print(f"[clock] sprint #{entry['sprint_no']} wrapped and logged ({entry['findings']} findings, {entry['negatives']} negatives). Zero-finding sprints still count: coverage is progress.")
    if guard_note:
        print(f"[clock] {guard_note}")
    return 0


def cmd_list(args) -> int:
    d = target_dir(args.target)
    hist = d / "sprints.jsonl"
    if not hist.exists():
        print("[clock] no sprint history")
        return 0
    for line in hist.read_text().splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        print(f"  #{e['sprint_no']:3} {e['started_at']}  {e['actual_minutes']:6}min  f:{e['findings']:2} n:{e['negatives']:3}  {e.get('focus', '')[:40]}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Sprint clock: no clock, no sprint")
    ap.add_argument("target")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp_start = sub.add_parser("start")
    sp_start.add_argument("--minutes", type=int, default=None)
    sp_start.add_argument("--focus", default="", help="the one surface/class this sprint targets")
    sub.add_parser("status")
    sp_wrap = sub.add_parser("wrap")
    sp_wrap.add_argument("--findings", type=int, default=0)
    sp_wrap.add_argument("--negatives", type=int, default=0)
    sp_wrap.add_argument("--note", default="")
    sp_wrap.add_argument("--force", action="store_true", help="break the sprint floor (recorded in the wrap log as forced)")
    sub.add_parser("list")
    args = ap.parse_args()
    return {"start": cmd_start, "status": cmd_status, "wrap": cmd_wrap, "list": cmd_list}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
