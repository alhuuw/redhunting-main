#!/usr/bin/env python3
"""rh_ledger: the findings ledger (append-only) + status tracker + per-class stats.

Findings live in NAMED folders (slug from the title, never a bare number):
targets/<slug>/findings/<finding-slug>/ with README, SUMMARY, VERIFICATION,
materials, evidence/raw, poc - all scaffolded from templates/ by `add`.
The ledger entry carries an internal RH-n id plus the slug; only honest fields
(status, triage_events, bounty, resolved_at) are ever mutated.
"""
import argparse
import datetime
import json
import re
import statistics
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
TPL = SKILL_DIR / "templates"

MUTABLE = ("status", "bounty", "resolved_at", "triage_events", "chain_refs")
TERMINAL = ("resolved", "duplicate", "informative", "not_accepted", "retracted")


def load_config() -> dict:
    return json.loads((SKILL_DIR / "config.json").read_text())


def target_dir(slug: str) -> Path:
    import os
    cfg = load_config()
    env_key = cfg.get("workspace", {}).get("env_override", "RH_HOME")
    root = (os.environ.get(env_key) if env_key else None) or cfg.get("workspace", {}).get("root", "./")
    base = Path.cwd() if root in (".", "./") else Path(os.path.expanduser(root))
    return base / slug


def ledger_path(slug: str) -> Path:
    return target_dir(slug) / "ledger.jsonl"


STOPWORDS = {"via", "in", "of", "the", "with", "on", "to", "a", "an", "and", "by", "for", "from", "at", "is", "are", "was"}


def slugify(title: str) -> str:
    words = [w for w in re.sub(r"[^a-z0-9]+", " ", title.lower()).split() if w and w not in STOPWORDS]
    s = "-".join(words[:6])
    s = re.sub(r"-{2,}", "-", s)[:40].strip("-")
    return s or "finding"


def load(slug):
    entries = []
    p = ledger_path(slug)
    if p.exists():
        for line in p.read_text().splitlines():
            if line.strip():
                entries.append(json.loads(line))
    return entries


def save(slug, entries):
    ledger_path(slug).write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entries))


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scaffold_finding(tdir: Path, fslug: str, fid: str, title: str, vclass: str, severity: str):
    fdir = tdir / "findings" / fslug
    fdir.mkdir(parents=True, exist_ok=True)
    (fdir / "evidence" / "raw").mkdir(parents=True, exist_ok=True)
    (fdir / "poc").mkdir(exist_ok=True)
    wrote = []
    if not (fdir / "README.md").exists():
        (fdir / "README.md").write_text(
            (TPL / "FINDING-README.md").read_text()
            .replace("<slug>", fslug).replace("<id>", fid).replace("<title>", title)
            .replace("<class>", vclass).replace("<severity>", severity))
        wrote.append("README.md")
    if not (fdir / "SUMMARY.md").exists():
        (fdir / "SUMMARY.md").write_text(
            (TPL / "FINDING-SUMMARY.md").read_text()
            .replace("<id>", fid).replace("<title>", title)
            .replace("<class>", vclass).replace("<severity>", severity))
        wrote.append("SUMMARY.md")
    if not (fdir / "VERIFICATION.md").exists():
        (fdir / "VERIFICATION.md").write_text(
            (TPL / "VERIFICATION.md").read_text().replace("<slug>", fslug))
        wrote.append("VERIFICATION.md")
    if not (fdir / "materials.md").exists():
        (fdir / "materials.md").write_text(
            (TPL / "MATERIALS.md").read_text().replace("<slug>", fslug))
        wrote.append("materials.md")
    return fdir, wrote


def cmd_add(args) -> int:
    tdir = target_dir(args.target)
    if not tdir.exists():
        print(f"[fatal] target workspace not found: {tdir} (rh_init first)")
        return 1
    entries = load(args.target)
    n = len(entries) + 1
    fid = f"RH-{n}"
    fslug = args.slug or slugify(args.title)
    base = fslug
    taken = {e.get("slug") for e in entries}
    i = 2
    while fslug in taken:
        fslug = f"{base}-{i}"
        i += 1
    fdir, wrote = scaffold_finding(tdir, fslug, fid, args.title, args.vclass, args.severity)
    entry = {
        "id": fid, "slug": fslug, "title": args.title, "class": args.vclass, "severity": args.severity,
        "url": args.url or "", "status": args.status,
        "bounty": None, "submitted_at": None, "resolved_at": None, "triage_events": [],
        "chain_refs": [], "evidence": f"findings/{fslug}/evidence/raw/", "target": args.target,
    }
    entries.append(entry)
    save(args.target, entries)
    print(f"[ledger] {fid} -> findings/{fslug}/ ({args.status})")
    for w in wrote:
        print(f"          scaffolded {w}")
    print(f"[next]   fill SUMMARY.md, verify per VERIFICATION.md, capture into {fdir}/evidence/raw/")
    print(f"[gate]   python3 bin/rh_validate.py {args.target} {fdir}/SUMMARY.md")
    return 0


def cmd_list(args) -> int:
    entries = load(args.target)
    if args.status:
        entries = [e for e in entries if e.get("status") == args.status]
    if not entries:
        print("[ledger] empty" + (f" for status {args.status}" if args.status else ""))
        return 0
    for e in entries:
        bounty = f" ${e['bounty']}" if e.get("bounty") else ""
        print(f"{e['id']:7} {e.get('status','-'):13} {e.get('severity','-'):9} {e.get('slug','-'):38}{bounty:8} {e.get('title','')[:50]}")
    return 0


def cmd_update(args) -> int:
    entries = load(args.target)
    for e in entries:
        if args.id in (e.get("id"), e.get("slug")):
            e["status"] = args.status
            if args.bounty is not None:
                e["bounty"] = args.bounty
            if args.status in TERMINAL:
                e["resolved_at"] = now_iso()
            event = {"at": now_iso(), "event": args.event or f"status -> {args.status}"}
            e.setdefault("triage_events", []).append(event)
            save(args.target, entries)
            print(f"[ledger] {e['id']} ({e['slug']}) -> {args.status}" + (f" (${args.bounty})" if args.bounty is not None else ""))
            return 0
    print(f"[fatal] {args.id} not found")
    return 1


def cmd_stats(args) -> int:
    entries = load(args.target)
    if not entries:
        print("[stats] ledger empty")
        return 0
    by_status = {}
    for e in entries:
        by_status[e.get("status", "?")] = by_status.get(e.get("status", "?"), 0) + 1
    resolved = [e for e in entries if e.get("resolved_at")]
    print(f"target {args.target}: {len(entries)} findings")
    print("  status: " + " ".join(f"{k}:{v}" for k, v in sorted(by_status.items())))
    classes = {}
    for e in entries:
        c = classes.setdefault(e.get("class", "?"), [0, 0])
        c[0] += 1
        if e.get("status") == "resolved":
            c[1] += 1
    print("  per-class:")
    for cname, (total, ok) in sorted(classes.items(), key=lambda kv: -kv[1][1]):
        print(f"    {cname:20} {ok}/{total} resolved")
    ttts = []
    for e in entries:
        if e.get("submitted_at") and e.get("resolved_at"):
            d0 = datetime.datetime.fromisoformat(e["submitted_at"].replace("Z", "+00:00"))
            d1 = datetime.datetime.fromisoformat(e["resolved_at"].replace("Z", "+00:00"))
            ttts.append((d1 - d0).total_seconds() / 86400)
    if ttts:
        print(f"  time-to-resolution: median {statistics.median(ttts):.1f}d (n={len(ttts)})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Findings ledger + per-class stats")
    ap.add_argument("target")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp_add = sub.add_parser("add")
    sp_add.add_argument("--title", required=True)
    sp_add.add_argument("--class", dest="vclass", required=True)
    sp_add.add_argument("--severity", required=True)
    sp_add.add_argument("--url", default="")
    sp_add.add_argument("--slug", default="", help="finding folder name (default: slugified title)")
    sp_add.add_argument("--status", default="draft", choices=["draft", "verified"])
    sp_list = sub.add_parser("list")
    sp_list.add_argument("--status", default="")
    sp_up = sub.add_parser("update")
    sp_up.add_argument("id", help="RH-n id or finding slug")
    sp_up.add_argument("--status", required=True)
    sp_up.add_argument("--bounty", type=int, default=None)
    sp_up.add_argument("--event", default="")
    sub.add_parser("stats")
    args = ap.parse_args()
    if args.cmd == "add":
        return cmd_add(args)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "update":
        return cmd_update(args)
    return cmd_stats(args)


if __name__ == "__main__":
    sys.exit(main())
