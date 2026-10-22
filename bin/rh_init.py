#!/usr/bin/env python3
"""rh_init: scaffold a persistent target workspace.

Layout, anti-cleanup doctrine, and the scope contract are documented in
knowledge/workspace.md. Idempotent: existing files are never overwritten, the
workspace is never cleaned. After init, run rh_kickoff before any dynamic work.
"""
import argparse
import datetime
import json
import re
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
TPL = SKILL_DIR / "templates"


def load_config() -> dict:
    cfg_path = SKILL_DIR / "config.json"
    if not cfg_path.exists():
        print(f"[fatal] config.json not found at {cfg_path}")
        sys.exit(2)
    return json.loads(cfg_path.read_text())


def workspace_root(cfg: dict) -> Path:
    import os
    env_key = cfg.get("workspace", {}).get("env_override", "RH_HOME")
    root = (os.environ.get(env_key) if env_key else None) or cfg.get("workspace", {}).get("root", "./")
    base = Path.cwd() if root in (".", "./") else Path(os.path.expanduser(root))
    return base


SCOPE_LINE = re.compile(r"^\s*(exclude:\s*)?([^\s#]++)\s*(?:#.*)?$")


def parse_scope_line(raw: str):
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    m = SCOPE_LINE.match(line)
    if not m:
        return {"type": "unparsed", "value": line}
    excluded = bool(m.group(1))
    value = m.group(2).strip()
    if value.startswith("http://") or value.startswith("https://"):
        from urllib.parse import urlparse
        u = urlparse(value)
        entry = {"type": "url", "value": value, "host": u.hostname or "", "path": u.path or "/"}
    elif value.startswith("*."):
        entry = {"type": "wildcard", "value": value, "base": value[2:]}
    elif re.match(r"^[a-zA-Z0-9._-]+(:\d+)?$", value):
        host = value.split(":")[0]
        entry = {"type": "domain", "value": value, "host": host}
    else:
        entry = {"type": "unparsed", "value": value}
    if excluded:
        return {"type": "exclusion", "value": entry.get("host") or entry.get("value", value)}
    return entry


def parse_scope_file(path: Path):
    entries, exclusions, unparsed = [], [], []
    for raw in path.read_text().splitlines():
        entry = parse_scope_line(raw)
        if entry is None:
            continue
        if entry["type"] == "exclusion":
            exclusions.append(entry["value"])
        elif entry["type"] == "unparsed":
            unparsed.append(entry["value"])
        else:
            entries.append(entry)
    return entries, exclusions, unparsed


def write_if_absent(path: Path, content: str):
    if not path.exists():
        path.write_text(content)
        return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Scaffold a persistent target workspace")
    ap.add_argument("slug", help="target slug, e.g. acme")
    ap.add_argument("--scope-file", help="file with scope lines (*.t.com, t.com, https://..., exclude: ..., # comments)")
    ap.add_argument("--org", default="", help="the org behind the app/system, for disclosure contact discovery")
    ap.add_argument("--notes", default="", help="free-form context: what the app is, where you found it")
    args = ap.parse_args()

    cfg = load_config()
    root = workspace_root(cfg)
    tdir = root / args.slug
    if tdir.exists():
        print(f"[info] target workspace exists: {tdir} (idempotent: nothing overwritten)")
    else:
        tdir.mkdir(parents=True)
        print(f"[init] workspace root: {root}")
        print(f"[init] target dir:    {tdir}")

    write_if_absent(tdir / "README.md", (TPL / "TARGET-README.md").read_text().replace("<slug>", args.slug))

    scope_txt = tdir / "scope.txt"
    if not scope_txt.exists():
        if args.scope_file:
            src = Path(args.scope_file)
            if not src.exists():
                print(f"[fatal] scope file not found: {src}")
                return 1
            scope_txt.write_text(src.read_text())
        else:
            scope_txt.write_text("# scope contract: one entry per line\n# *.target.com | target.com | https://target.com/path | exclude: evil.target.com\n")

    target_json = tdir / "target.json"
    entries, exclusions, unparsed = parse_scope_file(scope_txt)
    if not target_json.exists():
        tgt = {
            "slug": args.slug,
            "org": args.org,
            "notes": args.notes,
            "scope": entries,
            "exclusions": exclusions,
            "unparsed": unparsed,
            "disclosure_contact": "",
            "created": datetime.date.today().isoformat(),
            "rh_version": 2,
        }
        target_json.write_text(json.dumps(tgt, indent=2) + "\n")
        print(f"[init] target.json:   {len(entries)} scope entries, {len(exclusions)} exclusions, {len(unparsed)} unparsed (fail-closed)")
    else:
        tgt = json.loads(target_json.read_text())
        old_scope = tgt.get("scope", [])
        merged = old_scope + [e for e in entries if e not in old_scope]
        old_excl = tgt.get("exclusions", [])
        tgt["scope"] = merged
        tgt["exclusions"] = old_excl + [e for e in exclusions if e not in old_excl]
        tgt["unparsed"] = [u for u in tgt.get("unparsed", []) + unparsed if u not in merged]
        target_json.write_text(json.dumps(tgt, indent=2) + "\n")
        print(f"[import] merged into existing target.json: {len(merged)} scope entries, {len(tgt['exclusions'])} exclusions")

    for sub in ("findings", "leads", "assets"):
        (tdir / sub).mkdir(exist_ok=True)
    (tdir / "findings" / ".gitkeep").write_text("")
    for name in ("leads.jsonl", "ledger.jsonl", "sprints.jsonl"):
        write_if_absent(tdir / name, "")
    for name, tpl in (("vault.md", "VAULT-HEAD"), ("retest.md", "RETEST-HEAD"), ("accounts.md", "ACCOUNTS-HEAD"), ("notes.md", "NOTES-HEAD")):
        p = tdir / name
        if not p.exists():
            if tpl == "VAULT-HEAD":
                p.write_text("# Vault: chain ammunition (never submit these alone, never delete)\n\n### [V-NN] <one-liner (sev alone)>\n- Evidence: findings/<slug>/evidence/raw/\n- Chain hypothesis:\n- Revisit trigger:\n")
            elif tpl == "RETEST-HEAD":
                p.write_text("# Retest queue (target-change triggers)\n\n- [ ] TR-01: app version watch - last checked: <date>\n- [ ] TR-02: scope/estate re-scan monthly - last: <date>\n")
            elif tpl == "ACCOUNTS-HEAD":
                p.write_text("# Accounts (self-registered test identities, random per engagement)\n\n| Account | Purpose | Created | Notes |\n|---|---|---|---|\n")
            else:
                p.write_text("# Round notes / sprint wraps / mode transitions\n")

    print(f"[init] never-auto-cleanup doctrine active")
    print(f"[init] layout mirrors the engagement-scaffold pattern: target folder in the invocation directory; journal and playbook live in the skill knowledge/, machine state in the skill state/")
    print(f"[next] python3 bin/rh_kickoff.py {args.slug}          # setup -> hunt.json")
    print(f"[next] python3 bin/rh_scope.py {args.slug} --check <host>  # the law")
    return 0


if __name__ == "__main__":
    sys.exit(main())
