#!/usr/bin/env python3
"""rh_scope: the scope law. Fail-closed host checking against target.json.

Anchored suffix matching: *.target.com matches sub.target.com and target.com
but NOT evil-target.com. Exclusions always win. Unparsed entries answer
out-of-scope (fail-closed). Exit 0 = in scope, exit 1 = out.
"""
import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

SKILL_DIR = Path(__file__).resolve().parent.parent


def target_path(slug: str) -> Path:
    cfg = json.loads((SKILL_DIR / "config.json").read_text())
    import os
    env_key = cfg.get("workspace", {}).get("env_override", "RH_HOME")
    root = (os.environ.get(env_key) if env_key else None) or cfg.get("workspace", {}).get("root", "./")
    base = Path.cwd() if root in (".", "./") else Path(os.path.expanduser(root))
    return base / slug / "target.json"


def load_target(slug: str) -> dict:
    p = target_path(slug)
    if not p.exists():
        print(f"[fatal] no target.json for '{slug}' (run rh_init.py {slug} --scope-file ...)")
        print(f"        expected: {p}")
        sys.exit(2)
    return json.loads(p.read_text())


def host_in_entry(host: str, entry: dict) -> bool:
    t = entry.get("type")
    if t == "wildcard":
        base = entry["base"].lower().rstrip(".")
        h = host.lower().rstrip(".")
        return h == base or h.endswith("." + base)
    if t == "domain":
        return host.lower().rstrip(".") == entry["host"].lower().rstrip(".")
    if t == "url":
        return host.lower().rstrip(".") == entry.get("host", "").lower().rstrip(".")
    return False


def path_in_entry(path: str, entry: dict) -> bool:
    if entry.get("type") != "url":
        return True
    want = entry.get("path", "/") or "/"
    have = (path or "/").rstrip("/") or "/"
    return have.startswith(want.rstrip("/"))


def check(tgt: dict, probe: str):
    """Return (verdict, reason). Verdict: 'in', 'excluded', 'unparsed', 'out'."""
    probe = probe.strip()
    if "://" in probe:
        u = urlparse(probe)
        host, path = u.hostname or "", u.path or "/"
    else:
        parts = probe.split("/")
        host, path = parts[0], "/" + "/".join(parts[1:])
    host = host.lower().rstrip(".")

    for exc in tgt.get("exclusions", []):
        exc = exc.lower().rstrip(".")
        if exc.startswith("*."):
            if host_in_entry(host, {"type": "wildcard", "base": exc[2:]}):
                return "excluded", f"host matches exclusion {exc}"
        elif host == exc or host.endswith("." + exc):
            return "excluded", f"host matches exclusion {exc}"

    for entry in tgt.get("scope", []):
        if host_in_entry(host, entry) and path_in_entry(path, entry):
            return "in", f"matches {entry['type']} entry {entry['value']}"

    for entry in tgt.get("scope", []):
        if entry.get("type") == "unparsed":
            return "unparsed", f"scope contains unparsed entries (fail-closed): {entry['value']}"
    if tgt.get("unparsed"):
        return "unparsed", f"scope contains unparsed entries (fail-closed): {', '.join(tgt['unparsed'][:3])}"

    return "out", "no scope entry matches this host"


def main() -> int:
    ap = argparse.ArgumentParser(description="Scope law: fail-closed host check")
    ap.add_argument("target")
    ap.add_argument("--check", action="append", default=[], help="host or URL to check (repeatable)")
    ap.add_argument("--list", action="store_true", help="list parsed scope")
    args = ap.parse_args()

    tgt = load_target(args.target)

    if args.list or not args.check:
        print(f"target: {tgt.get('slug')} (org: {tgt.get('org') or '?'})")
        print(f"disclosure contact: {tgt.get('disclosure_contact') or '(discover via security.txt / org page)'}")
        print("scope:")
        for e in tgt.get("scope", []):
            note = f"  path-scoped {e['path']}" if e.get("type") == "url" else ""
            print(f"  [{e['type']:8}] {e['value']}{note}")
        print("exclusions:")
        for e in tgt.get("exclusions", []):
            print(f"  [excluded] {e}")
        print("unparsed (fail-closed, resolve at intake):")
        for e in tgt.get("unparsed", []):
            print(f"  [unparsed] {e}")
        if not args.check:
            return 0

    rc = 0
    for probe in args.check:
        verdict, reason = check(tgt, probe)
        if verdict == "in":
            print(f"[IN-SCOPE ] {probe} ({reason})")
        else:
            rc = 1
            label = {"excluded": "EXCLUDED", "unparsed": "UNPARSED", "out": "OUT-OF-SCOPE"}[verdict]
            print(f"[{label:12}] {probe} ({reason})")
            if verdict != "excluded":
                print("            fail-closed: do not test. Resolve the scope entry or extend target.json first.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
