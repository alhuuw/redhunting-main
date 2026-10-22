#!/usr/bin/env python3
"""rh_differential: parameter-semantics 3-way probe (valid / garbage / empty) via rh_capture.

The deep-chain gate: for each URL template parameter, fires three requests, captures
all three as raw evidence, and prints the verdict:

  IDENTICAL  -> parameter ignored by the server (impact multiplies by its cardinality: sweep it)
  VALIDATED  -> empty/garbage rejected, valid accepted (parameter enforced)
  MIXED      -> response differs across variants (parameter filters; chain via its values)

Usage:
  python3 bin/rh_differential.py <target> <slug> 'https://api.example/v1/things?sub={sub}&seq=1' \
      --valid <valid-sub-value> [--header 'K: V']... [--tag slug] [--param sub]
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURE = os.path.join(HERE, "rh_capture.py")


def size_of(target, finding, tag):
    import json
    cfg = json.loads((Path(HERE).parent / "config.json").read_text())
    import os as _os
    env_key = cfg.get("workspace", {}).get("env_override", "RH_HOME")
    root = (_os.environ.get(env_key) if env_key else None) or cfg.get("workspace", {}).get("root", "./")
    raw = Path(_os.path.expanduser(root)) / target / "findings" / finding / "evidence" / "raw"
    for ext in (".bin", ".txt"):
        p = raw / f"{finding}_{tag}{ext}"
        if p.exists():
            return p.stat().st_size
    return -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("slug")
    ap.add_argument("url")
    ap.add_argument("--valid", required=True, help="valid value for the {param}")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--data", default=None)
    ap.add_argument("--tag", default="param")
    ap.add_argument("--param", default="sub")
    a = ap.parse_args()

    if f"{{{a.param}}}" not in a.url:
        print(f"url must contain {{{a.param}}} placeholder", file=sys.stderr)
        return 2

    results = {}
    for name, value in (("valid", a.valid), ("garbage", "GARBAGECONTROL"), ("empty", "")):
        url = a.url.replace(f"{{{a.param}}}", value)
        tag = f"{a.tag}_{name}"
        cmd = [sys.executable, CAPTURE, a.target, a.slug, "GET", url,
               "--tag", tag, "--note", f"[differential {a.param}={name}]"]
        for h in a.header:
            cmd += ["--header", h]
        if a.data:
            cmd += ["--data", a.data]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr or r.stdout)
            return 3
        results[name] = size_of(a.target, a.slug, tag)
        print(r.stdout.strip())

    print(f"\ndifferential[{a.param}]: sizes {results}")
    if results["valid"] == results["garbage"] == results["empty"] and results["valid"] > 0:
        print("verdict: IDENTICAL - parameter IGNORED by server: impact multiplies by its cardinality (sweep values, bounded)")
    elif results["garbage"] == results["empty"] and results["valid"] != results["garbage"]:
        print("verdict: VALIDATED - empty/garbage treated alike, valid differs: parameter enforced")
    else:
        print("verdict: MIXED - response differs across variants: parameter FILTERS (chain via its values)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
