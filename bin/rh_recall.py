#!/usr/bin/env python3
"""rh_recall: search the skill knowledge base (including the learn-back book)
for prior art by technique.

Usage: python3 rh_recall.py <keyword> [keyword ...] [--targets ~/redhunting/targets]
       python3 rh_recall.py idor jwt otp
       python3 rh_recall.py "capability matrix" --targets ~/redhunting/targets
"""
import argparse
import sys
from pathlib import Path

KNOW = Path(__file__).resolve().parent.parent / "knowledge"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="+")
    ap.add_argument("--targets", help="also search SUMMARY/notes under this targets root")
    args = ap.parse_args()
    terms = [q.lower() for q in args.query]

    def hit(line: str) -> bool:
        low = line.lower()
        return all(t in low for t in terms)

    def scan(path: Path, label: str, max_hits: int = 4):
        out, count, ctx = [], 0, 0
        for line in path.read_text(errors="ignore").splitlines():
            if count >= max_hits:
                break
            if hit(line):
                count += 1
                ctx = 2
                out.append(f"  {path.name}: {line.strip()[:160]}")
            elif ctx and line.strip():
                out.append(f"     {line.strip()[:140]}")
                ctx -= 1
        return [(label, o) for o in out]

    results = []
    for f in sorted(KNOW.glob("*.md")):
        results += scan(f, "[knowledge]")
    cheats = KNOW / "cheatsheets"
    if cheats.is_dir():
        for f in sorted(cheats.glob("*.md")):
            results += scan(f, "[cheatsheet]")
    classes = KNOW / "classes"
    if classes.is_dir():
        for f in sorted(classes.glob("*/SKILL.md")):
            results += scan(f, f"[class:{f.parent.name}]")
    if args.targets:
        troot = Path(args.targets).expanduser()
        for d in sorted(troot.iterdir()) if troot.is_dir() else []:
            for f in sorted((d / "findings").glob("*/SUMMARY.md")):
                results += scan(f, f"[{d.name}]", max_hits=3)
            notes = d / "notes.md"
            if notes.exists():
                results += scan(notes, f"[{d.name}]", max_hits=2)

    if not results:
        print("no matches:", " ".join(terms))
        print("try playbook terms: bola, idor, jwt, otp, pbkdf2, firebase, s3, minio, keycloak, lmtp, takeover, signature, capability matrix, lateral, honeypot, push, fcm, sprint")
        return 1

    current = None
    for tag, line in results[:40]:
        if tag != current:
            print(f"\n{tag}")
            current = tag
        print(line)
    print(f"\n{len(results)} hits. knowledge: {KNOW}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
