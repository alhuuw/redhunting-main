#!/usr/bin/env python3
"""slice_playbook: one-time splitter that turns knowledge/playbook.md into
knowledge/classes/<slug>/SKILL.md (one folder per vuln class, frontmatter valid)
and rewrites playbook.md as the router index.

Re-runnable: reads the CURRENT playbook.md. When playbook.md is already a router
(class-less), the script exits 1 without touching anything. Content is moved, never
rewritten: each class SKILL.md is byte-identical to its source section plus frontmatter.
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
KNOW = HERE / "knowledge"
PLAYBOOK = KNOW / "playbook.md"
CLASSES = KNOW / "classes"

CLASS_HEADING = re.compile(r"^## (\d+)\. (.+?)\s*$", re.M)

SLUGS = {
    1: "hardcoded-secrets", 2: "idor-bola", 3: "ato-chains", 4: "oauth-jwt-saml",
    5: "client-crypto-signing", 6: "race-conditions", 7: "ssrf", 8: "subdomain-takeover",
    9: "enumeration-oracles", 10: "xss-dom", 11: "mobile-classes", 12: "cloud-storage",
    13: "injection", 14: "frontend-bundle-mining", 15: "business-logic",
    16: "firebase-remote-config", 17: "jenkins-cli", 18: "dev-box-services",
    19: "firebase-rtdb-paths", 20: "graphql", 21: "infra-exposure",
    22: "tenant-takeover", 23: "api-cache-buckets", 24: "client-aes-morgan",
    25: "no-arg-cursor", 26: "cloud-vendor-consoles",
}

CHEATSHEET_PAIRS = {
    1: "secrets-recovery.md", 2: "http.md", 3: "jwt-oauth.md", 4: "jwt-oauth.md",
    5: "crypto-replica.md", 6: "race-logic.md", 7: "http.md", 8: "target-recon.md",
    9: "http.md", 10: "payloads.md", 11: "adb-frida.md", 12: "cloud-storage.md",
    13: "injection.md", 14: "payloads.md", 15: "race-logic.md", 16: "firebase.md",
    17: "http.md", 18: "http.md", 19: "firebase.md", 20: "graphql.md",
    21: "http.md", 22: "payloads.md", 23: "cloud-storage.md", 24: "crypto-replica.md",
    25: "graphql.md", 26: "secrets-recovery.md",
}


def slug_title(n, title):
    slug = SLUGS.get(n)
    if not slug:
        sys.exit(f"[fatal] unmapped class number {n}: {title}")
    return slug


def main() -> int:
    text = PLAYBOOK.read_text()
    headings = list(CLASS_HEADING.finditer(text))
    if not headings:
        print("[slice] playbook.md is already a router (no class sections); nothing to do")
        return 1

    head = text[:headings[0].start()].rstrip() + "\n"
    tail_start = None
    for m in headings:
        nxt = text.find("\n## ", m.end())
    tail_idx = text.find("\n## Anti-patterns")
    tail = text[tail_idx:] if tail_idx != -1 else ""

    classes_dir = KNOW / "classes"
    classes_dir.mkdir(exist_ok=True)
    rows = []
    moved = 0
    for i, m in enumerate(headings):
        n, title = int(m.group(1)), m.group(2).strip()
        slug = slug_title(n, title)
        start = m.start()
        end = headings[i + 1].start() if i + 1 < len(headings) else (tail_idx if tail_idx != -1 else len(text))
        body = text[start:end].rstrip() + "\n"
        desc = title.split("(")[0].strip().rstrip(":")
        front = (
            "---\n"
            f"name: rh-class-{slug}\n"
            f"description: >-\n"
            f"  Class {n} of the redhunting attack playbook: {desc}. Loaded by the Confirm\n"
            f"  phase when the lead board routes a lead of this class. Pair it with the\n"
            f"  command-level depth in cheatsheets/{CHEATSHEET_PAIRS[n]} and close every\n"
            f"  claim through the verification ladders in verification.md.\n"
            f"triggers: {slug.replace('-', ' ')}\n"
            "---\n\n"
        )
        cdir = classes_dir / slug
        cdir.mkdir(exist_ok=True)
        (cdir / "SKILL.md").write_text(front + body)
        moved += len(body.splitlines())
        rows.append((n, slug, title))

    router = ["# Playbook: Class Router (26 classes, one folder each)", "",
              "The classes live in knowledge/classes/<slug>/SKILL.md, one folder per vuln class",
              "(the unit-load pattern: the Confirm phase reads ONLY the class it is working).",
              "This file is the router: class -> file -> signal -> its cheatsheet pair.",
              "Cross-class doctrine stays here: the proof-gate line, anti-patterns, and the",
              "never-submit list.", ""]
    router.append("| # | Class | File | First signal | Cheatsheet pair |")
    router.append("|---|-------|------|---------------|-----------------|")
    for n, slug, title in rows:
        sig = re.sub(r"^\d+\.\s*", "", title).split("(")[0].strip().rstrip(":")
        router.append(f"| {n} | {sig} | knowledge/classes/{slug}/SKILL.md | see class | cheatsheets/{CHEATSHEET_PAIRS[n]} |")
    router += ["",
               "Routing rule: the lead board's skill field names the class (playbook:N-<slug>);",
               "rh_recall indexes every class file by keyword; the Confirm phase opens exactly",
               "one class file, runs its workflow, closes its claims in VERIFICATION.md.", ""]
    router.append(head.split("---\n")[-1].strip())
    router.append("")
    router.append(tail.strip())
    router.append("")
    PLAYBOOK.write_text("\n".join(router))
    print(f"[slice] {len(rows)} classes written under {classes_dir} ({moved} lines moved)")
    print(f"[slice] playbook.md rewritten as router + cross-class doctrine")
    return 0


if __name__ == "__main__":
    sys.exit(main())
