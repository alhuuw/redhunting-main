#!/usr/bin/env python3
"""rh_materials: build the report MATERIAL PACK from a finding folder.

The agent never writes the final report and never submits anything. This tool
assembles what the operator needs to write it by hand: the evidence index
(every raw transcript with its SHA), the timeline from capture timestamps, the
command log from the SUMMARY's reproduce steps, and the impact numbers when a
parsed body is available. Missing pieces render as explicit TODO markers -
content is never invented.
"""
import argparse
import re
import sys
from pathlib import Path

SECTIONS = ("Summary", "Impact", "Reproduce", "Root cause", "Fix", "Self-Verify")


def load_summary(path: Path):
    text = path.read_text()
    fm = {}
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    body = text
    if m:
        body = text[m.end():]
        for line in m.group(1).splitlines():
            mm = re.match(r"^(\w[\w-]*):\s*(.*)$", line)
            if mm:
                fm[mm.group(1)] = mm.group(2).strip().strip('"').strip("'")
    return fm, body


def evidence_index(fdir: Path):
    raw = fdir / "evidence" / "raw"
    rows = []
    if raw.exists():
        for p in sorted(raw.glob("*")):
            if p.is_file() and p.name != "SHA256SUMS.txt":
                head = p.read_text(errors="ignore")[:600]
                req = re.search(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (\S+)", head, re.M)
                status = re.search(r"HTTP/[\d.]+\s+(\d{3})", head)
                note = re.search(r"^NOTE: (.+)$", head, re.M)
                what = (note.group(1) if note else "") or (req.group(1) if req else "")
                rows.append((p.name, p.stat().st_size, status.group(1) if status else "-", what[:90]))
    return rows


def timeline(fdir: Path):
    raw = fdir / "evidence" / "raw"
    stamps = []
    if raw.exists():
        for p in sorted(raw.glob("*.txt")):
            m = re.search(r"CAPTURE TIME \(UTC\): (\S+)", p.read_text(errors="ignore")[:300])
            if m:
                stamps.append((m.group(1), p.name))
    return sorted(stamps)


def extract_commands(body: str):
    cmds = []
    for block in re.findall(r"```(?:bash|sh|shell)?\s*\n(.*?)```", body, re.S):
        for line in block.splitlines():
            line = line.strip()
            if line.startswith("curl "):
                cmds.append(line)
    return cmds


def main() -> int:
    ap = argparse.ArgumentParser(description="Material pack builder (the report is written by the operator)")
    ap.add_argument("target")
    ap.add_argument("summary", help="path to the finding's SUMMARY.md")
    args = ap.parse_args()

    spath = Path(args.summary)
    if not spath.exists():
        print(f"[fatal] summary not found: {spath}")
        return 1
    fdir = spath.parent if spath.name == "SUMMARY.md" else spath.parent
    fm, body = load_summary(spath)
    fm.setdefault("title", fdir.name)

    lines = [f"# materials: {fm.get('title')}", "",
             "Report materials for the OPERATOR. The agent never writes the final report; write it yourself from this pack.", ""]

    rows = evidence_index(fdir)
    if rows:
        lines += ["## Evidence index", "", "| File | Size | HTTP | What it captures |", "|---|---|---|---|"]
        for name, size, status, what in rows:
            lines.append(f"| evidence/raw/{name} | {size}B | {status} | {what or '(see transcript)'} |")
        sums = fdir / "evidence" / "raw" / "SHA256SUMS.txt"
        if sums.exists():
            lines.append(f"| evidence/raw/SHA256SUMS.txt | {sums.stat().st_size}B | - | integrity chain over every raw file |")
        lines.append("")
    else:
        lines += ["## Evidence index", "", "TODO: no raw transcripts in evidence/raw/ (capture via rh_capture.py first)", ""]

    stamps = timeline(fdir)
    lines += ["## Timeline (UTC)", ""]
    if stamps:
        for ts, name in stamps:
            lines.append(f"- {ts}  {name}")
    else:
        lines.append("- TODO: no capture timestamps found")
    lines.append("")

    impact = re.search(r"^## Impact.*?\n(.*?)(?=^## )", body, re.S | re.M)
    lines += ["## Impact numbers", ""]
    if impact and re.search(r"\d", impact.group(1)):
        lines.append(impact.group(1).strip())
    else:
        lines.append("TODO: run rh_impact.py on the captured body and paste the measured numbers here")
    lines.append("")

    cmds = extract_commands(body)
    lines += ["## Command log (copy-paste reproduction)", "", "```bash"]
    if cmds:
        for i, c in enumerate(cmds, 1):
            lines.append(f"# {i}")
            lines.append(c)
    else:
        lines.append("# TODO: add the reproduce commands to SUMMARY.md first")
    lines += ["```", ""]

    lines += ["## Chain context", "",
              "TODO: chain matrix row, lateral map, and the deliberate boundary (what was NOT executed and why)", "",
              "## Novelty notes", "",
              "TODO: closest prior art and the delta (operator confirms before writing)", "",
              "## Writing notes", "",
              "TODO: emphasis, ordering, the questions a reader will ask first", ""]

    out = fdir / "materials.md"
    out.write_text("\n".join(lines) + "\n")
    print(f"[materials] pack built -> {out}")
    print("[materials] TODO markers are yours: the tool never invents content. You write the report.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
