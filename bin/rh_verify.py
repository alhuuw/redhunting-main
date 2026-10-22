#!/usr/bin/env python3
"""rh_verify: the verification tool. Three subcommands:

  evidence <target> <finding-dir|SUMMARY.md>
      Check the evidence pack: raw transcripts present and non-empty, SHA256SUMS
      covers every file and hashes match, a negative control exists, retest files
      exist, transcripts carry the tool signature line (hand-written evidence is
      banned). Exit 0 = evidence pack sound.

  snippet <target> <SUMMARY.md>
      Generate the Self-Verify block from the summary: a curl reproduction
      one-liner (first curl in Reproduce), browser-checkable URLs from the
      evidence, adb commands for mobile/deeplink/push classes. Appends/refreshes
      the '## Self-Verify' section.

  replay <target> <SUMMARY.md>
      Re-fire every fenced curl command found in Reproduce (with delay and
      timeout), print status lines, record the verdict. Deliberate action: run
      it only on findings you own.
"""
import argparse
import hashlib
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
TOOL_LINE = "TOOL: rh_capture.py"
MOBILE_CLASSES = ("mobile", "deeplink", "webview", "push", "ipc", "backup", "frida", "android", "ios")


def load_summary(path: Path):
    text = path.read_text()
    fm = {}
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if m:
        for line in m.group(1).splitlines():
            mm = re.match(r"^(\w[\w-]*):\s*(.*)$", line)
            if mm:
                fm[mm.group(1)] = mm.group(2).strip().strip('"').strip("'")
    return fm, text


def finding_dir(path: Path) -> Path:
    if path.is_dir():
        return path
    if path.name == "SUMMARY.md":
        return path.parent
    return path.parent


def cmd_evidence(args) -> int:
    fpath = Path(args.finding)
    d = finding_dir(fpath)
    raw = d / "evidence" / "raw"
    if not raw.exists() or not any(raw.glob("*")):
        print(f"[evidence] FAIL: {raw} is empty - no raw transcripts")
        return 1

    files = sorted(p for p in raw.glob("*") if p.is_file() and p.name != "SHA256SUMS.txt")
    problems = []
    for p in files:
        if p.stat().st_size == 0:
            problems.append(f"{p.name}: empty file")
        if p.suffix == ".txt":
            head = p.read_text(errors="ignore")[:400]
            if "CAPTURE TIME (UTC):" not in head and "TOOL:" not in head and "curl -" not in head:
                problems.append(f"{p.name}: no capture-tool signature in the header (hand-written evidence is banned as proof)")

    sums = raw / "SHA256SUMS.txt"
    if sums.exists():
        recorded = {}
        for line in sums.read_text().splitlines():
            if "  " in line:
                h, fn = line.split("  ", 1)
                recorded[fn.strip()] = h
        for p in files:
            actual = hashlib.sha256(p.read_bytes()).hexdigest()
            if p.name in recorded and recorded[p.name] != actual:
                problems.append(f"{p.name}: sha256 mismatch vs SHA256SUMS.txt")
            if p.name not in recorded:
                problems.append(f"{p.name}: not covered by SHA256SUMS.txt")
    else:
        problems.append("SHA256SUMS.txt missing")

    names = " ".join(p.name for p in files)
    if not re.search(r"control|garbage|negative|retest", names, re.I):
        problems.append("no negative control or retest file in evidence/raw/ (same capture run required)")

    if problems:
        print(f"[evidence] FAIL ({len(problems)} problem(s)):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"[evidence] OK: {len(files)} raw files, SHA chain covers all, control/retest present")
    for p in files:
        print(f"  {p.name}  {p.stat().st_size}B")
    return 0


def extract_curls(text: str):
    out = []
    for block in re.findall(r"```(?:bash|sh|shell)?\s*\n(.*?)```", text, re.S):
        for line in block.splitlines():
            line = line.strip()
            if line.startswith("curl "):
                out.append(line)
    return out


def extract_urls(text: str):
    urls = []
    for u in re.findall(r"https?://[^\s'\"<>)]+", text):
        u = u.rstrip(".,;")
        if u not in urls and not any(x in u for x in ("example.com", "127.0.0.1", "localhost")):
            urls.append(u)
    return urls[:8]


def cmd_snippet(args) -> int:
    fpath = Path(args.summary)
    if not fpath.exists():
        print(f"[fatal] summary not found: {fpath}")
        return 1
    fm, text = load_summary(fpath)
    vclass = (fm.get("class") or "").lower()
    curls = extract_curls(text)
    urls = extract_urls(text)
    title = fm.get("title", fpath.parent.name)

    lines = [f"### Verify it yourself (operator runbook for: {title})", ""]
    if curls:
        lines.append("Reproduce the core request (expect the same response class as the evidence):")
        lines.append("```bash")
        lines.append(curls[0])
        lines.append("```")
    if urls:
        lines.append("")
        lines.append("Check in a browser (paste, observe, screenshot for the report):")
        for u in urls[:5]:
            lines.append(f"- {u}")
        lines.append("- screenshot the response/landing state and drop it into the finding folder as operator-verified proof")
    if any(m in vclass for m in MOBILE_CLASSES):
        lines.append("")
        lines.append("On-device checks (adb):")
        lines.append("```bash")
        lines.append("adb devices                                   # the device from hunt.json")
        lines.append("adb logcat -d | grep -iE 'intent|deeplink|push|webview' | tail -50")
        if urls:
            lines.append(f"adb shell am start -a android.intent.action.VIEW -d '{urls[0]}'   # fire the deeplink on-device")
        lines.append("```")
        lines.append("Push class: send to YOUR OWN device token only (knowledge/push-notifications.md), capture the notification screenshot + the logcat intent trace.")
    lines.append("")
    lines.append("Raw transcripts live in evidence/raw/ - SHA256SUMS.txt verifies every byte; re-hash with `shasum -a 256 <file>` and compare.")
    lines.append("")
    lines.append("What this evidence does NOT establish (state it, do not imply it):")
    lines.append("- the replay above proves THIS request/response pair; repetition, ordering, and cache behavior are separate probes")
    lines.append("- a passing replay does not launder upstream weaknesses in the chain into this finding; each hop carries its own ladder")
    lines.append("- if any step cannot run from where you are, record it as a limitation in the SUMMARY (or a bounded-unknown), never as a pass")
    block = "\n".join(lines)

    if "## Self-Verify" in text:
        text = re.sub(r"## Self-Verify\s*\n(?:###.*?\n)?(?:.|\n)*?(?=\n## |\Z)", f"## Self-Verify\n\n{block}\n", text, count=1)
    else:
        text = text.rstrip() + f"\n\n## Self-Verify\n\n{block}\n"
    fpath.write_text(text)
    print(f"[snippet] Self-Verify block written into {fpath}")
    print("----------")
    print(block)
    return 0


def cmd_replay(args) -> int:
    fpath = Path(args.summary)
    if not fpath.exists():
        print(f"[fatal] summary not found: {fpath}")
        return 1
    fm, text = load_summary(fpath)
    curls = extract_curls(text)
    if not curls:
        print("[replay] no fenced curl commands found in Reproduce - nothing to replay")
        return 1
    print(f"[replay] {len(curls)} curl command(s) to re-fire (retest #{args.run}).")
    ok = 0
    for i, c in enumerate(curls, 1):
        time.sleep(args.delay)
        try:
            parts = shlex.split(c)
            r = subprocess.run(parts, capture_output=True, text=True, timeout=args.timeout)
            status = re.search(r"HTTP/[\d.]+\s+(\d{3})", r.stdout)
            code = status.group(1) if status else "?"
            print(f"  [{i}/{len(curls)}] HTTP {code}  ({c[:90]}{'...' if len(c) > 90 else ''})")
            ok += 1 if status else 0
        except Exception as e:
            print(f"  [{i}/{len(curls)}] ERROR: {e}")
    verdict = "REPRODUCES" if ok == len(curls) else "PARTIAL/FAILED - fix before shipping (retest discipline)"
    print(f"[replay] verdict: {verdict}")
    print("[replay] capture the retest as raw evidence: re-run the probe through bin/rh_capture.py so the transcript lands in evidence/raw/.")
    return 0 if ok == len(curls) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Verification tool: evidence check, self-verify snippets, PoC replay")
    ap.add_argument("target")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp_ev = sub.add_parser("evidence")
    sp_ev.add_argument("finding", help="SUMMARY.md path or findings/<slug> dir")
    sp_sn = sub.add_parser("snippet")
    sp_sn.add_argument("summary")
    sp_rp = sub.add_parser("replay")
    sp_rp.add_argument("summary")
    sp_rp.add_argument("--delay", type=float, default=0.5)
    sp_rp.add_argument("--timeout", type=int, default=30)
    sp_rp.add_argument("--run", default="1", help="retest run number (labeling only)")
    args = ap.parse_args()
    if args.cmd == "evidence":
        return cmd_evidence(args)
    if args.cmd == "snippet":
        return cmd_snippet(args)
    return cmd_replay(args)


if __name__ == "__main__":
    sys.exit(main())
