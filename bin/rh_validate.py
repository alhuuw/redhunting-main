#!/usr/bin/env python3
"""rh_validate: the verify gate as code. Exit 0 = verified and ready for materials.

Eleven questions, mechanically checkable where possible. Q11 (limitations) is the REA-pattern gate: an evidence-backed claim must also name what it does NOT establish. The verification bar:
claims are proven or deleted, severity matches demonstrated evidence, the
operator can self-verify, lows chain, and hedging words do not exist anywhere.
"""
import argparse
import importlib.util
import re
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent

BANNED = ("potential", "candidate", "likely", "possibly", "theoretical", "could", "maybe", "appears", "seems", "might")
AUTH_CLASSES = ("idor", "bola", "authz", "authorization", "auth-bypass", "ato", "session", "auth")
NEVER_SUBMIT = [
    (re.compile(r"self[\s-]?xss", re.I), "self-XSS is a universal rejection"),
    (re.compile(r"clickjacking(?!.*(?:session|token|impact))", re.I), "clickjacking without demonstrated impact"),
    (re.compile(r"missing (?:csp|header|security header)", re.I), "missing headers are informational"),
    (re.compile(r"(?:version|banner) (?:disclosure|leak)", re.I), "version disclosure is informational"),
    (re.compile(r"verbose error", re.I), "verbose errors alone are informational"),
]
SEVERITY_EVIDENCE = [
    (re.compile(r"\brce\b|remote code execution|command (?:injection|execution)", re.I),
     r"command (?:output|execution proof)|uid=\d+|whoami|/bin/(?:sh|bash)|exec\(|stdout|marker file|read.?back",
     "RCE claim needs captured command-execution output (id/whoami or a marker file written and read back) in the evidence"),
    (re.compile(r"takeover|ato|account takeover", re.I),
     r"takeover|controlled (?:the|victim|target) account|password (?:changed|reset) proof|login as victim|account control|recovery (?:email|password) changed",
     "takeover claim needs demonstrated control of the owned victim-test account"),
    (re.compile(r"\bxss\b|cross site scripting", re.I),
     r"execut(?:ed|ion)|alert\(|console\.|screenshot|onerror|javascript:|browser (?:executed|verified)",
     "XSS claim needs browser-executed proof, not a reflected string"),
    (re.compile(r"\bsqli\b|sql injection", re.I),
     r"SLEEP\(|pg_sleep|time(?:d)? (?:differential|delay)|data (?:extract|leak)|boolean differential",
     "SQLi claim needs a time/boolean/error differential vs control"),
    (re.compile(r"ssrf", re.I),
     r"callback|interact|collaborator|oob|169\.254|metadata|instance-id|internal (?:host|reach)",
     "SSRF claim needs callback capture or a metadata/internal response"),
    (re.compile(r"race|double spend|concurrent", re.I),
     r"sequential|concurrent|burst|N successes|balance delta|final state",
     "race claim needs the sequential control vs concurrent run comparison"),
    (re.compile(r"lateral|replay", re.I),
     r"lateral|replay|accepted by|sibling|cross-service",
     "lateral claim needs the replay transcript showing which services accepted the credential"),
]
SECTIONS = ("Summary", "Impact", "Reproduce", "Root cause", "Fix", "Self-Verify")


def parse_summary(text: str):
    fm = {}
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    body = text
    if m:
        body = text[m.end():]
        for line in m.group(1).splitlines():
            mm = re.match(r"^(\w[\w-]*):\s*(.*)$", line)
            if mm:
                fm[mm.group(1)] = mm.group(2).strip().strip('"').strip("'")
    sections = {}
    for name in SECTIONS:
        sm = re.search(rf"^##\s+{re.escape(name)}\s*\n(.*?)(?=^##\s|\Z)", body, re.S | re.M)
        sections[name] = sm.group(1).strip() if sm else ""
    return fm, sections, body


def hosts_from_summary(fm, sections):
    hosts = set()
    for url in re.findall(r"https?://([^/\s'\")]++)", " ".join([fm.get("url", "")] + [sections.get(s, "") for s in SECTIONS])):
        host = url.lower().rstrip(".").split(":")[0]
        hosts.add(host)
    return hosts


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify gate: exit 0 = ready for materials")
    ap.add_argument("target")
    ap.add_argument("summary", help="path to the finding's SUMMARY.md")
    args = ap.parse_args()

    fpath = Path(args.summary)
    if not fpath.exists():
        print(f"[fatal] summary not found: {fpath}")
        return 2
    fm, sections, body = parse_summary(fpath.read_text())

    results = []

    def gate(name, ok, detail=""):
        results.append((name, ok, detail))

    poc_text = sections.get("Reproduce", "") + sections.get("Self-Verify", "")
    has_request = bool(re.search(r"(curl |nc |http\.|fetch\(|GET |POST |PUT |PATCH |DELETE )\S+", poc_text, re.I))
    has_response = bool(re.search(r"HTTP/[\d.]+\s+\d{3}|Status(?:\s+code)?:\s*\d{3}", poc_text, re.I))
    raw_dir = fpath.parent / "evidence" / "raw"
    has_raw_transcripts = raw_dir.exists() and any(p.stat().st_size > 0 for p in raw_dir.glob("*") if p.is_file())
    gate("Q1 real request+response", has_request and (has_response or has_raw_transcripts),
         "Reproduce must contain the request as sent AND the response as received (inline status line or non-empty evidence/raw transcripts)")

    spec = importlib.util.spec_from_file_location("rh_scope", SKILL_DIR / "bin" / "rh_scope.py")
    rh_scope = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rh_scope)
    try:
        target = rh_scope.load_target(args.target)
        bad_hosts = []
        for h in sorted(hosts_from_summary(fm, sections)):
            verdict, _ = rh_scope.check(target, h)
            if verdict != "in":
                bad_hosts.append(f"{h} ({verdict})")
        gate("Q2 in-scope", not bad_hosts, "; ".join(bad_hosts) if bad_hosts else "")
    except SystemExit:
        gate("Q2 in-scope", False, "target.json missing (run rh_init)")

    impact = sections.get("Impact", "")
    has_numbers = bool(re.search(r"\d", impact))
    gate("Q3 impact quantified", len(re.sub(r"[-*`\s]", "", impact)) >= 20 and has_numbers,
         "Impact must carry measured numbers (record count, PII %, freshness, scale) with at least one real digit")
    hits = [w for w in BANNED if re.search(rf"\b{w}\b", body, re.I)]
    gate("Q3 hedging words absent", not hits, f"hedging words present: {', '.join(hits)}" if hits else "")

    vclass = (fm.get("class") or "").lower()
    title = fm.get("title", "") or ""
    claim_text = f"{title} {sections.get('Summary', '')} {sections.get('Reproduce', '')}"
    is_unauth_claim = bool(re.search(r"unauthenticated|no account|without (?:any )?(?:auth|credential|account)|no credentials|pre-?auth", claim_text, re.I))
    if any(a in vclass for a in AUTH_CLASSES):
        id_text = " ".join(str(p.name) for p in (fpath.parent / "evidence" / "raw").glob("*")) if (fpath.parent / "evidence" / "raw").exists() else ""
        id_text += sections.get("Reproduce", "")
        ok = bool(re.search(r"(session a|account a|account b|second account|two accounts|victim account|differential)", id_text, re.I))
        gate("Q4 identity check (two accounts)", ok or is_unauth_claim,
             "auth classes need the A-vs-B differential: self-observed access proves nothing about other users "
             "(unauthenticated claims satisfy it via the no-credential control)")
    else:
        gate("Q4 identity check", True, "(not an auth class)")

    steps = sections.get("Reproduce", "")
    gate("Q5 numbered repro steps", bool(re.search(r"^\s*1[\.\)]", steps, re.M)), "Steps must be numbered and copy-pasteable")
    ctrl_names = " ".join(str(p.name) for p in (fpath.parent / "evidence" / "raw").glob("*")) if (fpath.parent / "evidence" / "raw").exists() else ""
    gate("Q5 negative control", bool(re.search(r"control|garbage|negative|retest", ctrl_names, re.I)),
         "evidence/raw must contain the negative control and/or retest files (same capture run)")

    ver = fpath.parent / "VERIFICATION.md"
    ver_ok = False
    ver_detail = "VERIFICATION.md missing (scaffolded by rh_ledger add)"
    if ver.exists():
        vtext = ver.read_text()
        closed = len(re.findall(r"\| VERIFIED \|", vtext))
        open_rows = len(re.findall(r"^\| C\d+ \|.+\|\s*\|", vtext, re.M))
        ver_ok = closed >= 1 and open_rows == 0
        ver_detail = f"{closed} claims VERIFIED, {open_rows} rows still open (every claim row must close before the summary ships)"
    gate("Q6 verification rows closed", ver_ok, ver_detail)

    t_and_c = f"{title} {vclass}"
    ns_hit = next((msg for rx, msg in NEVER_SUBMIT if rx.search(t_and_c)), None)
    gate("Q7 never-submit list", ns_hit is None, ns_hit or "")

    sev_claim = f"{title} {vclass} {fm.get('severity', '')}"
    sev_detail = ""
    sev_ok = True
    for rx, need, msg in SEVERITY_EVIDENCE:
        if rx.search(sev_claim):
            if not re.search(need, poc_text, re.I):
                sev_ok = False
                sev_detail = msg
            break
    gate("Q8 severity-evidence match", sev_ok, sev_detail or "severity claims ship only with matching demonstrated evidence")

    sv = sections.get("Self-Verify", "")
    has_verify_cmd = bool(re.search(r"(curl |adb |open |browser|navigate|http)", sv, re.I))
    gate("Q9 self-verify snippet", has_verify_cmd,
         "every finding ships a Self-Verify block the operator runs themselves (generate: bin/rh_verify.py snippet)")

    has_chain = bool(re.search(r"chain|lateral|enables\b", body, re.I))
    if (fm.get("severity") or "").lower() in ("low", "medium", "info", "informational"):
        gate("Q10 chain matrix (low/med must chain)", has_chain,
             "unchained lows do not ship: chain it or vault it (knowledge/chains.md)")
    else:
        gate("Q10 chain matrix", True, "(high/critical: the ladder still runs after materials)")
    lim = re.search(r"(?im)^#+\s*limitations?\b|^limitations?:", body)
    amb = re.search(r"(?i)\b(unverified|not resolved|could not resolve|not establish|bounded-with-unknown|unknown cause)\b", body)
    gate("Q11 limitations stated or explicitly none", bool(lim) or bool(amb),
         "add a Limitations section (what this claim does NOT establish) or state the bounded-unknown explicitly")

    failed = [r for r in results if not r[1]]
    print(f"verify gate: {fpath}")
    for name, ok, detail in results:
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {name}"
        if detail:
            line += f" - {detail}"
        print(line)
    if failed:
        print(f"[gate] NOT READY - {len(failed)} gate(s) failed. Fix the finding, not the gate. Claims that cannot close get deleted, not softened.")
        return 1
    print("[gate] VERIFIED - build the material pack (rh_materials.py), the operator writes the report. Keep chaining.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
