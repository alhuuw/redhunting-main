#!/usr/bin/env python3
"""rh_leadboard: the attention-persistence system (adapted from the agentic
lead-board pattern: every recon signal becomes a ranked, never-lost work item).

A hunt surfaces hundreds of signals, you hyperfocus on ONE, and someone else
gets there first. The board is the fix: ingest everything, rank it, never
reset work state on re-ingest (upsert on skill+evidence), warn on stale
high-priority leads. Deleting leads is not a feature.

Commands:
  rh_leadboard.py <target> ingest <file|->        classify lines into leads
  rh_leadboard.py <target> show [--stale-days N]  ranked board + stale warnings
  rh_leadboard.py <target> next                   print the top unworked lead
  rh_leadboard.py <target> touch <id> --status X [--reason ...]
"""
import argparse
import datetime
import json
import re
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent

P_HIGH, P_MED, P_LOW = "high", "med", "low"
STATUSES = ("new", "investigating", "killed", "reported", "parked")

# (regex, skill, priority, signal, why) - first match per ROUTE per line; a
# line can produce multiple leads (one per matching route), upsert-deduped.
ROUTES = [
    (re.compile(r"[?&](url|uri|dest|destination|redirect|return|return_to|next|callback|fetch|load|proxy|page|target|u|link)=", re.I),
     "playbook:7-ssrf", P_HIGH, "URL-valued param", "server may fetch attacker URL -> SSRF/redirect/IMDS"),
    (re.compile(r"[?&](id|uid|user_id|userid|account|account_id|order|order_id|invoice|doc|document|ref|trx|transaction|booking|reservation)=", re.I),
     "playbook:1-idor", P_HIGH, "object reference param", "swap identifiers for IDOR/BOLA (identity check: two accounts)"),
    (re.compile(r"[?&](token|access_token|code|state|session|sid|jwt)=ey", re.I),
     "playbook:4-jwt", P_HIGH, "token in URL", "leakage via referrer/history + claim analysis"),
    (re.compile(r"/(oauth|authorize|auth)(/|\?|$)", re.I),
     "playbook:4-oauth", P_HIGH, "OAuth flow", "redirect_uri ladder, state, code interception chains"),
    (re.compile(r"/(graphql|gql|query)(/|\?|$)", re.I),
     "playbook:graphql", P_HIGH, "GraphQL endpoint", "introspection/error-oracle schema + mutation authz"),
    (re.compile(r"/api/v?(\d+)", re.I),
     "playbook:api-versions", P_MED, "versioned API tier", "sweep every vN: auth middleware wired to old version only is a recurring regression"),
    (re.compile(r"/(admin|internal|backoffice|dashboard|automation|debug|console|jenkins|actuator|eureka|\.env|config)(/|\.|$)", re.I),
     "playbook:hidden-surface", P_HIGH, "internal/debug path", "auth-matrix probe: no token / garbage / app fingerprint"),
    (re.compile(r"(firebase|firestore|firebaseio|googleapis)", re.I),
     "playbook:5-firebase", P_HIGH, "Firebase", "RC fetch (default-open vault), path-scoped rules, SSE listeners"),
    (re.compile(r"(s3\.amazonaws|storage\.googleapis|r2\.cloudflarestorage|minio|\.blob\.core|digitaloceanspaces)", re.I),
     "playbook:12-cloud", P_HIGH, "object storage", "anonymous listing, recency check, upload/poisoning path"),
    (re.compile(r"(herokuapp|github\.io|fastly|pantheon|zendesk|shopify|intercom|myshopify|readme\.io|cargo|webflow)", re.I),
     "playbook:8-takeover", P_MED, "takeover-prone host", "dangling CNAME claimability + parent-domain trust chain"),
    (re.compile(r"(login|signin|signin|password|forgot|reset|register|signup|verify|otp|2fa|mfa)", re.I),
     "playbook:3-ato", P_HIGH, "auth surface", "differentials, reset-token hygiene, OTP send/verify split"),
    (re.compile(r"(upload|file|attachment|import|export|download|media|avatar|image)", re.I),
     "playbook:upload", P_MED, "file handling path", "content-type/MIME confusion, stored-content serving context"),
    (re.compile(r"(webhook|callback|notify|ping|hook|subscribe)", re.I),
     "playbook:7-ssrf", P_MED, "webhook/callback", "SSRF callback proof via OOB listener"),
    (re.compile(r"(checkout|payment|pay|billing|cart|coupon|voucher|discount|refund|withdraw|balance|credit|wallet|point)", re.I),
     "playbook:2-business-logic", P_HIGH, "money surface", "step-skip/repeat, negative/zero, unit swap, race"),
    (re.compile(r"\.(map|js)(\?|$)", re.I),
     "playbook:14-bundle", P_MED, "JS/source map asset", "corpus mining: API bases, leftover test components, secrets"),
    (re.compile(r"(graphql|__schema|__type)", re.I),
     "playbook:graphql", P_MED, "GraphQL artifact", "error-oracle reconstruction on introspection-blocked"),
    (re.compile(r"(AIza[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.|BEGIN (RSA |EC )?PRIVATE KEY|client_secret)", re.I),
     "playbook:5-secrets", P_HIGH, "secret-looking string", "capability matrix + lateral replay"),
    (re.compile(r"(swagger|openapi|api-docs|rapidoc|redoc|graphiql|altair)", re.I),
     "playbook:api-docs", P_MED, "API docs surface", "full endpoint inventory for the auth matrix"),
    (re.compile(r":\d{4,5}\b"), "playbook:infra", P_MED, "non-standard port", "banner-grab, fingerprint, CVE triage, protocol proof"),
    (re.compile(r"(staging|stag|dev|test|uat|preprod|qa)[\.\-]", re.I),
     "playbook:env-replication", P_MED, "non-prod host", "enforcement often exists on exactly one layer; diff vs prod"),
    (re.compile(r"(websocket|wss?://|socket\.io|event-stream|text/event-stream|\bsse\b)", re.I),
     "playbook:websockets", P_MED, "streaming surface", "unauth listeners, live-channel data beats staleness arguments"),
]

RANK = {P_HIGH: 0, P_MED: 1, P_LOW: 2}
STATUS_RANK = {"new": 0, "investigating": 1, "parked": 2, "reported": 3, "killed": 4}


def board_path(slug: str) -> Path:
    cfg = json.loads((SKILL_DIR / "config.json").read_text())
    import os
    env_key = cfg.get("workspace", {}).get("env_override", "RH_HOME")
    root = (os.environ.get(env_key) if env_key else None) or cfg.get("workspace", {}).get("root", "./")
    base = Path.cwd() if root in (".", "./") else Path(os.path.expanduser(root))
    return base / slug / "leads.jsonl"


def load_leads(p: Path):
    leads = []
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line:
                leads.append(json.loads(line))
    return leads


def save_leads(p: Path, leads):
    p.write_text("".join(json.dumps(l, ensure_ascii=False) + "\n" for l in leads))


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify_line(line: str):
    """Yield one lead dict per matching route for one input line."""
    line = line.strip()
    if not line or line.startswith("#"):
        return
    out = []
    for rx, skill, prio, signal, why in ROUTES:
        if rx.search(line):
            out.append({
                "skill": skill, "priority": prio, "signal": signal, "why": why,
                "evidence": line[:300], "status": "new", "reason": "",
            })
    if not out:
        out.append({
            "skill": "triage-manual", "priority": P_LOW, "signal": "unclassified signal",
            "why": "no route matched; manual triage before it rots",
            "evidence": line[:300], "status": "new", "reason": "",
        })
    return out


def cmd_ingest(slug: str, source: str) -> int:
    p = board_path(slug)
    leads = load_leads(p)
    index = {(l.get("skill"), l.get("evidence")): l for l in leads}
    next_id = max((int(l["id"].split("-")[1]) for l in leads if re.match(r"^L-\d+$", str(l.get("id")))), default=0) + 1

    if source == "-":
        lines = sys.stdin.read().splitlines()
    else:
        src = Path(source)
        if not src.exists():
            print(f"[fatal] input file not found: {src}")
            return 1
        lines = src.read_text().splitlines()

    added = updated = 0
    for line in lines:
        new_leads = classify_line(line)
        if not new_leads:
            continue
        for nl in new_leads:
            key = (nl["skill"], nl["evidence"])
            if key in index:
                existing = index[key]
                if RANK[nl["priority"]] < RANK[existing.get("priority", P_LOW)]:
                    existing["priority"] = nl["priority"]
                updated += 1
            else:
                nl["id"] = f"L-{next_id:04d}"
                nl["created"] = now_iso()
                nl["touched"] = nl["created"]
                leads.append(nl)
                index[key] = nl
                next_id += 1
                added += 1

    save_leads(p, leads)
    print(f"[ingest] {added} new leads, {updated} re-seen (status never reset), board: {len(leads)} total")
    return 0


def cmd_show(slug: str, stale_days: int) -> int:
    p = board_path(slug)
    leads = load_leads(p)
    if not leads:
        print("[board] empty (ingest recon output first)")
        return 0
    leads.sort(key=lambda l: (STATUS_RANK.get(l.get("status"), 0), RANK.get(l.get("priority"), 2), l.get("id", "")))
    now = datetime.datetime.now(datetime.timezone.utc)
    print(f"{'ID':7} {'PRIO':5} {'STATUS':13} {'SKILL':24} SIGNAL")
    for l in leads:
        age = ""
        try:
            created = datetime.datetime.strptime(l.get("created", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
            days = (now - created).days
            if l.get("status") == "new" and l.get("priority") == P_HIGH and days >= stale_days:
                age = f"  <<< STALE {days}d: you found this and never worked it"
        except ValueError:
            pass
        reason = f"  [{l['reason']}]" if l.get("reason") else ""
        print(f"{l.get('id','-'):7} {l.get('priority','-'):5} {l.get('status','-'):13} {l.get('skill','-'):24} {l.get('signal','-')}{reason}{age}")
        print(f"{'':7} -> {l.get('evidence','')[:150]}")
    counts = {}
    for l in leads:
        counts[l.get("status", "?")] = counts.get(l.get("status", "?"), 0) + 1
    print(f"[stats] " + " ".join(f"{k}:{v}" for k, v in sorted(counts.items())))
    return 0


def cmd_next(slug: str) -> int:
    p = board_path(slug)
    leads = [l for l in load_leads(p) if l.get("status") == "new"]
    if not leads:
        print("[next] no new leads; ingest recon output or check show --stale-days")
        return 1
    leads.sort(key=lambda l: (RANK.get(l.get("priority"), 2), l.get("id", "")))
    l = leads[0]
    print(f"[next] {l['id']} {l['skill']} ({l['priority']}) - {l['signal']}")
    print(f"       {l['why']}")
    print(f"       evidence: {l['evidence'][:200]}")
    print(f"       work it: python3 bin/rh_leadboard.py {slug} touch {l['id']} --status investigating")
    return 0


def cmd_touch(slug: str, lead_id: str, status: str, reason: str) -> int:
    if status not in STATUSES:
        print(f"[fatal] status must be one of {STATUSES}")
        return 1
    p = board_path(slug)
    leads = load_leads(p)
    for l in leads:
        if l.get("id") == lead_id:
            l["status"] = status
            l["reason"] = reason or l.get("reason", "")
            l["touched"] = now_iso()
            save_leads(p, leads)
            print(f"[touch] {lead_id} -> {status}" + (f" ({reason})" if reason else ""))
            return 0
    print(f"[fatal] lead {lead_id} not found on board")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Lead board: attention persistence for solo hunters")
    ap.add_argument("target")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp_ing = sub.add_parser("ingest")
    sp_ing.add_argument("source", help="file path or - for stdin")
    sp_show = sub.add_parser("show")
    sp_show.add_argument("--stale-days", type=int, default=2)
    sub.add_parser("next")
    sp_touch = sub.add_parser("touch")
    sp_touch.add_argument("lead_id")
    sp_touch.add_argument("--status", required=True, choices=STATUSES)
    sp_touch.add_argument("--reason", default="")
    args = ap.parse_args()

    if args.cmd == "ingest":
        return cmd_ingest(args.target, args.source)
    if args.cmd == "show":
        return cmd_show(args.target, args.stale_days)
    if args.cmd == "next":
        return cmd_next(args.target)
    if args.cmd == "touch":
        return cmd_touch(args.target, args.lead_id, args.status, args.reason)
    return 1


if __name__ == "__main__":
    sys.exit(main())
