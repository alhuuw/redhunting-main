# Workspace: The Persistent Operation (anti-cleanup doctrine)

The workspace is the solo operator's capital: leads, ledger, vault, retest queues and the learn-back book compound across targets and years. NOTHING in it is ever auto-deleted by this skill.

Layout mirrors the engagement-scaffold pattern: the target workspace is created in the directory the tool is invoked from (`rh_init.py acme` -> `./acme/`), never in the home root. The journal (learn-back book) and the playbook live in the SKILL's own knowledge/ folder; machine state (device.json, machine.log) in the skill's state/ folder. RH_HOME overrides the target root for a fixed location; the default is the invocation directory.

Why persistence is a wage feature: a team forgets between engagements; a solo operator with a warm board, a vault of chain ammo, and a retest queue converts every target change into first-contact money. Archive targets you leave (mv to _archive/) rather than deleting; disk is cheaper than re-finding.

## Layout

```
./<slug>/                      (the invocation directory; RH_HOME redirects)

├── README.md             what this target is (templates/TARGET-README.md)
├── target.json           scope entries + exclusions + org + disclosure contact
├── scope.txt             the raw imported contract (append-only provenance)
├── hunt.json             current hunt parameters (rh_kickoff, re-read every session)
├── sprint.json           live sprint clock state (rh_clock)
├── sprints.jsonl         sprint history (wrap logs, findings/negatives per sprint)
├── assets/
│   ├── round-001/        recon snapshot: hosts.txt, live.txt, urls.txt, js/, ports.txt, apk/, extracted/, decoded/
│   └── round-002/        next round (never overwrite: rounds diff, diffs are retest triggers)
├── leads.jsonl           the lead board (one line per signal, upsert dedup, never reset)
├── ledger.jsonl          findings ledger (append-only)
├── findings/<slug>/      NAMED finding folders (never bare numbers)
│   ├── README.md         what this folder is (templates/FINDING-README.md)
│   ├── SUMMARY.md        the finding summary (impact statement + measured numbers)
│   ├── VERIFICATION.md   claim table + ladder log (knowledge/verification.md format)
│   ├── materials.md      the material pack the OPERATOR writes the report from
│   ├── evidence/raw/     tool-generated transcripts ONLY (+ SHA256SUMS.txt, .bin bodies)
│   └── poc/              self-verifying PoC scripts (--mask default)
├── vault.md              chain ammo (low-sevs with chain hypotheses + revisit triggers)
├── retest.md             the retest queue (target-change triggers)
├── accounts.md           random-identity test accounts (A/B, self-registered)
└── notes.md              round logs, sprint wraps, mode transitions
```

## target.json schema (rh_init writes it)

```json
{
  "slug": "acme",
  "org": "Acme Corp",
  "notes": "regional MSME finance app, found via store category crawl",
  "scope": [
    {"type": "wildcard", "value": "*.acme.com"},
    {"type": "domain", "value": "acme.com"},
    {"type": "url", "value": "https://api.acme.com/v2", "note": "path-scoped"}
  ],
  "exclusions": ["staging.acme.com", "blog.acme.com"],
  "unparsed": ["10.0.0.0/8"],
  "disclosure_contact": "security@acme.com /.well-known/security.txt verified 2026-09-06",
  "created": "2026-09-06",
  "rh_version": 2
}
```
`unparsed` entries are fail-closed: rh_scope answers OUT-OF-SCOPE until a human resolves them at intake. Exclusions always win.

## Findings: named folders, not numbered graves

The folder name IS the finding name: a slug derived from the title (unauthenticated-read-of-all-orders), unique per target, chosen at `rh_ledger.py add` (override with --slug). The internal RH-n ledger id is bookkeeping only; nothing user-facing ever says "finding 12". SUMMARY.md is the finding (impact statement + numbers + reproduce); VERIFICATION.md carries the proof state (claim table, ladder log); materials.md is what the operator writes from; evidence/raw holds the transcripts. The verify gate reads SUMMARY.md and VERIFICATION.md together: open claim rows block the pack.

## hunt.json (rh_kickoff writes it)

The current hunt's operating parameters (sprint, mode, adb, random identity handle, account strategy, rate policy, surface policy). Re-read at every session start: parameters persist, drift gets noticed, nothing gets re-litigated.

## Ledger schema (rh_ledger, JSONL append-only)

```json
{"id": "RH-7", "slug": "unauthenticated-read-of-all-orders", "title": "...", "class": "idor",
 "severity": "high", "url": "...", "status": "verified", "bounty": null,
 "submitted_at": null, "resolved_at": null, "triage_events": [],
 "evidence": "findings/unauthenticated-read-of-all-orders/evidence/raw/",
 "chain_refs": ["RH-3"], "target": "acme"}
```
Status flow: draft -> verified -> packed -> (operator handles disclosure) -> resolved/duplicate/informative/not_accepted/retracted. Every terminal state is recorded with a reason: they are wage data, not shame. Only the honest fields (status, triage_events, bounty, resolved_at) are mutable; never title/class/evidence.

## Vault discipline (chains.md)

One entry per parked chain-component with: evidence path, chain hypothesis, blocker + revisit condition, revisit trigger. Reviewed on every retest round; entries graduate into findings or die with a dated reason.

## Retest queue (retest.md)

Triggers: app release (Play Store version watch via play_meta.py / apkpure MCP), scope/estate change, new surface discovered, vault entries whose revisit conditions fired. On trigger: new assets/round, board re-ingest, diff-driven lead promotion.

## Evidence rules (dispute-proof)

- RAW TOOL OUTPUT only: rh_capture transcripts, curl -v, mitmproxy exports, HAR, logcat, screenshots. Hand-typed or AI-summarized evidence is banned (reads as fabrication).
- Transcripts carry UTC timestamp, request exactly-as-sent, response exactly-as-received; binary bodies byte-exact with sha256 recorded.
- Negative controls captured in the SAME run as the positive probe. Retests as separate files.
- rh_verify evidence re-checks the pack (SHA chain, signatures, control presence) before the gate.
- Masking: PII masked by default; operator-identifying data (inboxes, handles, device names) masked before anything leaves evidence/raw.
- Storage note: evidence lives under ~/redhunting, never inside the skill folder, never in any project dir that a session or machine cleanup could touch.

## Migration and portability

The workspace is plain files (JSON/JSONL/markdown): rsync-able, git-able (private repo for ledger; keep evidence out of git if sizes grow). The learn-back journal lives in the SKILL folder (knowledge/journal.md) and travels with the skill; target folders travel with their project directories. Machine state (device.json, machine.log) lives in the skill state/ folder and is gitignored runtime data. Nothing in the workspace references the skill; nothing in the skill references a workspace path (all paths resolved via config/env at runtime).
