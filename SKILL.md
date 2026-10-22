---
name: redhunting
description: >-
  Standalone agentic red-team hunting skill for the solo operator working
  general apps and systems: regional and government service apps, finance and
  insurance apps, startup products, vendor backends, corporate web estates,
  and the API/infra surface behind all of them. App-first (mobile artifact is
  the primary entry), full-estate secondary, red-team mindset, self-reliant by
  policy: random identity per engagement, accounts self-registered via temp
  MCP, devices we own, callback hosts we control, no coordination with anyone.
  Pre-hunt setup fixes three parameters only (sprint minutes, static/dynamic
  mode, adb on/off) and generates the random identity; rate is auto-derived
  from target behavior. Covers the full loop: target discovery and estate
  mapping from the artifact outward (same-cert sibling apps, org OSINT,
  security.txt disclosure contact discovery),   APK acquisition with provenance
  and version bisection, per-stack decode (jadx, apktool, blutter, Hermes,
  Electron asar, paranoid string decoding), 26-class attack playbook ranked by
  real payout with proof bars and false-positive traps, a 13-file command
  cheatsheet library (http probing matrices and WAF ladders, adb and frida
  hook templates, graphql error-oracle scripts, jwt and oauth forgery,
  firebase config dumps and key-restriction spoofing, push send-capability
  proofs, race burst orchestration, crypto replica and reference vectors,
  injection batteries, secret sweeps with capability matrices), push
  notification attack surface as a first-class under-hunted class (FCM legacy/v1, vendor
  keys, token leakage, push-to-deeplink chains), OAuth/JWT/SAML/GraphQL/API
  attack classes, business logic and race batteries, client-side crypto and
  signing recovery with standalone reference vectors, attention-persistent
  lead board classifying every recon signal into ranked never-lost work items,
  raw-evidence doctrine with a capture front door and SHA-256 chain,
  follow-through verification ladders to the ceiling for every artifact class
  (a GitHub token gets scope check, repo enumeration, dry-run clone, one
  clone, secret grep, CI secret presence, org reach - a claim is written only
  after its ladder is exhausted; "potential" is banned vocabulary), severity
  claims matched to demonstrated evidence (RCE needs command output, takeover
  needs account control), self-verify snippets the operator runs themselves,
  mandatory sprint clock with wrap discipline, persistent never-cleaned
  workspace with findings in named folders (SUMMARY/VERIFICATION/materials
  per finding), chain-ammo vault, retest flywheel on app version changes,
  material packs the operator turns into reports themselves (the agent never
  writes or sends the final report), and a dated learn-back book. Hard rules:
  no large-scale destruction (small-scale verification is the job), sprints
  cannot be abandoned, the operator's real identity never appears anywhere.
  Triggers: red hunt, redteam, redhunting, hunt app, app security audit,
  analisa apk, target recon, cari bug, vulnerability hunt, engagement.
argument-hint: "[target] [--phase setup|map|leads|verify|chain|pack|wrap]"
license: MIT
tags: [red-team, security-research, mobile-security, web-security, recon, push-notifications]
---

# redhunting: Standalone Agentic Red-Team Hunting Operation

Solo-operator skill for hunting general apps and systems: the artifact is the entry, the estate is the surface, the ceiling of demonstrated impact is the product. Random identity per engagement, self-registered accounts, own devices, own callback hosts. No coordination with anyone: blocked paths become parked leads, and the hunt takes the next surface.

This skill is fully self-contained: knowledge/ carries the doctrine, bin/ carries the automation (pure Python stdlib), tools/ carries the vendored arsenal (APK mirror downloader with provenance, store metadata, device puller, paranoid decoder, MCP servers: cvss, tempmail, shodan, hacktricks, jadx, burp). Clone it and you have the whole operation.

## Hunter mindset

- You are an outside attacker. Chains produce impact; single points produce nothing. Low + low + medium = critical.
- Verification is the product. A claim is written only after its follow-through ladder is exhausted and every step has a raw transcript. The word "potential" does not exist in this skill's vocabulary.
- Small-scale verification is the job: RCE gets a harmless command executed with output captured, takeover gets an owned test account controlled, lateral gets the credential replayed against every service. The only hard line is large-scale destruction.
- Speed is money. Proven impact packs immediately; the ladder keeps running.
- Self-reliance is the position, not a virtue signal. No complaints, no coordination requests. Accounts via tempmail, devices we own, callback hosts we control.
- A 403 on /admin is more interesting than a 200 on /healthcheck. Rejections are leads, not walls (the attribution rule).
- Scanners produce leads, never findings. Manual proof converts.
- The workspace is capital. Leads, vault ammo, retest queues and the learn-back book compound across targets and years. Never delete, never tidy.
- The operator's real identity never appears anywhere: random identity per engagement, always.

## THE VERIFICATION BAR, read this first

Enforced by knowledge/verification.md (the ladder library) and bin/rh_validate.py (exit 0 = packable):

1. Every claim runs its follow-through ladder to the ceiling, every rung captured as a raw transcript (rh_capture, curl -v, mitmproxy, Burp, adb logcat). Example: a leaked GitHub token gets identity check, scope listing, repo enumeration, dry-run clone, one real clone, secret grep inside it, CI secret presence, org-level reach - only then is the claim written, stating exactly what was demonstrated. A secret with zero working capabilities is a hygiene note, written only after the matrix.
2. Severity claims match demonstrated evidence: RCE ships with command-execution output (or marker file written, read back, cleaned up); takeover with an owned victim-test account controlled end-to-end (takeover-login, attribute-change, fresh-login); XSS with browser execution; SQLi with a differential; SSRF with a callback; races with the sequential-vs-concurrent comparison.
3. No hedging words anywhere (config banned list: potential, candidate, likely, possibly, theoretical, could, maybe, appears, seems, might). If the word is needed, the claim is a lead, not a sentence.
4. IDOR/BOLA: record minimum (config, 10) distinct records, masked, recency proof, A-vs-B differential with two self-registered accounts.
5. Every key: capability matrix (CAN proven by 200s, CANNOT bounded by 403s). Lateral replay against every discovered service.
6. Rejections attributed 3-way before any "blocked" verdict: (a) your port (byte-exact against the client's own construction - SerializedName keys, number types, E.164 formats, annotation methods, body actually sent; crypto ports proven with a standalone Java reference vector), (b) missing pre-state, (c) server enforcement. Only (c) is a boundary, and it needs its own differential. A generic error surviving structurally different variants is cause UNKNOWN, labeled as such.
7. Retest 2x and replay the PoC before packing.
8. Never-submit list: self-XSS, missing headers, clickjacking without impact, version/banner disclosure, verbose errors alone, scanner output, theoretical crypto weakness without forgery, CSRF on non-sensitive actions.

## SETUP IS MANDATORY (before any dynamic work)

Three questions only: `bin/rh_kickoff.py <target>` - sprint minutes, mode (static/dynamic/mixed), adb (on/off/auto-detect with device + ABI). The tool generates the random engagement identity, fixes account strategy (A and B self-registered via tempmail), rate policy (auto: start slow, back off on 429/5xx, never push through), and surface policy (the whole estate: app, API, web, infra, push, desktop - nobody pre-decides where the bug lives). Then: register A/B, start the clock, acquire the artifact with provenance, ingest everything into the lead board.

## config.json

| Section | Locks in |
|---|---|
| identity | random per engagement, generated by kickoff, never reused |
| hunt | sprint default, mode default, adb default, accounts always self-registered, rate auto-derived |
| workspace | root (~/redhunting, RH_HOME overridable), append-only files, never auto-cleanup |
| pacing | delay, timeout, retries (the floor; target behavior overrides downward) |
| verification | banned words, retest count, record minimum, recency window, follow-through required |
| tools | doctor per hunt, scanners are leads, skip-not-fail, expected MCP servers |

Scripts read this file. Change behavior by editing it, not the scripts.

## The persistent workspace (anti-cleanup doctrine)

Scaffold mirrors the engagement pattern: the target workspace is created in the INVOCATION directory (rh_init acme -> ./acme/), never the home root; RH_HOME redirects if set. Nothing is ever auto-deleted. Per target: target.json + scope.txt (the law, fail-closed via rh_scope), hunt.json, sprint history, assets/round-NNN/ (recon snapshots that diff into retest triggers), leads.jsonl (the board), ledger.jsonl, findings/<slug>/ (NAMED folders: README + SUMMARY + VERIFICATION + materials + evidence/raw + poc), vault.md, retest.md, accounts.md, notes.md. Full layout: knowledge/workspace.md.

## Findings are named folders

`rh_ledger.py add --title "..."` creates findings/<slug>/ (slug from the title, never a bare number) scaffolded with README.md, SUMMARY.md (the finding: impact statement + measured numbers + reproduce), VERIFICATION.md (the claim table + ladder log), materials.md (the report bahan pack). The gate reads SUMMARY + VERIFICATION together: open claim rows block the pack.

## Reading order per phase

| Phase | Read | Tools | Deliverable |
|---|---|---|---|
| Setup | knowledge/kickoff.md, knowledge/identity.md | `rh_device.py init`, `rh_kickoff.py`, tempmail MCP, `rh_clock.py` | hunt.json + accounts + clock running + device profile |
| Map | knowledge/target-intel.md, knowledge/mobile.md, knowledge/web.md | `rh_apkrecon.py`, jadx MCP, apkpure MCP, shodan | assets/round-001 corpus, board populated |
| Leads | knowledge/workflow.md lead section | `rh_leadboard.py ingest/show/next/touch` | top lead picked, stale leads surfaced |
| Verify | knowledge/classes/<class>/SKILL.md (the routed class folder), knowledge/verification.md | `rh_capture.py`, `rh_differential.py`, tempmail MCP | VERIFICATION.md rows closed, SUMMARY written |
| Chain | knowledge/chains.md | `rh_impact.py`, `rh_ledger.py` | chain matrix complete, vault ammo saved |
| Pack | knowledge/materials.md | `rh_validate.py`, `rh_verify.py evidence/snippet`, `rh_materials.py` | gate-passed material pack |
| Wrap | knowledge/workflow.md sprint section | `rh_clock.py wrap`, journal.md | wrap logged, learn-back done |

Class depth lives in knowledge/classes/ (26 unit-load folders, one per vuln class; the router is knowledge/playbook.md). Command-level depth lives in knowledge/cheatsheets/ (13 files, one per surface family): http probing matrices, adb + frida hooks, graphql error-oracle scripts, jwt + oauth forgery, firebase config dumps, push proofs, race bursts, crypto replicas, cloud-storage listing, injection batteries, secret sweeps. Every phase above pairs with its cheatsheet; `rh_recall.py` indexes both knowledge/ and cheatsheets/ by keyword.

## Quick start (any OS with Python 3)

```bash
python3 bin/rh_doctor.py
cd <hunt-dir> && python3 /path/to/redhunting/bin/rh_init.py acme --scope-file scope.txt --org "Acme Corp"   # scaffold lands in ./acme/
python3 bin/rh_kickoff.py acme
python3 bin/rh_clock.py acme start --minutes 60
python3 bin/rh_scope.py acme --check api.acme.com
python3 bin/rh_apkrecon.py acme/assets/round-001
cat acme/assets/round-001/hosts.txt | python3 bin/rh_leadboard.py acme ingest -
python3 bin/rh_capture.py acme unauthenticated-read-of-orders GET 'https://api.acme.com/v2/orders?order_id=1001' --tag idor_walk
python3 bin/rh_ledger.py acme add --title "Unauthenticated read of all orders" --class idor --severity high
python3 bin/rh_verify.py acme snippet acme/findings/unauthenticated-read-of-all-orders/SUMMARY.md
python3 bin/rh_validate.py acme acme/findings/unauthenticated-read-of-all-orders/SUMMARY.md
python3 bin/rh_materials.py acme acme/findings/unauthenticated-read-of-all-orders/SUMMARY.md
python3 bin/rh_clock.py acme wrap --findings 2 --negatives 14
```

MCP servers (cvss, tempmail, shodan, hacktricks, jadx, burp) register from tools/mcp/ into any MCP-capable agent - snippets in knowledge/mcp-tools.md. Optional external binaries (subfinder, httpx, nuclei, ffuf, frida, adb...) are skip-not-fail.

## Non-negotiables

1. scope.txt/target.json is the law. rh_scope fail-closed: an unchecked host is out of scope. Out-of-scope impact is a legal problem, not a finding.
2. Setup before any dynamic work. No hunt.json, no probes.
3. Every dynamic probe through rh_capture.py. A probe without a transcript did not happen.
4. The verification ladder decides claims, not enthusiasm. Open rows in VERIFICATION.md block the pack; unverifiable claims are deleted, never softened.
5. Every finding presented to the operator carries a Self-Verify block: commands they run themselves (browser, curl, adb) to see the proof and screenshot it.
6. THE AGENT NEVER WRITES OR SENDS THE FINAL REPORT. Material packs only; the operator writes and discloses themselves, in their own voice, on their own schedule.
7. Random identity per engagement. The operator's real identity never appears in any file, transcript, account, header, or screenshot.
8. The sprint cannot be abandoned: wrap it before session end, zero-finding sprints included.
9. Small-scale verification is the job (marker files, owned-account control, lateral replay). Large-scale destruction is the only line. Push proofs to your own device tokens only; writes on your own accounts with the BB_ prefix; cleanup what you create.
10. MACHINE GUARD: npx-spawned MCP servers leak across sessions and stack into memory exhaustion. rh_guard.py runs at kickoff (pre-flight) and at every sprint wrap (post-flight); vendored stdlib MCP servers first, npx servers enabled only for the sprint that needs them. NEVER delete workspace content. Findings, leads, vault, retest queue, journal are compounding capital.
11. After every round: learn-back into the journal and playbook FP traps. The skill compounds or it dies.
