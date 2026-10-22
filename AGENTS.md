# AGENTS.md - redhunting skill

Cross-agent instructions (opencode, Codex, Claude Code, Cursor, any CLI agent, any model - the same brain). This folder is the complete, standalone unit: everything the skill needs (knowledge, scripts, vendored tools) travels inside it. No external repo, no symlinked dependencies.

## If USING this skill (a hunt is running)

1. Read SKILL.md first: the VERIFICATION BAR, the SETUP requirement, workspace doctrine, and phase routing (Setup, Map, Leads, Verify, Chain, Pack, Wrap).
2. This is a standalone red-team hunting operation on general apps and systems. There is no company identity, no engagement contract, no coordination with anyone. The operator's real identity never appears anywhere; the engagement identity is random (hunt.json).
3. SETUP IS MANDATORY before any dynamic work and is asked ONCE: bin/rh_kickoff.py (three questions: sprint, mode, adb) writes hunt.json into the target folder and generates the random identity. When hunt.json exists, kickoff prints the saved state and exits (--refresh is the only re-interview path). Every later session READS hunt.json. Register the A/B accounts right after (tempmail MCP), start the clock (rh_clock), keep the clock visible every sprint turn.
4. The loop is knowledge/workflow.md; the playbook ROUTER is knowledge/playbook.md and the 26 classes live in knowledge/classes/<slug>/SKILL.md (unit-load: the Confirm phase opens exactly ONE class folder, the one the lead board routed); chain doctrine in knowledge/chains.md; the verification ladders in knowledge/verification.md; identity doctrine in knowledge/identity.md. Command-level depth lives in knowledge/cheatsheets/ (13 files: http probing matrices and WAF ladders, adb and frida hook templates, graphql error-oracle scripts, jwt and oauth forgery, firebase config dumps and key-restriction spoofing, push send-capability proofs, race burst orchestration, crypto replica and reference vectors, cloud-storage listing discipline, injection batteries, secret sweeps with capability matrices) - every phase pairs with its cheatsheet, and rh_recall.py indexes both by keyword.
5. Scripts (bin/, pure Python stdlib, any OS):
   - rh_doctor.py - environment check (run once per hunt)
   - rh_init.py - target scaffolding (persistent workspace, default ~/redhunting)
   - rh_kickoff.py - the pre-hunt setup (3 questions) -> hunt.json + random identity
   - rh_clock.py - sprint clock: start/status/wrap; no clock, no sprint. The sprint is a FLOOR: wrap is refused while time remains (longer fine, never shorter); --force breaks the floor and is logged. Wrap is mandatory at session end
   - rh_scope.py - the law: fail-closed scope check; every target host goes through it before the first request
   - rh_leadboard.py - ingest recon/decode output into ranked leads; show/next/touch
   - rh_ledger.py - findings ledger; add scaffolds the NAMED finding folder (README/SUMMARY/VERIFICATION/materials)
   - rh_capture.py - THE evidence front door: every dynamic probe goes through it
   - rh_differential.py - parameter semantics 3-way probe (valid/garbage/empty)
   - rh_impact.py - impact quantification from captured bodies
   - rh_apkrecon.py - APK decode pipeline (hosts, endpoints, secrets, manifest, signing SHA-1)
   - rh_verify.py - evidence pack checker + Self-Verify snippet generator + PoC replay
   - rh_validate.py - the verify gate as code (exit 0 = packable)
   - rh_materials.py - material pack builder (the operator writes the report from it)
   - rh_recall.py - search the knowledge base for prior art (journal included)
6. Vendored tools in tools/ (APK mirror downloader with provenance, store metadata, device puller, paranoid decoder, MCP servers under tools/mcp/<name>/server.py). Registration snippets in knowledge/mcp-tools.md.
7. Hard rules:
   - PROOF TO THE CEILING: every claim runs its follow-through ladder (knowledge/verification.md), every rung a raw transcript. A GitHub token is not "a leaked token" until scopes, repos, dry-run clone, one clone, secret grep, CI secrets, and org reach are each captured or bounded.
   - HEDGING IS BANNED: potential, candidate, likely, possibly, theoretical, could, maybe, appears, seems, might - none of these appear in any output. Unverified ideas are leads on the board.
   - SEVERITY MATCHES EVIDENCE: RCE ships with command-execution output, takeover with demonstrated owned-account control, XSS with browser execution. No costume titles.
   - EVERY DYNAMIC PROBE through rh_capture.py (curl -v / mitmproxy / Burp transcripts are the fallback when the tool cannot reach the surface; never retype or summarize any of them).
   - EVERY FINDING PRESENTED TO THE OPERATOR carries a Self-Verify block: the exact curl/browser/adb commands they run themselves, with what to expect (rh_verify.py snippet).
   - SCOPE IS THE LAW: fail-closed. A host that fails rh_scope is out of scope, full stop.
   - THE AGENT NEVER WRITES OR SENDS THE FINAL REPORT. Material packs only (rh_materials.py). The operator writes and discloses themselves.
   - IDENTITY: random per engagement. Never the operator's name, handle, email, phone, or any identifying data in any file, transcript, account, header, or screenshot.
   - THE SPRINT CANNOT BE ABANDONED: wrap before session end, zero-finding sprints included (rh_clock wrap; the wrap log lands in notes.md).
   - SELF-RELIANCE: blocked path -> parked lead with revisit condition -> next surface. No complaints, no coordination requests.
   - Small-scale verification is the job (marker files, owned-account control, lateral replay). Large-scale destruction is the only line. Pushes to your own device tokens only; writes on your own accounts with the BB_ prefix; cleanup what you create.
   - MACHINE GUARD: npx-spawned MCP servers leak across sessions (the OOM incident). rh_kickoff and rh_clock wrap run rh_guard.py automatically; vendored stdlib MCP servers first; npx servers (jshookmcp, cve-mcp, fetch) stay enabled:false except for the sprint that needs them. NEVER delete workspace content. No auto-cleanup, no tidying.
   - Scanner and recon-tool output enters as LEADS (rh_leadboard ingest), never as findings.
   - Retest 2x and replay the PoC before packing. Track every ledger terminal state honestly.
8. Hunter policy lives in config.json (identity, hunt, workspace, pacing, verification, tools). Read it at hunt start and obey it like law.

## If DEVELOPING this skill

- Keep it self-contained and portable: bin/ scripts stay pure-Python stdlib, single-file, readable, exit-code-honest. Vendored tools stay in their own folders under tools/ (MCP servers follow tools/mcp/<name>/server.py); external optional CLIs are referenced, never bundled.
- knowledge/ is the source of truth. bin/ is thin automation on top.
- After each hunt round, learn back into knowledge/ (playbook FP traps, workflow unblocks, journal dated entries). Never let lessons die inside a target workspace.
- English only. No emoji, no em-dashes. No marketing copy.
- Never commit real target names, org names, account data, or evidence into this repo: sanitize case studies to technique archetypes. Findings and evidence live in the workspace, never in the skill.
- When extending a vuln class, keep the per-class structure: Signal / Workflow / PROOF BAR / FP TRAPS / Chain tree / Payout notes.
- When adding a verification ladder, write it explicitly (command sequence per rung, expected transcript per step) - ladders are the product.
- Repo hygiene: no machine-specific absolute paths anywhere (resolve via __file__/config/env); the repo must clone-and-run on any OS with Python 3.
