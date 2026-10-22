# redhunting

Standalone agentic red-team hunting skill for the solo operator working general apps and systems: regional and government service apps, finance apps, startup products, vendor backends, and the estates behind them. App-first (the mobile artifact is the primary entry), full-estate secondary, random identity per engagement, no coordination with anyone.

The repo is the complete package: clone it and you have the whole operation. No external skill dependencies, no symlinked repos, no platform lock-in.

## What is in the box

- Device profiling and planning: rh_device.py init captures the machine profile (RAM, cores, disk, tool census, process baseline via the guard); check reports drift (memory leaks, vanished tools); plan writes a hunt-plan PROPOSAL per target (sprint sequence from the lead board, parallelism ceiling derived from free memory, mode from artifact presence). The operator adjusts the plan; nothing auto-executes.
- Sprint clock tooling with wrap discipline: the sprint cannot be abandoned, wrap logs are mandatory, zero-finding sprints included.
- Raw-evidence doctrine: every dynamic probe through a capture front door (request-as-sent / response-as-received transcripts, byte-exact binaries, SHA-256 chain). Hand-written evidence banned.
- Follow-through verification ladders to the ceiling for every artifact class, explicit command sequences per rung: a leaked GitHub token gets scope check, repo enumeration, dry-run clone, one clone, secret grep, CI secret presence, org reach - a claim is written only after its ladder is exhausted. "Potential" is banned vocabulary.
- Severity claims matched to demonstrated evidence (RCE needs command output or a marker file round-trip, takeover needs owned-account control), and a Self-Verify block per finding the operator runs themselves.
- 26-class attack playbook split into unit-load class folders (knowledge/classes/<slug>/SKILL.md, one per vuln class, routed by the lead board) with proof bars and false-positive traps.; push notification attack surface (FCM legacy/v1, vendor keys, token leakage, push-to-deeplink chains) as a first-class under-hunted class.
- A 13-file command cheatsheet library (http probing matrices and WAF ladders, adb and frida hook templates, graphql error-oracle scripts, jwt and oauth forgery, firebase config dumps and key-restriction spoofing, push send-capability proofs, race burst orchestration, crypto replica and reference vectors, cloud-storage listing discipline, injection batteries, secret sweeps, a validated payload library, target recon commands) - every copy-paste command valid, paired with the verification ladders.
- Mobile-first pipeline: APK acquisition with provenance and version bisection (two mirrors), per-stack decode (jadx, apktool, blutter, Hermes, Electron asar, paranoid string decoding), signing cert extraction, Frida cookbook, on-device execution via adb.
- Lead board: every recon/decode signal becomes a ranked, never-lost work item; stale-lead warnings; re-ingest never resets work state.
- Persistent workspace (~/redhunting, never auto-cleaned): findings in NAMED folders (README / SUMMARY / VERIFICATION / materials each), findings ledger, chain-ammo vault, retest flywheel on app version changes, dated learn-back book.
- Material packs per finding: the agent never writes or sends the final report; the operator writes it themselves from the pack.
- Vendored tools/: APK mirror downloader with provenance, store metadata, device APK puller, paranoid string decoder, MCP servers (cvss, tempmail, shodan, hacktricks, jadx, burp).

## Install

Clone this repo anywhere, then use the installer for any harness (opencode, claude, codex, cursor, agents, or all; symlink by default, --copy to duplicate, --uninstall to remove, --list to preview). Any MCP-capable CLI agent and any model work.

```bash
git clone <your-fork-url> redhunting
cd redhunting
./install.sh                 # every detected harness
./install.sh --agent claude  # one harness
./install.sh --list          # preview targets, no changes
```

## Regression suite and demo app

The repo ships its own proof: a stdlib-only vulnerable demo app (demo/serve.py, binds 127.0.0.1 only) and an 83-test suite (tests/) covering every script plus the full lifecycle end to end (init -> setup -> clock -> scope -> capture through the front door -> gate -> evidence check -> materials -> wrap).

```bash
python3 -m unittest discover -s tests -v
```

CI runs the same suite on every push (.github/workflows/tests.yml).

Pure Python 3 (stdlib) for bin/; the vendored tools optionally use `pip3 install requests androguard curl_cffi pycryptodome`. Optional external binaries (subfinder, httpx, nuclei, ffuf, frida, adb, jadx...) are skip-not-fail. Any MCP-capable CLI agent and any model work; registration snippets in knowledge/mcp-tools.md.

## Quick start

```bash
python3 bin/rh_doctor.py
python3 bin/rh_init.py acme --scope-file scope.txt --org "Acme Corp"
python3 bin/rh_kickoff.py acme
python3 bin/rh_clock.py acme start --minutes 60
python3 bin/rh_scope.py acme --check api.acme.com
cat urls.txt | python3 bin/rh_leadboard.py acme ingest -
python3 bin/rh_capture.py acme <finding-slug> GET 'https://api.acme.com/v2/orders?order_id=1001' --tag idor_walk
python3 bin/rh_ledger.py acme add --title "Unauthenticated read of all orders" --class idor --severity high
python3 bin/rh_verify.py acme snippet targets/acme/findings/unauthenticated-read-of-all-orders/SUMMARY.md
python3 bin/rh_validate.py acme targets/acme/findings/unauthenticated-read-of-all-orders/SUMMARY.md
python3 bin/rh_materials.py acme targets/acme/findings/unauthenticated-read-of-all-orders/SUMMARY.md
python3 bin/rh_clock.py acme wrap --findings 2 --negatives 14
```

Workspace scaffold lands in the invocation directory (./<slug>/, the engagement-scaffold pattern; RH_HOME redirects). Journal and playbook live in the skill knowledge/; machine state in the skill state/. Setup is asked once: hunt.json in the target folder is the config thereafter, and the configured sprint is a floor (longer fine, never shorter). Docs: SKILL.md (doctrine, verification bar), knowledge/ (kickoff, identity, target-intel, workflow, playbook, chains, verification, push-notifications, mobile, web, js-reverse, mcp-tools, materials, workspace, journal).

## Layout

```
redhunting/
├── SKILL.md / AGENTS.md / README.md / config.json / LICENSE
├── bin/        17 stdlib-only scripts (init, kickoff, clock, scope, leadboard, ledger,
│               capture, differential, impact, apkrecon, verify, validate, materials,
│               recall, doctor)
├── knowledge/  15 reference files (the doctrine, per-phase)
├── templates/  6 scaffolds (workspace/target/finding README, SUMMARY, VERIFICATION, MATERIALS)
└── tools/      vendored: apkpure downloader, play_store, device_pull, paranoid,
                mcp/{cvss,tempmail,shodan,hacktricks,jadx,burp}
```

## Standing rules (the short version)

Scope is fail-closed law. Setup before any dynamic work. Proof to the ceiling, raw transcripts only, severity matched to evidence, hedging banned. Small-scale verification is the job; large-scale destruction is the only line. Pushes to your own device tokens only; writes on your own accounts (BB_ prefix). Random identity per engagement; the operator's real identity never appears anywhere. Sprints cannot be abandoned. The agent never writes or sends the final report: material packs only, the operator writes. Never delete workspace content. Retest before packing, ledger every terminal state honestly, learn back after every round.
# redhunting-main
