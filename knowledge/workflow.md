# Workflow: The Red Loop (setup to ceiling to learn-back)

One loop per target round. The loop never deletes anything: every round ends in the ledger, the lead board, the vault, or a wrap log. Solo operation on general apps and systems: velocity and persistence beat completeness theater, and NOTHING dynamic happens before setup.

```
K SETUP   3 questions (sprint, mode, adb) -> hunt.json; identity random; accounts A/B self-registered
M MAP     acquire artifact with provenance, decode, sweep, expand the estate -> lead board
L LEADS   work the board: top lead -> investigate -> kill or promote (clock visible, every turn)
V VERIFY  follow-through ladders to the ceiling: raw transcripts, differentials, controls, A/B
C CHAIN   escalate: ladder + chain matrix until the impact is real (money/PII/ATO-scale)
P PACK    material pack per finding; the OPERATOR writes the report from it, always
W WRAP    sprint wrapped (mandatory), round closed, learn-back
```

## Phase specifications

| Phase | Entry | Core activities | Exit criteria |
|---|---|---|---|
| Setup | target workspace exists (rh_init) | `rh_kickoff.py` (3 questions) -> hunt.json; register A/B (tempmail MCP) into accounts.md; start the clock; acquire the artifact with provenance when static-first | hunt.json written, clock running, accounts owned or BLOCKED-with-revisit logged |
| Map | setup done | artifact decode pipeline (rh_apkrecon, mobile.md), estate expansion (subdomains, hosts, ports, desktop client, vendors), push-stack sweep, `rh_leadboard.py ingest` on EVERY output line | assets corpus exists, board populated, no signal unclassified |
| Leads | board non-empty | `rh_leadboard.py show`, pick ONE top lead, investigate per playbook class, classify outcome (killed / promoted / parked with revisit condition) | every worked lead has a status and a reason |
| Verify | lead promoted | the class ladder from knowledge/verification.md, rung by rung, every step through `rh_capture.py`; differential (valid/garbage/none in one run), negative controls, A/B identity check for auth classes, 3-way attribution on any rejection | VERIFICATION.md rows closed, SUMMARY.md written, self-verify block present |
| Chain | verified finding | escalation ladder + chain matrix (below); chain-shaped low-sevs go to vault.md | impact demonstrated at the ceiling the evidence supports |
| Pack | verified chain | `rh_materials.py` builds the material pack; ledger entry updated to verified | pack complete, operator takes over writing |
| Wrap | sprint end or session end | `rh_clock.py wrap` (mandatory, zero-finding sprints included), learn-back into journal.md and playbook FP traps | wrap logged, board state persisted |

## Sprint protocol (clock or it is not a sprint)

1. `rh_clock.py <target> start --minutes N --target "<one surface/class>"`. One target per sprint, chosen by expected value: untouched surface > extending a verified class > retesting.
2. Clock visible EVERY turn: `date "+%H:%M:%S"` + the rh_clock status line at the top of each sprint action. No clock, no sprint.
3. Oracle-first sequencing: enumeration theater is banned; bound enumeration to the smallest set that changes a verdict.
4. THE SPRINT CANNOT BE ABANDONED. A running sprint gets wrapped before any session end, wrap log mandatory (findings, negatives, time). Zero-finding sprints still wrap: coverage is progress and the wrap log is what keeps the coverage story honest.
5. WAITING IS NEVER A MOVE. The floor (wrap refused while time remains) and the no-idle rule are one principle: a sprint always has a next action, so it never sleeps to burn time. Blocked path -> park the lead with a revisit condition -> pull the next lead (`rh_clock status` now prints it for you). Genuinely async work (OOB callback, race window, rate-limit cooldown, long scan) -> fire it as a background job and switch to another lead; check the result when the board cycles back or the job signals. If the board has no fresh lead: deepen a verification ladder on an open finding, widen recon and ingest, or APK version-diff. Sleeping to pass sprint time is the one thing the floor forbids.
6. Sprints stack; the round ends per stop rules. Late-sprint finding rate exceeds early rate because the surface map is already built: early sprints are investment, late sprints are harvest.
7. Expired sprint: wrap before starting the next. An unwrapped expired sprint is an honesty gap in the log.

## The lead board discipline (attention persistence)

A real surface throws hundreds of signals at you. You will hyperfocus on ONE and forget the rest, and someone else gets there first. The board is the fix:

1. EVERY recon/decode output line goes through `rh_leadboard.py ingest` (URLs, hosts, tech fingerprints, ports, params, secret-sweep hits). Unclassified signals land as low-priority leads with the raw evidence string: nothing is dropped.
2. Work ONE lead at a time (`next` returns the top). After each: `touch --status killed|investigating|parked` with a reason. A killed lead with a reason is future intel, not waste.
3. `show` surfaces untouched leads and flags high-priority leads older than --stale-days (default 2): "you found these and never worked them". That warning is money talking.
4. Re-ingest never resets status: the board is upsert-on-(skill,evidence), so a growing corpus never erases work history.
5. Never delete leads. Old killed leads on a re-mapped target are the cheapest retest signal there is.

## Stop rules

A round stops when ANY of:
1. Every verified chain is packed (the operator writes and discloses on their own schedule; the skill's job ends at the pack).
2. The session budget is exhausted (wrap log + board state persist; the next session resumes exactly where this one stopped: the workspace never forgets).
3. The surface is exhausted per the coverage table (every discovered endpoint probed, every key matrixed, every lead killed-with-reason).

NOT stop conditions: the first Medium ("verify it, pack it, keep going"), a blocked path ("park it with a revisit condition and take the next surface"), fatigue ("the board will be there tomorrow"). Intermediate states are never stops. Self-reliance is the position: no complaints, no coordination requests, find the next path.

## Hypothesis queue (runs inside the lead board)

Every untested idea is a lead with status queued: ID, hypothesis, basis, state (QUEUED/TESTING/PROVEN/DEAD/BLOCKED-with-revisit). A round that neither consumes nor adds hypotheses is a wasted round. DEAD hypotheses keep their evidence line (negatives are target intel and future FP-traps). BLOCKED hypotheses get a revisit condition ("blocked on second account; revisit when tempmail registration completes").

## The escalation ladder (run on every verified finding)

| After verifying | Mandatory escalation before/after packing |
|---|---|
| Any leaked key/token | capability matrix, then replay against every discovered service (lateral) |
| Any read access to objects | scale proof (record minimum), recency proof, then hunt the write path |
| Any write access | chain upward: write to privilege, privilege to cross-tenant or admin |
| Any user-level foothold | vertical escalation attempt, then credential reuse across the estate |
| Any single-service impact | map every sibling service sharing auth, tokens, or infrastructure |
| Any Medium | ask what it enables; chain until the real impact is demonstrated or bounded honestly |
| Any low that chains | do not pack alone: vault.md it, chain it, pack the chain |

## The chain matrix (one row per verified finding)

Every other discovered surface is a column. A finding is pack-ready when its row is complete:

```md
| Finding / enables | chat API | tracking API | gateway | web SPA | IdP | push |
|---|---|---|---|---|---|---|
| leaked token | mint OK | 401 | 401 | session OK | pwd-grant OK | send OK |
```

Cell states: TESTED (with evidence link), NOT-APPLICABLE (reason), BLOCKED (reason). Parameter-space chaining counts: if the endpoint ignores a parameter (sub/sid/tenant), sweeping that parameter's cardinality is part of the row (bounded sweep, minimization respected).

Deep-chain minimums per finding: parameter semantics 3-way (valid/garbage/empty: `rh_differential.py`), scale proof, data-class inventory of the captured bytes (`rh_impact.py`), foothold export (identifiers other surfaces accept), environment replication (dev/stg/prod from bundle mining), write-sibling check (POST/PUT/SSE on the same prefix).

## Evidence discipline (the capture front door)

- Every dynamic probe goes through `rh_capture.py`: transcript (request exactly-as-sent, response exactly-as-received, UTC), byte-exact .bin for binary bodies, SHA256SUMS.txt regenerated. curl -v / mitmproxy / Burp transcripts are the fallback for surfaces the tool cannot reach (TLS-fingerprint WAFs need curl_cffi with the impersonation profile; HTTP/2-only hosts need Burp). NEVER retype, summarize, or "clean up" any of them.
- Negative controls captured in the SAME run as the positive probe. Retests as separate files (config: 2).
- Evidence checks and self-verify generation: `rh_verify.py evidence|snippet`. Full doctrine: knowledge/verification.md.
- PII masked by default; full records only on explicit request, disposed after.
- PoC scripts self-verifying and --mask by default.

## Mode selection (static-first vs dynamic-first)

- Static-first when a client artifact exists (APK, IPA, SPA bundle): decode, sweep secrets, map routes FIRST; the static map decides which dynamic probes are worth firing. A dynamic probe without a static basis is guessing.
- Dynamic-first for pure API/no-artifact targets: live surface mapping (OPTIONS, auth matrices, error differentials), grow the static side from captured traffic.
- Switch triggers: an unauth-contract question only the server can answer (go dynamic); traffic reveals a bundle (go static, the bundle knows more endpoints than traffic shows). Log mode transitions in notes.md with the trigger.
- Whichever mode found the lead, only raw captured evidence makes it a finding.

## Common stalls and proven unblocks (self-reliance rules)

| Stalled on | Unblock |
|---|---|
| WAF/CDN challenge pages | curl_cffi impersonation, low concurrency, rotate vantage (public DNS + pinned IP; a 0.0.0.0 answer is the LOCAL resolver, not the target); challenge page (solvable with a real browser) vs hard block (vantage-bound) - record which |
| Need a second account | tempmail MCP; invite-only/phone-walls => BLOCKED-with-revisit, pivot to unauthenticated surfaces |
| Opaque 4xx on a write path | attribution rule: port byte-exact first (mobile.md section 9 checklist), Java reference vector for crypto ports, then variant sweep, then exercise the suspected layer directly |
| Introspection blocked on GraphQL | "Did you mean" error-oracle schema reconstruction (playbook class 20); probe __type on every /public sibling |
| No device for mobile classes | emulator (ABI-matched), or setup adb:off and run the static+API side fully; on-device-only claims stay leads until a device exists |
| Every finding already known | stop the class, switch surface (mobile is systematically less hunted), or target (the retest queue brings you back on version changes) |
| Org silent after disclosure | the operator's cadence; the next target's board is already warm |

## After the pack

1. Ledger status discipline: draft -> verified -> packed; terminal states (resolved/duplicate/informative/not_accepted/retracted) recorded with dates and reasons. Every terminal state is wage data: what worked, what got ignored, per class.
2. Retest queue: on app release, scope growth, estate change, retest.md gets entries; version changes are unpaid money for solo operators.
3. Learn-back: playbook FP traps, workflow unblocks, journal entry (the book compounds or it dies).
