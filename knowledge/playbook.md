# Playbook: Class Router (26 classes, one folder each)

The classes live in knowledge/classes/<slug>/SKILL.md, one folder per vuln class
(the unit-load pattern: the Confirm phase reads ONLY the class it is working).
This file is the router: class -> file -> signal -> its cheatsheet pair.
Cross-class doctrine stays here: the proof-gate line, anti-patterns, and the
never-submit list.

| # | Class | File | First signal | Cheatsheet pair |
|---|-------|------|---------------|-----------------|
| 1 | Hardcoded Secrets in Mobile Binaries | knowledge/classes/hardcoded-secrets/SKILL.md | see class | cheatsheets/secrets-recovery.md |
| 2 | IDOR / BOLA | knowledge/classes/idor-bola/SKILL.md | see class | cheatsheets/http.md |
| 3 | ATO Chains | knowledge/classes/ato-chains/SKILL.md | see class | cheatsheets/jwt-oauth.md |
| 4 | OAuth / JWT / SAML | knowledge/classes/oauth-jwt-saml/SKILL.md | see class | cheatsheets/jwt-oauth.md |
| 5 | Client-Side "Encryption" and Signing | knowledge/classes/client-crypto-signing/SKILL.md | see class | cheatsheets/crypto-replica.md |
| 6 | Race Conditions | knowledge/classes/race-conditions/SKILL.md | see class | cheatsheets/race-logic.md |
| 7 | SSRF / Request Forgery | knowledge/classes/ssrf/SKILL.md | see class | cheatsheets/http.md |
| 8 | Subdomain Takeover / Dangling DNS | knowledge/classes/subdomain-takeover/SKILL.md | see class | cheatsheets/target-recon.md |
| 9 | Enumeration and Info Oracles | knowledge/classes/enumeration-oracles/SKILL.md | see class | cheatsheets/http.md |
| 10 | XSS / DOM | knowledge/classes/xss-dom/SKILL.md | see class | cheatsheets/payloads.md |
| 11 | Mobile-Specific Classes | knowledge/classes/mobile-classes/SKILL.md | see class | cheatsheets/adb-frida.md |
| 12 | Public Cloud Storage and Object Exposure | knowledge/classes/cloud-storage/SKILL.md | see class | cheatsheets/cloud-storage.md |
| 13 | Injection | knowledge/classes/injection/SKILL.md | see class | cheatsheets/injection.md |
| 14 | Frontend Bundle Mining | knowledge/classes/frontend-bundle-mining/SKILL.md | see class | cheatsheets/payloads.md |
| 15 | Business Logic Abuse | knowledge/classes/business-logic/SKILL.md | see class | cheatsheets/race-logic.md |
| 16 | Firebase Remote Config as the Prod->Dev Pivot | knowledge/classes/firebase-remote-config/SKILL.md | see class | cheatsheets/firebase.md |
| 17 | Jenkins Anonymous CLI | knowledge/classes/jenkins-cli/SKILL.md | see class | cheatsheets/http.md |
| 18 | Dev-box service patterns after a pivot | knowledge/classes/dev-box-services/SKILL.md | see class | cheatsheets/http.md |
| 19 | Firebase RTDB Path-Scoped Rules | knowledge/classes/firebase-rtdb-paths/SKILL.md | see class | cheatsheets/firebase.md |
| 20 | GraphQL Surfaces | knowledge/classes/graphql/SKILL.md | see class | cheatsheets/graphql.md |
| 21 | Infra Exposure | knowledge/classes/infra-exposure/SKILL.md | see class | cheatsheets/http.md |
| 22 | Tenant Takeover / Mass Assignment | knowledge/classes/tenant-takeover/SKILL.md | see class | cheatsheets/payloads.md |
| 23 | API Cache Buckets and CDN Hosts | knowledge/classes/api-cache-buckets/SKILL.md | see class | cheatsheets/cloud-storage.md |
| 24 | Client-Side AES "morgan" Pattern | knowledge/classes/client-aes-morgan/SKILL.md | see class | cheatsheets/crypto-replica.md |
| 25 | No-Arg / Cursor Semantics and Parameter-Space Chaining | knowledge/classes/no-arg-cursor/SKILL.md | see class | cheatsheets/graphql.md |
| 26 | Cloud and Vendor Consoles Behind App Config | knowledge/classes/cloud-vendor-consoles/SKILL.md | see class | cheatsheets/secrets-recovery.md |

Routing rule: the lead board's skill field names the class (playbook:N-<slug>);
rh_recall indexes every class file by keyword; the Confirm phase opens exactly
one class file, runs its workflow, closes its claims in VERIFICATION.md.

# Playbook: Vuln Classes Ranked by Bounty Payout (outside hunter, public targets)

Ranked by expected payout per hour for a solo hunter, not by CVSS. Every class has the same structure: Signal, Detection workflow, PROOF BAR, FP TRAPS (the N/A killers), Chain tree, Bounty notes. The submit gate (SKILL.md, bin/rh_validate.py) governs everything below. Case patterns are technique distillations from real hunts, sanitized to target archetypes - no client names travel with the skill.

Doctrine: a vuln class is a search strategy, not a submission. Findings are born when a real request meets a real response and impact is demonstrated. Mobile surfaces systematically pay better than web: most hunters never decode the APK, so dupes are rarer. This is an app-first playbook; the web classes serve the app's estate.

## Anti-patterns (wage killers)

- Submitting scanner output. Leads become submissions through manual proof only.
- Submitting stale data as impact. Recency-proof it or pivot.
- Stopping at "key is valid". Enumerate what the key DOES.
- One-endpoint proof when the credential is accepted by ten services. Lateral movement is the report.
- Stopping at the FIRST data hit. Parse the captured bytes: school buses inside the charter fleet, names inside telemetry, children's data inside a generic feed. Impact quantification is where severity comes from.
- Treating one environment's fix as the story. Test the same chain on every environment the bundle reveals (dev/stg/prod) - enforcement often exists on exactly one layer.
- Bulk-downloading PII. The record minimum, masked, plus scale-by-sampling keeps the account alive and the claim unanswerable.
- Skipping the negative control. A lone 200 is an anecdote; the differential is the proof.
- Skipping retests. Verified findings retest 2x before reporting.
- Skipping the chain matrix. A VERIFIED finding with an incomplete row is unfinished work.
- Reporting "blocked" without 3-way attribution. An opaque 4xx is an unresolved state, not a defense.
- Submitting unchained lows. Vault them, build the chain, submit the chain.
- Skipping the Self-Verify block. The operator verifies before anyone else does.

## Never-submit list (universal N/A bait)

Self-XSS; missing CSP/headers; clickjacking without demonstrated impact; version/banner disclosure; verbose stack traces alone; rate-limited SSH/brute-force without account compromise; CSRF on non-sensitive actions; open redirect without token/context leakage; scanner output as the finding; theoretical crypto weakness without a forgery; mixed content; directory listing without sensitive files; expired/abandoned subdomain without claimability.
