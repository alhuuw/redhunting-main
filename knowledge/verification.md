# Verification: Follow-Through to the Ceiling, Always

The bar: a claim is written only after its follow-through ladder is exhausted, every step has a raw transcript, and the claim states exactly what was demonstrated. There is no such thing as a "potential" finding here: the word is banned in every output this skill produces. An unverified idea is a lead on the board, never a sentence in a summary.

The single hard line: no large-scale destruction. Small-scale verification is the JOB, not an exception: an RCE claim gets a command executed (harmless command, marker file, read-back, cleanup); a takeover claim gets demonstrated control of an owned test account; lateral movement gets replayed against every discovered service. We verify with our own accounts, our own tokens, our own devices, our own artifacts - and we clean up what we create.

## Evidence boundaries (what a capture does NOT establish)

Adopted from the REA investigation model: every artifact carries its identity, integrity, and its LIMITATIONS explicitly. Correlation is never causation; a missing observation never establishes that two runs behaved the same way; an unverified upstream weakness stays a lead, never a claim.

- Every rh_capture.py run writes a machine-readable sidecar next to the transcript (`<slug>_<tag>.evidence.json`): artifact identity (sha256, bytes), request identity, tool, timestamps, manifest reference, and a LIMITATIONS block naming what the single request/response pair cannot prove (repetition, ordering, cache behavior).
- Findings state what the evidence does NOT establish: a Limitations section (or an explicit bounded-unknown line). rh_validate Q11 enforces this; a claim that cannot name its boundary gets deleted, not softened.
- Self-verify runbooks end with the negative space: what the replay proves, and which conclusions it cannot launder in (upstream chain weaknesses, repetition semantics).
- Decode/recon snapshots are reused only for byte-identical artifacts with an identical toolset (rh_apkrecon, state/apkrecon-snapshots.json); anything else re-runs. Cached results are never presented as fresh observation.

## The universal ladder (every finding, every class)

1. State the claim as a testable sentence ("this key can read every customer record").
2. Find the ladder for the artifact class (below, or write a new one in VERIFICATION.md).
3. Run EVERY rung, capturing each as a raw transcript (rh_capture.py; curl -v / mitmproxy / Burp / adb logcat where the surface demands it). No rung gets skipped because "the previous one probably implies it".
4. A rung that fails gets attributed before it is recorded as a boundary (the 3-way rule below).
5. The negative control runs in the SAME capture session (garbage credential, no credential, wrong account).
6. Retest the verified chain (config: 2x), separate files.
7. Write the ceiling statement: exactly what was proven, and the exact boundary where proof stops. Only then does the claim enter SUMMARY.md.

A finding whose ladder stops early is not "partially verified": it is a lead. Delete the sentence, keep the lead, continue the ladder when the blocker resolves.

## Ladder library (per artifact class, explicit)

### Leaked GitHub token / PAT

1. `curl -s -H "Authorization: token <TOKEN>" https://api.github.com/user` - identity behind the token (200 = valid; record the login, the plan, the scopes header if present).
2. `curl -s -H "Authorization: token <TOKEN>" https://api.github.com/user/repos?per_page=100&visibility=all` - what repos are reachable (private included). Record count and visibility split.
3. Dry-run clone: `git ls-remote https://<TOKEN>@github.com/<org>/<repo>.git` - reachability without materializing anything.
4. Clone the SMALLEST reachable repo once: `git clone https://<TOKEN>@github.com/<org>/<small-repo>.git` (the transcript is the proof; delete the clone after).
5. Inside the clone: `grep -rniE "(secret|password|api[_-]?key|token|credential|AKIA|AIza|ghp_|gho_)" --include="*" .` plus check `.github/workflows/*.yml` for `secrets.` references (CI secret presence - names, not values) and `.git` history: `git log --all --diff-filter=D --name-only` for deleted sensitive files.
6. Org-level reach (if org token): `curl -s -H "Authorization: token <TOKEN>" https://api.github.com/orgs/<org>/repos?per_page=100` and `/orgs/<org>/members` - private-org reach multiplies impact.
7. Look for MORE secrets the access reveals: `.env` files, `docker-compose.yml` environment blocks, `application.yml`, Terraform state references. A CI-secret presence + a write-scope token = the write story: DO NOT execute pushes; document scope, try a canary-free dry run (`git push --dry-run` on a throwaway branch ONLY if scope is confirmed write and the repo is the target org's; otherwise stop at documented capability).
8. Ceilings: read-only scope = read ceiling (with repo counts + secret presence). Write scope proven but not exercised = "write capability demonstrated by scope + dry-run; not exercised" in the boundary line. Never say "could push code" - either the dry-run proved it or it is a lead.

### Leaked cloud key (AWS / GCP / Firebase / vendor)

1. Identify the key class from the prefix (AKIA = AWS long-lived, ASIA = temporary, AIza = Google API family, service-account JSON = GCP full identity).
2. One harmless call per service to map capability: AWS (sts get-caller-identity, then s3 list-buckets, then iam list-users ONLY if policy allows - every 403 is recorded as a boundary), GCP (oauth2 token mint, then the service list for the project the key belongs to), Firebase (the class-1/16 battery: RTDB leaf paths, RC fetch, storage rules probe).
3. The capability matrix is the deliverable: CAN (each proven by one 200), CANNOT (each proven by one 403), with per-call transcripts. "Valid key" appears nowhere; "key reads 12 partner credentials" does.
4. Lateral: the same key against every sibling service in the same project/tenant (the 401s bound the blast radius, the 200s are the story).
5. Cost ceiling: one billable call maximum per service class (a single model list, a single geocode) - quantified as per-call cost x observed rate, never spammed.

### RCE / command execution

1. Harmless command first: `id` / `whoami` / `uname -a` in the injection point; capture the output verbatim in the transcript (command output IS the evidence; "the command ran" without output is nothing).
2. Marker file: write a uniquely-named file to the web root or temp (`echo <random-marker> > /tmp/<marker>` then `curl https://<host>/<marker>` or read it back through the same injection). Write + read-back in separate transcript lines.
3. Cleanup: delete the marker through the same primitive; capture the deletion and a 404 read-back. Cleanup is proof of precision, not bureaucracy.
4. Boundary: if the command executes but output is blind (no echo), the proof is the OOB callback (command output piped to your listener) or the marker round-trip. Blind-without-callback is a lead, not a claim.
5. Never escalate beyond harmless commands: no recon of their internal network beyond the one host, no persistence, no lateral RCE. The marker round-trip IS the finding.

### Account takeover / session control

1. The victim is ALWAYS a test account you own (A attacks B, both under the random engagement identity).
2. Demonstrate control end-to-end: log in as the victim via the takeover path (forged token, reset flow hijack, session theft), then change ONE recovery attribute (password or recovery email) with a capture, then log in with the NEW credential from a fresh session. Three transcripts: takeover-login, attribute-change, fresh-login.
3. Restore the attribute afterward (cleanup log in the same evidence block).
4. The ceiling statement names the exact control demonstrated (which attribute, which flow) and stops there. "Full account control" without the attribute-change round-trip is a lead.

### IDOR / BOLA

1. A reads B's object (the differential transcript; A and B both owned).
2. Scale: random sample to the record minimum (config, 10), masked, fixed seed; status-code-only sweep for scale; bodies parsed for data classes with rh_impact.py.
3. Recency: newest record timestamps, active statuses, and (gold standard) a BB_-prefixed artifact created through the official flow then read back through the bug.
4. Write path: B mutates A's object; read-back as A; restore state. Versioned tiers: every api/vN swept.

### Secret in binary / bundle (APK, JS, asar)

1. Localize (file:line) and classify the secret class.
2. Replay against production through the capture front door - the minted token, the API call, the bucket list (class-1 ladders above).
3. Version bisection: 2-3 historical builds from the mirror; byte-identical marker across versions = measured no-rotation window; absence in the oldest build = positive control.
4. Capability matrix + lateral replay. A secret with zero working capabilities is a hygiene note, not a finding - that verdict is written only after the matrix.

### Push notification capability

1. Send to YOUR OWN device token only (extracted from your install); capture the 200 + message_id AND the on-device arrival (screenshot + logcat).
2. Negative control: garbage key -> 401. Wrong-project token -> arrival check fails (arrival, not status code, is the verdict).
3. Payload control: your data payload reaching the app's deeplink handler (on-device logcat intent trace). Sending to any token you do not own is a violation, full stop.

### Race / double-spend

1. Sequential control: 1 success, captured.
2. Concurrent burst: N successes, captured (barrier sync, your own accounts).
3. Final state delta: the balance/coupon/receipt count after the burst, from a fresh read.
4. The cap math (per-account, per-day) closes the claim.

### Takeover of dangling namespace

1. Pre-claim: NXDOMAIN / "no such app" capture.
2. Claim the namespace with your own account; serve a harmless proof file containing the random identity handle.
3. Capture the subdomain serving YOUR content.
4. Unclaim (delete the registration); capture the post-state. Parent-domain trust analysis (cookie scope, OAuth allowlists) completes the chain story.

### JWT / token forgery (playbook class 3/4)

1. Decode header + claims (cheatsheets/jwt-oauth.md section 1); record alg, exp, iss, aud, role/scope.
2. Identify the signing material: static key in the binary/JS, derivation from public value, RS256 public key (confusion candidate), weak HS256 (wordlist crack, offline).
3. Forge ONE claim change at a time (sub -> another owned account's id; role -> admin; exp -> future). Each variant replayed through the capture front door, negative control (garbage signature) in the same session.
4. The accepted forgery performing a real action (reads the admin list, acts as the other owned account) = the claim. Cross-surface prefix matrix (raw / bearer / Bearer / stripped) runs on every replay surface before any "dead token" verdict.
5. Boundary: which claims are trusted (matrix of accepted vs rejected forgeries) bounds the impact honestly.

### OAuth authorization code (playbook class 4)

1. Register your own client (or use the app's public client id); set up the authorize URL with a redirect_uri from the allowed ladder.
2. Walk the redirect_uri mutation ladder (subdomain, suffix, userinfo, path traversal, fragment, open-redirect chain, parameter pollution) - each variant captured with its Location header.
3. A variant that lands the code on YOUR controlled origin (callback host hit, or Location pointing at it) = interception capability.
4. Complete the chain on your own accounts: exchange the code at the token endpoint (capture the 200 + token), call one API as the victim-test account.
5. state analysis (missing/reused/reflected) and postMessage-origin audit on the callback page complete the session-linking story.

### Session token / cookie replay

1. Capture the token/cookie from YOUR account A through the app's own flow (login transcript).
2. Replay across EVERY surface: mobile API, web SPA, desktop client, sibling services - all four header shapes from the prefix matrix.
3. The acceptance map (which surfaces accept, which reject) IS the finding's blast radius; the A-vs-B differential on the accepting surfaces proves cross-user capability.
4. Session lifetime probe: token after logout (server-side invalidation or not), token after password change, token expiry behavior - each a capture.
5. Boundary: session-fixation-adjacent behaviors get documented, not weaponized beyond the owned-account proof.

### Vendor API key (analytics / push / CRM / payments)

1. Identify the vendor from the key shape + the SDK in the corpus (class table in cheatsheets/secrets-recovery.md section 4).
2. One harmless call per vendor capability family: send (own device/own contact only), read (apps list, users, segments), write-bounded (never execute on real customer data).
3. The read APIs are frequently the bigger story (user/segment dumps): one page, masked, counted - never paginated hoarding.
4. Billable abuse quantified from one call's semantics (per-call cost x observed rate), never by generating traffic.
5. Matrix closes the claim; sibling keys in the same vendor org get the same battery (org-level sprawl was real).

### Leaked presigned URL / OOB callback (SSRF completion)

1. The callback host you control gets the request: the hit log line IS the dispatch proof (timestamp, source IP, path).
2. Metadata path: one harmless field only (instance-id prefix, timestamp); credential paths get DOCUMENTED and never executed.
3. Internal mapping: response differentials (open/closed/refused) with a bounded sweep; error text that names internal hosts.
4. The chain into internal admin surfaces is documented; the marker file round-trip (verification.md RCE ladder) only when the surface executes commands.

## The 3-way attribution rule (before ANY "blocked" verdict)

An opaque 4xx/5xx is an UNRESOLVED STATE. Before writing any boundary:

(a) YOUR port: prove the request byte-exact against the client's own construction - serialization keys from @SerializedName (not Java field names), number types (int vs float), identifier formats (E.164 +, countryCode concatenation, UUID case), HTTP method from the annotation (@PUT vs POST), and the body actually sent ({} and "" are falsy in Python - assert the transcript contains it). For crypto ports: recompile the DECOMPILED algorithm as a standalone Java program with fixed salt/nonce, run one vector, diff byte-for-byte against the Python port. MATCH = the port is proven, the rejection is the server's.
(b) MISSING PRE-STATE: prior step, linked resource, enrolled identity, session binding - test each hypothesis with a capture.
(c) SERVER ENFORCEMENT: only (c) is a boundary, and it needs its own differential (the enforcing layer hit directly, rejecting FOR THAT REASON, the error naming or isolating the check).

A generic error that survives structurally different request variants is cause UNKNOWN - the boundary line says so. Never write "the OTP layer holds" from static code reading: the layer is a boundary only after it is exercised end-to-end and rejects you for that reason.

## Evidence pack rules (checked by rh_verify.py evidence)

- RAW TOOL OUTPUT only: rh_capture transcripts (request as sent, response as received, UTC, tool signature line), curl -v, mitmproxy exports, Burp transcripts, adb logcat, HAR. Hand-typed or AI-summarized evidence is banned - it is indistinguishable from fabrication and kills the pack's credibility.
- Binary bodies byte-exact (.bin + sha256 recorded). SHA256SUMS.txt regenerated after every capture run and covering every file.
- Negative controls and retests captured in the same session as the positive probe.
- Every VERIFICATION.md row cites its transcript file. The gate (rh_validate.py Q6) fails on open rows.

## Self-Verify (the operator's own eyes)

Every finding ships a Self-Verify block (rh_verify.py snippet): the curl one-liner, the browser URLs (paste, observe, screenshot), the adb sequence for mobile/push. The operator runs it before writing the report. If the operator cannot verify in under 5 minutes, the evidence design is wrong, not the operator.

## Retraction discipline

When a later run breaks an earlier claim (cache masquerading as data, per-user isolation fooling the sample, a "no lockout" that was per-IP), retract in the same minute: strike the row in VERIFICATION.md, mark the ledger entry retracted with the reason, learn-back into the journal. One fast retraction preserves every other claim's credibility; a defended wrong claim poisons the whole pack.
