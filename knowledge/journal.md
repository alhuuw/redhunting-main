# Journal: the learn-back book (dated, append-only)

Append-only, one entry per learned technique. This file exists so rh_recall finds dated prior art that does not yet belong in a playbook class. When an entry hardens into a class (battle-tested, proof bar validated), promote it into playbook.md and leave a stub line here pointing at the class number.

Entry format (keep every field, one screen max):

```md
## YYYY-MM-DD - <technique in one imperative line>
- Engagement type: mobile / web / infra / mixed (anonymized, no target names)
- Signal: what made us look
- Technique: the exact commands or code shape that worked
- Proof bar: what evidence converted it (or why it stayed a lead)
- Status: LEAD / PROVEN / RETRACTED / PROMOTED to playbook class N
```

Rules:
- No target names, no org names, no raw secrets. Techniques and shapes only.
- A RETRACTED entry is as valuable as a PROVEN one: it kills a repeat detour.
- After every target round (workflow.md: after the round closes), append what was new.
- Techniques that repeat across two engagements get promoted into playbook.md.

## 2026-09-01 - Vendor an MCP server by writing a stdlib stdio JSON-RPC loop

- Engagement type: tooling (skill development, first external contributions)
- Signal: two community PRs (merged as #1, #2) arrived following an undocumented but repeatable format
- Technique: the repeatable contribution shape is: one folder tools/mcp/<name>/server.py (pure Python stdlib, hand-rolled initialize/tools/list/tools/call dispatch, newline-delimited JSON-RPC on stdin/stdout) + a doctor row in rh_doctor.py + a table row and registration snippet in knowledge/mcp-tools.md + a SKILL.md routing line. No mcp SDK dependency, no machine paths, config via env var override.
- Proof bar: py_compile plus a live stdio handshake test (printf initialize + tools/list into the server, parse the JSON out). That is enough to trust the server before registering it.
- Status: PROVEN (both PRs merged, jadx handshake verified live: 5 tools listed)

## 2026-09-01 - Ghidra on macOS via brew needs JAVA_HOME pointed at the keg-only JDK

- Engagement type: tooling (environment setup for native RE)
- Signal: brew formula ghidra installed but analyzeHeadless failed with "Unable to locate a Java Runtime" even though openjdk@21 was present as a dependency
- Technique: brew installs openjdk@21 keg-only (not linked, java stub cannot see it). Fix: export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home in the shell profile. Ghidra 12.x requires JDK 21+.
- Proof bar: analyzeHeadless prints the JDK banner and usage text with JAVA_HOME set; it errors without.
- Status: PROVEN

## 2026-09-01 - semgrep-mcp wrapper hard-fails without a Semgrep account; CLI suffices

- Engagement type: tooling (MCP wiring)
- Signal: uvx semgrep-mcp died in server lifespan even with the semgrep CLI installed
- Technique: semgrep-mcp v0.9.0 runs `semgrep --pro --version` at startup, which requires semgrep-core-proprietary (login or SEMGREP_APP_TOKEN). Same doctrine as nuclei: scanner = leads only, so the CLI is sufficient; keep the MCP entry disabled.
- Proof bar: reproduce with a stdio initialize handshake; the traceback names ensure_semgrep_available and the --pro check.
- Status: PROVEN (decision: CLI-only, same reasoning as nuclei-MCP skip)

## 2026-09-01 - MCP servers that proxy a host GUI app only live with the host running

- Engagement type: tooling (architecture pattern)
- Signal: burp bridge and ghidra-mcp bridge both fail fast when their host app is down
- Technique: treat GUI-backed MCP bridges as on-demand: the bridge exits when the host is unreachable, and the agent restarts it next session. Before a round needing Burp or Ghidra, start the host app first (Burp with MCP enabled on 9876; Ghidra GUI with the GhidraMCP plugin server started on 8080). Cache jshookmcp's large npx deps before a hunt; first download is slow.
- Proof bar: handshake tests with and without the host running.
- Status: PROVEN

## 2026-09-02 - Attribute every rejection 3-way before recording any "blocked" verdict

- Engagement type: mobile + payment-gateway API (carrier consumer app, payment router backend)
- Signal: a write-path probe rejected with "Invalid Phone Number" was nearly recorded as a server-side validation layer; attribution proved it was our own payload missing the E.164 '+' prefix the real client always sends - the corrected retry proved the OPPOSITE verdict (write accepted, Critical). Later, the debit step rejected 21 operator test numbers with an opaque "amount mismatch" across 6 structurally different variants; the honest verdict is BOUNDED-with-UNKNOWN-cause, not "OTP layer holds".
- Technique: before blaming the server: (1) byte-exact port check - Gson SerializedName keys not field names, int vs float, E.164 '+' prefix (literal countryCode+phone concat), HTTP method from the annotation (@PUT cancel on a POST-shaped API), assert the body was actually sent (Python falsy-body bug: `cond and body` drops '{}'); (2) error differential across structurally different variants - a message that never changes is generic, cause UNKNOWN; (3) test missing-prestate hypotheses (prior step, linked funding source, enrolled identity); (4) exercise the suspected defensive layer directly instead of inferring it from client code.
- Proof bar: the retracted-then-flipped verdict (documented retraction, corrected-format reproduction 3x, 21-number batch) is the proof the method works; the debit boundary shipped as UNKNOWN-cause because no variant isolated the check.
- Status: PROMOTED to the verification doctrine (verification.md), playbook class 1 case pattern, mobile.md section 9 porting checklist

## 2026-09-02 - A "dev" storage bucket referenced by PROD code is production exposure, not a dev artifact

- Engagement type: mobile + web hybrid (B2B marketplace APK + API estate)
- Signal: anonymous listing on a `*-dev-assets` bucket returned 200 with 1000 keys/page while the sibling prod buckets returned 403 - and the prod seller SPA hardcoded object URLs from the dev bucket in its shipped OG meta tags
- Technique: when a dev-suffixed bucket is publicly listable, before discounting it as dev-only: (1) grep ALL shipped front-end bundles (prod SPAs included, not just the app) for the bucket name; (2) check newest object timestamps for same-day writes; (3) count private-class prefixes (KYC docs, tax cards, uploads, users) vs public-class (banners, category icons); (4) prove byte-level read with a 16-byte Range GET on the most sensitive object instead of downloading it. The prod-reference + same-day-freshness pair defeats the "it's just dev" discount in one evidence block.
- Proof bar: listing 200 + tax-card Range GET 206 (PNG magic) + prod SPA bundle reference + newest object 6.5 hours old - shipped as a 7.5 High with full chain matrix; write path bounded by 403 PUT + 404 read-back.
- Status: PROVEN (promoted to playbook cloud-storage class)

## 2026-09-03 - Gate tools parse scaffold templates: placeholder IDs must stay inert

- Engagement type: mobile (Flutter/AppGuard, national social-insurance app, no-adb HTTP-only)
- Signal: the verify gate reported a phantom finding with 0 raw files - the scaffold's HTML-comment template placeholder was parsed as a real finding because finding parsing runs on raw text before comment-stripping
- Technique: two failure classes compound here: (1) template placeholder IDs matching the finding-id pattern create phantom findings - rename scaffold placeholders to non-matching ids; (2) round logs written with bold text are invisible to heading-regex parsers - consolidation rounds must re-state findings under real `### [ID] VERIFIED - title` headings with per-finding chain-matrix blocks (no empty cells) and re-captured negative controls whose filenames contain "control".
- Proof bar: gate went FAIL (phantom finding + 0 gated) -> PASS exit 0 (3 findings, 13+13+9 raw files) after placeholder rename + Round-6 consolidation + control re-capture.
- Status: PROVEN (gate-tooling gotcha; remember for every round close-out)

## 2026-09-03 - Packer-blocked Flutter app: recover the signing stack from the last pre-packer build via CDN versionCode probing

- Engagement type: mobile (Flutter+AppGuard, national social-insurance app, no-adb HTTP-only)
- Signal: current build's libapp.so is AppGuard-mangled (dynsym stripped, ~75% of snapshot encrypted) - blutter dead, request construction unreachable. blutter ALSO failed on the old build until a Dart-version mismatch in DartApp.cpp was patched (dump-table diagnostics for shared_field_table removed - they exist only for newer Dart APIs).
- Technique: (1) the packer was added at a specific version - walk the mirror CDN directly with `HEAD https://d.apkpure.net/b/XAPK/<pkg>?versionCode=N` (the redirect's filename reveals the version; N-1 down to the history floor, ~0.8s pacing to avoid F5 resets); (2) grab the last build BEFORE the packer, download the XAPK from the redirect target; (3) blutter it for full pp.txt + asm recovery; (4) read the URL/header/signing construction straight from the RestAsync/Config/Authentic disassembly; (5) verify every recovered constant still exists in the CURRENT build's readable string pool before replaying against prod.
- Proof bar: complete signing stack (cons-id, HMAC-SHA256 over "consId&timestamp", user_key, AES-CBC master key + IV wrapping BOTH request params and response envelopes) replayed against the live prod gateway: unsigned control 401 -> signed 200/204 on the participant-by-NIK route; server error envelopes decrypt with the recovered key.
- Status: PROMOTED to mobile.md section 4 as the standard packer fallback

## 2026-09-03 - Firebase Remote Config as an unauthenticated credential vault (RC fetch leaks prod secrets)

- Engagement type: mobile (MSME finance super-app with KYC-gated payments)
- Signal: static map showed the app consumes payment-provider credentials from Firebase Remote Config at runtime; both RC API keys + appId are plaintext in the APK
- Technique: the Remote Config REST fetch (POST firebaseremoteconfig.googleapis.com/v1/projects/<proj>/namespaces/firebase:fetch, header X-Goog-Api-Key, body {appId, appInstanceId}) accepts a ZEROED instance id with no auth. Anyone holding the public APK values gets the full production config - credential-grade values included. After fetching, walk ALL entries with a nested value-pattern sweep (password|secret|credential) rather than grepping key names, then replay every recovered credential against its consumer service the same session with a garbage-credential control pair.
- Proof bar: RC fetch 200 (273KB, 344 entries) with both baked keys, garbage-key control 400; recovered KYC-provider credentials replayed: setup 200, media-transaction write 200 (even with garbage signature), signed-url 200 + live RS256 JWT that loads the real branded KYC web app; garbage creds -> 401. 10.0 chain.
- Status: PROMOTED to playbook class 16 ("Remote Config is not config - it is a credential channel")

## 2026-09-03 - Paranoid string obfuscation: port DeobfuscatorHelper byte-exact from smali, not jadx

- Engagement type: mobile (same engagement; a KYC-bureau SDK hides header names/values behind io.michaelrocks.paranoid)
- Signal: jadx shows `Deobfuscator$<module>$Release.getString(<long>)` everywhere; the decoded strings are what you need (API header names, crypto algorithm names, endpoints)
- Technique: port `DeobfuscatorHelper.getString` + `RandomHelper` to Python from the SMALI, not the Java - jadx renders `(short)` casts ambiguously. The trap is Java short sign-extension: `(long) short` in `next()` sign-extends to 64 bits, and the final packing depends on it. Extract the chunks array from the jadx Java (unicode escapes are fine), verify chunk lengths, then decode with the long keys from call sites. tools/paranoid/paranoid_decode.py is the reusable port.
- Proof bar: decoded the header set + crypto names - the recovered headers were accepted by the live bureau endpoint (400-after-auth with org id leaked vs garbage-cred 401).
- Status: PROVEN

## 2026-09-03 - Prove a crypto port with a standalone Java reference vector, then blame the server

- Engagement type: mobile (same engagement; liveness submit rejected with 422 "Invalid Media Signature")
- Signal: after porting the client's AES-GCM media encryption (HKDF-ish 1000-iteration XOR chain) the server still rejected; the attribution rule says attribute before calling it a control
- Technique: re-compile the DECOMPILED algorithm as a standalone Java program (javax.crypto, deterministic fixed salt+nonce passed as args), run one fixed vector, diff against the Python port byte-for-byte. MATCH => the port is provably byte-exact, which converts an opaque 422 into an ATTRIBUTED verdict: the rejection is server-side content validation, not your port. Then sweep 6+ structurally different signature constructions (interleave on/off, md5-over-encrypted, bare-b64, timezone shifts, distinct images) - identical errors across variants = the gate is the media content, not the signature.
- Proof bar: Java/Python vector identical (Base64 output MATCH); 6 variants -> identical 422; garbage signature ALSO accepted at the transaction-mint stage -> final verdict: signature header unverified, content validation holds. Saved the write-completion boundary as an honest positive control.
- Status: PROMOTED to mobile.md section 9 checklist ("port verification vector before any rejection verdict")

## 2026-09-04 - A local DNS sinkhole (0.0.0.0) is NOT a BLOCKED verdict: rotate vantage via public DNS + pinned IP

- Engagement type: mobile (same engagement; analytics hosts)
- Signal: three analytic API hosts resolved to 0.0.0.0 from the box; stdlib and curl_cffi failed identically -> almost wrote BLOCKED-vantage for all three
- Technique: `dig <host> @8.8.8.8` resolved every one of them normally - the 0.0.0.0 was the LOCAL resolver policy. Rotate vantage: fetch the A record from public DNS, then request with the IP pinned (`curl --resolve host:443:IP`, or raw socket with correct SNI). curl verbose transcripts and a raw-socket script both satisfy the raw-evidence rule.
- Proof bar: one host reached via pinned IP -> both baked keys DEAD server-side ("Invalid API key", 400) - an honest NEGATIVE that would have shipped as "untested"; a second host's verbose=1 differential exposed an edge that returns success for ANY well-formed token (bounded UNCONFIRMED); a third returns empty-200 for every path including nonexistent ones (UNRESOLVED, attributed to edge behavior).
- Status: PROVEN (audit of my own round caught 3 premature BLOCKED verdicts; never write BLOCKED from one resolver's answer)

## 2026-09-04 - apkcombo.com is the version-bisection fallback when apkpure.net is CF-challenged

- Engagement type: mobile (same engagement; secret-age proof for the leaked material)
- Signal: apkpure.net /versions page returns 403 "Just a moment" for stdlib, curl_cffi chrome124, AND Jina; the vendored apkpure CLI's get_app_his_version returned version_list:[] (the documented API-empty failure)
- Technique: apkcombo.com serves the same version history WITHOUT the challenge under curl_cffi chrome124: `/app/com.<pkg>/old-versions/` lists every version + release dates. The per-version download page embeds direct CDN links wrapped as `href="https://apkcombo.com/d?u=<base64url>"` - decode to the pureapk CDN (time-limited tokens; the embedded c= param carries vn/vm/filename - parse it for provenance). Then run the same-signer check (androguard) before diffing, and bisect markers with byte-exact `in blob` checks across dex+libs+resources (resources.arsc strings are often UTF-16 - check both encodings).
- Proof bar: two historical builds downloaded with SHA256 provenance; same signer across all 3 builds; 21-marker matrix measured: leaked material unrotated across the measured window; HMAC key + bureau SDK absent in the oldest build (positive control - the pipeline CAN ship without them).
- Status: PROMOTED to mobile.md section 1 (second mirror fallback)

## 2026-09-05 - Time-boxed sprint protocol: a visible deadline drives discovery rate, not exhaustion

- Engagement type: mobile+web (deviceless, 30 findings, 7-hour single engagement)
- Signal: operator demanded a time-budget race. Discovery rate exploded once the clock became a visible constraint: 15 findings in 4 hours pre-sprint, 15 MORE in 90 minutes of time-boxed sprints.
- Technique: every sprint turn begins `date "+%H:%M:%S"` and states deadline + minutes remaining (rh_clock.py automates this). The pressure forces priority triage: skip enumeration theater, go straight to schema-oracle -> differential -> verify. Sprint closes with a wrap-up log regardless of findings state.
- Proof bar: 15 findings in the time-boxed window vs 15 in 4 unstructured hours. Correlated: operator engagement (live feedback per finding) + visible clock = the compounding loop. Also: findings-per-minute RISES late in the sprint because surface maps are already built - early rounds are investment, late rounds are harvest.
- Status: PROMOTED to workflow.md sprint protocol (the sprint cannot be abandoned; wrap is mandatory)

## 2026-09-05 - GraphQL "Did you mean" error = free schema oracle on introspection-blocked gateways

- Engagement type: mobile+web (19 GraphQL services behind an allowlist-blocked introspection)
- Signal: `{ __schema }` was blocked but field-not-found errors returned "Cannot query field X. Did you mean Y, Z?"
- Technique: probe ANY field name on a blocked gateway; the validation error leaks the 3 closest REAL field names. Iterate: wrong-name -> suggested names -> correct name -> next level (args via "argument X of type Y is required"). This reconstructs entire mutation input shapes without introspection. On ONE public endpoint the `__type(name: "...")` meta-query worked UNAUTHENTICATED (worth probing on every /public/ path sibling).
- Proof bar: reconstructed live schema for 12 services (bundle was 2.11.2, live was 2.13.12 - drift!) and the input shape of a mutation purely from error oracles; used it to execute the first anonymous mutation write.
- Status: PROMOTED to playbook class 20 (error-oracle schema reconstruction)

## 2026-09-05 - RTDB: root-denied does NOT mean path-denied (Firebase rules cascade downward)

- Engagement type: mobile (4 Firebase RTDB projects + 1 SSO project)
- Signal: shallow root listing returned 401 Permission denied on the SSO database - almost closed it as locked
- Technique: test the EXACT leaf path used by the real client flow (found by code-reversing the desktop Electron asar: `/remote-auth/<authCode>`). Rules like {".read": true, ".write": true} at a SUBPATH leave root denied but the leaf fully open. Always mine the client bundle for the literal path strings before concluding a database is locked.
- Proof bar: PUT/GET/DELETE on remote-auth/<code> all 200 unauthenticated while root stayed 401. SSE EventStream listener on the same leaf path ALSO worked (Accept: text/event-stream) - real-time push of victim tokens to an unauthenticated listener, beating the desktop's consume-and-delete.
- Status: PROMOTED to playbook class 19 (Firebase path-scoped rules)

## 2026-09-05 - JWT "bearer " prefix is a VALUE inside the token, not a header convention

- Engagement type: mobile+web+desktop (one auth family across 3 client types)
- Signal: a valid token failed a password-change call with 401 "Unauthorized" despite being freshly captured
- Technique: the login API RETURNS "bearer eyJ..." as the token VALUE (prefix included). Client A (mobile) sends raw; client B (web fetch) needed `Authorization: <full-value>`; client C (desktop) ADDS its own prefix. When replaying across surfaces, try BOTH: raw-value header AND stripped-JWT header. A 302-with-empty-body usually means wrong prefix shape, not invalid token.
- Proof bar: same JWT 401 with one prefix, 200 "ok" changepwd with the other. Cost 20 minutes of misattribution.
- Status: PROMOTED to playbook class 4 (auth header prefix matrix)

## 2026-09-05 - Watermark proof: non-destructive signed writes beat "trust me" in disputes

- Engagement type: mobile+web (vendor demanded proof-of-modification, dismissed chain demos as social engineering)
- Signal: the vendor said "prove you can modify, do not soceng" - they wanted server-side state change they could verify in their own database, not a video of my own account
- Technique: place short text markers via ALREADY-PROVEN unscoped mutations into (a) my own objects and (b) the STAFF account from the leaked corpus (bookmark via setBookmark(userId), counter via RTDB PUT, notification row via mutation). Read-back EVERY mark via a DIFFERENT account/session to prove persistence + cross-visibility. Hand over the exact artifact ids (BookmarkId, node paths, row ids) so they verify in their own database - their own database becomes the evidence.
- Proof bar: 8 marks placed, all read-back exact, 2 visible in the web UI (screenshots), staff-account bookmark visible to any user via the mass-read bug (two bugs in one artifact). The vendor's own DB rows are undeniable.
- Status: PROMOTED to playbook class 24 (watermark protocol)

## 2026-09-05 - REST auth gate and GraphQL auth gate are SEPARATE (302 vs 200 on same host)

- Engagement type: mobile+web (one api host serves both REST and 19 GraphQL services)
- Signal: REST endpoints redirected to /auth/401/ (302) on bad tokens while GraphQL returned 200 with {"message":"Unauthorized"} in-band - and SOME GraphQL queries needed NO auth at all
- Technique: never assume one surface's auth verdict for another. Probe: (1) REST unauth, (2) REST bad-token, (3) GraphQL per-SERVICE unauth (each /xxx/graphql has its own gate), (4) GraphQL per-OPERATION (queries may be public while mutations 401, and vice versa - one public mutation was found fully anonymous-executable).
- Proof bar: one service path = fully anonymous (reads + writes + introspection), sibling path = 302, gateway = in-band Unauthorized. Three different gates on one host family.
- Status: PROMOTED to mobile.md section 14 (per-service, per-operation auth matrix)

## 2026-09-05 - Playwright as visual-evidence engine (not just automation)

- Engagement type: web (login portal v-if form bug blocked normal automation)
- Signal: the org wanted screenshots; the portal's email form had a render bug (v-if never true) making normal fill impossible
- Technique: (1) force-enable disabled buttons via DOM (removeAttribute + classList.remove + click) - the same Vue event fires; (2) for login flows, call the app's OWN Vuex store dispatch + component methods directly - you execute their real code, not a bypass; (3) screenshot per stage: portal-with-attacker-URL, logged-in state, token-in-store, attacker-read, final ownership. For broken thumbnails (their prefix bug), set img.src to the STORED db value and screenshot - the URL is theirs, the renderer is theirs, the failure is theirs.
- Proof bar: 11 screenshots across the full ATO chain + watermark proof, all from real flows (their code, their domain, their DB values).
- Status: PROMOTED to web.md (visual evidence protocol)

## 2026-09-05 - account-vs-account differential: register a SECOND controlled account for cross-tenant proof

- Engagement type: mobile+web (all BOLA-write findings needed clean proof without touching third parties)
- Signal: proving "any user can delete any user's object" requires an OBJECT owned by someone else - but the rules forbid touching real users
- Technique: register account B (same API the app uses). A creates object -> B attacks it -> read-back as A. Full cross-account proof with ZERO third-party data. Cost: 10 seconds per account via tempmail. This is the DEFAULT for every BOLA-write hypothesis.
- Proof bar: 7 cross-account findings (forum delete, schedule delete, consult rewrite, bookmark delete, feedback spoof, notif inject, group-pay read) - all A/B, all 200 + read-back, zero collateral.
- Status: PROMOTED to playbook class 23 (A/B account differential)

## 2026-09-05 - Desktop Electron app is a first-class attack surface (asar extracts in 60 seconds)

- Engagement type: mixed (mobile-only scope assumption cost 3 hours)
- Signal: hunting JWT secrets failed in the mobile bundle; the desktop app's asar contained the SSO handoff flow that unlocked the Critical
- Technique: dmg -> hdiutil attach -> npx @electron/asar extract app.asar -> grep renderer.prod.js + main.prod.js for apiKey/databaseURL/firebaseConfig AND business logic (SSO flows, token handling). Desktop apps often embed SECOND Firebase projects and their own web configs. The SSO remote-auth pattern (web portal deposits session token into RTDB, desktop picks it up) is a token-theft primitive whenever the RTDB path is open.
- Proof bar: extracted full SSO flow, found a world-writable /remote-auth path, built the end-to-end ATO chain on it.
- Status: PROMOTED to mobile.md section 12 (always check for a desktop client)

## 2026-09-05 - mass-PII dump: a 30MB single response IS the entire corpus (no pagination needed)

- Engagement type: mobile (a report/bookmark query)
- Signal: query returned 29.6MB in ONE response with 195K records
- Technique: when a query has no page/pageSize args in the app's own call-site, test the NO-ARG variant first - if the server does not paginate, one request IS the dump. Save the full response as evidence (the raw file IS the proof of scale), parse locally for counts (distinct userIds, PII-field presence ratios) with rh_impact.py. Read-back with a SECOND account to rule out per-user caching.
- Proof bar: 195,777 records / 59,414 distinct users in one file, confirmed identical from account B.
- Status: PROMOTED to playbook class 26 (no-arg query test)

## 2026-09-06 - npx-spawned MCP servers stack across sessions: machine guard is now mandatory

- Engagement type: tooling (machine reliability incident during skill development)
- Signal: a 16 GB machine slid into memory exhaustion and thrashing mid-session; process census showed an npx-spawned MCP server (jshook) leaked across sessions: the old instance never died with its session, each new session spawned another, and duplicated npm-exec MCP servers stacked within a single agent session as well. Three-plus instances at hundreds of MB each.
- Technique: (1) census first: `/bin/ps -axo pid,ppid,rss,command` then group by normalized signature (npx cache-hash dirs collapse to a placeholder); (2) classify: ORPHAN (parent pid gone - nothing owns it, safe kill), DUPLICATE (same signature twice under live parents - the respawn-left-the-old-one-alive pattern), LIVE; (3) kill orphans always, kill the OLDER duplicate per signature with --dedupe (newest kept - it is the one the live parent reconnected to); (4) daemonize-aware: adb fork-server and frida-server parent to pid 1 by design, never count them as orphans; (5) never kill the guard's own ancestor chain. macOS gotcha: `ps -axo pid:1,ppid:1` is NOT valid (keyword errors, rc 0, output degrades to command-only columns) - use plain `pid,ppid,rss,command`.
- Proof bar: guard run live on the leaking machine: 34 watched processes holding 1973MB, 16 duplicates killed (~741MB), the orphaned codegraph child they left behind killed next (~485MB), plus the earlier jshook pairs (~350MB); memory free percentage recovered and budget verdict went FAIL -> OK. Reap log persisted to machine.log.
- Status: PROMOTED to the skill: bin/rh_guard.py (status/reap/budget), config machine section (limits + patterns), kickoff pre-flight and sprint-wrap post-flight run it automatically, mcp-tools.md carries the registration doctrine (vendored-first, npx servers enabled:false except for the sprint that needs them).
## 2026-09-05 — sayurbox sprint 1 (60 min, mixed, adb off) — 0 findings / 5 negatives / surface fully mapped

- RN plain-JS bundle (not Hermes) = full readable business logic. 178 GraphQL operations extracted verbatim — the schema is known without introspection.
- FP trap: Apollo's default uri is "/graphql" — the real endpoint was /graphql/v1, found ONLY by fetching the live web homepage with a browser UA and mining window.WWW_STARTUP_SETTINGS. python-stdlib UA got a 500 (SSR UA-sensitivity) that still leaked the anonymous JWT cookie. Lesson: on RN "www-shared" codebases, the web SSR page IS the config oracle.
- FP trap: secret_sweep HMAC/hits (encryptWithHmac/HmacSHA256) were TikTok SDK X-TT-Signature internals, not app signing. Attribute the owning package before promoting class-5.
- Session mechanics: www mints anonymous RS256 JWTs (cookie `token`, aud sayurbox-audience) on ANY hit, HttpOnly, 30d. GraphQL accepts no-cookie requests.
- RTDB root 401 (rules deny); app bundle has zero firebaseio refs — RTDB likely messaging-only. Don't burn time on class 19 without app-derived paths.
- Tool bug: rh_clock wrap post-flight guard call crashes (NameError: subprocess) — ran rh_guard.py manually instead. Guard found 15 duplicate MCP instances from other sessions (~150MB, under floor); left for operator decision, not reaped.
- Next sprint entry: tempmail A/B via web email auth (registerEnabled+emailAuthWebEnabled true), then class-20 gate matrix + BOLA with the 178-op corpus.

## 2026-10-06 - REA investigation-model adoption (morluto/rea)

- Tool itself (Hopper/Ghidra bridge) is redundant for us: jadx/blutter + vendored MCP + ghidra-bridge already cover the native side. What transferred is the EVIDENCE EPISTEMOLOGY: (1) machine-readable evidence envelope sidecar with explicit LIMITATIONS per capture, (2) validate gate Q11: a finding must state what its evidence does NOT establish or get deleted, (3) byte-exact snapshot cache for expensive decode (reuse only on identical sha256 + toolset), (4) machine-readable capabilities/doctor --json (missing optional tools are informational, never blocking).
- FP trap avoided: REA's honest-disclaimer doctrine ("does not claim to recover original source") maps to our proof-bar doctrine; do NOT adopt their recreation workflow (we hunt, we do not rebuild features).
