# Chains: Red-Team Chain Doctrine (low + low + medium = critical)

Solo hunters get paid for impact, and impact lives at the END of chains, not at the first 200. The chain matrix (workflow.md) is the enforcement; this file is the recipe book. Read it before submitting any Medium or below: the question is always "what does this enable?"

## Chain doctrine

1. Every confirmed finding is a foothold, not a finish line. The escalation ladder (workflow.md) runs on everything.
2. Never submit a bare low that chains. Two options: build the chain now, or vault.md it with the exact chain hypothesis and revisit condition. The vault is the finding bank: low-sev ammo compounds interest across target rounds.
3. The chain IS the severity story: per-finding CVSS plus the aggregate chain position, both in the report (dual framing, reporting.md). Isolated findings score low; chains carry the impact.
4. Cross-surface pivots are the red-team edge: mobile -> API -> cloud -> web -> SSO. A secret from an APK becomes a mass-data chain on the web estate. Enforcement differs per surface; the weakest surface defines the finding.
5. Data from one finding feeds the next: leaked member codes feed IDOR sweeps; enumeration feeds OTP targeting; an internal hostname from a bundle feeds infra hunting. Chain findings into findings, not just surfaces.

## The recipe library (each ends in a payout-grade impact)

### 1. Enumeration -> OTP abuse -> password reset -> ATO
Enumeration oracle (login/forgot differentials) + OTP no-lockout (uniform failures, feasibility math) + reset flow weakness (token in URL, host-header injection) = account takeover on any targeted user, demonstrated on your own two accounts. Feasibility math converts "no lockout" into "ATO of user X in N days" - that math is the report's spine.

### 2. XSS -> token/session theft -> action forgery -> ATO
Reflected/stored XSS + what the JS context reaches (non-HttpOnly session, CSRF token in DOM, OAuth code in fragment) + a delivery path (crafted link for reflected; stored self-delivery for stored) = ATO. If session cookies are HttpOnly: chain via CSRF-token theft into state-changing actions; if nothing is reachable, the XSS is P4 - find the chain before submitting.

### 3. Open redirect -> OAuth redirect_uri relaxation -> code theft -> ATO
Open redirect on the target domain (or its trusted subdomain) used as an intermediate hop that the OAuth server's allowlist permits = authorization-code interception = token mint = API access as the victim. The redirect alone is P4; this chain is P1. PostMessage-origin confusion on the callback page substitutes for the redirect.

### 4. APK secret -> token mint -> lateral services -> mass data
Static secret in the APK (OAuth pair, service-account key, signing secret) -> minted token accepted by the gateway -> replay against every sibling microservice and cloud API in the same project (the 401s bound the blast radius, the 200s are the impact) -> record minimum + scale proof = mass disclosure. Capability matrix is the evidence shape.

### 5. IDOR read -> write path -> privilege escalation
Read-IDOR proven (A reads B) -> hunt the write sibling (PUT/DELETE on the same object family, method confusion, versioned-tier regressions: v2 open while v1 correctly 401s) -> write-BOLA as owner-confused -> admin objects -> cross-tenant. Write paths pay multiples of read paths.

### 6. SSRF -> metadata -> cloud role assumption
SSRF callback proof -> internal reachability differential -> cloud metadata (harmless field first) -> role/credential path documented and NOT executed -> (with target permission where policy demands) temporary credentials -> storage/database access. Document the boundary honestly: metadata reachability with the credential path documented is already P1 on most targets.

### 7. Subdomain takeover -> parent-domain session theft
Claimable dangling DNS -> serve your content on the subdomain -> what does the parent trust? (cookies scoped to the parent domain, JS window.opener/postMessage to the trusted origin, OAuth redirect allowlists containing the subdomain) -> session or code theft. Plain takeover without parent trust is P3-P4; with cookie theft it is P1.

### 8. Race -> double spend -> monetary cap
Race condition on balance/coupon/booking (sequential control vs burst) -> repeatable multi-spend on your own account -> cross-account transfer variant -> monetary cap estimate (max misuse per account/day) = the payout number. Readers act on numbers, not techniques.

### 9. Info oracle -> targeting pipeline -> ATO at scale
Phone/email enumeration + leaked user ids from any data finding -> OTP bombing reachability or credential stuffing feasibility (documented, not executed) -> ATO feasibility at scale. The math is the impact; the execution is the target's problem.

### 10. Bundle mining -> hidden surface -> unauth chain
SPA build manifest reveals /admin or staging API bases -> hidden endpoints never linked in UI -> auth-matrix probe (garbage token, no token, app fingerprint) -> unauth data or debug surface -> chain per classes above. Every environment the bundle reveals gets the same chain (enforcement often exists on exactly one layer).

### 11. Guest/weak token -> business logic -> money
Guest JWT with id=0 accepted by user endpoints (or token mint with marker binding) -> business-logic surface reachable pre-auth (negative quantities, workflow skips) -> monetary impact = P1 from two P3s.

### 12. Firebase path-scoped rules -> live channel -> real-time PII
RTDB root 401 (looks locked) -> leaf paths with {".read": true} discovered from the client's literal path strings -> GET/PUT artifact proof -> SSE listener (curl -N Accept: text/event-stream) receives real-time pushes -> live-data proof beats every staleness argument.

### 13. Push key -> own-token send -> deeplink payload control -> in-app execution (knowledge/push-notifications.md)
Leaked FCM legacy server key / vendor REST key in the APK -> push to YOUR OWN device token with a controlled data payload -> payload feeds the app's deeplink handler (read onMessageReceived in jadx to learn which data keys become intent URIs) -> tap on-device -> exported activity or WebView loads attacker content -> bridge/token theft. The push key alone is P3; push-to-deeplink-to-bridge is P1. Every send proof runs on your own token - never another user's.

### 14. Token disclosure -> targeting pipeline -> push-as-app phishing
User-object endpoint leaking OTHER users' push tokens (A-vs-B differential) + any send capability = targeted push AS THE APP to enumerated users: instant delivery, app-grade trust, attacker-chosen deeplink. Documented, demonstrated on your own token pair only.

## Vault discipline (the ammo bank)

vault.md per target, one entry per parked chain-component:
```md
### [V-03] OTP verify accepts unlimited attempts (P3 alone)
- Evidence: findings/RH-2/evidence/raw/
- Chain hypothesis: + enumeration oracle (V-01) + reset flow (untested) -> ATO
- Blocker: second account for the reset differential; revisit when tempmail completes registration
- Revisit trigger: any password-reset change in app updates
```
Rules: every vault entry has evidence, a chain hypothesis, and a revisit trigger. Retest the vault on every target change (retest.md). Low-sev findings submitted alone are wasted ammunition; the same finding inside a chain is the P1.

## Boundary honesty inside chains

- The chain ends where proof ends: "fund movement not proven; payer-OTP layer exists but was never exercised" is a valid P1-with-boundary. Overclaiming one link poisons every other link in the reader's mind.
- Attribution rule on every blocked link: 3-way (your input error / missing pre-state / server enforcement) before writing "blocked". Wrong E.164 formatting on a payment field has flipped BOUNDED verdicts to write-accepted Criticals.
- Chain into only what scope allows: the vault keeps the out-of-scope half of a chain documented-and-dormant until scope grows.
