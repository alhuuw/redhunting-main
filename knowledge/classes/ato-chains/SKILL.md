---
name: rh-class-ato-chains
description: >-
  Class 3 of the redhunting attack playbook: ATO Chains. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/jwt-oauth.md and close every
  claim through the verification ladders in verification.md.
triggers: ato chains
---

## 3. ATO Chains (auth bypass, OTP abuse, password reset: P1 anywhere)

Signal: guest tokens with id=0, tokens in URLs, deterministic signatures, login/forgot differentials, OTP endpoints, session fixation, staging secrets identical to prod.

OTP (audit SEND and VERIFY as separate surfaces): SEND - trigger to YOUR OWN number/inbox (arrival is the only dispatch proof), repeat to attempt-count, probe limit dimensions (per-target vs per-account vs per-IP - limits often bind the wrong key). VERIFY - uniform wrong codes at minimum attempts (config 10), watch lockout/counters/invalidation, then feasibility math (attempts/sec x window x keyspace = takeover time or the claim dies).

Password reset: token in URL? entropy? expiry? host-header/X-Forwarded-Host injection into reset links (reset to your controlled host, capture the token, complete takeover on the victim account you own)? enumeration via response differentials?

Tokens: decode alg/claims (exp, iss, aud, scope, role); identify signing material (static key in binary/JS, key derivation from public value); forge minimally ONE claim at a time; staging-signed against prod; negative control garbage signature (if garbage passes: signature not verified at all, bigger finding). Fingerprint ladder: when a gateway 401s everything, replay the app client's exact User-Agent/headers (okhttp UA is a public constant in the APK; WAF client-fingerprint rules are sometimes the ONLY gate - test browser-UA, okhttp-UA, curl-UA in one matrix). Token-mint marker binding: grep the decompiled corpus for request constructors with literal URL markers to extract every marker string (each is a scoped capability), then matrix mint-marker x endpoint. ERR_SID_CHANGED-style device-binding errors are PASSWORD-VALIDITY PROOFS - record and continue, do not submit as ATO alone.

PROOF BAR: the forged/guest token performs an action or reads data requiring a real user, captured 200 + negative control in the same block. OTP: arrivals on your own inbox + uniform-failure transcript + feasibility math. Reset: the takeover completed on an account you own.

FP TRAPS: OTP "result:true" without arrival (dispatch APIs lie); client-side lockout counters (server behavior is the only truth); reset token in URL but single-use + short expiry (reportable as LOW unless referrer leakage proven); device-binding error mistaken for a failed login (it is the opposite - the credential check passed).

Case patterns (sanitized archetypes, all real):
- 16 uniform verify failures with no lockout feeding a password-reset ATO chain with the feasibility math included: the math (attempts/sec x window x keyspace) is what converts "no lockout" into "takeover of a chosen account in N days".
- OTP bombing to arbitrary numbers via a forged JWT plus a deterministic md5 signature scheme, messages actually received on the operator's own numbers: dispatch proven by arrival, never by result:true.
- request_otp to any number with only a 45-second cooldown: per-target limit bound to the wrong dimension (time, not identity) - rotate the unbound dimension and the throttle is decorative.

Chain tree: no-lockout verify > reset chain > ATO > pair with enumeration for targeting > aggregate with any leaked credential class.
