---
name: rh-class-oauth-jwt-saml
description: >-
  Class 4 of the redhunting attack playbook: OAuth / JWT / SAML. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/jwt-oauth.md and close every
  claim through the verification ladders in verification.md.
triggers: oauth jwt saml
---

## 4. OAuth / JWT / SAML (protocol bugs, high payout density)

Signal: /oauth/authorize, redirect_uri params, state params, id_token handling, /callback routes, SAMLResponse XML, JWT in any header/cookie/storage, SSO handoffs, one-click flows.

Detection workflow:
1. redirect_uri mutation ladder: subdomain (callback.evil via takeover or registration), suffix tricks (target.com.evil.com vs target.com/.evil.com), userinfo tricks (@, backslash), path traversal (/callback/../../), fragment injection (#), open-redirect chain (an intermediate redirect the target's own page allows), parameter pollution (duplicate redirect_uri).
2. state: missing (CSRF into session-fixation-like account linking), reused, reflected.
3. code interception: token/code in URL fragment vs POST, referrer leakage on the callback page, postMessage origins.
4. JWT: alg none family (none/None/nOnE), RS256->HS256 confusion (re-sign with the public PEM as HMAC secret), weak HS256 secret (wordlist crack), missing exp/aud/iss (prove by minting and replaying), claim confusion (sub from id_token trusted in a different context). Cross-surface prefix matrix when replaying a token family: Authorization: <raw>, bearer <raw>, Bearer <raw>, <stripped-jwt> - APIs that return "bearer eyJ..." inside the value are already-prefixed; a 302-with-empty-body usually means wrong prefix shape, not dead token.
5. SAML: XSW signature-wrapping variants, comment injection into NameID, Audience/Recipient relaxation.

PROOF BAR: code/token captured by your controlled origin (interaction proof), or the forged token accepted with a real 200 + negative control. SAML: the wrapped assertion accepted by the SP with attacker-chosen NameID.

FP TRAPS:
- redirect_uri fragment-only modification: the browser ignores everything after #; the parser difference exists, the exploit does not land. Disproof: capture the request the OAuth server actually sees.
- "state missing" without demonstrable session-linking impact: targets N/A it unless the linking attack is shown.
- alg:none rejected by every modern library: test it, but expect the ladder (confusion, weak secret) to be the real story.
- Open redirect the OAuth allowlist actually blocks: the intermediate chain must be captured end-to-end.

Chain tree: code theft > token mint > API access as victim > full ATO > (SSO) cross-service lateral. OAuth bugs are chains by definition; the chain IS the severity.

Bounty notes: check every OAuth client the target runs (mobile app, web, desktop) - enforcement differs per client, and the weakest client defines the finding. redirect_uri bypass = P1-P2 typical; full code-interception ATO = P1.
