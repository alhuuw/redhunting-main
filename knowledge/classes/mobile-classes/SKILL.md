---
name: rh-class-mobile-classes
description: >-
  Class 11 of the redhunting attack playbook: Mobile-Specific Classes. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/adb-frida.md and close every
  claim through the verification ladders in verification.md.
triggers: mobile classes
---

## 11. Mobile-Specific Classes (the low-competition surface)

### 11a. WebView / Deeplink chains
Signal: autoVerify hosts, OneLink/app.link attribution domains, exported activities, custom schemes, addJavascriptInterface, JS bridges, file access in WebViews, shouldInterceptRequest overrides.
Workflow: manifest triage; .well-known/assetlinks.json per autoVerify host (broken/default JSON is reportable as-is via the HTTP response); static chain construction (redirect entry > WebView load > bridge exposure > native handlers); ON-DEVICE execution (adb intent fire, logcat, callback host, screenshots) - static chains are hypotheses until executed; deeplink parameter fuzzing per handler; CF-challenged webview URLs verified in a REAL browser (navigate, wait 8-10s for the challenge, read the final URL + body - first-party consumers redirect to error pages with distinct codes per failure reason, and that post-challenge page is the actual verdict).
PROOF BAR: on-device execution evidence of the full chain, or the assetlinks HTTP proof for the configuration finding.
FP TRAPS: bridge methods that only log; file:// access without a reachable exfil path; scheme hijack when the app checks the host.
Chains: open redirect > webview+bridge > file read > token theft > payment activity abuse. Account-deletion links carrying tokens in the URL (leakage via history/referrer) are their own finding.

### 11b. Cert-pinning bypass into traffic analysis (technique, not a finding)
Bypass (frida objection or hook script) reaches the API surface; the findings live in what traffic reveals (hidden endpoints, admin routes, weak id semantics). Pinning bypass is reportable only when the target scopes client-hardening.

### 11c. Secrets/keys in APK: class 5 in the mobile pipeline. Firebase special cases: RTDB root 401 is NOT a verdict (path-scoped rules leave leaves open - probe the exact literal paths the client uses: GET, then PUT-readback-DELETE with an artifact, SSE listener on live channels); Remote Config fetch (class 1); same project, multiple databaseURLs; Maps/LLM/payment keys via restriction checks (X-Android-Package + X-Android-Cert with the raw-hex SHA-1 and package - both public inside the APK; a 200 with headers while naked calls fail = restriction is public information).

### 11d. Insecure data storage / logging
Sensitive data in logcat, SharedPreferences plaintext, world-readable files; adb backup analysis (allowBackup=true > ABE unpack > grep for tokens/PII - a standalone finding on targets that scope local data theft). Reportable only when policy scopes it; otherwise chain material.

### 11e. Push notifications: full class in knowledge/push-notifications.md (FCM legacy/v1, vendor keys, token leakage, push-to-deeplink chains). Proofs on your OWN device token only.
