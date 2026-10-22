---
name: rh-class-firebase-remote-config
description: >-
  Class 16 of the redhunting attack playbook: Firebase Remote Config as the Prod->Dev Pivot. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/firebase.md and close every
  claim through the verification ladders in verification.md.
triggers: firebase remote config
---

## 16. Firebase Remote Config as the Prod->Dev Pivot (generalizes to every Firebase-backed app)

Signal: an app whose runtime behavior or credentials come from Remote Config; RC API keys plus appId plaintext in the APK; payment or KYC vendor entries in config maps.

Detection workflow: the data planes can be fully locked (RTDB rules, Firestore, Storage denied, API keys properly restricted) and the estate still falls to ONE unauthenticated POST (the ladder below).

The data planes can be fully locked (RTDB rules, Firestore, Storage denied, API keys properly restricted) and the estate still falls to ONE unauthenticated POST: Firebase Remote Config fetch with the app's own public identity (API key + package + cert SHA-1, all from strings.xml/manifest) returns the full production config map.

- Exact working request shape (memorize this): POST https://firebaseremoteconfig.googleapis.com/v1/projects/<projnum>/namespaces/firebase:fetch?key=<google_api_key> with X-Android-Package and X-Android-Cert headers, body {"appId":"<google_app_id>","appInstanceId":"required_but_unused_value"} - the appId field is REQUIRED, appInstanceId is a placeholder, no FIS registration needed.
- The RC namespace is default-open: NOT covered by RTDB/Firestore/Storage rules, and the Android key restriction (package+cert) is satisfied by anyone who can read strings.xml.
- Mine the dump for: dev/staging hostnames (DuckDNS, *.dev, ip_-style keys), WebView tokens (vendor webviews with encrypted URL params), key-material entries (privateKey/publicKey), feature flags revealing hidden surfaces (kiosk versions, dev menus), vendor URLs (preview links in PROD config are a real thing), and literal CREDENTIALS (KYC-provider username/password/merchantKey entries - the credential-channel case pattern in class 1).
- Chain: RC dump -> dev hostname resolution -> full port scan (dev clusters run Jenkins, Node dev servers, DBs) -> anonymous-reachable CI -> known CVE.

PROOF BAR: the RC dump transcript (200 + entries) plus the pivot evidence (port scan + service fingerprint). The data planes being locked is NOT evidence the config plane is locked.
