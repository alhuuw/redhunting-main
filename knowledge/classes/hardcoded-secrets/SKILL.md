---
name: rh-class-hardcoded-secrets
description: >-
  Class 1 of the redhunting attack playbook: Hardcoded Secrets in Mobile Binaries. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/secrets-recovery.md and close every
  claim through the verification ladders in verification.md.
triggers: hardcoded secrets
---

## 1. Hardcoded Secrets in Mobile Binaries (the mobile goldmine)

Signal: BuildConfig fields, @Headers("Authorization: Basic ..."), base64 blobs, long int-arrays in Dart source, AIza/AKIA/BEGIN PRIVATE markers, client_secret, keys in JS bundles, .env-style assets, Firebase google-services.json.

Detection workflow:
1. Decode per stack (mobile.md pipeline): jadx + apktool + per-stack dumper (blutter for Flutter, hbc-decompiler for Hermes).
2. Regex sweep over string dumps: cloud keys (AIza, AKIA, ASIA, GOOG), JWTs (eyJ...), basic auth blobs, private key PEM blocks, generic secret naming (secret, apiKey, signing, salt, iv).
3. Decode base64 candidates immediately. A basic auth blob is a client:secret pair.
4. Localize precisely: file:line for the report. BuildConfig.AUTH_TOKEN, Retrofit @Headers, Dart object pool indices, assets/app.config.
5. Classify the secret: OAuth client pair, symmetric key, cloud service account, API key, signing secret. The class determines the capability matrix.
6. Capability matrix per secret: what it CAN do (each proven by one real call) and what it CANNOT (the 403s are evidence too). Lateral replay: gateway, every sibling microservice, cloud APIs in the same project, admin consoles.

PROOF BAR: USE the secret against production (mint the token, call the API, list the bucket - captured 200), the completed capability matrix with raw responses, lateral replay results, billable abuse quantified (per-call cost x scale).

FP TRAPS:
- Public-by-design keys (Firebase web configs, Maps keys with working package+SHA-1 restrictions): still test them, restrictions fail more often than they hold; if they hold, matrix the cannot-do side and move on.
- Test/staging keys in prod builds: check which environment actually accepts them before claiming prod impact.
- Demo-bundle keys (separate project, usually dead): prove the project id before claiming linkage.
- Client-identifier-only keys: every capability 403s even with correct spoofed context - a note, not a submission.

Case patterns (sanitized, all real):
- OAuth basic pair (client:123456-grade) baked into a production APK: the minted client_credentials token was accepted by 5+ microservices with no scope checks. Mass disclosure followed. The chain, not the string, was the Critical.
- GCP service-account private key stored as a 4658-element int array inside Dart source: proven with a live oauth2 token mint plus secretmanager list. 10.0.
- Partner-hub clientSecret in a Flutter pool: an all:read token unlocked 12 partner credentials plus CRUD, proven with a 201 create followed by delete.
- AES key + IV + admin password in an Expo app config: minted a channel JWT; every mutation returned an auth error, so the finding was honestly bounded to read-only High. Boundary proof is proof discipline.
- Payment-router merchant credentials in a public APK (2026-09): login accepted (rotating 30-min sessions, registry-validated clientId), payment pre-init/init ACCEPTED with merchant session alone - but the first run was rejected "Invalid Phone Number" and nearly recorded as server validation. Attribution proved the rejection was OUR payload (missing E.164 '+' the real app always sends); the corrected port flipped the verdict to write-accepted Critical. The debit step rejected all 21 operator test numbers with an opaque "amount mismatch" across 6 structurally different variants - recorded as BOUNDED-with-UNKNOWN-cause, explicitly NOT "OTP layer holds".
- Secret-age proof via version bisection: acquire 2-3 historical builds from the mirror and diff secret markers. Byte-identical values across versions = a MEASURED no-rotation window, which converts rotation urgency from assumption to evidence; a clean OLD build doubles as a positive control (proves the pipeline CAN ship without the secret, killing the "unavoidable in Flutter" objection).
- Firebase Remote Config is a credential channel, not config: the app consumed KYC-provider credentials from RC at runtime while both RC API keys + appId sat in plaintext in the APK. The REST fetch (POST firebaseremoteconfig.googleapis.com/v1/projects/<p>/namespaces/firebase:fetch, X-Goog-Api-Key header, {appId, appInstanceId}) accepts a ZEROED instance id with no auth - anyone with the public APK reads the full production config. Sweep ALL entries with a nested value-pattern pass (not key names), then replay recovered creds same-session with garbage controls.

Chain tree: secret > token mint > read one sensitive object > scale > write path > **rejection attribution 3-way before ANY blocked verdict** > privilege chain > cross-service lateral > aggregate.

Bounty notes: secret-in-APK with a proven capability chain is reliably P1-P2. Version bisection via the mirror tools (apkpure MCP detail gives version + SHA-256 per version) upgrades urgency cheaply.
