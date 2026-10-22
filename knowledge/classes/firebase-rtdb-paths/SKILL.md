---
name: rh-class-firebase-rtdb-paths
description: >-
  Class 19 of the redhunting attack playbook: Firebase RTDB Path-Scoped Rules. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/firebase.md and close every
  claim through the verification ladders in verification.md.
triggers: firebase rtdb paths
---

## 19. Firebase RTDB Path-Scoped Rules (root-401 is NOT a verdict)

Signal: Firebase databaseURLs in the corpus (several per project); root listing returning 401; live data channels (SSO handoff, OTP state) whose literal path strings appear in the client bundle.

Detection workflow: rules cascade, a subpath rule leaves root denied while every leaf under it is fully open.

PROOF BAR: PUT 200 + read-back exact + DELETE 200 (artifact) at the leaf while root shallow stays 401; SSE frame captured live.

Root listing denied does NOT mean the database is locked. Rules cascade; a subpath rule {".read": true, ".write": true} leaves root 401 while every leaf under it is fully open.

Protocol: mine the client bundle (mobile OR desktop asar) for literal path strings - the client code tells you exactly which paths the app USES, and those are the paths where open rules bite; probe those exact leaves (GET, then PUT with a pre-registered artifact, read-back, DELETE); if the path is a live data channel (SSO handoff, OTP state), ALSO test SSE: curl -N -H "Accept: text/event-stream" <path>.json - an unauth SSE listener receives real-time `event: put` frames and always beats a consume-and-delete client. Same project, multiple databaseURLs: initializeApp can register several (main + "-desktopsso"); enumerate all of them from config blobs.

Proof bar: PUT 200 + read-back exact + DELETE 200 (artifact) at the leaf while root shallow stays 401; SSE frame captured live.
