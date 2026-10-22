---
name: rh-class-cloud-vendor-consoles
description: >-
  Class 26 of the redhunting attack playbook: Cloud and Vendor Consoles Behind
  App Config. Loaded by the Confirm phase when the lead board routes a lead of
  this class. Pair it with the command-level depth in
  cheatsheets/secrets-recovery.md and close every claim through the
  verification ladders in verification.md.
triggers: vendor console analytics push payment key
---

## 26. Cloud and Vendor Consoles Behind App Config

Signal: vendor SDK keys in the app config or JS corpus: analytics (Amplitude/Segment/Mixpanel), crash reporting, push vendors (OneSignal/Airship/Braze), payment SDK public keys, CI tokens, dashboard URLs referencing admin panels.

Detection workflow:
1. Classify the key by vendor from its shape and the SDK around it (cheatsheets/secrets-recovery.md section 4 table).
2. Find the vendor REST surface: each vendor exposes send, list/read, and config capability families on documented endpoints.
3. Capability-matrix with one harmless call per family: send (own device/own contact only), read (apps list, users, segments: one page, masked, counted), write bounded (never execute against real customer data).
4. Sibling keys in the same vendor org get the same battery: org-level sprawl was real; one key often reaches more than one app/workspace.
5. Billable abuse quantified from one call's semantics (per-call cost x observed rate), never by generating traffic.

PROOF BAR: the capability matrix (CAN proven by 200s, CANNOT bounded by 403s, each with a transcript) and the read-API page (masked sample, counts). The vendor read APIs (user/segment dumps) are frequently the bigger story than the send capability.

FP TRAPS: client-identifier-only keys (every capability 403s with correct spoofed context: a note, not a finding); demo-tier keys on a separate workspace (prove the workspace linkage before claiming); payment SDK public keys that are public-by-design (only the secret side matters, and it never ships in the client).

Chain tree: vendor key > read APIs > user/segment census > org sprawl (sibling workspaces) > mass-impact framing; send capability > own-device proof > push-to-deeplink chain (knowledge/push-notifications.md).
