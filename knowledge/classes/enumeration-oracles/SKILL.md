---
name: rh-class-enumeration-oracles
description: >-
  Class 9 of the redhunting attack playbook: Enumeration and Info Oracles. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/http.md and close every
  claim through the verification ladders in verification.md.
triggers: enumeration oracles
---

## 9. Enumeration and Info Oracles (force multiplier)

Signal: login/forgot/register differentials, tracking endpoints, user lookup by phone/email, mail-server RCPT behavior, error-message specificity, timing differentials.

Detection workflow: pair every probe (known-valid vs known-invalid identifier); any consistent differential (status, timing, body shape, error text) is an oracle. Mail servers: the 550-vs-250 RCPT dialogue (QUIT before DATA, zero emails sent). Quantify: oracle + OTP-no-lockout + reset = targeting pipeline for ATO.

PROOF BAR: the differential pair in one capture block; repetition statistics for timing claims (3x, medians).

FP TRAPS: enumeration on a private/S2S endpoint (no attacker path); timing oracle from network jitter (repeat before claiming).
