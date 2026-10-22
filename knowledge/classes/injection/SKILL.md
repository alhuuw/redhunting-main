---
name: rh-class-injection
description: >-
  Class 13 of the redhunting attack playbook: Injection. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/injection.md and close every
  claim through the verification ladders in verification.md.
triggers: injection
---

## 13. Injection (SQLi / NoSQL / SSTI / Command)

Signal: string-concatenated queries in decompiled code, sort/filter params, template rendering of user input, export/report generators, legacy PHP surfaces, filename/zip/path params.

Detection workflow: time-based first (SLEEP equivalents), boolean second, error-based third; NoSQL operator injection ($gt, $ne, $regex in JSON bodies, Mongo filter patterns); SSTI math probes in fields that look rendered; every test bounded by a control payload in the same block.

PROOF BAR: time differential vs control (5.0s payload vs 0.16s control, repeated, medians reported), an error-based leak, or a boolean differential on real data. Flat responses are honest negatives - keep them as target intel.

FP TRAPS: WAF-blocked probes misread as patched; SQL "errors" from generic exception handlers; time-based claims from network jitter (repeat 3x).

Chains: detection > data read path (minimization: COUNT + one masked sample) > write path > OS-level > aggregate.
