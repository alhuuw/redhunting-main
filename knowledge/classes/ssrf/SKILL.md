---
name: rh-class-ssrf
description: >-
  Class 7 of the redhunting attack playbook: SSRF / Request Forgery. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/http.md and close every
  claim through the verification ladders in verification.md.
triggers: ssrf
---

## 7. SSRF / Request Forgery

Signal: url/image/webhook/callback params, PDF generators, importers, proxy endpoints, internal hostnames in client configs, gopher/file schemes in fetchers.

Detection workflow: point the parameter at a callback host you control (interactsh/OOB) - interactivity is the first proof; cloud metadata (169.254.169.254 family, per-provider variants) via GET only, read one harmless field (timestamp/instance-id prefix), never exfiltrate credentials you do not need; internal mapping via response differentials (open/closed/refused) and error text; scheme and redirect abuse (redirects to internal, gopher/file where the fetcher allows).

PROOF BAR: callback capture, or a harmless metadata field, plus the differential map. Blind SSRF to internal ranges without a data path is P3-P4; metadata credential path documented (not executed) is P1.

FP TRAPS: DNS rebinding claimed but not demonstrated (capture two resolutions minimum); redirect-based "SSRF" where the initial fetch is denied (chain must be captured end-to-end); internal 200 on a health endpoint (reachability is not impact).
