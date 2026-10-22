---
name: rh-class-no-arg-cursor
description: >-
  Class 25 of the redhunting attack playbook: No-Arg / Cursor Semantics and
  Parameter-Space Chaining. Loaded by the Confirm phase when the lead board
  routes a lead of this class. Pair it with the command-level depth in
  cheatsheets/graphql.md and close every claim through the verification
  ladders in verification.md.
triggers: no-arg query cursor semantics parameter space
---

## 25. No-Arg / Cursor Semantics and Parameter-Space Chaining

Signal: list/search endpoints whose client call-site passes no page/pageSize; parameters the server appears to ignore (identical responses across values); cursor shapes (seq, after, marker) riding list responses.

Detection workflow:
1. No-arg test: fire the app's own query shape WITHOUT pagination arguments; when the call-site sends none, the server may return the entire corpus in one response. The full raw response IS the scale evidence; parse locally with rh_impact.py and read back with the second account to rule out per-user caching.
2. Parameter 3-way: rh_differential.py per candidate (valid/garbage/empty). IDENTICAL = parameter ignored, impact multiplies by its cardinality (bounded sweep next). VALIDATED = enforced. MIXED = the parameter filters, chain via its values.
3. Cursor semantics: a response carrying a cursor (seq/after) means an enumerable history; an enumerable archive outranks a live snapshot, prove which with a two-read differential.
4. Bounded sweep: on an IGNORED parameter, sweep just enough values to count distinct datasets (the census number is the claim, never the hoard).

PROOF BAR: the differential trio captured in one run, the no-arg response saved whole when it is the corpus, the distinct-dataset count from the bounded sweep, second-account read-back.

FP TRAPS: "no pagination" that is actually per-user caching (always re-read with account B); an "ignored" parameter that only matters cross-tenant (sweep the tenant axis, not just values); response-identical because a CDN layer serves them (check cache headers before claiming the server ignores anything).

Chain tree: ignored parameter > cardinality sweep > per-value datasets > mass-impact framing; no-arg corpus dump > record census + PII population > aggregate with data classes.
