---
name: rh-class-race-conditions
description: >-
  Class 6 of the redhunting attack playbook: Race Conditions. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/race-logic.md and close every
  claim through the verification ladders in verification.md.
triggers: race conditions
---

## 6. Race Conditions (concurrency: modern payout driver)

Signal: balances, counters, coupons, referral credits, booking hold/release, withdrawal flows, check-then-act patterns visible in responses, idempotency keys absent or client-controlled.

Detection workflow: baseline single-request behavior (sequential truth, YOUR OWN account) > parallel burst (20 to start, up to 100) with synchronized starts (barrier release or last-byte sync) > compare outcome counts vs sequential truth > final-state verification (balance delta, coupon count, email receipt count) > idempotency check.

PROOF BAR: sequential control (1 success) vs concurrent run (N successes), raw responses, final state on your own account; money bounded at the provider boundary.

FP TRAPS: N requests, N responses, 1 actual state change (optimistic locking worked - final state is the verdict); caching layers returning identical responses during the burst (check state, not bodies); "race" that is actually client retry logic (server-side counters tell the truth).

Chain tree: single double-spend > repeatable > cross-account (gift/transfer races) > monetary cap estimate > aggregate.

Bounty notes: P2-P1 on anything with money; report the monetary cap, not just the technique.
