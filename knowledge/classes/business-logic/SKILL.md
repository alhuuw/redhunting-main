---
name: rh-class-business-logic
description: >-
  Class 15 of the redhunting attack playbook: Business Logic Abuse. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/race-logic.md and close every
  claim through the verification ladders in verification.md.
triggers: business logic
---

## 15. Business Logic Abuse (fintech gold, least competition from scanners)

Signal: anything with money math: balances, coupons, refunds, withdrawals, quantity/price in request bodies, multi-step checkout, state machines (order status), referral credits, currency or unit fields.

Detection workflow: map the workflow state machine from the app UI/API; enumerate states (skip steps - call step 3 directly; repeat steps - replay step 2; reorder); negative and zero values on quantity/amount/price; swapped units (cents vs units, currency A vs B); integer overflow at boundaries; mass-assignment probes on writable objects (role, isAdmin, is_paid, approved, balance, amount, status + app-specific fields); race the state-changing endpoints (class 6).

Domain classics: e-commerce (client-side prices, stackable discounts, coupon reuse, negative stock, checkout races); finance (double refunds, negative amounts, fee bypass, settlement IDOR, currency confusion); ticketing (seat price tamper, double booking, ticket transfer); logistics (tracking IDOR, shipping fee manipulation, status skip); subscriptions (trial forever, downgrade-keep-features, invoice manipulation).

PROOF BAR: sequential control (1 success) + the abused sequence (N successes / wrong state) with final-state verification on YOUR OWN accounts. Money-movement claims bounded: a rejected final settlement is a state-differential proof, not a payout demo.

FP TRAPS: cart shows negative total but checkout rejects downstream (the display is fiction - complete the flow to the payment boundary); coupon "accepted" client-side (server recomputes at settlement - capture the settlement request/response); test-mode payment gateway (identify the environment before claiming); "logic bug" that is actually a race (10 sequential runs never reproduce = race protocol).

Chain tree: single abuse > repeatable > cross-account (gift/transfer) > monetary cap estimate > aggregate (usually P1 on payments).
