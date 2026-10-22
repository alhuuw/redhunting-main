---
name: rh-class-idor-bola
description: >-
  Class 2 of the redhunting attack playbook: IDOR / BOLA. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/http.md and close every
  claim through the verification ladders in verification.md.
triggers: idor bola
---

## 2. IDOR / BOLA (the bread and butter: highest hit-rate, pays everywhere)

Signal: integer /{id}, user_public_id, trxID, reservation_id, barcode/tracking number, UUID v1 (timestamp-leaking), predictable base64 identifiers, incrementing order numbers in email links, GraphQL connection cursors.

Detection workflow:
1. Inventory every object reference: path params, query params, body fields, headers (X-User-Id), GraphQL variables.
2. Range probe: 1, 100, 500, 1000, 10000, 99999999. Classify each response: 200-full, 200-empty, 404, 403, redirect. Build the response-signature table.
3. Differential with two owned accounts: A reads B's object (the identity check the discipline demands).
4. Random sample to the record minimum (config, default 10), masked, fixed seed.
5. Scale by status-code-only sweeps (bodies discarded). Recency: newest record timestamps, active statuses; gold-standard artifact write-read-back.
6. Write path: update/delete as owner-confused (write-BOLA pays 2-3x read). Versioned tiers: v2 open while v1 correctly 401s is a recurring regression - sweep every api/vN.
7. Architectural oracle: a NotFoundException AFTER auth passed = missing authorization layer. A domain error ("currentUser.id must not be null") proves the request passed every gate and died in business logic - stronger than any single record.

PROOF BAR: response-signature table + masked record set at minimum + newest-record dates + negative control (garbage token 401/403 in the same block) + A-vs-B differential transcript.

FP TRAPS:
- 200 with empty shells (soft-deleted rows): check content, not status.
- Public-by-design objects (catalog items): confirm the object class is user-scoped.
- Self-IDOR (reading your own object with your own token): the most common N/A in the class; the two-account differential is the disproof.
- Stale datasets: newest-record timestamp outside the recency window downgrades to nothing.

Case patterns: prescription detail by integer ID - 100/100 random IDs returned full records, zero 401/403, current-year data. Hotel/flight booking walk: 135 bookings with real values plus 101 employee profiles, sequential IDs. Tracking by public barcode plus postal code: recipient PII plus a signed JWT with no account at all. A/B account differential for write-BOLA: A creates object, B attacks it, read-back as A - the default setup for every write hypothesis.

Chain tree: read one > read many > recency proof > write path > privilege objects (admin records) > cross-tenant > aggregate with enumeration for targeting.

Bounty notes: maps to the standard broken-access-control class; write-BOLA and cross-tenant are P1-grade on fintech/health. GraphQL IDOR via node ids or connection reuse is under-hunted.
