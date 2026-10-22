---
name: rh-class-cloud-storage
description: >-
  Class 12 of the redhunting attack playbook: Public Cloud Storage and Object Exposure. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/cloud-storage.md and close every
  claim through the verification ladders in verification.md.
triggers: cloud storage
---

## 12. Public Cloud Storage and Object Exposure

Signal: bucket names in strings/JS, presigned URL patterns, storage hosts in recon, MinIO consoles, S3/GCS/R2 endpoints, apicache/CDN-host buckets behind web-bundle bases.

Detection workflow: anonymous list (GET /?list-type=2, v2 continuation-token pagination - v1 marker silently re-serves page 1 and fakes scale); assess object dates (recency!) and classes (exports, backups, uploads, logs, cached API responses); ONE small sample or HEAD+Content-Length; sensitivity via filter queries with match-zero result; upload path (poisoning: RAG knowledge bases, code, CI artifacts).

PROOF BAR: listing + one sample + dates + filter-match-zero proof. Sample and mask; scale by sampling, never by dumping.

FP TRAPS: abandoned buckets (old-only dates, no write path) are notes; public-by-design CDN buckets; cached API responses without direct identifiers (report the design flaw, bound the claim with recency); demo bundles shipping DEMO Firebase keys (different project - prove the project id first).

Case patterns (sanitized archetypes, all real):
- S3 bulk-export buckets carrying voucher archives: listing + one masked sample + LastModified dates + filter-match-zero on the sensitive prefix = the block; scale by key-census counts, never by downloading the archive.
- MinIO anonymous listing with an open console on :9001: the console HTML captured verbatim is the transcript; listing proves read, console proves the management plane.
- Unauthenticated upload into a RAG knowledge-pipeline bucket: a harmless marker document placed through the same ingest path the pipeline reads = knowledge-poisoning capability, a documented integrity impact without touching real corpus content.
- A "dev" bucket referenced by PROD code: prod-bundle grep reference + same-day LastModified + private-class prefix census + 16-byte Range GET on the most sensitive object defeats the "it's just dev" discount in one evidence block (the full ladder: cheatsheets/cloud-storage.md sections 3-4).

Case pattern: an apicache bucket behind the app's web bundle: 1000 keys / 334 user UUIDs of cached per-user API responses, all stale - recency-bounded Medium; the design (authenticated API responses cached to a public bucket) was the finding.
