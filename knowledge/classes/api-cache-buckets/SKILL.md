---
name: rh-class-api-cache-buckets
description: >-
  Class 23 of the redhunting attack playbook: API Cache Buckets and CDN Hosts. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/cloud-storage.md and close every
  claim through the verification ladders in verification.md.
triggers: api cache buckets
---

## 23. API Cache Buckets and CDN Hosts

Signal: web bundle defining server bases like cdn-host/apicache/-frontend-api-cache.

Workflow: collect every hardcoded base URL from the bundle; GET each root - `<?xml ... ListBucketResult` = public bucket; list-type=2 with proper continuation-token pagination (v1 marker re-serves page 1 - a trap that fakes scale); characterize content (per-user path shape data/<UUID>/<api-path>/index.json = cached per-user API responses); recency via LastModified range vs the config window.

PROOF BAR: listing + object GET + content characterization + recency. Stale-only cache bounds the claim - report the design (authenticated API responses cached to a public bucket) with the historical-exposure caveat, never as live PII.
