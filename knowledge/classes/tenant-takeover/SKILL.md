---
name: rh-class-tenant-takeover
description: >-
  Class 22 of the redhunting attack playbook: Tenant Takeover / Mass Assignment. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/payloads.md and close every
  claim through the verification ladders in verification.md.
triggers: tenant takeover
---

## 22. Tenant Takeover / Mass Assignment (B2B gold)

Signal: invitation flows, tenant-scoped object refs without tenant checks, role fields in writable payloads, self-service user management, UUID exposure in URLs.

Workflow: two owned tenants/accounts minimum (tempmail); inventory writable fields per endpoint; mass-assignment field list (role, isAdmin, is_paid, approved, balance, amount, status) + app-specific; invitation abuse (invite to a tenant you do not control, register via invitation, observe role granted); cross-tenant object refs by raw ID; 403 vs 422 differential as a per-field permission oracle.

PROOF BAR: the full chain executed against a tenant you control; the role-change response captured; victim-count claims only when the chain is demonstrably reproducible pre-auth.

Case pattern: register, POST invitations to an arbitrary company with no check, fetch invitations, register with the invitation UUID, become admin of any tenant - proven on three controlled tenants. Unauthenticated role-types endpoint dumping the entire RBAC model.

Chain tree: member > admin of own tenant > admin of arbitrary tenant > system-level roles > cross-tenant exfil > aggregate (usually Critical).
