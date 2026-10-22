---
name: rh-class-infra-exposure
description: >-
  Class 21 of the redhunting attack playbook: Infra Exposure. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/http.md and close every
  claim through the verification ladders in verification.md.
triggers: infra exposure
---

## 21. Infra Exposure (protocol interaction proofs)

PROOF BAR: the protocol transcript is the finding (the raw 250/550 dialogue, the console HTML, the version fingerprint) plus per-path CVE verification; unverified CVEs are surface notes, never claims.

Signal: non-standard ports open (7025/7071 mail stacks, 9000/9001 object storage, 8084 MQTT, 8243 gateways, 1025 SMTP, 8761/9xxx Java dev stacks), admin consoles, K8s API servers, database ports, out-of-date management planes.

Workflow: port sweep the in-scope IP estate (scope law first); banner-grab; fingerprint versions from public assets (versioned JS URLs, ETag patterns, error pages); CVE triage via the cve MCP tools; per-path verification of every candidate (404 = patched, 501 = wrong service; unverified CVEs are surface notes); protocol-level interaction proofs: SMTP/LMTP dialogue (MAIL FROM arbitrary sender 250 = spoof accepted; RCPT TO 550-vs-250 = user enumeration oracle; QUIT before DATA = zero emails; delivery proof only to your own test account - unauthenticated LMTP injection is post-filter delivery, the perfect BEC vector), MQTT anonymous subscribe (harmless topic first), storage listing, admin console HTML, Keycloak open registration + public admin console (prove with prefixed test accounts).

Case patterns (sanitized archetypes, all real):
- Unauthenticated LMTP mail injection on an internet-open port plus 550-vs-250 user enumeration with ZERO emails sent (QUIT before DATA): the raw dialogue transcript is the evidence; spoof-accepted (250 on arbitrary MAIL FROM) + post-filter delivery path = the integrity story, delivery demonstrated only to the operator's own mailbox.
- A CodePush-style PHP update panel public on a shared IP (OTA RCE chain surface): console HTML captured verbatim; the panel reachable unauthenticated is the exposure, the update-write stays documented-not-executed.
- Keycloak with open registration plus a public admin console: proven with two BB_-prefixed test accounts; registration open on the realm + console HTML = the management-plane exposure.
