---
name: rh-class-subdomain-takeover
description: >-
  Class 8 of the redhunting attack playbook: Subdomain Takeover / Dangling DNS. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/target-recon.md and close every
  claim through the verification ladders in verification.md.
triggers: subdomain takeover
---

## 8. Subdomain Takeover / Dangling DNS

Signal: NXDOMAIN answers to CNAMEs pointing at cloud services (herokuapp, s3 website endpoints, github.io, fastly, pantheon, zendesk, shopify, intercom), stale DNS after migrations, "domain not found" pages on live subdomains.

Detection workflow: enumerate subdomains (crt.sh, subfinder, wayback); resolve all; flag CNAME chains; probe the target service; where the CNAME target says "no such app/site/bucket", check if the namespace is claimable (registration with YOUR OWN account); claim it, serve a harmless proof file (HTML with your handle), capture the subdomain serving your content; unclaim after evidence capture.

PROOF BAR: pre-claim NXDOMAIN/no-app capture + claimed-subdomain-serving-your-content capture in one evidence block.

FP TRAPS: CNAME to a provider that no longer offers public registration (unclaimable = note only); "takeover" of a domain you already control via your own DNS (nonsense); wildcard DNS answering everything (verify the actual CNAME chain, not the wildcard).

Chain tree: takeover > cookie/session theft on the parent domain (parent-scoped cookies, OAuth redirects trusted by JS window.opener/postMessage) > phishing-grade credibility > aggregate.

Bounty notes: plain takeover of an unused subdomain is P3-P4 unless chained into session theft on the parent domain. Check what the parent trusts before submitting.
