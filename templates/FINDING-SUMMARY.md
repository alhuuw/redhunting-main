---
id: <id>
title: "<imperative impact statement, not a class name>"
class: <class>
severity: <severity>
url: "<primary affected URL/endpoint>"
status: draft
---

# <title>

## Summary

2-3 sentences. What the attacker achieves, on which asset, at what scale. Present tense, active voice. Hedging words are banned (config verification.banned_words); if a word like that is needed, the claim is not ready: verify it in VERIFICATION.md or delete it.

## Impact (measured)

- Record count: N distinct records (per parameter value; note cardinality if the parameter is ignored)
- PII field population: which fields, on how many of N (%)
- Freshness: newest record timestamp vs capture date; oldest
- Scale: parameter values / tenants / environments returning distinct datasets
- Data classes present: (names, device ids, financial hints, health, children markers)
- Monetary cap (logic/race classes): max misuse per account/day with the math

## Reproduce

1. (numbered, copy-pasteable, under 2 minutes)

```bash
curl -i 'https://...'
```

## Root cause

The engineering reason (missing ownership check at the resolver, static secret in build config, unkeyed cache header).

## Limitations (what this evidence does NOT establish)

- repetition / ordering / cache semantics beyond the captured request-response pair (state which were probed, which were not)
- upstream chain weaknesses (a bypassed hop stays its own finding; name it or park it as a lead)
- anything that could not be run from the operator seat: record as an explicit bounded-unknown, never as a pass

## Fix

1. The fix
2. How to verify the fix closes it

## Self-Verify (operator runbook)

(generate: bin/rh_verify.py <target> snippet <this file>)

- Reproduce the core request (expect the same response class as the evidence):
```bash
<curl one-liner>
```
- Check in a browser (paste, observe, screenshot): <urls>
- On-device (mobile/deeplink/push): `adb logcat -d | grep -iE 'intent|deeplink|push|webview' | tail -50`
- Raw transcripts: evidence/raw/ - SHA256SUMS.txt verifies every byte (`shasum -a 256 <file>`).
