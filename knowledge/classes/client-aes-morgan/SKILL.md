---
name: rh-class-client-aes-morgan
description: >-
  Class 24 of the redhunting attack playbook: Client-Side AES "morgan" Pattern.
  Loaded by the Confirm phase when the lead board routes a lead of this class.
  Pair it with the command-level depth in cheatsheets/crypto-replica.md and
  close every claim through the verification ladders in verification.md.
triggers: client aes morgan
---

## 24. Client-Side AES "morgan" Pattern (vendor web stacks)

Signal: Nuxt/Vue vendor apps whose axios wrapper encrypts bodies with a passphrase derived from public material; wire shape `{data: CryptoJS.AES.encrypt(...)}` with "/"->"-" substitution; response envelopes `{data: "U2FsdGVkX1..."}`; a literal string (historically "morgan") concatenated onto the Authorization header inside a hash.

Detection workflow:
1. Find the wrapper in the JS corpus: CryptoJS.AES.encrypt plus a passphrase function reading the Authorization header.
2. Reconstruct the KDF offline: EVP_KDF (md5-based), Salted__ header, CBC (cheatsheets/crypto-replica.md section 3 is the working replica).
3. Decrypt a captured response envelope with the recovered passphrase.
4. Forge an encrypted request with the same construction and replay it through the capture front door, garbage-padding control in the same run.

PROOF BAR: the offline round-trip (captured payload decrypts to readable JSON, replica script in evidence) AND a forged envelope the server accepts with the garbage control rejected. The round-trip alone bounds the claim to a design weakness.

FP TRAPS: the "encryption" is not authentication: a valid forge AND garbage padding both accepted is itself the finding. Alone (no paired gate bypass) it lands LOW: report it only inside a chain.

Chain tree: decrypt capability > forged body accepted > the gate sitting behind the encrypted field (auth or validation bypass) > aggregate with the paired finding.
