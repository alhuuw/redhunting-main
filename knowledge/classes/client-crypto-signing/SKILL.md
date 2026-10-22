---
name: rh-class-client-crypto-signing
description: >-
  Class 5 of the redhunting attack playbook: Client-Side "Encryption" and Signing. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/crypto-replica.md and close every
  claim through the verification ladders in verification.md.
triggers: client crypto signing
---

## 5. Client-Side "Encryption" and Signing (forge the wire)

Signal: hardcoded AES key/IV, low PBKDF2 iterations, RSA-as-auth, salt:::iv:::b64 wire formats, encrypted bodies with static material, "signing" that is base64(hash(static + body)), an OkHttp interceptor adding X-*-Signature, a Secrets-style class loading libsecrets.so.

Detection workflow:
1. Recover the material: keys, IVs, salts, iteration counts, ordering; localize file:line.
2. Replicate offline: a small decrypter for a captured payload (evidence artifact).
3. Replicate the encrypt path: craft a valid encrypted/signed request.
4. Submit the forged ciphertext. Server acceptance is the proof.
5. Differential: replace the encrypted field with garbage padding. If both are accepted, the "encryption" is not authentication.

Native-lib HMAC secrets (the XOR-of-hash pattern): a Secrets-style Java class with System.loadLibrary("secrets") + JNI getApiSecret(package); a tiny .so in the arm64 split (single-digit KB). nm -D libsecrets.so for JNI symbols (the obfuscated secret will NOT be in strings); objdump the JNI function: hash wrapper call (sha256) + a tight 64-iteration EOR loop reading a static blob = secret[i] = blob[i] ^ sha256(input)[i]; compute statically; watch for dev/stag/prod JNI variants in the same lib, each targeting a tier. Reconstruct byte-exact: the signed body is the EXACT wire bytes - Gson default is compact, field names from @SerializedName annotations; pretty-printed or camelCase bodies sign differently and fail.

PROOF BAR: offline-decrypted REAL payload (replica script in evidence) AND a server-accepted forged request; for signature schemes: forged-signature 2xx + unsigned 401 differential + retest 2x + a self-verifying PoC that re-derives the secret from the published derivation inputs.

FP TRAPS:
- Hardware-backed keys (KeyStore/StrongBox): bound honestly.
- A 400 "field can't be blank" on an unauth endpoint means the signature gate PASSED - fix the body shape and continue. 401 "Invalid signature" means gate failed (secret, timestamp, or canonicalization - not the endpoint).
- The inverse trap: a WRONG field name makes BOTH signed and unsigned return 400 null-validation - deserialization runs BEFORE the signature check, voiding the differential. Only a cleanly-deserializing body reveals the gate.
- Method-blindness + versioned-tier regressions: a GET-404 does NOT mean the POST routes are dead - apps declare real methods in the Retrofit interface. "v2 open while v1 correctly 401s" recurs: sweep POSTs on all api/vN tiers of any service with one open endpoint.
- Assuming one tier's enforcement is global: web bundles often call the same host WITHOUT any signature (older tier, Bearer-only). Map accepts/rejects per service.
- Crypto-port attribution: recompile the DECOMPILED algorithm as a standalone Java target with FIXED salt/nonce, run one vector, diff byte-for-byte against the Python port. MATCH converts an opaque rejection into an ATTRIBUTED verdict. Obfuscated-string constants (io.michaelrocks.paranoid) must be ported from SMALI (short sign-extension in RandomHelper) - jadx renders (short) casts ambiguously. tools/paranoid/paranoid_decode.py decodes them offline.

Chain tree: decrypt > forge > which endpoints accept forgeries > auth bypass > write operations > aggregate.
