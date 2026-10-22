# HTTP Cheatsheet: probing matrices, auth gates, WAF ladders, evidence capture

Copy-paste commands for every HTTP probing pattern in the playbook. Every command here feeds the raw-evidence doctrine: run them through rh_capture.py when they prove something (the tool wraps the request and writes the transcript), or use curl -v when the surface demands it. Replace <TARGET>, <HOST>, <TOKEN> placeholders.

## 1. The auth-gate matrix (run on EVERY discovered endpoint)

The 4-way probe that classifies a surface. Run per endpoint, capture all four in one session:

```bash
# 1. no credential
curl -sv 'https://<TARGET>/api/v1/resource' -o /dev/null 2>&1 | grep -E '< HTTP|< location'
# 2. garbage credential (the negative control)
curl -sv 'https://<TARGET>/api/v1/resource' -H 'Authorization: Bearer aaaa.bbbb.cccc' -o /dev/null 2>&1 | grep '< HTTP'
# 3. app fingerprint (the client's own UA; WAF client-fingerprint rules are sometimes the ONLY gate)
curl -sv 'https://<TARGET>/api/v1/resource' -H 'User-Agent: okhttp/4.9.3' -H 'Accept-Encoding: gzip' -H 'Connection: Keep-Alive' -o /dev/null 2>&1 | grep '< HTTP'
# 4. valid credential (the positive probe)
curl -sv 'https://<TARGET>/api/v1/resource' -H 'Authorization: Bearer <TOKEN>' 2>&1 | grep '< HTTP'
```

Verdict table: 401/403 on 2+4 but 200 on 3 = fingerprint-gated (playbook class 3 fingerprint ladder). 200 on 1 = unauthenticated surface. 302 on REST + 200-in-band on GraphQL = per-surface gates (mobile.md section 14, probe each).

## 2. Method and verb confusion sweep

```bash
for m in GET POST PUT PATCH DELETE OPTIONS; do
  printf '%s: ' "$m"
  curl -s -o /dev/null -w '%{http_code}\n' -X "$m" 'https://<TARGET>/api/v1/resource' -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{}'
done
```

405 on POST + 200 on PUT (or any asymmetry) = method confusion lead. @PUT on a POST-shaped path in the decompiled Retrofit interface is the ground truth; sweep every api/vN sibling (v1 401 while v2 open is the recurring versioned-tier regression).

## 3. OPTIONS / CORS probe

```bash
curl -sv -X OPTIONS 'https://<TARGET>/api/v1/resource' \
  -H 'Origin: https://evil.example' \
  -H 'Access-Control-Request-Method: GET' 2>&1 | grep -iE 'access-control|< HTTP'
```

Reflected Origin with `Access-Control-Allow-Credentials: true` = the CORS finding. Also test null origin (`-H 'Origin: null'`) and wildcard+credentials combos.

## 4. Parameter semantics 3-way (the differential gate)

Use the tool (it captures all three as evidence):

```bash
python3 bin/rh_differential.py <target> <finding-slug> 'https://<TARGET>/api/v1/things?sub={sub}&seq=1' --valid <VALID_SUB>
```

Manual form when a browser flow is needed: same URL with valid value, GARBAGECONTROL, and empty. IDENTICAL sizes = parameter ignored (impact multiplies by cardinality, sweep it bounded).

## 5. IDOR range probe (the response-signature table)

```bash
for id in 1 100 500 1000 10000 99999999; do
  printf 'id=%s -> ' "$id"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "https://<TARGET>/api/v1/orders/$id" -H 'Authorization: Bearer <TOKEN>'
done
```

Classify each: 200-full, 200-empty, 404, 403, redirect. 404-after-auth = the architectural oracle (auth passed, authorization missing). Follow with the A/B differential (two tempmail accounts) and the masked random sample at the record minimum.

## 6. A/B identity check (auth classes, mandatory)

```bash
# A reads B's object (both accounts self-registered via tempmail)
curl -sv 'https://<TARGET>/api/v1/orders/<B-OBJECT-ID>' -H 'Authorization: Bearer <A-TOKEN>' 2>&1 | tail -20
# control: garbage token on the same object, same session
curl -sv 'https://<TARGET>/api/v1/orders/<B-OBJECT-ID>' -H 'Authorization: Bearer aaaa.bbbb.cccc' 2>&1 | grep '< HTTP'
```

## 7. WAF / CDN ladder (in order, record which rung fires)

```bash
# rung 1: plain
curl -sv 'https://<TARGET>/' -o /dev/null 2>&1 | grep -E '< HTTP|cf-ray|server:'
# rung 2: TLS impersonation (curl_cffi, the configured profile)
python3 -c "
from curl_cffi import requests
r = requests.get('https://<TARGET>/', impersonate='chrome124', timeout=20)
print(r.status_code, len(r.text), r.headers.get('server'))
"
# rung 3: app UA (okhttp is a public constant in the APK)
curl -sv 'https://<TARGET>/' -H 'User-Agent: okhttp/4.9.3' -o /dev/null 2>&1 | grep '< HTTP'
# rung 4: rotate vantage (local resolver lies; 0.0.0.0 answers are LOCAL policy)
dig <HOST> @8.8.8.8 +short
curl -sv 'https://<TARGET>/' --resolve '<HOST>:443:<PUBLIC-IP>' -o /dev/null 2>&1 | grep '< HTTP'
```

Distinguish: challenge page (contains "Just a moment" / challenge script, solvable in a real browser, 8-10s wait) vs hard block ("Sorry, you have been blocked" = vantage-bound, record as vantage limit + positive control).

## 8. Host header / X-Forwarded family injection

```bash
# password reset poisoning (capture the emailed link target)
curl -sv 'https://<TARGET>/api/v1/password/reset' -H 'Host: attacker.example' -H 'Content-Type: application/json' -d '{"email":"<A-ACCOUNT>@inbox.example"}' 2>&1 | grep -iE '< HTTP|reset|link'
# forwarded-for trust probe (rate limit dimension confusion)
curl -sv 'https://<TARGET>/api/v1/otp/send' -H 'X-Forwarded-For: 1.2.3.4' -H 'Content-Type: application/json' -d '{"phone":"<OWN-NUMBER>"}' 2>&1 | grep '< HTTP'
```

If the reset email arrives with attacker.example in the link: token captured, takeover chain on the owned test account.

## 9. Cache poisoning quick probe

```bash
# unkeyed header reflection check
curl -sv 'https://<TARGET>/' -H 'X-Forwarded-Host: attacker.example' -o /dev/null 2>&1 | grep -i 'x-forwarded-host'
# then fetch the bare URL (no header) and check if the poison stuck
curl -sv 'https://<TARGET>/' 2>&1 | grep -i 'attacker.example'
```

## 10. Open redirect chain capture (for OAuth relay)

```bash
# step 1: confirm the redirect
curl -sv 'https://<TARGET>/redirect?url=https://evil.example' -o /dev/null 2>&1 | grep -iE '< HTTP|< location'
# step 2: the OAuth relay form (does the authorize endpoint accept the intermediate?)
curl -sv 'https://<TARGET>/oauth/authorize?client_id=<ID>&redirect_uri=https://<TARGET>/redirect?url=https://evil.example&response_type=code&state=x' -o /dev/null 2>&1 | grep -iE '< HTTP|< location'
```

## 11. Infra port triage (in-scope IPs only, rh_scope first)

```bash
# banner grab the interesting ports
for port in 7025 7071 8243 9000 9001 8761 9100 1025 8080 8880; do
  (echo > /dev/tcp/<IP>/$port) 2>/dev/null && echo "OPEN <IP>:$port" &
done; wait
# SMTP enumeration (QUIT before DATA, zero emails sent)
printf 'LHLO probe\r\nMAIL FROM:<probe@attacker.example>\r\nRCPT TO:<admin@<TARGET-DOMAIN>>\r\nQUIT\r\n' | timeout 10 nc <IP> 7025
# 550 vs 250 = the user oracle; 250 on MAIL FROM = spoof accepted
```

## 12. JWT quick decode (always decode before theorizing)

```bash
echo '<JWT>' | cut -d. -f1 | base64 -d 2>/dev/null; echo
echo '<JWT>' | cut -d. -f2 | base64 -d 2>/dev/null; echo
# Python form (handles padding correctly)
python3 -c "
import base64, json
p = '<JWT>'.split('.')
for part in p[:2]:
    pad = part + '=' * (-len(part) % 4)
    print(json.dumps(json.loads(base64.urlsafe_b64decode(pad)), indent=1))
"
```

Check: alg (none family, HS256 with RSA public key = confusion), exp (missing = mint-and-replay proof), aud/iss (missing = cross-service replay), role/scope claims.

## 13. SSE / streaming listener (live-channel proof)

```bash
curl -N -sv 'https://<TARGET>/path.json' -H 'Accept: text/event-stream' --max-time 60 2>&1 | head -40
# Firebase RTDB leaf form:
curl -N 'https://<PROJECT>-rtdb.firebaseio.com/<leaf-path>.json' -H 'Accept: text/event-stream' --max-time 60
```

An `event: put` frame landing during your own write (via the official flow) = real-time interception, beats every staleness argument.

## 14. Response-shape oracles

```bash
# verbose error oracle (compare bodies across malformed inputs)
curl -s 'https://<TARGET>/api/v1/thing' -H 'Content-Type: application/json' -d '{"id": "a"}' | head -5
curl -s 'https://<TARGET>/api/v1/thing' -H 'Content-Type: application/json' -d '{"id": 1}' | head -5
# timing oracle (3x each, medians not anecdotes)
for i in 1 2 3; do curl -s -o /dev/null -w '%{time_total}\n' 'https://<TARGET>/api/v1/search?q=<VALID>'; done
for i in 1 2 3; do curl -s -o /dev/null -w '%{time_total}\n' 'https://<TARGET>/api/v1/search?q=<INVALID>'; done
```

## 15. Pacing discipline (the auto rate rule)

Default floor from config (150ms). Wrap sweeps:

```bash
sleep_per_request=0.15
do_request() { curl -s -o /dev/null -w '%{http_code}\n' "$1"; sleep $sleep_per_request; }
```

On any 429/503: double the sleep, halve the concurrency, and never push through. The ceiling is the target's tolerance, discovered not assumed.
