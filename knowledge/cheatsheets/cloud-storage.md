# Cloud Storage Cheatsheet: listing, sampling, poisoning paths, vendor consoles

Command set for playbook class 12 (public cloud storage and object exposure). Every proof follows data minimization: listing + ONE small sample + dates + filter-match-zero. Scale by sampling, never by dumping.

## 1. Anonymous listing per family

```bash
# S3-family (AWS, MinIO, R2 behind s3 endpoints):
curl -s 'https://<BUCKET>.s3.amazonaws.com/?list-type=2&max-results=100' | head -c 500
curl -s 'https://<BUCKET>.s3.<REGION>.amazonaws.com/?list-type=2' | head -c 300
# MinIO console + API:
curl -s 'https://<HOST>:9000/<BUCKET>/?list-type=2' | head -c 300
curl -sv 'https://<HOST>:9001/' -o /dev/null 2>&1 | grep -E '< HTTP|server:'
# GCS (XML API):
curl -s 'https://<BUCKET>.storage.googleapis.com/?max-keys=100' | head -c 500
# R2 / B2 / Spaces (S3-compatible, same list shape):
curl -s 'https://<ACCOUNT>.r2.cloudflarestorage.com/<BUCKET>/?list-type=2' | head -c 300
```

`<?xml ... <ListBucketResult` = public bucket. List first page only until the sample decision is made.

## 2. Pagination discipline (the v1 trap)

```bash
# v2 continuation-token (CORRECT - walks real pages):
TOKEN=$(curl -s 'https://<BUCKET>.s3.amazonaws.com/?list-type=2&max-results=100' | grep -o '<NextContinuationToken>[^<]*' | cut -d'>' -f2)
[ -n "$TOKEN" ] && curl -s "https://<BUCKET>.s3.amazonaws.com/?list-type=2&max-results=100&continuation-token=$TOKEN" | head -c 300
# v1 marker silently RE-SERVES page 1 and fakes scale (an 8x inflation was real):
curl -s 'https://<BUCKET>.s3.amazonaws.com/?marker=whatever' | head -c 200   # compare keys vs page 1
```

Count keys via `grep -c '<Key>'` per page, sum across pages; never trust a single page's count as the total.

## 3. Recency + class assessment (the anti-honeypot pass)

```bash
# object dates from the listing: LastModified per key
curl -s 'https://<BUCKET>.s3.amazonaws.com/?list-type=2&max-results=100' | grep -oE '<LastModified>[^<]+' | cut -d'>' -f2 | sort | tail -3
# private-class prefix census (KYC docs, tax cards, uploads, users vs banners, icons):
curl -s 'https://<BUCKET>.s3.amazonaws.com/?list-type=2&max-results=1000' | grep -oE '<Key>[^<]+' | cut -d'>' -f2 | cut -d/ -f1-2 | sort | uniq -c | sort -rn | head
# same-day writes + prod-reference pair (grep the shipped bundles for the bucket name):
grep -rn '<BUCKET>' js-corpus/ extracted/hosts.txt 2>/dev/null | head -5
```

Old-only dates + no write path = abandoned bucket (exposure note, not impact). Same-day LastModified + referenced by prod code = live production exposure.

## 4. Sampling rules (one, small, harmless)

```bash
# HEAD + Content-Length (zero content transferred):
curl -sI 'https://<BUCKET>.s3.amazonaws.com/<SMALLEST-PUBLIC-CLASS-OBJECT>' | grep -iE 'HTTP|content-length|last-modified'
# 16-byte Range GET on the most sensitive object (PNG magic check, 16 bytes only):
curl -s -H 'Range: bytes=0-15' 'https://<BUCKET>.s3.amazonaws.com/<OBJECT>' | xxd | head -1
# filter-based sensitivity proof (match-zero or single-benign result):
curl -s 'https://<BUCKET>.s3.amazonaws.com/?list-type=2&prefix=kyc/' | grep -c '<Key>'   # 0 keys shown = bounded claim
```

## 5. Upload / poisoning path checks

```bash
# anonymous PUT (harmless marker object, then delete):
curl -sv -X PUT 'https://<BUCKET>.s3.amazonaws.com/BB_probe.txt' -H 'Content-Type: text/plain' -d '<MARKER>' 2>&1 | grep '< HTTP'
curl -s 'https://<BUCKET>.s3.amazonaws.com/BB_probe.txt'          # read-back
curl -sv -X DELETE 'https://<BUCKET>.s3.amazonaws.com/BB_probe.txt' 2>&1 | grep '< HTTP'
# presigned-URL shape discovery (grep the corpus for the pattern):
grep -roE 'https://[^"]+\?.*X-Amz-Signature[^"]*' js-corpus/ | head -3
# RAG/knowledge-pipeline buckets: upload a harmless text named like an ingest doc, check whether consumers read it (documented, not weaponized)
```

## 6. GCS-specific and BigQuery-adjacent surfaces

```bash
# public object via the API form:
curl -s -o /dev/null -w '%{http_code}\n' 'https://storage.googleapis.com/<BUCKET>/<OBJECT>'
# bucket website endpoints (takeover-prone when removed):
curl -sI 'https://<BUCKET>.storage.googleapis.com/' | head -3
# service-account JSON found? -> firebase.md section 6 token mint + storage API matrix:
curl -s 'https://storage.googleapis.com/storage/v1/b?project=<PROJECT>' -H 'Authorization: Bearer <ACCESS-TOKEN>' | head -c 400
```

## 7. CDN-fronted API-cache buckets (class 23 shape)

```bash
# web-bundle base like cdn-host/ or apicache-: GET the root, look for ListBucketResult
curl -s 'https://<CDN-HOST>/' | head -c 200
# per-user path shape census (data/<UUID>/<api-path>/index.json = cached per-user responses):
curl -s 'https://<CDN-HOST>/?list-type=2&max-results=1000' | grep -oE '<Key>[^<]+' | cut -d'>' -f2 | cut -d/ -f1-2 | sort | uniq -c | head
# distinct-user count from the key census (scale-by-sampling, not a dump):
curl -s 'https://<CDN-HOST>/?list-type=2&max-results=1000' | grep -oE '<Key>data/[^/]+' | cut -d'>' -f2 | cut -d/ -f2 | sort -u | wc -l
```

## 8. Firebase Storage (rules-gated; pairs with firebase.md)

```bash
curl -s 'https://firebasestorage.googleapis.com/v0/b/<BUCKET>/o?list-type=2&maxResults=50' | head -c 400
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' 'https://firebasestorage.googleapis.com/v0/b/<BUCKET>/o/<PATH>?alt=media'
```

## 9. Vendor consoles behind the app config

Analytics/dashboards/storage consoles referenced by app strings (MinIO :9001, Keycloak :8443, Jenkins :8080, Eureka :8761, Spring Config 9xxx) get the http.md infra triage; console HTML captured verbatim is the transcript. Keycloak pattern: open registration + public admin console, prove with BB_-prefixed test accounts.
