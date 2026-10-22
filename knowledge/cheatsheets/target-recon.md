# Target Recon Cheatsheet: general app and system discovery, estate expansion, disclosure contact

Command set for knowledge/target-intel.md. We find apps and systems nobody hunts: regional service apps, state-enterprise digital services, small startup products, vendor backends. No directories, no listings - discovery runs from stores, certs, DNS, and the artifact itself.

## 1. App discovery by store category

```bash
# store metadata without any account (vendored tool):
python3 tools/play_store/play_meta.py <PACKAGE>          # live version, update date
# apkpure MCP equivalents: apkpure_detail (version/SHA/downloads), apkpure_target_score (engagement fit + drift)
# category crawl shapes to feed the lead board (via the MCP tools per package):
#   finance / health / government / education / logistics, regional stores, sort by installs + last-updated
# selection heuristics: monthly releases (fresh code), 500k+ installs (impact scale), no security page
```

Every acquired APK is a map: decode first (rh_apkrecon), then expand from its own strings.

## 2. Sibling apps by signing cert (same cert = same org family)

```bash
# extract the cert from every decoded app you hold, group by it:
python3 - <<'EOF'
from androguard.core.apk import APK
import hashlib, glob
for p in glob.glob("apps/*.apk") + glob.glob("apps/*.xapk"):
    try:
        a = APK(p)
        certs = a.get_certificates_der_v3() or a.get_certificates_der_v2() or [a.get_certificate_der()]
        print(hashlib.sha1(certs[0]).hexdigest()[:12], p, a.get_package())
    except Exception as e:
        print("ERR", p, str(e)[:40])
EOF
# apps sharing a cert prefix share an org: their endpoints and estates merge into one target
```

## 3. Estate expansion from the artifact

```bash
# hosts and endpoints out of the decode (rh_apkrecon outputs):
cat extracted/hosts.txt | sort -u
cat extracted/endpoints.txt | head -50
# resolve every discovered host (public DNS; a 0.0.0.0 answer is the LOCAL resolver, rotate vantage):
for h in $(cat extracted/hosts.txt | grep -oE '[a-z0-9.-]+\.[a-z]{2,}' | sort -u | head -60); do
  printf '%s -> ' "$h"; dig +short "$h" @8.8.8.8 A | head -1
done
# live probe (https then http, title + server):
while read h; do curl -s -o /dev/null -w "%{http_code} %{remote_ip} $h\n" --max-time 8 "https://$h/"; done < <(cat extracted/hosts.txt | grep -oE '[a-z0-9.-]+\.[a-z]{2,}' | sort -u)
# dev/staging discovery inside the corpus (then treat as in-scope ONLY after rh_scope):
grep -oE '(stg|stag|dev|uat|preprod|qa)[a-z0-9.-]*\.[a-z0-9.-]+' extracted/allstrings.txt | sort -u | head
grep -oE '[a-z0-9-]+\.duckdns\.org' extracted/allstrings.txt | sort -u
```

## 4. Domain and subdomain expansion (org side)

```bash
# certificate transparency (2+ sources, crt.sh 502s regularly):
curl -s 'https://crt.sh/?q=%.<ORG-DOMAIN>&output=json' | python3 -c "import json,sys; [print(e['name_value']) for e in json.load(sys.stdin)]" | sort -u | head -40
curl -s 'https://certspotter.com/v0/omitted-certificates?domain=<ORG-DOMAIN>' 2>/dev/null | head -c 400
# wayback history for forgotten hosts and endpoints:
curl -s 'http://web.archive.org/cdx/search/cdx?url=*.<ORG-DOMAIN>/*&output=text&fl=original&collapse=urlkey&limit=300' | head -60
# subfinder when present (skip-not-fail):
subfinder -d <ORG-DOMAIN> -silent | head -50
# DNS anomalies worth a round every time:
for h in <SUBDOMAIN-LIST>; do
  ip=$(dig +short "$h" @8.8.8.8 A | head -1)
  [ "$ip" = "127.0.0.1" ] && echo "SUSPECT-local-override $h"
  [ -z "$ip" ] && echo "NXDOMAIN $h (dangling? takeover ladder)"
done
```

## 5. Org OSINT (thin-security signals)

```bash
# careers page stack leaks (a hiring signal cuts both ways):
curl -s https://<ORG>/careers | grep -ioE '(jenkins|kubernetes|terraform|devops|spring|golang|microservice|application security|devsecops)[a-z ]*' | sort | uniq -c | sort -rn | head
# public GitHub org surface (repos, members):
curl -s 'https://api.github.com/orgs/<ORG-NAME>' | python3 -m json.tool | grep -E '"(name|public_repos|created_at)"'
curl -s 'https://api.github.com/orgs/<ORG-NAME>/repos?per_page=100' | python3 -c "import json,sys; [print(r['name'], r['updated_at'], r.get('language')) for r in json.load(sys.stdin)]" | head -20
# certificate transparency weekly growth (active infrastructure):
#   re-run section 4 monthly, diff against targets/*/assets/round-NNN/hosts.txt (retest.md trigger)
```

## 6. Desktop client discovery (the 60-second asar surface)

```bash
# vendor blogs and emails link direct dmg/exe (storage bucket URLs are often public):
curl -s https://<ORG>/blog | grep -oE 'https://[^"]+\.(dmg|exe|AppImage|zip)' | sort -u | head
hdiutil attach <CLIENT>.dmg -nobrowse -mountpoint /tmp/rh_client 2>/dev/null
npx @electron/asar extract /tmp/rh_client/*.app/Contents/Resources/app.asar asar-out/
grep -niE 'firebaseConfig|apiKey|databaseURL|projectId|remote-auth' asar-out/*.js | head -20
```

## 7. Disclosure contact discovery (operator-owned, never automated sending)

```bash
for d in <ORG-DOMAIN> www.<ORG-DOMAIN> app.<ORG-DOMAIN>; do
  printf '%s: ' "$d"
  curl -s --max-time 8 "https://$d/.well-known/security.txt" | head -3
  echo
done
curl -s https://<ORG>/security | grep -ioE '[a-z0-9._-]+@<ORG-DOMAIN>|security[a-z.]*@[^"< ]+' | head -5
# CSIRT shapes for state-enterprise targets: search the org's main site for 'CSIRT|CERT|incident'
# record findings in target.json disclosure_contact; the OPERATOR writes and sends anything, ever
```

## 8. Feed everything into the board

```bash
cat extracted/hosts.txt extracted/endpoints.txt assets/round-001/urls.txt 2>/dev/null \
  | python3 bin/rh_leadboard.py <target> ingest -
# un-ingested signal = lost signal; the board upserts (status never reset)
```

## 9. Selection heuristics (wage-per-hour ranking)

Rank candidate targets before investing sprints: userbase scale (installs, order-id density), release freshness (version history on the mirror), security-attention thinness (no security.txt, no disclosed history, small team), surface richness (payments, KYC, health, push, deep links). A mid-size regional finance app with monthly releases and no security page outranks any famous target.
