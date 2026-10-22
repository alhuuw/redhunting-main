# Mobile Hunting: APK Acquisition to Proof Pipeline (per stack)

The proven loop across many APK hunts: acquire with provenance, decode, extract, sweep, signature, dynamic instrumentation, minimal live proof, lateral movement. This is the PRIMARY surface of the operation (app-first doctrine). Sections 1-10 are the Android pipeline; section 11 is iOS; section 12 is the desktop Electron client (first-class, always check); 13-14 are cross-cutting techniques. All case references are sanitized archetypes.

## 1. Acquisition WITH PROVENANCE EVIDENCE

A report must answer "how did you obtain the app?". Record it every time.

| Method | Tool | Evidence produced |
|---|---|---|
| App-store mirror | `python3 tools/apkpure/apkpure_dl/cli.py <package>` (vendored) or the apkpure MCP | versioned downloads/{pkg}/{ver}/ plus SHA256; handles CDN bot walls via TLS impersonation |
| Play Store metadata | `python3 tools/play_store/play_meta.py <pkg>` or apkpure MCP play_verify | live version/update date - the authoritative newest-version check (retest trigger) |
| From a device | `python3 tools/device_pull/get_app_from_device.py` (vendored) | apk-dumps/{pkg}/base.apk plus splits, SHA256 per file |
| Provided file | copy into app/, hash immediately | app/SHA256SUMS.txt plus app/PROVENANCE.txt |

Rules:
- app/ is the untouched source of truth. Decode elsewhere.
- XAPK is a zip: extract, use the non-config apk as base, keep splits (signatures and native libs differ per split). config.arm64_v8a.apk carries the native libs; config.* density/locale splits matter for same-signer checks.
- Version diffing is a first-class technique: acquire two versions and diff string dumps and pools. Secrets get added between versions; the diff IS the retest engine.
- Old-version acquisition when the mirror API returns empty (version_list:[] while full history exists): fetch the mirror WEBSITE - apkpure.net/<slug>/versions lists every old build; each /download/<version> page carries the direct CDN link with the versionCode embedded (d.apkpure.net/b/XAPK/<pkg>?versionCode=N), the published SHA-256/SHA-1 for provenance verification, and the release date. Verify the downloaded hash against the page value.
- Second-mirror fallback when apkpure.net is CF-challenged (403 "Just a moment" for stdlib, curl_cffi chrome124, AND Jina while apkcombo.com served the same history clean): apkcombo.com/<app>/<pkg>/old-versions/ under curl_cffi chrome124 lists every version + release dates. The per-version download page wraps its direct CDN link as href="https://apkcombo.com/d?u=<base64url>" - decode to download.pureapk.com/b/XAPK/... with time-limited tokens. Verify same-signer (androguard) before diffing; bisect markers with byte-exact checks across dex+libs+resources.arsc (resources strings are often UTF-16 - check both encodings).
- Record the app-store metadata (version code) alongside the hash: builds are identified by versionCode, not versionName.

## 2. Decode (all stacks)

`python3 bin/rh_apkrecon.py <target-dir>` automates the core (hosts, endpoints, secret sweep, manifest triage, signing SHA-1). Manual depth beyond it:

- jadx: full Java/Kotlin source; `--deobf` for obfuscated builds; keep both raw and deobf outputs. On huge APKs (35MB / 7-dex) decompile ONCE via CLI in the background (nohup jadx -d decoded/jadx --no-res --deobf app/base.apk, ~40 min worst case) and mine apktool's smali tree with python regex meanwhile; jadx also fails on ~6.8k-class builds (RegionMaker overflow) - those classes exist ONLY in smali. Use python glob or find -exec for smali enumeration, never shell globs that touch $-containing filenames (proguard inner classes Foo$Bar.smali silently fail).
- apktool: manifest, res/, assets/, lib/. The smali is the fallback when jadx chokes.
- strings: rh_apkrecon implements a stdlib printable-run extractor (no binary dependency). For huge .so files, targeted extraction after the first pass.
- hosts.txt and endpoints.txt come from URL and path regexes. Also extract: base64-looking blobs, JSON assets, embedded .env files, protobuf descriptors.

Manifest triage, 2 minutes, pays off every time:
- allowBackup, usesCleartextTraffic, missing networkSecurityConfig
- exported activities/services/receivers/providers (payment activities are a classic)
- autoVerify hosts: fetch https://<host>/.well-known/assetlinks.json for each immediately (broken/default JSON is reportable as-is via the HTTP response)
- URL schemes and intent-filter actions
- BASE_URLs pointing at dev domains in prod builds: hygiene finding plus dangling-host risk
- debuggable, testOnly flags

## 3. Signing signature, REQUIRED for key-restriction proofs

The app's signing cert SHA-1 unlocks X-Android-Cert proofs (Maps restriction bypass) and proves which build you tested.

Modern APKs are v2/v3-only signed and `keytool -printcert -jarfile` FAILS on them ("Not a signed jar file"). Use androguard (rh_apkrecon does this automatically):

```python
from androguard.core.apk import APK
import hashlib
a = APK("base.apk")
certs = a.get_certificates_der_v3() or a.get_certificates_der_v2() or [a.get_certificate_der()]
print(hashlib.sha1(certs[0]).hexdigest())  # raw lowercase hex, no colons
```

Use the raw hex in X-Android-Cert and the package name in X-Android-Package. Cross-check: the SHA-1 must be consistent across splits. Mandatory, not optional.

## 4. Per-stack deep dive

### Flutter (Dart AOT), libapp.so
- blutter (github.com/worawit/blutter) dumps the Dart class pool into pp.txt, asm, and a frida hook template. Point BLUTTER_HOME at your clone; the doctor checks it.
- blutter needs the Dart SDK matching the snapshot version; mismatch errors name the version needed - fetch that SDK and retry.
- The object pool is the secret magnet: service-account keys as int-arrays, OAuth creds at fixed pool indices. Static-only extraction is preferred over runtime hooks when possible. Strings from libapp.so miss pool data that blutter recovers - run both.

### React Native / Hermes (HBC bytecode)
- hbc-decompiler or hbctool disasm. Output is large JS: grep for secrets and endpoints directly. AES keys hide at exact line numbers in the decompiled bundle. Match the Hermes bytecode version to the tool build.

### Expo
- assets/app.config, app.json, embedded manifest: credentials frequently ship in plaintext there. Always cat the assets directory listing.

### Native Kotlin/Java
- Custom .so config libraries: run the strings extractor over every lib/*/lib*.so, not just libapp.so. Check assets/ and res/raw/ for embedded JSON configs, certs, databases.

### WebView hybrids
- Grep for loadUrl, addJavascriptInterface, shouldInterceptRequest, @JavascriptInterface methods. Map every bridge method and its native capability.

## 5. Secret sweep (before ANY live request)

Regex classes: AIza..., AKIA/ASIA..., BEGIN PRIVATE, eyJ... (JWT), Authorization: Basic, client_secret, BuildConfig.AUTH, aesKey/ivB64/hmac/salt/signing, sk_live/pk_live, ghp_/gho_ (GitHub), xox (Slack), webhook URLs, plus the push-stack patterns (fcm.googleapis.com, onesignal, REST keys - push-notifications.md section 1).

Post-sweep discipline: classify each hit (secret class per playbook class 1), then plan the capability matrix. All hits are LEADS until proven.

## 6. Network capture stack (dynamic)

1. Device or emulator with developer options (kickoff adb). Check `getprop ro.product.cpu.abi` BEFORE pushing anything (mismatched arch wastes sessions).
2. Proxy: Burp or mitmproxy at a known IP:port on your host.
3. CA certificate: Android 7+ blocks user CAs for app traffic by default. Options in order: (a) app targets API < 24 or has a permissive networkSecurityConfig (check the manifest first - several prod apps still do), (b) system CA via rooted device or AVB-disabled emulator, (c) Frida unpinning plus SSLUnpinning hooks, (d) repair the client's TLS stack at the Frida layer if needed.
4. Proxy-detection bypass: apps that check system_proxy_properties or test connectivity directly get Frida hooks neutralizing the checks.
5. Capture the full first-run flow: install > register (tempmail) > login > browse every main feature. Save har/flows into traffic/.

## 7. Dynamic instrumentation cookbook (Frida)

Standard hooks that pay off across targets (each is a small script; keep a per-target harness folder under recon/harness/):

| Hook target | What it gives you |
|---|---|
| Signature/header builders (sign, X-Signature, wToken, nonce methods) | the exact signing inputs and key material at runtime |
| Cipher.init / Cipher.doFinal (javax.crypto) | keys and IVs as used, for the crypto class |
| okhttp Interceptor chain | every request with headers, before pinning |
| WebView.loadUrl + shouldInterceptRequest | deeplink chain execution tracing |
| SharedPreferences reads/writes | token storage locations and formats |
| FirebaseMessagingService.onMessageReceived | push payload -> intent URI mapping (push class) |
| root/attestation checks | bypasses for protected apps |

Method: locate the method statically (jadx/blutter), hook it, exercise the app, capture inputs/outputs. A captured real signature plus a replayed accepted request is proof.

Anti-analysis you will meet and their standard bypasses:
- Root detection (su, magisk, busybox paths): hook the detection methods, not the filesystem.
- Frida detection (port 27042, frida-server name, thread names): rename frida-server, gadget mode, or spawn-time hooks.
- Integrity checks (Play Integrity, SafetyNet remnants): usually out of scope to attack; note and continue.
- Certificate pinning: standard unpinning scripts first, custom pins via okhttp/SSLContext hooks second.
- Commercial packers (LIAPP, PairIP/DexGuard VM): static extraction still works on string pools; runtime hooks may need anti-anti-frida work; budget time. PairIP VM lives in the config split's .so - unzip the XAPK first.

## 8. IPC and exported surface testing

For every exported component from manifest triage:
- Activities: start via adb am start with crafted extras; watch for crashes and unauthorized UI access (exported payment activities are a classic).
- Receivers: broadcast crafted intents (protected broadcasts will refuse; note which are protected).
- Providers: query via content:// URIs; check grantUriPermissions, path traversal in openFile implementations.
- Deeplinks: fire the full intent chain (playbook class 11a), fuzz handler parameters.
- Backup analysis (allowBackup=true): adb backup > ABE unpack > grep for tokens and PII. Standalone finding where policy scopes local data theft.

## 9. Live proof: minimal, differential, lateral

### Port the client's request byte-exact BEFORE blaming the server (rejection-attribution prerequisite)

When a hand-ported request is rejected, the FIRST suspect is your port, not the server. A "server-side phone validation" that turned out to be our own missing E.164 `+` prefix, and an "amount mismatch" that persisted until the port was checked field-by-field - both real. Checklist, in order before recording ANY rejection as server behavior:

1. Serialization keys: match the wire format the client actually produces, not the field names in source. Gson uses @SerializedName (finish_url, order_id - NOT finishUrl/orderId); Retrofit/OkHttp use whatever the converter is configured with. Read the annotation, not the variable.
2. Number types: the server stores what it parsed. 1000 (int) vs 1000.0 (float) serialize differently and can fail strict comparisons.
3. Identifier formats: E.164 with/without +, country-code concatenation (countryCode + phone is literal string concat in most SDKs), prefix vs no-prefix, UUID case. The construction site is ground truth - read it, don't guess.
4. HTTP method: from the annotation, not the endpoint name. Payment cancel was @PUT on a pymnt-cncl path while siblings were POST - a POST cancel returned 405 and looked "protected".
5. Body actually sent: assert the request transcript contains the body. {} and "" are FALSY in Python - `x = cond and body or None` silently drops bodies. Every rejected probe gets its transcript body eyeballed against the client construction before the server is blamed.
6. Session/state binding: some resources bind to the creating session (a cancel with a fresh session 400s while the original session's 200s - that IS a server behavior worth reporting, but only after the port is proven).
7. Crypto ports: prove the port with a standalone reference vector - recompile the DECOMPILED algorithm as a standalone Java target (javax.crypto; fix the randomness by passing salt/nonce as args), run one fixed vector through it and your Python port, diff byte-for-byte. MATCH converts an opaque rejection into an ATTRIBUTED verdict. Do this BEFORE the variant sweep; it halves the hypothesis space.
8. When the port is proven and the rejection persists: sweep structurally different variants (both methods, int/float, pid/referenceId, linked/unlinked identity) and record the error differential. A generic message that never changes across variants = cause UNKNOWN, not a proven control.

### Proof mechanics

- Every dynamic probe through rh_capture.py: one real request with the recovered credential against the most sensitive READ endpoint + negative control (garbage token 401/403) in the same block.
- TLS-fingerprint WAFs: rh_capture uses the Python stdlib TLS stack, which Cloudflare hard-blocks. When probes 403 with a CF block page, do NOT conclude "gated" - re-fire through curl_cffi with the configured impersonation profile (chrome124 / chrome99_android / okhttp UA ladder), keeping the transcript format. A block page saying "Sorry, you have been blocked" (not a solvable challenge) is a geo/IP hard block: record as vantage limit + positive control, hand the probe to a browser-side run. Distinguish challenge page (solvable with a real browser) vs hard block (vantage-bound).
- Lateral movement is mandatory: replay the credential against EVERY host in hosts.txt and EVERY endpoint in endpoints.txt. "One public client secret accepted by five microservices" is the report.
- NXDOMAIN vs geofence: resolve via public DNS before claiming unreachable; several "geo-fenced" hosts are dead DNS.
- Writes: BB_-prefixed artifacts on your own accounts, dummy IDs or terminal-state objects, cleaned up.
- OTP dispatch proof: your OWN number or inbox. Arrival, not result:true.

## 10. Required outputs per target

```
app/SHA256SUMS.txt + PROVENANCE.txt
extracted/{allstrings, flutter_strings, hosts, endpoints, secret_sweep, manifest_triage, signature}.txt
decoded/{jadx-out, apktool, blutter_out or hbc-out}
traffic/first-run.har or .flows
recon/harness/ (frida scripts per target)
poc/poc_<id>.py            self-verifying, --mask default, prints PASS/FAIL
findings/<id>/evidence/raw/  rh_capture transcripts + SHA256SUMS.txt
```

For iOS targets the equivalent outputs are: ipa/SHA256SUMS.txt + PROVENANCE.txt, extracted/{allstrings, hosts, endpoints, secret_sweep, entitlements, url_schemes}.txt, decoded/ headers and disassembly, traffic/, recon/harness/.

## 11. iOS pipeline (methodology; label confidence honestly until case-hardened)

Same loop: acquire with provenance, decode, sweep, hook, prove. Acquisition: provided IPA, device pull (frida + frida-ps -Uai lists apps; pull via SSH/ideviceinstaller on jailbroken), TestFlight only through your own account. An IPA is a signed zip: unzip, work under Payload/*.app, keep the original untouched. No public mirror with provenance: version-diff needs the account's build history.

Decode: Info.plist (CFBundleURLTypes schemes, NSAppTransportSecurity/NSAllowsArbitraryLoads, background modes); embedded.mobileprovision (security cms -D; App Store builds strip it, enterprise/dev builds carry it); entitlements (codesign -d --entitlements) drive keychain-sharing and app-group surfaces; class-dump/dsdump for ObjC headers, swift-demangle for Swift; Frameworks/, PlugIns/ (extensions run as their own process with own entitlements), bundled configs.

iOS-specific surfaces: universal links (https://<domain>/apple-app-site-association - the assetlinks twin); keychain runtime dump (kSecAttrAccessibleAlways items, weak access groups); pasteboard copies on background; URL-scheme conflicts (two apps registering one scheme = hijack); WKWebView bridges (WKScriptMessageHandler exposure); ATS exceptions + cleartext endpoints.

Frida on iOS: ObjC Interceptor.attach; unpinning for NSURLSession/AFNetworking/TrustKit; anti-debug (ptrace PT_DENY_ATTACH, sysctl checks, fishhook) - hook the checks, not the syscalls. Jailbroken/corepatched device for full hooking; a stock device limits to network-level + static (log the boundary honestly).

## 12. Desktop Electron client: first-class surface (always check, 60-second extract)

App-first scoping misses the desktop app. Vendor blogs/emails link direct dmg/exe downloads (storage bucket URLs are often public). Extract: hdiutil attach -> npx @electron/asar extract app.asar <dir> -> grep renderer.prod.js + main.prod.js for: apiKey/databaseURL/firebaseConfig (desktop apps frequently register SECOND Firebase projects for SSO flows), token-handling logic, and literal RTDB path strings (the SSO remote-auth handoff: web portal deposits the session token into a world-readable RTDB path, desktop adopts it - an open path = token-theft primitive). Same-signer check applies (the desktop signing cert is also extractable).

## 13. SSE race on open RTDB paths (listener beats consume-and-delete)

If a Firebase RTDB path is world-readable AND is a write-channel (SSO handoff, live counters), test Server-Sent-Events: curl -N -H "Accept: text/event-stream" <path>.json. The stream pushes event: put frames the MOMENT a write lands - an unauthenticated listener permanently beats any legitimate client that reads-then-deletes. Verified frame shape: event: put\ndata: {"path":"/","data":{...}}. This converts "readable path" into "real-time interception".

## 14. Auth-gate divergence matrix (REST vs GraphQL per-service, per-operation)

On hosts serving both REST and GraphQL: REST may 302-redirect on missing auth while each /graphql service has its OWN gate (in-band {"message":"Unauthorized"} 200, or fully open). Within one service, queries and mutations can differ. Build the matrix: REST-unauth, REST-bad-token, per-service unauth, per-op. A host-level verdict is always wrong. Probe /public/ siblings of every service path - full anonymous introspection + reads + writes have been found on exactly those.

## 15. Version diffing (the retest flywheel's mobile engine)

On every app update (Play version via play_meta.py / apkpure MCP): pull the new APK, diff string dumps (new endpoints, new secrets, changed crypto), diff manifests (new exported components, new autoVerify hosts, new push handlers), diff API bases. Stable secret markers across versions = measured no-rotation window; new markers = fresh class-1 round; new deeplinks = fresh class-11a round; new push receivers = fresh push round.
