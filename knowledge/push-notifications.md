# Push Notifications: The Attack Surface Nobody Hunts

Push is a first-class surface on mobile targets and almost nobody audits it: most hunters grep for API keys and stop. Every push system ships server-side send credentials (or references them), every push carries a deeplink payload that lands in the app's handler chain, and every notification renders content on the lock screen. This file is the full class: recover the send credentials, abuse them on YOUR OWN token, then chase the payload into the app.

Standing rule first: all send-proofs run against YOUR OWN device token (install the app, extract your token, push to yourself). Sending to any token you do not own is messaging a real user - a violation, full stop. The proof of capability is the push arriving on your device with your payload; scale claims come from the API's response semantics, not from spamming.

## 1. The push stacks and where their credentials hide

| Stack | Send credential | Where it lives | Send primitive |
|---|---|---|---|
| FCM legacy | server key (long AIza...) | strings.xml, google-services.json, BuildConfig, backend responses | POST https://fcm.googleapis.com/fcm/send, `Authorization: key=<server-key>` |
| FCM v1 (HTTP v1) | service-account JSON (OAuth) | full JSON in repo/APK/backend, private_key field | POST https://fcm.googleapis.com/v1/projects/<id>/messages:send, Bearer access token |
| GCM sender ID | 11-digit numeric sender | strings.xml (gcm_defaultSenderId) | none by itself - public-by-design |
| OneSignal | REST API key (Key readable) + app_id | app config, JS bundles, React-Native configs | POST https://api.onesignal.com/notifications, headers X-ONE-SIGNAL-API-KEY + app_id |
| Airship | app key + master secret | config files | Basic auth on their API |
| Braze/other SaaS | REST keys in app config or API responses | varies | vendor REST API |

Detection sweep: run the standard secret sweep (mobile.md section 5) and add push-specific patterns: `fcm.googleapis.com`, `onesignal.com`, `app_id` + `REST` proximity, `master.?secret`, `push`-adjacent base64 blobs. Cross-reference: an AIza key found near Firebase config could be an Android API key (restricted) OR a legacy FCM server key (unrestricted send) - the test in section 2 disambiguates cheaper than static analysis.

## 2. FCM legacy server key: the classic still shipping

The legacy send endpoint is the full capability test. With the candidate key:

```
POST https://fcm.googleapis.com/fcm/send
Authorization: key=<AIza...>
Content-Type: application/json

{"to": "<YOUR-OWN-DEVICE-TOKEN>",
 "notification": {"title": "BB_PROOF", "body": "redhunting self-test"},
 "data": {"bb_probe": "1"}}
```

- 200 + `message_id`/`success: 1` with the notification arriving on your device: the key is a live server key - full send capability proven, on your own token, screenshot + logcat as evidence.
- 200 but the notification never lands: the key may be valid-but-scope-limited, or your token/project mismatch (tokens are project-scoped - a token from another app's project cannot receive from this project).
- 401: not a server key (probably an Android API key - matrix it per playbook class 5 instead).
- 403 with a scope error: v1-era key or restricted; read the error body, it names the actual scope.

Legacy server keys additionally allow topic operations: `POST /iid/v1/<token>/rel/topics/<topic>` (subscribe abuse) and `{"to": "/topics/<name>"}` sends. Topic enumeration is blind, so the honest finding is the send capability + topic-operations capability, demonstrated on your own subscription.

## 3. FCM v1: the service-account path

The v1 endpoint needs an OAuth access token minted from the FULL service-account JSON (private_key + client_email). An AIza string alone proves nothing on v1 - check for the JSON blob itself (BEGIN PRIVATE KEY inside a JSON asset, `firebase-adminsdk` in client_email). When found: mint the token (self-signed JWT, RS256, scope `https://www.googleapis.com/auth/firebase.messaging`), send to your own token via `POST /v1/projects/<id>/messages:send`. Capability proven the same way. This is the same capability-matrix discipline as any leaked cloud key (playbook class 5): one real call per capability, 403s bound the rest, lateral replay against the whole Firebase project.

## 4. Push token leakage and enumeration (the IDOR of push)

- Where tokens appear: profile API responses (user object carrying `fcm_token`/`device_token`), device-list endpoints, analytics events, logs. Any endpoint returning OTHER users' push tokens is the finding: tokens are semi-secret identifiers - with a server key (section 2) or a vendor send API, token access = targeted push to that user as the app.
- Test: your two accounts (A and B). A's token returned by B's call to the profile/devices endpoint = cross-user token disclosure, differential transcript per normal IDOR discipline.
- Impact framing WITHOUT a send key: targeted-push-as-app needs the send primitive; token leakage alone is a privacy/design issue (P4-ish) - chain it with section 2/3 for the real severity, or vault it when the send key is absent.
- Never demonstrate by pushing to the leaked token: that is messaging a real user. The chain is documented (token leak + send capability), the demo runs on your own token.

## 5. Notification content and lock-screen disclosure

The notification itself leaks: body text carrying PII (order contents, medical/finance wording), continuation of message bodies under notification previews. Target-dependent classification (some orgs treat notification content as by-design), so check the app's settings surface first; report when the content class is sensitive (health/finance/children) and the app allows notification content on the lock screen without the hide setting. Evidence: your own device screenshot with the notification rendered (set up a real notification through the app's own trigger first - e.g. send yourself a message via account B - never a third party).

## 6. Push-to-deeplink: the chain that pays

Every push notification carries a click action and data payload that lands in the app's deeplink handler (FirebaseMessagingService onMessageReceived → Intent parse → activity/WebView). The chain worth a P1:

push payload (attacker-controlled data field) → notification tap → deeplink handler parses it → exported activity or WebView loads attacker URL → JS bridge / token theft (playbook class 11a).

Protocol: construct the payload with YOUR deeplink test URL (an app-registered scheme/host pointing at your callback content), send to YOUR OWN token, tap on-device, capture: screenshot of the notification, logcat intent trace (`adb logcat -d | grep -iE 'intent|push|fcm'`), and the callback-host hit or the WebView load. Static-first: read the service's onMessageReceived in jadx to learn which data keys become intent URIs (look for `getStringExtra("...")` feeding `Uri.parse`/`Intent(...)`), so the payload is built right the first time.

## 7. Vendor consoles and project sprawl

- OneSignal/Airship/Braze REST keys also authenticate read APIs (list apps, view users, segments). The capability matrix runs those too - mass-user views are the bigger finding than send.
- Multi-project sprawl: an app sometimes registers a SECOND Firebase project for push/notifications (marketing SDK). google-services.json in assets tells you the main one; grep for other `project_id` values near messaging code. Keys from the marketing project often have looser restrictions.
- Backend send-proxy endpoints: some apps expose their own "send notification" API (admin panels, internal endpoints). Those are normal API findings (auth matrix) that happen to grant push - route through playbook class 1/5 gates.

## PROOF BAR (the class in one block)

- Send capability: 200 + message_id from the send API, notification ARRIVING on your own device (screenshot + logcat), payload content controlled by you. Plus the negative control (garbage key → 401) in the same block.
- Token disclosure: A-vs-B differential transcript showing cross-user token access.
- Push-to-deeplink: notification screenshot + logcat intent trace + the on-device execution evidence of the landing chain (WebView/bridge/callback hit).
- Capability matrix for any recovered key: send, topic ops, vendor read APIs - each one real call, 403s recorded.

## FP TRAPS

- GCM sender ID (numeric) mistaken for a server key: public-by-design, zero capability, not a finding.
- Android API key (AIza, restricted) vs legacy server key (AIza, send-capable): same prefix family - the send test disambiguates; do not claim from prefix shape.
- Valid key but wrong project: tokens are project-scoped; a 200 to a token from another project means nothing arrived - check arrival, not status code.
- Client-side "push" (local notifications scheduled by the app): no server send primitive, not this class.
- Web Push (VAPID) keys: public keys by design; only the private key in the backend matters, and you will not find it in the client.

## Chain tree

send key > push to own token > deeplink payload control > exported activity/WebView bridge > token theft / action forgery; token disclosure > targeting pipeline (with enumeration) > send key = targeted push as the app (phishing-grade trust, instant delivery); vendor read API > user/segment dumps > mass-impact framing.
