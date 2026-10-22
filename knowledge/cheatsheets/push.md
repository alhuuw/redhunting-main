# Push Cheatsheet: send-capability proofs, token leakage, payload-to-deeplink tracing

Command set for knowledge/push-notifications.md. The standing rule is absolute: every send proof runs against YOUR OWN device token (install the app, extract your token, push to yourself). Any send to a token you do not own is messaging a real user - a violation, full stop, and a ban-grade offense everywhere.

## 1. Find your own device token

```bash
# after installing + logging in on your test device, hook the token reporter:
adb logcat -d | grep -iE 'fcm.?token|registration.?id|push.?token' | head -5
# or from the API surface (your own profile/devices endpoint):
curl -s 'https://<TARGET>/api/v1/me' -H 'Authorization: Bearer <A-TOKEN>' | python3 -m json.tool | grep -iE 'token|device'
# or SharedPreferences after login (adb backup analysis, adb-frida.md section 5)
# or Frida:
frida -U -f <PKG> -l token-dump.js   # hook FirebaseMessaging.getToken / getInstanceId onNewToken callbacks
```

Tokens are project-scoped: a token from another app's project cannot receive from this project - arrival, not the HTTP status code, is the verdict.

## 2. FCM legacy server key test (the classic still shipping)

```bash
curl -sv -X POST 'https://fcm.googleapis.com/fcm/send' \
  -H 'Authorization: key=<AIza-CANDIDATE-KEY>' -H 'Content-Type: application/json' \
  -d '{"to": "<YOUR-OWN-TOKEN>",
       "notification": {"title": "BB_PROOF", "body": "<MARKER>"},
       "data": {"bb_probe": "1", "deeplink": "<APP-SCHEME>://probecanary"}}' 2>&1 | grep -E '< HTTP|message_id|multicast_id'
```

- 200 + `"success":1` AND the notification arriving on your device (screenshot + logcat): live server key, full send capability proven.
- 200 but nothing lands: wrong project (token mismatch) or scope-limited key; check arrival, not the status code.
- 401: not a server key (probably an Android API key - matrix it per firebase.md section 4 instead).
- 403 with a scope error: v1-era key or restricted; read the error body, it names the actual scope.

Negative control in the same session: garbage key -> 401.

## 3. Topic operations (legacy keys)

```bash
# subscribe your own token to a topic (then observe it):
curl -sv -X POST 'https://iid.googleapis.com/iid/v1/<YOUR-OWN-TOKEN>/rel/topics/BB-probe' \
  -H 'Authorization: key=<SERVER-KEY>' 2>&1 | grep '< HTTP'
# topic send (arrival = verdict, on your own subscription):
curl -sv -X POST 'https://fcm.googleapis.com/fcm/send' \
  -H 'Authorization: key=<SERVER-KEY>' -H 'Content-Type: application/json' \
  -d '{"to": "/topics/BB-probe", "data": {"bb": "1"}}' 2>&1 | grep -E '< HTTP|success'
```

## 4. FCM v1 (service-account JSON -> OAuth -> send)

See firebase.md section 5 for the full token-mint script. The send (own token only):

```bash
curl -sv -X POST 'https://fcm.googleapis.com/v1/projects/<PROJECT>/messages:send' \
  -H 'Authorization: Bearer <ACCESS-TOKEN>' -H 'Content-Type: application/json' \
  -d '{"message": {"token": "<YOUR-OWN-TOKEN>",
       "notification": {"title": "BB_PROOF", "body": "<MARKER>"},
       "data": {"deeplink": "https://<AUTOVERIFY-HOST>/probecanary"},
       "android": {"notification": {"click_action": "OPEN_ACTIVITY"}}}}' 2>&1 | grep -E '< HTTP|"name"'
```

The `data.deeplink` field is the payload-control primitive for section 6.

## 5. Vendor REST keys (OneSignal / Airship / Braze / etc)

```bash
# OneSignal (app_id + REST key, both commonly in the JS/RN corpus):
curl -sv -X POST 'https://api.onesignal.com/notifications' \
  -H 'X-ONE-SIGNAL-API-KEY: <REST-KEY>' -H 'Content-Type: application/json' \
  -d '{"app_id": "<APP-ID>", "include_player_ids": ["<YOUR-OWN-PLAYER-ID>"],
       "headings": {"en": "BB_PROOF"}, "contents": {"en": "<MARKER>"}}' 2>&1 | grep -E '< HTTP|recipients|errors'
# read APIs (often the bigger finding than send):
curl -s 'https://api.onesignal.com/apps/<APP-ID>/users?limit=5' -H 'X-ONE-SIGNAL-API-KEY: <REST-KEY>' | head -c 400
curl -s 'https://api.onesignal.com/apps' -H 'X-ONE-SIGNAL-API-KEY: <REST-KEY>' | head -c 400
```

Each vendor: find the REST surface in their docs pattern (send endpoint, apps/list endpoint, users/segments read endpoints), capability-matrix with one real call per capability, 403s bounding the CANNOT side.

## 6. Push-to-deeplink tracing (the chain that pays)

First read the handler statically so the payload is built right:

```bash
# which data keys become intent URIs (onMessageReceived -> getStringExtra -> Uri.parse/Intent):
grep -rn -A8 'onMessageReceived' decoded/jadx-out/ | grep -E 'getStringExtra|Uri\.parse|Intent\(' | head -20
```

Then the live trace (send with your deeplink key from section 2/4, tap on-device):

```bash
adb logcat -c
# (tap the notification on the device)
sleep 4
adb logcat -d | grep -iE 'intent|deeplink|fcm|push|loadUrl|chromium' > push_deeplink_<n>.log
adb exec-out screencap -p > push_receipt_<n>.png
# fire the same deeplink directly for the control trace:
adb shell am start -a android.intent.action.VIEW -d '<SAME-DEEPLINK-URL>'
adb logcat -d | grep -iE 'intent|loadUrl' | tail -10
```

Payload controlled by you + landing chain executed on-device + callback hit or WebView load = the push->deeplink->bridge chain evidence pack (push-notifications.md section 6).

## 7. Push-token leakage probes (the IDOR of push)

```bash
# A/B differential on the endpoints that carry tokens:
curl -s 'https://<TARGET>/api/v1/profile' -H 'Authorization: Bearer <A-TOKEN>' | grep -ioE '(fcm|device|push)[_-]?token"?[: ]+"[^"]{20,}"' | head -3
curl -s 'https://<TARGET>/api/v1/users/<B-ID>' -H 'Authorization: Bearer <A-TOKEN>' | grep -ioE '(fcm|device|push)[_-]?token"?[: ]+"[^"]{20,}"' | head -3
# device-list endpoints, analytics events, logs:
curl -s 'https://<TARGET>/api/v1/devices' -H 'Authorization: Bearer <A-TOKEN>' | head -c 300
```

A's token returned by B's call = cross-user token disclosure (differential transcript). NEVER push to the leaked token: the chain (token leak + send capability) is documented, the demo runs on your own token pair.

## 8. Notification content disclosure (lock-screen class)

Set up a real notification through the app's own trigger (message yourself from account B via the app), then:

```bash
adb exec-out screencap -p > lockscreen_<n>.png      # with the screen locked
adb shell dumpsys notification --noredact | grep -B3 -A10 '<PKG>' | head -40
```

Sensitive body classes (health/finance/order contents) rendered on the lock screen with no hide setting = the content finding (check the app's settings surface first).
