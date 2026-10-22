# ADB + Frida Cheatsheet: on-device execution, instrumentation, traffic capture

On-device commands for the mobile classes (deeplink, push, IPC, backup) and the Frida hook patterns that pay off across targets. The device comes from kickoff hunt.json (adb on/detect with ABI). Every dynamic proof lands in evidence/raw (adb logcat captures satisfy the raw-evidence rule; pipe them to files).

## 1. Device basics

```bash
adb devices -l                                  # attached devices + transport
adb -s <SERIAL> shell getprop ro.product.cpu.abi   # ABI BEFORE pushing anything
adb -s <SERIAL> shell getprop ro.build.version.release
adb shell settings get global http_proxy        # current proxy state
adb -s <SERIAL> install -r app/base.apk         # install the exact build under test
adb shell pm list packages | grep <PKG>         # confirm install
adb shell dumpsys package <PKG> | grep -A4 'android.intent.action.VIEW'   # registered handlers
```

## 2. Proxy + CA for traffic capture

```bash
# set proxy to your host running Burp/mitmproxy
adb shell settings put global http_proxy <HOST-IP>:8080
# clear it after
adb shell settings put global http_proxy :0
# push the CA (works only if app targets API<24 or permissive networkSecurityConfig, check the manifest first)
adb push burp-ca.crt /sdcard/
# system CA (rooted/AVB-disabled emulator only):
adb root && adb remount && adb push burp-ca.crt /system/etc/security/cacerts/c8750f0d.0 && adb shell chmod 644 /system/etc/security/cacerts/c8750f0d.0 && adb reboot
```

Pinned anyway = the Frida unpinning pass (section 6).

## 3. Deeplink firing (class 11a, on-device execution is the proof)

```bash
# fire the scheme form
adb shell am start -a android.intent.action.VIEW -d '<APP-SCHEME>://path/param?x=<CANARY>'
# fire the https/App-Link form (autoVerify host)
adb shell am start -a android.intent.action.VIEW -d 'https://<AUTOVERIFY-HOST>/path?x=<CANARY>'
# explicit exported activity (from manifest triage)
adb shell am start -n <PKG>/<PKG>.ExportedActivity --es param '<CANARY>'
# trace what happened (logcat capture -> evidence/raw/deeplink_<n>.log)
adb logcat -c && adb shell am start -a android.intent.action.VIEW -d '<DEEPLINK>' && sleep 3 && adb logcat -d | grep -iE 'intent|deeplink|webview|chromium|loadUrl' > deeplink_<n>.log
```

Fuzz the handler parameters: wrap the am start in a loop over your param list, one logcat capture per variant.

## 4. IPC / exported surface

```bash
# exported providers (content:// query)
adb shell content query --uri content://<AUTHORITY>/items
# path traversal in openFile implementations
adb shell content query --uri 'content://<AUTHORITY>/../../data/data/<PKG>/shared_prefs/auth.xml'
# exported receivers: broadcast crafted intents (protected broadcasts refuse; note which)
adb shell am broadcast -a <CUSTOM-ACTION> --es extra '<CANARY>'
# grant check on providers
adb shell dumpsys package <PKG> | grep -B2 -A6 'grantUriPermissions'
```

## 5. Backup analysis (allowBackup=true)

```bash
adb backup -f app.ab -noapk <PKG>          # say NO to the password prompt
dd if=app.ab bs=24 skip=1 | zlib-flate -uncompress > backup.tar 2>/dev/null || java -jar abe.jar unpack app.ab backup.tar
tar -tf backup.tar | grep -iE 'pref|xml|db|token|auth'
grep -rniE 'token|session|password|bearer' extracted-backup/ | head -30
```

Tokens in the backup = the local-data-theft finding (report where policy scopes it; chain material otherwise).

## 6. Frida standard passes

```bash
# frida-server (ABI-matched!) on device
adb push frida-server-<VER>-android-<ABI> /data/local/tmp/fs && adb shell "chmod 755 /data/local/tmp/fs && /data/local/tmp/fs &"
frida-ps -U | grep <PKG>                      # confirm the session

# universal SSL unpinning (one of these always fits)
frida -U -f <PKG> -l unpinning-script.js --no-pause
# root detection neutralization (hook the methods, not the files)
frida -U -f <PKG> -l root-bypass.js --no-pause
```

## 7. Frida hook templates (the ones that pay)

```javascript
// hook a signature/header builder (class + method from jadx/blutter; javadecomp names first)
Java.perform(function () {
    var Builder = Java.use('com.<PKG>.net.SignatureInterceptor');
    Builder.intercept.implementation = function (chain) {
        var req = chain.request();
        console.log('[SIG] url=' + req.url());
        var h = req.headers();
        console.log('[SIG] headers=' + h.toString());
        return this.intercept(chain);
    };
});

// dump Cipher keys/IVs as used
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('javax.crypto.SecretKey', 'java.security.spec.AlgorithmParameterSpec').implementation = function (k, spec) {
        console.log('[CIPHER] algo=' + this.getAlgorithm());
        try { console.log('[CIPHER] key=' + Java.use('java.util.Arrays').toString(k.getEncoded())); } catch (e) {}
        try {
            var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
            if (spec.$className === 'javax.crypto.spec.IvParameterSpec') console.log('[CIPHER] iv=' + Java.use('java.util.Arrays').toString(Java.cast(spec, IvParameterSpec).getIV()));
        } catch (e) {}
        return this.init(k, spec);
    };
});

// trace WebView loads + JS bridges (deeplink chain execution evidence)
Java.perform(function () {
    var WV = Java.use('android.webkit.WebView');
    WV.loadUrl.overload('java.lang.String').implementation = function (url) {
        console.log('[WV] loadUrl=' + url);
        return this.loadUrl(url);
    };
});

// SharedPreferences reads (token storage locations)
Java.perform(function () {
    var SPE = Java.use('android.app.SharedPreferencesImpl');
    SPE.getString.implementation = function (k, d) {
        var v = this.getString(k, d);
        console.log('[PREF] ' + k + ' = ' + v);
        return v;
    };
});

// FirebaseMessagingService payload -> intent mapping (push class)
Java.perform(function () {
    var FMS = Java.use('com.<PKG>.push.MyFirebaseMessagingService');
    FMS.onMessageReceived.implementation = function (msg) {
        console.log('[PUSH] data=' + JSON.stringify(msg.getData()));
        console.log('[PUSH] notification=' + (msg.getNotification() ? msg.getNotification().getTitle() : null));
        return this.onMessageReceived(msg);
    };
});
```

Method: locate statically (jadx MCP get_class), hook, exercise the app in the UI, capture the console output to evidence/raw/frida_<n>.log. A captured real signature + a replayed accepted request is proof.

## 8. Frida anti-detection notes

- Rename frida-server; gadget mode embedded in a repackaged APK when port 27042/name detection fires.
- Spawn-time hooks (`-f`) beat attach for packers that check at startup.
- LIAPP/DexGuard/PairIP: static extraction on string pools still works; runtime hooks need anti-anti-frida work; budget it (a sprint wrap note, not a stall).

## 9. Push on-device proof (push-notifications.md, own token only)

```bash
# after sending to YOUR OWN token via the recovered key:
adb logcat -d | grep -iE 'fcm|push|FirebaseMessaging' > push_receipt_<n>.log
# screenshot the notification (the operator-verified artifact)
adb exec-out screencap -p > notification_<n>.png
# notification listener state (proves the payload reached the system layer)
adb shell dumpsys notification --noredact | grep -A8 '<PKG>'
```

## 10. Version diff driver (the retest flywheel)

```bash
# current installed version vs newest store version (play_meta.py / apkpure MCP)
adb shell dumpsys package <PKG> | grep -E 'versionName|versionCode|lastUpdateTime'
# pull the installed build for comparison (device_pull tool)
python3 tools/device_pull/get_app_from_device.py <PKG>
# diff two decoded builds (after mirror acquisition + same-signer check)
diff <OLD>/extracted/allstrings.txt <NEW>/extracted/allstrings.txt | grep -iE 'secret|key|token|http' | head -40
```
