# JS Reverse: Web Crypto and Signing Recovery (pairs with playbook classes 5 and 14)

Purpose: when a web target (or a web bundle shipped inside an app) signs or encrypts request parameters, recover the algorithm and material from the shipped JavaScript, then prove it per the submit gate. The proof bar is unchanged: an offline replica decrypting a REAL captured payload, plus a server-accepted forged request. A recovered key with no replica is a lead. A replica with no forged request is a half-proof. Both halves ship together.

## 1. Acquire the corpus

- Download every JS the URL corpus references (web.md recon outputs), plus source maps when present. Record URLs, hashes, and timestamps: the corpus is provenance, same as app/.
- Check for sourceMappingURL comments (minified tail, //# sourceMappingURL=). A production .map file is itself a reportable information disclosure: it leaks original source, paths, and internal comments.
- Fetch lazy chunks (playbook class 14 webpack workflow): the build manifest lists routes, the runtime chunk maps webpack ids to filenames, every lazy chunk is a candidate carrier.

## 2. Source maps, the cheapest win

- .map files carry sourcesContent: original, unminified, pre-transpile source. Rename and pretty-print; grep for secret, sign, hmac, aes, key in the ORIGINAL source.
- No .map on the wire? Probe common siblings (app.js.map, main.js.map, chunk-*.js.map) and archive sources (wayback) for maps that were pulled later. Missing today is not proof they never shipped.

## 3. Deobfuscation ladder (obfuscator.io and friends)

Work the ladder in order, each rung verifiable by re-running the decoded output:

| Pattern | Recognition | Decode |
|---|---|---|
| String array | top-level array + a decoder function that rotates/shifts it; all strings are _0x4e2c(0x1a) style calls | replicate the decoder (pure JS), call it over every index, substitute literals |
| String array + rotation | wrapper IIFEs that call the decoder k times first (self-defending) | run the exact warmup sequence before decoding; a sandboxed node run of the real warmup is the ground truth |
| Eval hiding | eval(...), Function(...), atob chains feeding execution | override eval/Function in a Node sandbox to dump instead of execute; never execute unknown code with network access |
| Control-flow flattening | one giant dispatcher switch over a state variable inside while(true) | map each case as a basic block, build the state graph, reorder statically or trace one real execution and record the path |
| Dead code injection | long chains of never-taken branches | reachability from the dispatcher graph; discard the rest |
| Domain lock / self-defense | code that checks location.host and redirects or infinite-loops on mismatch | patch the check in the extracted copy only; the shipped file is evidence, never edited in place |

Rules: keep the ORIGINAL files untouched in the corpus; deobfuscation output goes to a work directory and is reproducible (script the transformation, keep the script). Node + Babel AST transforms beat regex for anything structural; regex is for string arrays and constant pools only. CyberChef (or a small Python replica) for quick base64/hex/xor checks before writing code.

## 4. Anti-debug and packer walls

- debugger loops: in devtools use a conditional breakpoint that skips, or neutralize via a CDP attach (Playwright/agent-browser) where you control the debugger protocol.
- Devtools detection (console accessor timing, window outer/inner size, console.clear spam, dates/toString tampering): strip the detector function in the work copy.
- JSFuck/aaencode-style packers: run in a Node sandbox with eval overridden to dump; the unpacked payload is usually plain minified JS.

## 5. Localize the signing/encryption path

- Set XHR/fetch breakpoints (devtools, or Frida on the WebView when the same web bundle ships inside the app): the stack trace at the moment the encrypted param is added names the builder function.
- Grep the deobfuscated corpus for crypto API fingerprints: CryptoJS, forge., crypto.subtle, HmacSHA256, AES.encrypt, WordArray, PBKDF2 + iteration constants.
- Hex/base64 constants near the param name are key/IV candidates. Constants that appear in BOTH the request builder and a login response model are the server-side blob pattern (passwords encrypted with the app's static key - playbook class 5).
- Recover the exact input order: salt:::iv:::b64 style separators, timestamp + nonce + body concatenation order, header casing. Replicating the client's EXACT construction is the difference between 400 and 200 (playbook class 14 parameter semantics rule).
- The vendor "morgan" pattern (playbook class 24): passphrase = md5(Authorization header || "morgan"), CryptoJS.AES with Salted__/EVP_KDF - reimplement in Python (md5-based KDF, CBC), decrypt response bodies offline.

## 6. VM / DSL bytecode (rare, treat as RE)

Some apps ship a custom interpreter: a big opcode dispatcher switch, a constant pool, and data arrays as "bytecode". When a param is built inside such a VM:

1. Identify the dispatcher and opcode semantics by tracing real executions (instrument the switch, log opcode + operands).
2. Write a disassembler for the observed opcode set; disassemble the param-builder target.
3. Read the algorithm from the disassembly; port it to Python for the replica.
4. The proof bar is unchanged: replica + forged request.

Budget discipline: a VM is a multi-round detour. Log it as a hypothesis, set a round budget, and fall back to hooking the VM's entry point in a real browser (breakpoint, capture inputs and outputs at the boundary) - often 10x cheaper than full disassembly.

## 7. Proof and evidence

- The replica script (Python or Node) goes in evidence: input a REAL captured payload, print the plaintext. The captured payload goes through rh_capture.py like any other probe.
- The forged request ships with the differential (garbage-encrypted field vs valid forge vs control, one evidence block) and the self-verify block (verification.md).
- Key material recovered statically gets file:line (or .map source:line) in the report, same as APK findings.
- Learn-back: new obfuscation patterns and their decoders go to journal.md, so rh_recall finds them next hunt.
