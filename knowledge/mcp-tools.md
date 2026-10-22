# MCP Toolbox: What to Call, When (proof-oriented usage)

The skill is self-contained: vendored tools live in tools/ inside this repo, MCP servers register with any MCP-capable agent (opencode, Claude Code, Codex CLI). Nothing assumes a specific machine layout. Registration snippets below.

## Vendored tools (in this repo)

Each tool is a self-contained folder. Every MCP server follows the same convention: one folder, one server.py.

| Tool | Path | What it does |
|---|---|---|
| APK mirror downloader | tools/apkpure/ | acquire target APKs with provenance (versioned + SHA256), bypasses CDN bot walls via TLS impersonation. CLI: `python3 tools/apkpure/apkpure_dl/cli.py <package>` |
| Play Store metadata | tools/play_store/ | `play_meta.py <pkg>` live Play Store version/update date, no account, no mirror lag - the authoritative newest-version check (retest trigger). `play_pull.py` downloads directly from Play but needs a burner Google account (see its README) |
| Device APK puller | tools/device_pull/ | ADB split-APK pull with SHA256, when you have a physical device |
| Paranoid string decoder | tools/paranoid/ | decodes io.michaelrocks.paranoid obfuscated strings offline (DeobfuscatorHelper/RandomHelper ported byte-exact from SMALI). `python3 tools/paranoid/paranoid_decode.py <Deobfuscator$Module$Release.java> <long-key> [...]` |
| CVSS MCP | tools/mcp/cvss/ | cvss31 score/explain/batch, honest severity for reports |
| Tempmail MCP | tools/mcp/tempmail/ | 7-provider disposable email: account registration + OTP arrival proofs (the self-reliance engine) |
| Shodan MCP | tools/mcp/shodan/ | host/search intel (needs SHODAN_API_KEY) |
| HackTricks MCP | tools/mcp/hacktricks/ | technique lookup before touching unfamiliar surface |
| JADX MCP | tools/mcp/jadx/ | APK decompile over the jadx CLI: single class, code search, class list, manifest (needs jadx on PATH, JADX_BIN overrides) |
| Burp MCP bridge | tools/mcp/burp/ | transparent stdio proxy to Burp's native MCP server: raw HTTP requests, Repeater/Intruder, Collaborator, scanner issues, proxy history (needs Burp running, BURP_MCP_URL overrides) |

Python deps for the vendored tools: requests, androguard, curl_cffi, pycryptodome (all listed by rh_doctor.py).

Host-level MCP servers (registered in the agent config, not vendored here; they serve js-reverse.md and native-lib RE):

| Server | Command | Serves |
|---|---|---|
| jshookmcp | `npx -y @jshookmcp/jshook@0.3.4` (env MCP_TRANSPORT=stdio) | js-reverse.md: JS hooks, CDP debugging, network monitoring, code analysis. Meta-router server: search_tools/activate_domain then call. First npx run downloads large deps; cache it before a hunt. LIFECYCLE WARNING: see the process-leak section below before registering it |
| ghidra-mcp | `uv run <bridge path>` | native .so/.dylib/ELF RE: decompile, xrefs, rename, imports/exports (25 tools). Plugin (LaurieWired GhidraMCP 1.4) in the Ghidra Extensions dir; plugin HTTP server starts from the Ghidra GUI, bridge talks to 127.0.0.1:8080. Ghidra brew formula needs JAVA_HOME pointed at the keg-only openjdk@21 |
| semgrep CLI | `brew install semgrep` | SAST leads; run directly via CLI |
| cve-mcp | `npx -y cve-mcp` | CVE enrichment: NVD/EPSS/KEV/PoC availability |

## Registering the MCP servers (any machine, any agent)

Example for an opencode config (~/.config/opencode/opencode.json), adapt <repo> to your clone path:

```json
{
  "mcp": {
    "cvss":      { "type": "local", "command": ["python3", "<repo>/tools/mcp/cvss/server.py"], "enabled": true },
    "tempmail":  { "type": "local", "command": ["python3", "<repo>/tools/mcp/tempmail/server.py"], "enabled": true },
    "shodan":    { "type": "local", "command": ["python3", "<repo>/tools/mcp/shodan/server.py"], "enabled": true,
                   "environment": { "SHODAN_API_KEY": "<key>" } },
    "hacktricks":{ "type": "local", "command": ["python3", "<repo>/tools/mcp/hacktricks/server.py"], "enabled": true },
    "jadx":      { "type": "local", "command": ["python3", "<repo>/tools/mcp/jadx/server.py"], "enabled": true },
    "burp":      { "type": "local", "command": ["python3", "<repo>/tools/mcp/burp/server.py"], "enabled": true },
    "jshookmcp": { "type": "local", "command": ["npx", "-y", "@jshookmcp/jshook@0.3.4"], "enabled": false,
                   "environment": { "MCP_TRANSPORT": "stdio" } },
    "cve-mcp":   { "type": "local", "command": ["npx", "-y", "cve-mcp"], "enabled": true }
  }
}
```

For Claude Code or Codex, the same servers register with their respective MCP config formats, same commands.

## When to call what

### Accounts and self-reliance (kickoff follow-up, immediately)
- Second account for an A-to-B IDOR proof: tempmail create -> register on the target with the emailed code -> tempmail wait with from/subject filters. Record both in accounts.md. Try skipping email verification entirely first - some backends never check it.
- OTP arrival proof: tempmail wait. The received message IS the evidence. Arrival, not result:true.
- Need more than 2 inboxes: create additional sessions; providers rotate.

### Acquisition and evidence chain
- Need the target APK (kickoff, version diffing, exact prod build): apkpure (CLI or MCP). The versioned download + SHA256 answers the report question "how did you obtain the app". apkpure_detail gives version + SHA-256 for version bisection; apkpure_play_verify gives the authoritative live version (retest trigger); apkpure_target_score gives engagement-fit and mirror-vs-Play drift.
- Raw request/response transcripts through the same engine used by hand: burp send_http1_request / send_http2_request - the returned transcript is the evidence block (capture.front_door honors it as an acceptable alternate to rh_capture).
- Out-of-band proof (SSRF, blind injection, callback reachability): burp generate_collaborator_payload, then poll get_collaborator_interactions. An interaction log entry is dispatch evidence, nothing more.
- Hand a raw request to the operator for a verdict: burp create_repeater_tab (HTTP/2 variant for modern targets), send_to_intruder for parameter sweeps.

### Validation and severity
- Exposed version fingerprint (mail servers, storage, K8s, frameworks): cve-mcp cve_by_product / nvd_search.
- Which CVEs are weaponized: cve_enrich (EPSS + KEV + PoC availability), cve_prioritize.
- PoC / metasploit / nuclei template for a candidate: exploit_search, msf_check, nuclei_check.
- CWE classification and ATT&CK impact framing: cwe_get, cvss_to_attack.
- Severity: cvss31_score + cvss31_explain, full vector in evidence, never invent scores.

Rule: a CVE from version matching is a HYPOTHESIS. Proof is the vulnerable path actually responding (404 means patched, 501 means wrong service). Report verified impact; list the unverified as surface notes.

### Recon and intel
- Unknown product or port before touching it: hacktricks search, then get_page.
- Map an IP estate, ports, banners, CPEs: shodan host. Feeds lateral movement targets.

### Static analysis (APK, agent-driven)
- Decode one suspicious class fast, no full decompile first: jadx get_class with the fully qualified name.
- Secret and endpoint sweep over decompiled sources: jadx search_code (substring; warms the cache on first call - big apps take a while, later calls are instant).
- Manifest review (permissions, exported components, deeplinks): jadx get_manifest.
- Class inventory for the coverage table: jadx list_classes with a filter.
- What jadx finds is a LEAD: hardcoded keys, endpoints, weak crypto. Capability matrices and lateral replay still convert leads into findings.
- Big-APK pattern: first MCP call on a 35MB/7-dex build exceeds the client timeout - decompile ONCE via CLI in the background and mine smali meanwhile (mobile.md section 2).

### JS reverse and native RE (js-reverse.md)
- Web target with signed or encrypted params: jshookmcp is the runtime side of js-reverse.md. search_tools for hook/CDP/network domains, activate, then hook the signer at runtime to capture exact signing inputs when static deobfuscation is ambiguous.
- Native libs (lib/*.so, .dylib, JNI): ghidra-mcp decompile_function, xrefs, list_imports for the static key-material sweep that strings misses. Rename as you confirm - the project file IS the work product.
- Both servers only live while their host app runs (Ghidra GUI + plugin server; browser session for jshook). Start the host before calling.

## Division of labor (memorize)

- Scanners (nuclei, semgrep, Burp scanner, any external scanner CLI) produce LEADS. They never produce reportable findings.
- MCP tools VALIDATE: cve-mcp turns versions into verified-or-discarded CVEs, tempmail proves dispatch and owns the accounts, cvss makes severity defensible, jadx serves the static corpus, burp issues and replays the real requests.
- Manual requests (curl, Burp, Frida, python, rh_capture) are THE PROOF. The evidence block in every report is a real request you made and a real response you received. That is what gets paid.
- Every finding presented to the operator carries a Self-Verify block they can run themselves (verification.md).

## Process lifecycle: npx-spawned MCP servers are a leak vector (learned the hard way)

The incident: an npx-spawned MCP server (jshookmcp) registered as always-on did not die with the session that spawned it. Every new session spawned a fresh instance, the old ones lingered, and three stacked instances each pulling hundreds of MB plus CPU pushed a 16 GB machine into memory exhaustion and thrashing. The same stacking appeared for npm-exec MCP servers duplicated within a single agent session.

Doctrine, in order:

1. Prefer OUR vendored MCP servers (tools/mcp/*/server.py, pure Python stdlib, tens of MB resident) over npx/npm-exec package servers. They register with the same config shape and never stack the same way.
2. npx-based servers (jshookmcp, cve-mcp, fetch) register with `"enabled": false` by default. Flip a server on ONLY for the sprint that needs it (js-reverse sprint: jshook; CVE triage: cve-mcp), and flip it off when the sprint wraps. One purpose, one sprint, one instance.
3. The machine guard runs automatically: `rh_kickoff.py` pre-flight reaps orphans and checks the budget (config machine section: memory floor, process-MB ceiling, duplicate-instance limit), `rh_clock.py wrap` reaps again at sprint close.
4. Manual control: `rh_guard.py status` (census: ORPHAN / DUPLICATE / LIVE with memory), `rh_guard.py reap` (kills orphans, safe), `rh_guard.py reap --dedupe` (also kills the OLDER duplicate of each stacked instance, newest kept), `rh_guard.py budget` (exit 0/1 for scripting). Every reap is logged to the workspace machine.log.
5. Symptoms of the leak returning: fans spin with no hunt running, memory_pressure free percentage sinking, `ps -axo pid,ppid,rss,command | grep -E "npx|npm exec"` showing multiple identical commands. Run the guard, do not reboot.
6. Heavy host-app bridges (ghidra, burp) only live with their host app running; the guard census shows them when they leak too.
