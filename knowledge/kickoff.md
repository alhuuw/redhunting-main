# Kickoff: Pre-Hunt Setup

Setup runs before any dynamic work: `bin/rh_kickoff.py <target>` (interactive) or flags + `--yes` (agent mode). It fixes the operating parameters in <slug>/hunt.json and is asked ONCE: when hunt.json already exists, kickoff prints the saved state and exits without asking (config lives in the target folder; --refresh is the only re-interview path). Every session after reads hunt.json instead of re-deciding.

Three questions only. Everything else is decided by the system, because asking about it would be guessing:

- Sprint length (minutes): the operator's clock budget, and a FLOOR: sessions may run longer, never shorter (config hunt.sprint_min_minutes, default 30; kickoff rejects shorter). Drives rh_clock. The sprint CANNOT be abandoned once started: wrap is refused while sprint time remains (only a deliberate --force, recorded in the wrap log, breaks the floor).
- Mode: static-first (default when an app artifact exists: decode and map first, the static map decides which dynamic probes are worth firing) / dynamic-first (no artifact: live surface mapping, grow the static side from captured traffic) / mixed (the honest reality of most hunts).
- ADB: on / off / auto-detect (default: the tool lists attached devices with ABI, plus frida availability). ADB unlocks deeplink firing, push on-device proofs, logcat tracing, backup analysis, device pulls. Check `getprop ro.product.cpu.abi` before pushing anything (mismatched arch wastes sessions).

What kickoff decides FOR the operator (never asked, never optional):

- Identity: random handle generated per engagement (word.letters+digits). The operator's real identity never appears in any file, transcript, account, or header. Previous engagement identities are never reused.
- Accounts: A and B, self-registered via the tempmail MCP at sprint start, recorded in accounts.md. Two accounts are the minimum for every auth-class identity check; OTP arrival proofs come from the same inbox. Registration walls (phone-only, invite-only) become BLOCKED-with-revisit leads and the hunt pivots to unauthenticated surfaces.
- Rate: auto-derived from target behavior. Start at config pacing (150ms), watch for 429/5xx/backpressure, back off on first signal, never push through. The ceiling is the target's tolerance, not a preference.
- Surface: the whole target estate (app, API, web, infra, push, desktop client) is mapped and hunted. Nobody pre-decides where the bug lives: app-vs-web split is an output of analysis, not an input.

## After setup, immediately

1. Register A and B (tempmail MCP) into accounts.md under the random identity.
2. Start the clock: `rh_clock.py <target> start --minutes N --target "<the one surface/class>"`.
3. Acquire the app artifact with provenance if static-first (mobile.md section 1).
4. Ingest every recon/decode output line through `rh_leadboard.py ingest`.

## hunt.json shape (written by the tool)

```json
{
  "target": "acme",
  "started": "2026-09-06T09:00:00Z",
  "sprint_minutes": 60,
  "mode": "static",
  "adb": "on:emulator-5554",
  "adb_note": "device emulator-5554 (x86_64) attached",
  "frida": "available",
  "identity": "amber.kq42",
  "identity_note": "random per engagement; the operator's real identity never appears anywhere",
  "accounts": "A and B self-registered via tempmail MCP at sprint start",
  "rate": "auto: start at config pacing.delay_ms, back off on 429/5xx, never push through",
  "surface": "the whole target estate (app, api, web, infra) is mapped before hunting; nobody pre-decides where the bug lives"
}
```

The agent re-reads hunt.json at every session start of this target: parameters persist, drift gets noticed, and nothing gets re-litigated.
