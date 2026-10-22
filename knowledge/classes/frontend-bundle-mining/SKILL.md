---
name: rh-class-frontend-bundle-mining
description: >-
  Class 14 of the redhunting attack playbook: Frontend Bundle Mining. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/payloads.md and close every
  claim through the verification ladders in verification.md.
triggers: frontend bundle mining
---

## 14. Frontend Bundle Mining (technique class: multiplies every other class)

Signal: any modern SPA/Next/Nuxt build in the corpus (app-embedded web bundles, offline webviews, desktop asar).

Detection workflow: every build ships a map of its own attack surface; mine it before touching endpoints.

PROOF BAR: each mined artifact (route, host, leftover component, path string) converts through the class it feeds; the bundle output itself is the input map, not the finding.

Every modern SPA/Next/Nuxt build ships a map of its own attack surface. Mine it before touching endpoints:
- Build manifest: /_next/static/<buildId>/_buildManifest.js lists EVERY route including internal tooling (/admin, /automation) the UI never links.
- Lazy chunk resolution: page chunks reference webpack ids; the runtime chunk maps ids to filenames; the real API code lives in lazy chunks, not the shell.
- API host inventory: grep chunks for https:// bases - staging AND production bases leak environment topology; dev/stg/prod builds differ in chunk hashes; diff them.
- Leftover TEST/DEBUG components are gold: hardcoded working request examples, pool UUIDs, token formats the UI never uses.
- Binary parsers ship in the bundle: port the SPA's own DataView decoder to parse API responses mechanically (impact quantification becomes counting, not guessing).
- postMessage origin audits: enumerate window.addEventListener('message') handlers and their origin checks; craft messages from an attacker page.
- Parameter semantics: replicate the client's EXACT URL construction (trailing slash, seq cursor, param order) - the difference between 400 and 200 is routinely the client's own quirk.
- Same mining applies to web bundles embedded in apps (assets/liveupdates, offline webviews) and desktop Electron asar (npx @electron/asar extract; grep renderer.prod.js/main.prod.js for firebaseConfig - desktop apps frequently register SECOND Firebase projects for SSO; literal RTDB path strings reveal the SSO token-handoff pattern).
