---
name: rh-class-xss-dom
description: >-
  Class 10 of the redhunting attack playbook: XSS / DOM. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/payloads.md and close every
  claim through the verification ladders in verification.md.
triggers: xss dom
---

## 10. XSS / DOM (chained, or it pays nothing)

Signal: reflected parameters, stored fields (names, addresses, chat), DOM sinks (innerHTML, document.write, eval), postMessage handlers without origin checks, JSONP callbacks, template rendering of user input.

Detection workflow: context analysis first (which sink, which context, which encoder); canary + unique markers per injection point; browser-verified execution (a headless harness that reports CONFIRMED only when the payload actually executes: dialog, hooked sink, console artifact) - alert(1) in a screenshot is not impact, it is a screenshot; stored: plant via your account, trigger via your second account (the cross-user hop is the impact proof); DOM: source-to-sink trace in the JS, then live execution; postMessage: enumerate origins, fire crafted messages from an attacker page.

PROOF BAR: browser-executed payload capture + the cross-account hop for stored + what the JS context actually reaches (cookies? tokens in localStorage? CSRF token theft?).

FP TRAPS: alert(1) with HttpOnly session (session theft NOT proven - find what the JS context reaches before claiming ATO); self-XSS (instant N/A, chain or vault); reflected XSS behind authentication on your own account page (needs a victim-delivery path); WAF-blocked variants (blocked-by-WAF is not fixed; document the bypass ladder attempt honestly).

Chain tree: XSS > session/CSRF-token theft > action forgery > ATO > (stored) mass victims > aggregate. On modern targets the chain IS the report; bare reflected XSS is P4-P3.
