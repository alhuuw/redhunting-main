# Identity: Random Per Engagement, Always

The operator's real identity (name, handle, email, phone, account names, device ids, anything personally identifying) NEVER appears in: any workspace file, any transcript, any request header, any registered account, any PoC script, any screenshot, any communication. This is a hard, unbreakable rule - not a preference, not a default.

## The doctrine

1. Every engagement gets ONE random identity: a generated handle (word.letters+digits, rh_kickoff generates it), one tempmail inbox family, and test accounts registered under it. The identity is recorded in accounts.md under the engagement and never reused on another target. Cross-target identity reuse builds a correlation trail: two orgs comparing notes see the same actor; an abuse report on one burns the other.
2. Account creation is self-service only: tempmail MCP create -> register on the target with the emailed verification code -> tempmail wait. When the target requires SMS/phone verification that cannot be self-served, the account becomes a BLOCKED-with-revisit lead and the hunt pivots to unauthenticated surfaces. No complaining, no workarounds that touch other people.
3. User-Agent, headers, and fingerprints in probes come from the target's own client (replayed app UA, configured impersonation profile), never from anything tied to the operator.
4. Screenshots and HAR captures get a masking pass before they enter evidence: crop/blur anything that names the operator (inbox addresses, account handles, device names). The evidence pack proves things about the TARGET, never about us.
5. PoC scripts and transcripts never embed the operator's environment: no real home paths, no real usernames, no personal config. Test values are the random identity's values.
6. If a finding's evidence unavoidably includes operator-identifying data (e.g. the inbox address of account A in an OTP transcript), it stays in evidence/raw (masked in SUMMARY references) and the operator masks it further before writing anything external.

## Why this is not paranoia

- We hunt apps and systems whose owners do not know us. A correlated identity across targets turns independent hunting into a tracked campaign, invites legal attention, and gets findings dismissed as one actor's pattern.
- Random-per-engagement identities make every engagement a clean experiment: no reputation to defend, no history to poison, no ban to inherit.
- The operator communicates with orgs (if at all) as themselves, separately, from the material packs. The hunting identity and the human never mix.

## Practical rules

- One identity = one target = one engagement folder. accounts.md maps identity -> accounts -> purpose.
- Never register a test account with a pattern that ties engagements together (same birthday, same password shape across targets, sequential usernames). The generator randomizes.
- When an org's dispute process demands identity (rare, and only for coordinated disclosure), the OPERATOR decides that, outside this skill's loop.
