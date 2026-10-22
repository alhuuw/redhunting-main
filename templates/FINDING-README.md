# <title>

- ID: <id>  (internal ledger id; the folder name is the finding's real name)
- Class: <class>  Severity: <severity>
- Folder: findings/<slug>/
- Status: draft | verified | sent | resolved | duplicate | retracted
- VERIFICATION.md: the verification state (every claim -> command -> raw transcript)
- materials.md: the material pack the OPERATOR turns into a report

## What this folder contains

```
README.md          this file
SUMMARY.md         the finding summary (impact statement + measured numbers)
VERIFICATION.md    verification checklist: claim / ladder / evidence / verdict
materials.md       report materials: evidence index, timeline, numbers, commands
evidence/raw/      tool-generated raw transcripts (+ SHA256SUMS.txt, .bin bodies)
poc/               self-verifying PoC scripts (--mask default)
```

## Rules

Every claim in SUMMARY.md maps to a row in VERIFICATION.md and a raw transcript in evidence/raw/. Unverified claims are deleted, not softened. The agent never writes the final report; the operator writes it from materials.md.
