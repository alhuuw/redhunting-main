# VERIFICATION: findings/<slug>

Every claim in SUMMARY.md gets a row here. A row is not closed until its follow-through ladder is exhausted and every step cites a raw transcript in evidence/raw/. Unverified rows are deleted from SUMMARY.md, never softened. The word "potential" does not exist in this file's vocabulary: a claim is verified, or it is not written.

## Claim table

| # | Claim | Follow-through ladder (per knowledge/verification.md) | Evidence | Verdict |
|---|-------|--------------------------------------------------------|----------|---------|
| C1 | | (steps, one per line, each ending in a transcript) | evidence/raw/<file> | VERIFIED / DELETED |
| C2 | | | | |

## Ladder log (append-only, one block per attempt)

```md
### C1 attempt 1 (date, command, result)
$ <command as run>
<raw output or pointer to evidence/raw file>
verdict: <what this step proved or killed>
next: <the next step in the ladder, or DONE>
```

## Identity check (auth classes: A attacks B, both self-registered)

- Account A: (random identity handle, accounts.md)
- Account B: (random identity handle, accounts.md)
- Differential transcript: evidence/raw/<file>
- Fresh-session reproduction: evidence/raw/<file>

## Negative controls

- Garbage credential on the same endpoint, same capture run: evidence/raw/<file>
- Result: (401/403/differential that proves the gate exists)

## Retests

- Retest 1: evidence/raw/<file> (result identical: yes/no)
- Retest 2: evidence/raw/<file> (result identical: yes/no)

## Ceiling statement (write only after every row closes)

The demonstrated ceiling of this finding is: (exactly what was proven, and the exact boundary where proof stops: which capability was exercised, which was documented-but-not-executed and why).
