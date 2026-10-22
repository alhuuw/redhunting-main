# materials: findings/<slug> (report materials for the OPERATOR)

This pack contains everything needed to write the report by hand. The agent never writes the final report and never sends anything: the operator reads this pack, writes the report in their own voice, and handles disclosure themselves.

## Evidence index

| File | What it proves |
|---|---|
| evidence/raw/<file> | (one line per transcript: the request, the response, what it demonstrates) |
| evidence/raw/SHA256SUMS.txt | integrity chain over every raw file |

## Timeline (UTC, from transcripts)

- (capture timestamps in order: first probe, differential, controls, retests)

## Numbers (from rh_impact / counted from transcripts)

- Record count, PII population %, freshness (newest/oldest), scale, data classes, monetary cap.

## Command log (copy-paste reproduction)

```bash
# 1. (step)
<command>
# 2. (step)
<command>
```

## Chain context

- What this finding enables elsewhere (chain matrix row, lateral map).
- Boundary: what was deliberately NOT executed and why.

## Novelty notes

- Closest prior art you know of and the delta (the operator confirms this before writing).

## Writing notes (for the operator, not for the report)

- Suggested emphasis, ordering of impact facts, anything the numbers imply that a triager would ask about.
