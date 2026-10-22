# Materials: The Report Bahan Doctrine

The agent NEVER writes the final report and NEVER sends anything to anyone. The operator writes the report themselves, in their own voice, from the material pack - and handles all communication themselves. Two reasons: organizations do not accept reports that read as machine-generated (a slop-shaped report kills the finding's credibility before it is read), and the operator owns the disclosure relationship and its timing.

What the skill owes the operator: a complete, honest, copy-from-able material pack per finding, so writing the report is an hour of composition, never archaeology.

## The material pack (findings/<slug>/materials.md, built by rh_materials.py)

1. Evidence index: every raw transcript with what it proves (request, response, the demonstrated fact). SHA256SUMS integrity chain included.
2. Timeline: UTC capture timestamps in order (first probe, differential, controls, retests).
3. Impact numbers: the measured block from rh_impact.py (record count, PII population, freshness, scale, monetary cap) - numbers only, framing stays with the writer.
4. Command log: the copy-paste reproduction sequence (from SUMMARY's Reproduce section), each command with expected behavior.
5. Chain context: the chain-matrix row, the lateral map (which services accepted the credential), and the deliberate boundary (what was NOT executed and why).
6. Novelty notes: closest prior art and the delta (the operator confirms before writing).
7. Writing notes: emphasis suggestions, ordering, the questions a reader will ask first.

TODO markers for anything missing. Content is never invented; gaps are marked, not filled.

## What the operator does with it

- Writes the report in their own words: impact first, evidence links, root cause, fix. The banned-words discipline carries over by construction (the material pack contains only verified claims with transcripts).
- Decides disclosure: security.txt contact, CSIRT email, or nothing. Timing and rotation grace periods are the operator's call.
- Sends it themselves. The skill has no submit mechanism anywhere, by design.

## Quality bar for the pack

Every claim in the pack maps to a transcript. Every number is counted or parsed from captured bytes, never estimated. Every boundary is explicit (what was demonstrated vs documented-not-executed). If the operator cannot reconstruct the story from the pack alone, the pack is unfinished - same rule as the verification gate: fix the pack, not the reader.
