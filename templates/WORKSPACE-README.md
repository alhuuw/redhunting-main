# redhunting workspace

Persistent operation workspace. Nothing in here is ever auto-deleted: findings, leads, vault ammo, retest queues and the journal are the compounding capital of the operation.

## Layout

```
targets/<slug>/        one directory per target (app, system, estate)
  target.json          scope + org + disclosure contact
  scope.txt            raw imported scope, the contract
  hunt.json            current hunt parameters (rh_kickoff)
  sprint.json          live sprint clock state (rh_clock)
  sprints.jsonl        sprint history with wrap logs
  findings/<slug>/     NAMED finding folders (never bare numbers)
  leads.jsonl          the lead board
  ledger.jsonl         findings ledger (append-only)
  vault.md             chain ammunition
  retest.md            target-change triggers
  accounts.md          self-registered random test identities
  notes.md             round logs, sprint wraps, mode transitions
journal.md             dated learn-back log (the book)
```

## Standing rules

Random identity per engagement; the operator's real identity never appears in any file. Every claim verified to its ceiling before it is written. Small-scale verification of impact is the job; large-scale destruction is the only line. The sprint cannot be abandoned: wrap it before session end. Reports are written by the operator from the material packs; the agent never writes or sends the final report.
