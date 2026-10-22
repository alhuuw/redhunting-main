---
name: rh-class-graphql
description: >-
  Class 20 of the redhunting attack playbook: GraphQL Surfaces. Loaded by the Confirm
  phase when the lead board routes a lead of this class. Pair it with the
  command-level depth in cheatsheets/graphql.md and close every
  claim through the verification ladders in verification.md.
triggers: graphql
---

## 20. GraphQL Surfaces (error-oracle + per-service gates + mass dumps)

Signal: /graphql service paths in the corpus (one host serving many); introspection blocked at the gateway; list queries whose call-sites pass no pagination.

Detection workflow: three probes carry this class: the error oracle, the per-service/per-operation gate matrix, and the no-arg test.

PROOF BAR: the reconstructed schema proven by an executed query built purely from suggestions; the gate matrix captured per service and per operation (a host is not a verdict); the no-arg response saved whole with a second-account read-back.

- Introspection blocked? "Cannot query field X. Did you mean Y, Z?" leaks 3 closest real field names per probe. Iterate: wrong field -> suggested names -> correct field -> args discovery ("argument input of type ThreadPropAggrInput! is required") -> input-shape via more suggestions. Full mutation inputs reconstructed purely from validation errors on gateways where __schema was blocked. Also probe __type(name: "...") on every /public/ path sibling - one family had full unauth introspection on public while authed endpoints blocked it.
- Per-service, per-operation auth matrix: REST may 302 on missing auth while each /graphql service has its OWN gate (in-band 200 {"message":"Unauthorized"} or fully open); within one service queries and mutations can differ. A host-level verdict is always wrong.
- No-arg query test for mass dumps: before writing pagination loops, test the query's NO-ARG variant. If the app's own call-site passes no page/pageSize, the server may return the entire corpus in one response (a 29.6MB / 195K-record response was observed). The full raw response IS the scale evidence; read-back with a second account rules out caching.
