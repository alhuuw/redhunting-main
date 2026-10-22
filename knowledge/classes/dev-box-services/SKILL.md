---
name: rh-class-dev-box-services
description: >-
  Class 18 of the redhunting attack playbook: Dev-Box Service Patterns After a
  Pivot (Eureka / Spring Cloud Config). Loaded by the Confirm phase when the
  lead board routes a lead of this class. Pair it with the command-level depth
  in cheatsheets/http.md and close every claim through the verification
  ladders in verification.md.
triggers: eureka spring config dev box 8761
---

## 18. Dev-Box Service Patterns After a Pivot (Eureka / Spring Cloud Config)

Signal: dev/staging hostnames resolved from the artifact corpus (DuckDNS, *.dev, ip_-style keys in Remote Config dumps); open Java ports (8761/8763, 9xxx) on boxes the app references; anonymous-reachable microservice registries or config servers.

Detection workflow:
1. Full 1-65535 scan FIRST (a 36-port common list missed 14 of 17 services on one real box). Java dev stacks live at 8761/8763 (Eureka) and 9xxx (Spring Cloud Config).
2. Eureka read: GET /eureka/apps lists every microservice plus internal IPs, usually unauthenticated: that listing is the estate map.
3. Spring Cloud Config: GET /{app}/{profile} serves ANY app name's full YAML: routes, ports, auth-exempt path maps, plaintext passwords.
4. Auth discriminator per service: garbage Bearer -> 403 = a service filter exists (honest negative); no header -> 500 = the same filter's exception, NOT a bypass. "/actuator/env" returning config-server JSON is the config route pattern-matching name="actuator", not a real actuator.
5. Eureka write discipline: POST /eureka/apps/{APPNAME} -> 204, UPPERCASE names, registering under an EXISTING app name appends a second instance. SAFE routing-hijack proof: register a canary pointing at a port on the SAME BOX serving a distinctive body (metrics exporters are perfect), call the gateway route with YOUR OWN probe, watch the body swap. Never intercept real user tokens to prove impact.
6. Lease hygiene: durationInSecs 60-300 with renewalInterval HIGHER than duration makes the instance self-evict; still DELETE and verify a 404 read-back.

PROOF BAR: the Eureka listing + config YAML captured verbatim (they are the estate map), the 403-vs-500 discriminator pair per service, and for the write: canary registration + own-probe body swap + DELETE + 404 read-back.

FP TRAPS: gateways that REGISTER into Eureka but do not FETCH from it (fetch-registry=false) make routing-hijack a non sequitur: test it and report the registry write separately from the (negative) routing claim; the 500-on-no-header is the filter's exception, not an open service.

Chain tree: dev-host resolution > port census > registry listing > config YAML (routes, credentials) > anonymous-reachable CI > known CVE (class 17 Jenkins ladder) > aggregate.
