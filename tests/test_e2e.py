#!/usr/bin/env python3
"""redhunting regression suite (part 2: end-to-end against the bundled demo app).

Boots demo/serve.py on a random 127.0.0.1 port, then drives the real pipeline as a
hunter would: init -> kickoff -> clock -> scope -> capture (positive + control through
the front door) -> ledger scaffold -> SUMMARY + VERIFICATION -> gate -> evidence check
-> materials -> wrap. Asserts the gate exits 0 (submittable-by-operator state).

Run: python3 -m unittest discover -s tests -v
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BIN = REPO / "bin"
DEMO = REPO / "demo" / "serve.py"

SUMMARY = """---
id: RH-1
title: "Unauthenticated read of all demo orders via sequential order ids"
class: idor
severity: high
url: "http://127.0.0.1:{port}/api/orders/1001"
status: draft
---
# Unauthenticated read of all demo orders via sequential order ids

## Summary
An attacker with no account reads every order on the demo service by walking sequential order ids. 10 of 10 sampled ids returned full records including names and phones.

## Impact
- Record count: 10 distinct orders (ids 1001..1010, zero gaps rejected)
- PII field population: customer_name on 10 of 10 (100%), phone on 10 of 10 (100%)
- Freshness: newest created_at 2026-09-0x (current month); oldest 2026-09-01
- Scale: single global sequence; no tenant scoping
- Data classes: personal names, home addresses, phone numbers

## Reproduce
1. Request an order with no credentials:

```bash
curl -i 'http://127.0.0.1:{port}/api/orders/1001'
```

3. The response returns the full order record (200, JSON).
4. Walk order ids 1001..1010: 10 distinct orders returned, zero 401/403.

## Limitations (what this evidence does NOT establish)

- repetition, ordering, and cache semantics beyond the captured pair were not probed (bounded-unknown, parked as a lead)
- no upstream chain weakness is claimed or laundered into this finding
## Root cause
The handler resolves the order by primary key with no authentication or ownership predicate.

## Fix
1. Require an authenticated principal and an ownership predicate at the resolver.
2. Replay the PoC: unauthenticated request must 401.

## Self-Verify
### Verify it yourself (operator runbook)
```bash
curl -i 'http://127.0.0.1:{port}/api/orders/1001'
```
Check in a browser: http://127.0.0.1:{port}/api/orders/1001 (paste, observe, screenshot)
"""

VERIFICATION = """# VERIFICATION: findings/unauthenticated-read-all-demo-orders

## Claim table

| # | Claim | Follow-through ladder (per knowledge/verification.md) | Evidence | Verdict |
|---|-------|--------------------------------------------------------|----------|---------|
| C1 | unauthenticated read of every order by sequential id | no-credential differential (positive vs 401 control same run); range walk 1001..1010 (10/10); recency from created_at; garbage-bearer control on /api/me | evidence/raw/unauthenticated-read-all-demo-orders_idor_walk.txt | VERIFIED |

## Ladder log

### C1 attempt 1 (regression run)
$ rh_capture idor_walk (no credentials) + control_garbage (garbage bearer on /api/me, 401)
verdict: positive 200 with PII; control 401; 10/10 sequential ids return records
next: DONE

## Identity check

- Control surface: /api/me rejects garbage bearer (401), proving the gate exists while /api/orders ignores it entirely
- Differential transcript: evidence/raw/unauthenticated-read-all-demo-orders_control_garbage.txt

## Negative controls

- Garbage bearer on /api/me, same capture run: 401 captured
- Result: authentication exists on the estate; object reads on /api/orders bypass it

## Retests

- Retest 1: evidence/raw/unauthenticated-read-all-demo-orders_idor_walk_retest1.txt (identical: yes)

## Ceiling statement

Demonstrated: unauthenticated read of all 10 orders with PII fields, negative control captured. Boundary: write path does not exist on the demo surface.
"""


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestEndToEndDemo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.proc = subprocess.Popen([sys.executable, str(DEMO), str(cls.port)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=1):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            cls.tearDownClass()
            raise RuntimeError("demo app did not start")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="rh_e2e_")
        self._old = os.environ.get("RH_HOME")
        os.environ["RH_HOME"] = self.home

    def tearDown(self):
        if self._old is None:
            os.environ.pop("RH_HOME", None)
        else:
            os.environ["RH_HOME"] = self._old
        shutil.rmtree(self.home, ignore_errors=True)

    def cli(self, *args, expect=None):
        cmd = [sys.executable, str(BIN / args[0])] + [str(a) for a in args[1:]]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if expect is not None:
            self.assertEqual(r.returncode, expect, f"rc={r.returncode}\n{r.stdout}\n{r.stderr}")
        return r

    def test_full_lifecycle_gate_passes(self):
        slug = "demotarget"
        scope = self.home and (Path(self.home) / "scope.txt")
        scope.write_text("127.0.0.1\n")
        base = f"http://127.0.0.1:{self.port}"

        self.cli("rh_init.py", slug, "--scope-file", scope, "--org", "Demo Corp", expect=0)
        self.cli("rh_kickoff.py", slug, "--yes", "--sprint", "30", "--mode", "dynamic", "--adb", "off", expect=0)
        self.assertTrue((Path(self.home) / slug / "hunt.json").exists())
        self.cli("rh_clock.py", slug, "start", "--minutes", "30", "--focus", "demo idor", expect=0)

        r = self.cli("rh_scope.py", slug, "--check", "127.0.0.1")
        self.assertEqual(r.returncode, 0)
        self.assertIn("IN-SCOPE", r.stdout)

        r = self.cli("rh_ledger.py", slug, "add",
                     "--title", "Unauthenticated read of all demo orders via sequential order ids",
                     "--class", "idor", "--severity", "high", expect=0)
        import re as _re
        m = _re.search(r"findings/([^/]+)/", r.stdout)
        self.assertIsNotNone(m, r.stdout)
        fslug = m.group(1)
        fdir = Path(self.home) / slug / "findings" / fslug
        self.assertTrue(fdir.is_dir(), fdir)

        self.cli("rh_capture.py", slug, fslug, "GET", f"{base}/api/orders/1001",
                 "--tag", "idor_walk", "--note", "positive probe: no credentials", expect=0)
        self.cli("rh_capture.py", slug, fslug, "GET", f"{base}/api/me",
                 "--header", "Authorization: Bearer garbage.token.value",
                 "--tag", "control_garbage", "--note", "negative control: garbage bearer", expect=0)
        self.cli("rh_capture.py", slug, fslug, "GET", f"{base}/api/orders/1001",
                 "--tag", "idor_walk_retest1", "--note", "retest 1", expect=0)

        raw = fdir / "evidence" / "raw"
        walk = (raw / f"{fslug}_idor_walk.txt").read_text()
        self.assertIn("200 OK", walk)
        self.assertIn("customer_name", walk)
        self.assertIn("TOOL: rh_capture.py", walk)
        control = (raw / f"{fslug}_control_garbage.txt").read_text()
        self.assertIn("401", control)
        self.assertTrue((raw / "SHA256SUMS.txt").exists())

        (fdir / "SUMMARY.md").write_text(SUMMARY.replace("{port}", str(self.port)))
        (fdir / "VERIFICATION.md").write_text(VERIFICATION)

        r = self.cli("rh_validate.py", slug, fdir / "SUMMARY.md")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("VERIFIED", r.stdout)

        r = self.cli("rh_verify.py", slug, "evidence", fdir)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("SHA chain covers all", r.stdout)

        r = self.cli("rh_verify.py", slug, "snippet", fdir / "SUMMARY.md", expect=0)
        self.assertIn("Verify it yourself", (fdir / "SUMMARY.md").read_text())

        r = self.cli("rh_materials.py", slug, fdir / "SUMMARY.md", expect=0)
        pack = (fdir / "materials.md").read_text()
        self.assertIn("Evidence index", pack)
        self.assertIn("idor_walk", pack)

        state_path = Path(self.home) / slug / "sprint.json"
        state = json.loads(state_path.read_text())
        state["started_at"] = "2000-01-01T00:00:00Z"
        state_path.write_text(json.dumps(state))
        self.cli("rh_clock.py", slug, "wrap", "--findings", "1", "--negatives", "0",
                 "--note", "e2e regression", expect=0)
        hist = [json.loads(l) for l in (Path(self.home) / slug / "sprints.jsonl").read_text().splitlines()]
        self.assertEqual(hist[-1]["findings"], 1)

    def test_demo_surfaces_alive(self):
        import urllib.request

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None

        opener = urllib.request.build_opener(NoRedirect)
        try:
            opener.open(f"http://127.0.0.1:{self.port}/redirect?url=https://example.org", timeout=5)
            self.fail("expected 302 redirect")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 302)
            self.assertEqual(e.headers.get("Location"), "https://example.org")
            e.close()
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/debug/config", timeout=5) as resp:
            body = json.loads(resp.read())
            self.assertIn("payment_api_key", body)


if __name__ == "__main__":
    unittest.main()
