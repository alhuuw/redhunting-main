#!/usr/bin/env python3
"""redhunting regression suite (part 1: unit tests for every bin script).

Run: python3 -m unittest discover -s tests -v
Pure stdlib. No network. Each test drives the real scripts (imported or via CLI).
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BIN = REPO / "bin"


def load(name):
    spec = importlib.util.spec_from_file_location(name, BIN / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class BaseWithHome(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="rh_test_")
        self._old = os.environ.get("RH_HOME")
        os.environ["RH_HOME"] = self.home

    def tearDown(self):
        if self._old is None:
            os.environ.pop("RH_HOME", None)
        else:
            os.environ["RH_HOME"] = self._old
        shutil.rmtree(self.home, ignore_errors=True)

    def run_cli(self, *args, expect=None):
        cmd = [sys.executable, str(BIN / args[0])] + [str(a) for a in args[1:]]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if expect is not None:
            self.assertEqual(r.returncode, expect, f"rc={r.returncode}\n{r.stdout}\n{r.stderr}")
        return r


def make_target(home, slug="t1", scope_lines=None):
    tdir = Path(home) / slug
    tdir.mkdir(parents=True)
    lines = scope_lines if scope_lines is not None else ["*.acme.com", "acme.com", "exclude: staging.acme.com"]
    (tdir / "scope.txt").write_text("\n".join(lines) + "\n")
    (tdir / "target.json").write_text(json.dumps({
        "slug": slug, "scope": [
            {"type": "wildcard", "value": "*.acme.com", "base": "acme.com"},
            {"type": "domain", "value": "acme.com", "host": "acme.com"},
        ], "exclusions": ["staging.acme.com"], "unparsed": [],
    }))
    return tdir


class TestSlugify(unittest.TestCase):
    def setUp(self):
        self.ledger = load("rh_ledger")

    def test_stopwords_skipped(self):
        self.assertEqual(self.ledger.slugify("Unauthenticated read of all orders via sequential order_id"),
                         "unauthenticated-read-all-orders-sequenti")

    def test_short_title(self):
        self.assertEqual(self.ledger.slugify("SSRF in webhook"), "ssrf-webhook")

    def test_all_stopwords_falls_back(self):
        self.assertEqual(self.ledger.slugify("of the and"), "finding")

    def test_length_cap(self):
        s = self.ledger.slugify(" ".join(["word"] * 20))
        self.assertLessEqual(len(s), 40)


class TestScopeLaw(BaseWithHome):
    def setUp(self):
        super().setUp()
        self.scope = load("rh_scope")
        self.tgt = json.loads((make_target(self.home) / "target.json").read_text())

    def test_wildcard_and_base(self):
        for host in ("acme.com", "api.acme.com", "deep.sub.acme.com"):
            v, _ = self.scope.check(self.tgt, host)
            self.assertEqual(v, "in", host)

    def test_suffix_attack_rejected(self):
        v, _ = self.scope.check(self.tgt, "evil-acme.com")
        self.assertEqual(v, "out")
        v, _ = self.scope.check(self.tgt, "acme.com.evil.io")
        self.assertEqual(v, "out")

    def test_exclusion_wins(self):
        v, _ = self.scope.check(self.tgt, "staging.acme.com")
        self.assertEqual(v, "excluded")

    def test_fail_closed_on_unparsed(self):
        tgt = dict(self.tgt)
        tgt["unparsed"] = ["10.0.0.0/8"]
        v, _ = self.scope.check(tgt, "other.example")
        self.assertEqual(v, "unparsed")
        v, _ = self.scope.check(tgt, "something.acme.com")
        self.assertEqual(v, "in")

    def test_cli_exit_codes(self):
        self.run_cli("rh_scope.py", "t1", "--check", "api.acme.com", expect=0)
        self.run_cli("rh_scope.py", "t1", "--check", "evil-acme.com", expect=1)

    def test_path_scoped_url_entry(self):
        tgt = dict(self.tgt)
        tgt["scope"] = [{"type": "url", "value": "https://api.acme.com/v2", "host": "api.acme.com", "path": "/v2"}]
        v, _ = self.scope.check(tgt, "https://api.acme.com/v2/orders")
        self.assertEqual(v, "in")
        v, _ = self.scope.check(tgt, "https://api.acme.com/v3/orders")
        self.assertEqual(v, "out")


class TestKickoffIdentity(BaseWithHome):
    def test_random_identity_format_and_uniqueness(self):
        ko = load("rh_kickoff")
        ids = {ko.random_identity()["handle"] for _ in range(30)}
        self.assertEqual(len(ids), 30)
        for h in ids:
            self.assertRegex(h, r"^[a-z]+\.[a-z]{2}\d{2,4}$")

    def test_kickoff_writes_hunt_json(self):
        make_target(self.home)
        self.run_cli("rh_kickoff.py", "t1", "--yes", "--sprint", "45", "--mode", "mixed", "--adb", "off", expect=0)
        hunt = json.loads((Path(self.home) / "t1" / "hunt.json").read_text())
        self.assertEqual(hunt["sprint_minutes"], 45)
        self.assertEqual(hunt["mode"], "mixed")
        self.assertIn("adb", hunt)
        self.assertRegex(hunt["identity"], r"^[a-z]+\.[a-z]{2}\d{2,4}$")

    def test_kickoff_asks_once_only(self):
        make_target(self.home)
        self.run_cli("rh_kickoff.py", "t1", "--yes", "--sprint", "45", "--adb", "off", expect=0)
        r = self.run_cli("rh_kickoff.py", "t1", "--yes", "--sprint", "90")
        self.assertEqual(r.returncode, 0)
        self.assertIn("asked ONCE", r.stdout)
        hunt = json.loads((Path(self.home) / "t1" / "hunt.json").read_text())
        self.assertEqual(hunt["sprint_minutes"], 45, "re-kickoff must not overwrite existing config")

    def test_kickoff_sprint_below_floor_rejected(self):
        make_target(self.home)
        r = self.run_cli("rh_kickoff.py", "t1", "--yes", "--sprint", "15")
        self.assertEqual(r.returncode, 1)
        self.assertIn("below the floor", r.stdout)
        self.assertFalse((Path(self.home) / "t1" / "hunt.json").exists())


class TestClock(BaseWithHome):
    def setUp(self):
        super().setUp()
        make_target(self.home)

    def test_start_status_wrap_cycle(self):
        self.run_cli("rh_clock.py", "t1", "start", "--minutes", "60", "--focus", "x", expect=0)
        r = self.run_cli("rh_clock.py", "t1", "status")
        self.assertIn("TIME LEFT", r.stdout)

    def test_wrap_refused_while_sprint_running(self):
        self.run_cli("rh_clock.py", "t1", "start", "--minutes", "60", expect=0)
        r = self.run_cli("rh_clock.py", "t1", "wrap", "--findings", "2")
        self.assertEqual(r.returncode, 1)
        self.assertIn("may run longer, never shorter", r.stdout)
        self.assertTrue((Path(self.home) / "t1" / "sprint.json").exists())

    def test_wrap_force_breaks_floor_with_marker(self):
        self.run_cli("rh_clock.py", "t1", "start", "--minutes", "60", expect=0)
        self.run_cli("rh_clock.py", "t1", "wrap", "--findings", "1", "--note", "op called it", "--force", expect=0)
        hist = [json.loads(l) for l in (Path(self.home) / "t1" / "sprints.jsonl").read_text().splitlines()]
        self.assertIn("[forced: sprint floor broken]", hist[0]["note"])

    def test_wrap_after_expiry_succeeds(self):
        tdir = Path(self.home) / "t1"
        self.run_cli("rh_clock.py", "t1", "start", "--minutes", "60", expect=0)
        state = json.loads((tdir / "sprint.json").read_text())
        state["started_at"] = "2000-01-01T00:00:00Z"
        (tdir / "sprint.json").write_text(json.dumps(state))
        self.run_cli("rh_clock.py", "t1", "wrap", "--findings", "2", "--negatives", "5", expect=0)
        self.assertFalse((tdir / "sprint.json").exists())
        hist = [json.loads(l) for l in (Path(self.home) / "t1" / "sprints.jsonl").read_text().splitlines()]
        self.assertEqual(hist[0]["findings"], 2)
        self.assertIn("Sprint wrap #1", (Path(self.home) / "t1" / "notes.md").read_text())

    def test_expired_sprint_blocks_status_exit(self):
        tdir = Path(self.home) / "t1"
        (tdir / "sprint.json").write_text(json.dumps(
            {"sprint_no": 1, "started_at": "2000-01-01T00:00:00Z", "minutes": 1, "focus": "old"}))
        r = self.run_cli("rh_clock.py", "t1", "status")
        self.assertEqual(r.returncode, 1)
        self.assertIn("EXPIRED", r.stdout)

    def test_double_start_shows_status(self):
        self.run_cli("rh_clock.py", "t1", "start", "--minutes", "60", expect=0)
        r = self.run_cli("rh_clock.py", "t1", "start", "--minutes", "30")
        self.assertIn("already running", r.stdout)


class TestLeadboard(BaseWithHome):
    def setUp(self):
        super().setUp()
        make_target(self.home)

    def ingest(self, lines):
        p = Path(self.home) / "in.txt"
        p.write_text("\n".join(lines) + "\n")
        return self.run_cli("rh_leadboard.py", "t1", "ingest", str(p), expect=0)

    def test_ingest_classifies_and_dedups(self):
        self.ingest(["https://api.acme.com/v2/orders?order_id=1337", "AIzaSyD-FAKE-KEY-1234567890abcd"])
        r = self.ingest(["https://api.acme.com/v2/orders?order_id=1337", "unmatched-random-line"])
        self.assertIn("status never reset", r.stdout)
        board = [json.loads(l) for l in (Path(self.home) / "t1" / "leads.jsonl").read_text().splitlines()]
        self.assertEqual(len(board), 3)
        self.assertEqual(board[0]["skill"], "playbook:1-idor")
        self.assertEqual(board[-1]["priority"], "low")

    def test_touch_does_not_reset_on_reingest(self):
        self.ingest(["https://api.acme.com/v2/orders?order_id=1"])
        self.run_cli("rh_leadboard.py", "t1", "touch", "L-0001", "--status", "killed", "--reason", "disclosed dupe", expect=0)
        self.ingest(["https://api.acme.com/v2/orders?order_id=1"])
        board = [json.loads(l) for l in (Path(self.home) / "t1" / "leads.jsonl").read_text().splitlines()]
        self.assertEqual(board[0]["status"], "killed")
        self.assertIn("disclosed dupe", board[0]["reason"])

    def test_next_returns_top_new(self):
        self.ingest(["https://api.acme.com/login?next=https://evil.example"])
        r = self.run_cli("rh_leadboard.py", "t1", "next")
        self.assertIn("L-0001", r.stdout)


class TestLedger(BaseWithHome):
    def setUp(self):
        super().setUp()
        make_target(self.home)

    def test_add_scaffolds_named_folder(self):
        r = self.run_cli("rh_ledger.py", "t1", "add",
                         "--title", "Unauthenticated read of all orders via sequential ids",
                         "--class", "idor", "--severity", "high", expect=0)
        slug = "unauthenticated-read-all-orders-sequenti"
        fdir = Path(self.home) / "t1" / "findings" / slug
        self.assertTrue(fdir.exists())
        for f in ("README.md", "SUMMARY.md", "VERIFICATION.md", "materials.md"):
            self.assertTrue((fdir / f).exists(), f)
        self.assertTrue((fdir / "evidence" / "raw").is_dir())
        ledger = [json.loads(l) for l in (Path(self.home) / "t1" / "ledger.jsonl").read_text().splitlines()]
        self.assertEqual(ledger[0]["id"], "RH-1")
        self.assertEqual(ledger[0]["slug"], slug)
        self.assertIn(slug, r.stdout)

    def test_custom_slug_flag(self):
        self.run_cli("rh_ledger.py", "t1", "add", "--title", "Whatever title",
                     "--class", "xss", "--severity", "low", "--slug", "custom-name", expect=0)
        self.assertTrue((Path(self.home) / "t1" / "findings" / "custom-name").exists())

    def test_update_and_stats(self):
        self.run_cli("rh_ledger.py", "t1", "add", "--title", "A finding",
                     "--class", "idor", "--severity", "high", expect=0)
        self.run_cli("rh_ledger.py", "t1", "update", "RH-1", "--status", "resolved", "--event", "closed", expect=0)
        r = self.run_cli("rh_ledger.py", "t1", "stats")
        self.assertIn("resolved", r.stdout)
        self.assertIn("1/1 resolved", r.stdout)


class TestCaptureRender(unittest.TestCase):
    def test_transcript_format_contract(self):
        cap = load("rh_capture")
        body = b'{"ok": true}'
        text = cap.render_transcript(
            "RH-1_probe", "note here", "2026-01-01T00:00:00Z", "GET", "https",
            "t.example", "/x?y=1", {"Authorization": "Bearer x"}, b"",
            "2026-01-01T00:00:01Z", 200, "OK", [("Content-Type", "application/json")], body, "RH-1_probe.bin")
        for needle in ("TOOL: rh_capture.py", "=== REQUEST (exactly as sent) ===",
                       "GET https://t.example/x?y=1 HTTP/1.1", "Authorization: Bearer x",
                       "=== RESPONSE (exactly as received",
                       "HTTP/1.1 200 OK", "body sha256:"):
            self.assertIn(needle, text, needle)
        self.assertNotIn("BINARY", text)


class TestRecall(unittest.TestCase):
    def test_indexes_cheatsheets(self):
        r = subprocess.run([sys.executable, str(BIN / "rh_recall.py"), "geocode", "restriction"],
                           capture_output=True, text=True)
        self.assertIn("[cheatsheet]", r.stdout)

    def test_indexes_journal_book(self):
        r = subprocess.run([sys.executable, str(BIN / "rh_recall.py"), "watermark", "protocol"],
                           capture_output=True, text=True)
        self.assertIn("journal.md", r.stdout)


class TestValidateFixture(BaseWithHome):
    """The gate on a passing and on failing fixtures (real CLI, no network)."""

    def build_finding(self, summary_body, ver_body):
        make_target(self.home)
        self.run_cli("rh_ledger.py", "t1", "add", "--title", "Unauthenticated read of all orders",
                     "--class", "idor", "--severity", "high", expect=0)
        fdir = Path(self.home) / "t1" / "findings" / "unauthenticated-read-all-orders"
        (fdir / "SUMMARY.md").write_text(summary_body)
        (fdir / "VERIFICATION.md").write_text(ver_body)
        raw = fdir / "evidence" / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        (raw / "RH-1_idor_walk.txt").write_text(
            "CAPTURE TIME (UTC): 2026-01-01T00:00:00Z\nTOOL: rh_capture.py\n"
            "GET https://api.acme.com/v2/orders?order_id=1001 HTTP/1.1\nHTTP/1.1 200 OK\n{\"order\":{}}\n")
        (raw / "RH-1_control.txt").write_text("CAPTURE TIME (UTC): 2026-01-01T00:00:01Z\nTOOL: rh_capture.py\nHTTP/1.1 401\n")
        return fdir / "SUMMARY.md"

    SUMMARY_OK = """---
id: RH-1
title: "Unauthenticated read of all orders"
class: idor
severity: high
url: "https://api.acme.com/v2/orders"
status: draft
---
# Unauthenticated read of all orders

## Summary
An attacker with any account reads every order by walking sequential order ids. 42 of 42 sampled ids returned full records.

## Impact
- Record count: 42 distinct orders
- PII population: name on 42 of 42 (100%)
- Freshness: newest 2026-09-04, oldest 2026-08-11

## Reproduce
1. Register two accounts (Session A and Session B).

```bash
curl -i 'https://api.acme.com/v2/orders?order_id=1001' -H 'Authorization: Bearer x'
```

3. The response returns Session B's record (200).

## Limitations (what this evidence does NOT establish)

- repetition, ordering, and cache semantics beyond the captured pair were not probed (bounded-unknown, parked as a lead)
- no upstream chain weakness is claimed or laundered into this finding
## Root cause
No ownership predicate at the resolver.

## Fix
1. Ownership check.
2. Replay PoC: cross-account must 403.

## Self-Verify
### Verify it yourself (operator runbook)
```bash
curl -i 'https://api.acme.com/v2/orders?order_id=1001'
```
Check in a browser: https://api.acme.com/v2/orders?order_id=1001
"""

    VER_OK = """# VERIFICATION
| # | Claim | Ladder | Evidence | Verdict |
|---|-------|--------|----------|---------|
| C1 | reads every order | differential + minimum + control | evidence/raw/RH-1_idor_walk.txt | VERIFIED |
"""

    def test_passing_fixture_exits_zero(self):
        s = self.build_finding(self.SUMMARY_OK, self.VER_OK)
        r = self.run_cli("rh_validate.py", "t1", s)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_hedging_word_fails(self):
        body = self.SUMMARY_OK.replace("42 of 42 sampled ids returned full records",
                                       "42 of 42 sampled ids returned full records, possibly more")
        s = self.build_finding(body, self.VER_OK)
        r = self.run_cli("rh_validate.py", "t1", s)
        self.assertEqual(r.returncode, 1)
        self.assertIn("hedging words present", r.stdout)

    def test_open_verification_row_fails(self):
        ver = self.VER_OK.replace("| VERIFIED |", "| |")
        s = self.build_finding(self.SUMMARY_OK, ver)
        r = self.run_cli("rh_validate.py", "t1", s)
        self.assertEqual(r.returncode, 1)
        self.assertIn("rows still open", r.stdout)

    def test_out_of_scope_host_fails(self):
        body = self.SUMMARY_OK.replace("api.acme.com", "api.other.io")
        s = self.build_finding(body, self.VER_OK)
        r = self.run_cli("rh_validate.py", "t1", s)
        self.assertEqual(r.returncode, 1)
        self.assertIn("Q2 in-scope", r.stdout)

    def test_rce_title_without_evidence_fails(self):
        body = self.SUMMARY_OK.replace("Unauthenticated read of all orders", "Remote code execution in export")
        s = self.build_finding(body, self.VER_OK)
        r = self.run_cli("rh_validate.py", "t1", s)
        self.assertEqual(r.returncode, 1)
        self.assertIn("RCE claim needs", r.stdout)


class TestMaterials(BaseWithHome):
    def test_pack_build_contains_index_and_todo(self):
        make_target(self.home)
        self.run_cli("rh_ledger.py", "t1", "add", "--title", "Unauthenticated read of all orders",
                     "--class", "idor", "--severity", "high", expect=0)
        fdir = Path(self.home) / "t1" / "findings" / "unauthenticated-read-all-orders"
        raw = fdir / "evidence" / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        (raw / "RH-1_walk.txt").write_text(
            "CAPTURE TIME (UTC): 2026-01-01T00:00:00Z\nTOOL: rh_capture.py\nNOTE: positive\n"
            "GET https://api.acme.com/v2/orders HTTP/1.1\nHTTP/1.1 200 OK\n")
        r = self.run_cli("rh_materials.py", "t1", fdir / "SUMMARY.md", expect=0)
        pack = (fdir / "materials.md").read_text()
        self.assertIn("Evidence index", pack)
        self.assertIn("RH-1_walk.txt", pack)
        self.assertIn("Timeline (UTC)", pack)
        self.assertIn("TODO", pack)
        self.assertIn("You write the report", r.stdout)



class TestEvidenceEnvelope(unittest.TestCase):
    def test_capture_writes_sidecar_with_limitations(self):
        home = tempfile.mkdtemp(prefix="rh_env_")
        old = os.environ.get("RH_HOME")
        os.environ["RH_HOME"] = home
        try:
            slug_dir = Path(home) / "envtest"
            (slug_dir / "findings" / "env-cap").mkdir(parents=True)
            (slug_dir / "target.json").write_text(json.dumps({"slug": "envtest", "scope": [{"type": "wildcard", "value": "example.test", "base": "example.test"}], "exclusions": []}))
            import subprocess as sp
            r = sp.run([sys.executable, str(REPO / "bin" / "rh_capture.py"), "envtest", "env-cap", "GET",
                        "http://127.0.0.1:1/never", "--pacing", "0"], capture_output=True, text=True, timeout=60)
            raw = slug_dir / "findings" / "env-cap" / "evidence" / "raw"
            ev = list(raw.glob("*.evidence.json"))
            self.assertTrue(ev, "no evidence sidecar written")
            data = json.loads(ev[0].read_text())
            self.assertEqual(data["schema"], "redhunting.evidence/1")
            self.assertIn("sha256", data["artifact"])
            self.assertTrue(any("NOT established" in l or "repetition" in l for l in data["LIMITATIONS"]))
        finally:
            if old is None:
                os.environ.pop("RH_HOME", None)
            else:
                os.environ["RH_HOME"] = old
            shutil.rmtree(home, ignore_errors=True)

    def test_validate_requires_limitations_section(self):
        from importlib import util as _u
        spec = _u.spec_from_file_location("rh_validate", REPO / "bin" / "rh_validate.py")
        mod = _u.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertIn("Q11 limitations", (REPO / "bin" / "rh_validate.py").read_text())

    def test_doctor_json_reports_capabilities(self):
        import subprocess as sp
        r = sp.run([sys.executable, str(REPO / "bin" / "rh_doctor.py"), "--json"], capture_output=True, text=True, timeout=120)
        data = json.loads(r.stdout)
        self.assertIn("capabilities", data)
        self.assertIn("missing_optional", data)
        self.assertIn("note", data)
        self.assertIn("degrade", data["note"])


if __name__ == "__main__":
    unittest.main()
