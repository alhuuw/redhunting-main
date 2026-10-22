#!/usr/bin/env python3
"""redhunting regression suite (part 3: the machine guard).

The guard logic is tested against FAKE ps output (no real processes are created or
killed). Covers: ps parsing, signature normalization (npx cache hashes collapse),
orphan/duplicate/live classification, daemon-by-design exclusion, ancestor protection,
and the budget verdict.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def load_guard():
    spec = importlib.util.spec_from_file_location("rh_guard", REPO / "bin" / "rh_guard.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


G = load_guard()

FAKE_PS = """  PID  PPID   RSS COMMAND
    1     0   200 /sbin/launchd
  100    90  1000 -zsh
  101   100 50000 /usr/local/bin/opencode
  200   101 90000 npm exec @jshookmcp/jshook@0.3.4
  201   200 85000 node /Users/x/.npm/_npx/8ee692545a5a4fb8/node_modules/.bin/jshook
  300   101 92000 npm exec @jshookmcp/jshook@0.3.4
  301   300 88000 node /Users/x/.npm/_npx/8ee692545a5a4fb8/node_modules/.bin/jshook
  400     1  3072 adb -L tcp:5037 fork-server server --reply-fd 4
  500   101 61000 npm exec cve-mcp
  501   500 58000 node /Users/x/.npm/_npx/cbc35b6a12a955a3/node_modules/.bin/cve-mcp
  600 77777 70000 node /Users/x/.npm/_npx/deadbeef1234/node_modules/.bin/mcp-server-github
  700   101  1200 /usr/local/bin/python3 server.py
"""

PROCS = G.parse_ps(FAKE_PS)


class TestParsePs(unittest.TestCase):
    def test_parses_rows(self):
        self.assertEqual(len(PROCS), 12)

    def test_fields(self):
        p = next(p for p in PROCS if p["pid"] == 201)
        self.assertEqual(p["ppid"], 200)
        self.assertEqual(p["rss_kb"], 85000)
        self.assertIn("jshook", p["cmd"])

    def test_empty_and_garbage(self):
        self.assertEqual(G.parse_ps(""), [])
        self.assertEqual(G.parse_ps("PID PPID RSS COMMAND\nxx yy zz not-a-proc"), [])


class TestSignature(unittest.TestCase):
    def test_npx_cache_hash_collapses(self):
        a = G.signature("node /Users/x/.npm/_npx/8ee692545a5a4fb8/node_modules/.bin/jshook")
        b = G.signature("node /Users/someoneelse/.npm/_npx/deadbeef9999/node_modules/.bin/jshook")
        self.assertEqual(a, b)

    def test_version_pins_collapse(self):
        self.assertEqual(
            G.signature("npm exec @jshookmcp/jshook@0.3.4"),
            G.signature("npm exec @jshookmcp/jshook@1.9.9"))

    def test_flags_ignored(self):
        self.assertEqual(
            G.signature("npx -y @jshookmcp/jshook"),
            G.signature("npx @jshookmcp/jshook --another-flag"))


class TestClassify(unittest.TestCase):
    def setUp(self):
        self.orphans, self.dupes, self.live, self.watched = G.classify(
            PROCS, G.DEFAULT_PATTERNS, own_pid=999999)

    def test_dead_parent_is_orphan(self):
        pids = {p["pid"] for p in self.orphans}
        self.assertIn(600, pids)  # ppid 77777 does not exist

    def test_daemon_by_design_never_orphan(self):
        pids = {p["pid"] for p in self.orphans}
        self.assertNotIn(400, pids)  # adb fork-server parents to 1 by design
        allp = {p["pid"] for p in self.orphans + self.dupes + self.live}
        self.assertNotIn(400, allp)

    def test_duplicate_older_killed_newest_kept(self):
        dupe_pids = {p["pid"] for p in self.dupes}
        live_pids = {p["pid"] for p in self.live}
        self.assertIn(200, dupe_pids)   # older npm exec jshook wrapper
        self.assertIn(201, dupe_pids)   # older node jshook child
        self.assertIn(300, live_pids)   # newer wrapper kept
        self.assertIn(301, live_pids)   # newer child kept
        self.assertIn(500, live_pids)   # single cve-mcp wrapper: live, not a duplicate
        self.assertIn(501, live_pids)   # single cve-mcp child: live
        self.assertIn(600, {p["pid"] for p in self.orphans})

    def test_ancestor_chain_protects_self_line(self):
        orphans, dupes, live, _ = G.classify(PROCS, G.DEFAULT_PATTERNS, own_pid=201)
        allp = {p["pid"] for p in orphans + dupes}
        self.assertNotIn(201, allp)   # self
        self.assertNotIn(200, allp)   # parent
        self.assertNotIn(101, allp)   # grandparent (opencode)

    def test_unwatched_stays_out(self):
        allp = {p["pid"] for p in self.orphans + self.dupes + self.live}
        self.assertNotIn(700, allp)   # plain python server, matches no watch pattern
        self.assertNotIn(100, allp)   # zsh


class TestBudgetVerdict(unittest.TestCase):
    def test_clean_machine_passes(self):
        mem = {"total_mb": 16384, "free_mb": 8000, "swap_free_mb": 0}
        reasons = G.budget_verdict(mem, 400, [], [], {"memory_floor_mb": 2048, "max_hunt_process_mb": 1500, "max_duplicate_instances": 1})
        self.assertEqual(reasons, [])

    def test_low_memory_fails(self):
        mem = {"total_mb": 16384, "free_mb": 1000, "swap_free_mb": 0}
        reasons = G.budget_verdict(mem, 100, [], [], {"memory_floor_mb": 2048})
        self.assertTrue(any("below floor" in r for r in reasons))

    def test_orphans_fail(self):
        reasons = G.budget_verdict({"free_mb": 8000, "swap_free_mb": 0}, 100,
                                   [{"rss_kb": 500 * 1024}], [], {"memory_floor_mb": 2048, "max_duplicate_instances": 1})
        self.assertTrue(any("orphaned" in r for r in reasons))

    def test_duplicates_fail(self):
        reasons = G.budget_verdict({"free_mb": 8000, "swap_free_mb": 0}, 100,
                                   [], [{"rss_kb": 1024}] * 3, {"memory_floor_mb": 2048, "max_duplicate_instances": 1})
        self.assertTrue(any("duplicate" in r for r in reasons))

    def test_process_ceiling_fails(self):
        reasons = G.budget_verdict({"free_mb": 8000, "swap_free_mb": 0}, 2000,
                                   [], [], {"memory_floor_mb": 2048, "max_hunt_process_mb": 1500, "max_duplicate_instances": 1})
        self.assertTrue(any("ceiling" in r for r in reasons))


class TestConfigWiring(unittest.TestCase):
    def test_config_has_machine_section(self):
        import json
        cfg = json.loads((REPO / "config.json").read_text())
        self.assertIn("machine", cfg)
        self.assertIn("memory_floor_mb", cfg["machine"])
        self.assertIn("watch_patterns", cfg["machine"])
        self.assertTrue(cfg["machine"]["watch_patterns"])


if __name__ == "__main__":
    unittest.main()
