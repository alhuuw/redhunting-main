#!/usr/bin/env python3
"""redhunting regression suite (part 4: the device profiler and hunt planner).

In-process tests with the environment faked (no real memory reads, no real
process census): module-level snapshot sources are replaced before each test.
"""
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def load_device():
    spec = importlib.util.spec_from_file_location("rh_device", REPO / "bin" / "rh_device.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


D = load_device()


def fake_snapshot_patch(total=16384, free=8000, disk=50000, tools=None, guard_ok=True, watched=None):
    tools = tools if tools is not None else {"jadx": True, "adb": False}
    watched = watched if watched is not None else {"count": 2, "mb": 100, "orphan": 0, "duplicate": 0, "live": 2}

    def snap():
        return {
            "captured_at": "2026-01-01T00:00:00Z", "host": "fakehost", "os": "FakeOS 1", "arch": "arm64",
            "python": "3.11.8", "cores": 10, "memory_total_mb": total, "memory_free_mb": free,
            "disk_free_mb": disk,
            "tools": dict(tools),
            "python_deps": {"requests": True, "androguard": True, "curl_cffi": True, "pycryptodome": True},
            "vendored": {"apkpure": True, "tempmail": True, "paranoid": True, "jadx": True},
            "guard": {"watched": dict(watched), "machine": {"total_mb": total, "free_mb": free},
                      "budget_ok": guard_ok},
        }

    return snap


class DeviceBase(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="rh_dev_test_")
        self._old = os.environ.get("RH_HOME")
        os.environ["RH_HOME"] = self.home
        self._snap = D.snapshot
        D.snapshot = fake_snapshot_patch()
        self.root = Path(self.home)

    def tearDown(self):
        D.snapshot = self._snap
        if self._old is None:
            os.environ.pop("RH_HOME", None)
        else:
            os.environ["RH_HOME"] = self._old
        shutil.rmtree(self.home, ignore_errors=True)


    def make_target(self, slug="t1", with_apk=False, leads=None):
        tdir = self.root / slug
        (tdir / "assets").mkdir(parents=True, exist_ok=True)
        (tdir / "scope.txt").write_text("*.acme.com\n")
        (tdir / "target.json").write_text(json.dumps(
            {"slug": slug, "scope": [{"type": "wildcard", "value": "*.acme.com", "base": "acme.com"}],
             "exclusions": ["staging.acme.com"]}))
        if with_apk:
            (tdir / "assets" / "round-001").mkdir(exist_ok=True)
            (tdir / "assets" / "round-001" / "app.apk").write_bytes(b"fake")
        if leads is not None:
            with (tdir / "leads.jsonl").open("w") as f:
                for l in leads:
                    f.write(json.dumps(l) + "\n")
        return tdir

    def lead(self, lid, skill, priority, status="new"):
        return {"id": lid, "skill": skill, "priority": priority, "status": status,
                "evidence": "x", "signal": "s", "why": "w"}


class TestInit(DeviceBase):
    def test_init_writes_profile(self):
        rc = D.cmd_init(None)
        self.assertEqual(rc, 0)
        prof = json.loads((D.SKILL_DIR / "state" / "device.json").read_text())
        self.assertEqual(prof["memory_free_mb"], 8000)
        self.assertEqual(prof["cores"], 10)
        self.assertIn("jadx", prof["tools"])
        self.assertTrue(prof["guard"]["budget_ok"])

    def test_profile_is_machine_only(self):
        D.cmd_init(None)
        prof = json.loads((D.SKILL_DIR / "state" / "device.json").read_text())
        self.assertNotIn("identity", prof)
        self.assertNotIn("accounts", prof)


class TestCheck(DeviceBase):
    def test_within_baseline(self):
        D.cmd_init(None)
        self.assertEqual(D.cmd_check(None), 0)

    def test_low_memory_fails(self):
        D.cmd_init(None)
        D.snapshot = fake_snapshot_patch(free=1000)
        rc = D.cmd_check(None)
        self.assertEqual(rc, 1)

    def test_process_growth_flags_leak_pattern(self):
        D.cmd_init(None)
        D.snapshot = fake_snapshot_patch(watched={"count": 9, "mb": 900, "orphan": 0, "duplicate": 3, "live": 6})
        rc = D.cmd_check(None)
        self.assertEqual(rc, 1)

    def test_guard_budget_fail_flags(self):
        D.cmd_init(None)
        D.snapshot = fake_snapshot_patch(guard_ok=False)
        rc = D.cmd_check(None)
        self.assertEqual(rc, 1)

    def test_new_tool_detected_without_failure(self):
        D.cmd_init(None)
        D.snapshot = fake_snapshot_patch(tools={"jadx": True, "adb": True})
        self.assertEqual(D.cmd_check(None), 0)

    def test_missing_profile_fails_cleanly(self):
        import shutil as _sh
        fake_skill = Path(tempfile.mkdtemp(prefix="rh_skill_fake_"))
        _sh.copy(REPO / "config.json", fake_skill / "config.json")
        old_dir = D.SKILL_DIR
        D.SKILL_DIR = fake_skill
        try:
            self.assertEqual(D.cmd_check(None), 1)
        finally:
            D.SKILL_DIR = old_dir
            _sh.rmtree(fake_skill, ignore_errors=True)


class TestPlan(DeviceBase):
    def test_plan_static_when_artifact(self):
        self.make_target(with_apk=True, leads=[])
        rc = D.cmd_plan(type("A", (), {"target": "t1"})())
        self.assertEqual(rc, 0)
        plan = (self.root / "t1" / "plan.md").read_text()
        self.assertIn("## Mode: static", plan)
        self.assertIn("PROPOSAL", plan)
        self.assertIn("parallel probe ceiling: 5", plan)

    def test_plan_dynamic_without_artifact(self):
        self.make_target(leads=[])
        D.cmd_plan(type("A", (), {"target": "t1"})())
        plan = (self.root / "t1" / "plan.md").read_text()
        self.assertIn("## Mode: dynamic", plan)

    def test_plan_groups_leads_into_sprints(self):
        leads = [self.lead(f"L-{i:04d}", "playbook:1-idor", "high") for i in range(9)]
        leads += [self.lead("L-0100", "playbook:5-secrets", "high")]
        self.make_target(leads=leads)
        D.cmd_plan(type("A", (), {"target": "t1"})())
        plan = (self.root / "t1" / "plan.md").read_text()
        self.assertIn("sprint-1 (60 min, focus playbook:1-idor): leads L-0000, L-0001, L-0002, L-0003", plan)
        self.assertIn("10 new leads", plan)
        self.assertIn("sprint-3", plan)

    def test_plan_parallel_ceiling_scales_with_memory(self):
        self.make_target(leads=[])
        D.snapshot = fake_snapshot_patch(free=2600)
        D.cmd_plan(type("A", (), {"target": "t1"})())
        plan = (self.root / "t1" / "plan.md").read_text()
        self.assertIn("parallel probe ceiling: 1", plan)

    def test_plan_missing_target_fails(self):
        self.assertEqual(D.cmd_plan(type("A", (), {"target": "nope"})()), 1)

    def test_plan_only_new_leads_counted(self):
        leads = [self.lead("L-0001", "playbook:1-idor", "high"),
                 self.lead("L-0002", "playbook:1-idor", "high", status="killed")]
        self.make_target(leads=leads)
        D.cmd_plan(type("A", (), {"target": "t1"})())
        plan = (self.root / "t1" / "plan.md").read_text()
        self.assertIn("1 new leads", plan)
        self.assertIn("L-0001", plan)
        self.assertNotIn("L-0002", plan)


class TestHasArtifact(DeviceBase):
    def test_apk_in_latest_round(self):
        self.make_target(with_apk=True)
        self.assertTrue(D.has_artifact("t1", self.root))

    def test_no_artifact(self):
        self.make_target()
        self.assertFalse(D.has_artifact("t1", self.root))


if __name__ == "__main__":
    unittest.main()
