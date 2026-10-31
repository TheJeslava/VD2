"""Integration tests: execute the analyzed handlers over real loopback HTTP."""
from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from examples.logic_lab.run_experiment import build_source_zip, run_dynamic, run_static, _request
from examples.logic_lab.server import running_lab


class TestLogicLabDynamic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = run_dynamic()
        cls.by_case = {(item["variant"], item["case_id"]): item for item in cls.results}

    def test_all_http_state_expectations(self):
        self.assertEqual(len(self.results), 32)
        self.assertFalse([item for item in self.results if not item["passed"]])

    def test_negative_quantity_really_increases_credits_only_in_vulnerable_version(self):
        vulnerable = self.by_case["vulnerable", "quantity_negative"]
        fixed = self.by_case["fixed", "quantity_negative"]
        self.assertEqual(vulnerable["state_after"]["credits"]["alice"], 120)
        self.assertEqual(fixed["state_after"]["credits"]["alice"], 100)
        self.assertEqual(fixed["state_after"]["purchases"], [])

    def test_other_users_order_really_changes_only_without_guard(self):
        vulnerable = self.by_case["vulnerable", "object_other_order"]
        fixed = self.by_case["fixed", "object_other_order"]
        self.assertEqual(vulnerable["state_after"]["orders"]["202"]["memo"], "changed")
        self.assertEqual(fixed["state_after"]["orders"]["202"]["memo"], "bob-original")

    def test_verified_workflow_still_works_and_token_is_consumed(self):
        valid = self.by_case["fixed", "workflow_verified"]
        replay = self.by_case["fixed", "workflow_replay"]
        self.assertEqual(valid["state_after"]["passwords"]["alice"], "changed")
        self.assertEqual(replay["state_after"]["passwords"]["alice"], "first-change")
        self.assertEqual(replay["http_status"], 403)

    def test_client_cannot_set_server_identity_or_verification_state(self):
        for scenario in ("workflow_forged_client_flag", "workflow_other_session", "object_forged_user"):
            with self.subTest(scenario=scenario):
                self.assertFalse(self.by_case["fixed", scenario]["state_changed"])

    def test_authorized_operations_are_preserved(self):
        for scenario in ("object_own_order", "quantity_valid", "workflow_client_verified"):
            with self.subTest(scenario=scenario):
                self.assertTrue(self.by_case["fixed", scenario]["state_changed"])
        self.assertEqual(self.by_case["fixed", "quantity_valid"]["state_after"]["credits"]["alice"], 80)

    def test_unknown_routes_do_not_change_state(self):
        with running_lab("fixed") as (lab, base):
            self.assertTrue(base.startswith("http://127.0.0.1:"))
            before = lab.store.snapshot()
            status, _ = _request(base, "/unknown", {})
            self.assertEqual(status, 404)
            self.assertEqual(before, lab.store.snapshot())


class TestLogicLabStatic(unittest.TestCase):
    def test_all_three_categories_have_positive_fixed_and_incomplete_context(self):
        assessments, checks = run_static()
        self.assertEqual(len(checks), 11)
        self.assertFalse([item for item in checks if not item["passed"]], checks)
        for category in ("workflow_bypass", "object_authorization", "business_constraint"):
            statuses = {item["status"] for item in assessments if item["category"] == category}
            self.assertEqual(statuses, {"candidate", "guarded", "needs_context"})

    def test_archive_reproducible_and_policy_kept_outside_untrusted_source(self):
        with tempfile.TemporaryDirectory(prefix="logic-lab-test-") as directory:
            root = Path(directory)
            first = build_source_zip(root / "first.zip")
            second = build_source_zip(root / "second.zip")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(set(archive.namelist()), {"vulnerable.py", "fixed.py", "missing_context.py"})


if __name__ == "__main__":
    unittest.main()