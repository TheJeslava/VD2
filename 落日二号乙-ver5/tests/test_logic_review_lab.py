"""The experiment cannot pass when its setup/precondition did not occur."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from examples.logic_lab import run_experiment as experiment


class TestLabPreconditions(unittest.TestCase):
    def _scenario(self, name, request_override=None):
        case = next(c for c in experiment._cases() if c["id"] == name)
        with patch.object(experiment, "_cases", return_value=[case]):
            if request_override is None:
                return experiment.run_dynamic()
            with patch.object(experiment, "_request", side_effect=request_override):
                return experiment.run_dynamic()

    def test_real_setup_records_verified_session_and_preserves_other_session(self):
        rows = self._scenario("workflow_other_session")
        self.assertTrue(all(row["passed"] and row["setup_passed"] for row in rows))
        for row in rows:
            setup = row["setup"][0]
            self.assertEqual(setup["http_status"], 200)
            self.assertTrue(setup["sessions_after"]["bob-demo"]["captcha_passed"])
            self.assertFalse(setup["sessions_after"]["alice-demo"]["captcha_passed"])
            self.assertEqual(setup["state_before"], setup["state_after"])

    def test_failed_verification_cannot_count_as_session_isolation_proof(self):
        original = experiment._request

        def fail_setup(base, path, body, session="alice-demo"):
            if path == "/verify":
                return 403, {"status": 403}
            return original(base, path, body, session)

        rows = self._scenario("workflow_other_session", fail_setup)
        self.assertTrue(all(not row["passed"] and not row["setup_passed"] for row in rows))
        # The final fixed request still returns the desired denial; invalid setup
        # must prevent that denial from being accepted as isolation evidence.
        fixed = next(row for row in rows if row["variant"] == "fixed")
        self.assertEqual(fixed["http_status"], 403)
        self.assertFalse(fixed["state_changed"])

    def test_setup_success_response_without_state_change_is_rejected(self):
        original = experiment._request

        def fake_success(base, path, body, session="alice-demo"):
            if path == "/verify":
                return 200, {"status": 200}
            return original(base, path, body, session)

        rows = self._scenario("workflow_other_session", fake_success)
        self.assertTrue(all(not row["passed"] and not row["setup_passed"] for row in rows))
        self.assertTrue(all(row["setup"][0]["http_status"] == 200 for row in rows))

    def test_setup_verifying_wrong_session_is_rejected(self):
        original = experiment._request

        def wrong_session(base, path, body, session="alice-demo"):
            return original(base, path, body, "alice-demo" if path == "/verify" else session)

        rows = self._scenario("workflow_other_session", wrong_session)
        self.assertTrue(all(not row["setup_passed"] for row in rows))
        self.assertTrue(all(not row["passed"] for row in rows))

    def test_setup_for_wrong_answer_requires_expected_rejection_status(self):
        original = experiment._request

        def wrong_response(base, path, body, session="alice-demo"):
            if path == "/verify":
                return 200, {"status": 200}
            return original(base, path, body, session)

        rows = self._scenario("workflow_wrong_verification", wrong_response)
        self.assertTrue(all(not row["setup_passed"] and not row["passed"] for row in rows))

    def test_replay_setup_proves_first_password_change_and_token_consumption(self):
        rows = self._scenario("workflow_replay")
        self.assertTrue(all(row["passed"] and row["setup_passed"] for row in rows))
        for row in rows:
            first_change = row["setup"][1]
            self.assertEqual(first_change["state_after"]["passwords"]["alice"], "first-change")
            self.assertEqual(first_change["sessions_after"]["alice-demo"]["captcha_passed"],
                             row["variant"] == "vulnerable")


if __name__ == "__main__":
    unittest.main()
