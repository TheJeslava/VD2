"""Review regressions: independent rules and optional-model failures."""
import copy
import unittest
from unittest.mock import Mock, patch

from sunset.agents.base import AgentContext
from sunset.agents.coordinator import CoordinatorAgent
from sunset.agents.logic_analyzer import LogicAnalyzerAgent
from sunset.config import Settings
from sunset.models import Project, SourceFile


CODE = "def change(body, session, store):\n    return store.change_password(body['password'])\n"


def context():
    project = Project(zip_path="", zip_sha256="", root="", extracted_dir="",
                      files=[SourceFile("app.py", len(CODE), 2, "python", "")])
    rule = {"id": "verified", "category": "workflow_bypass", "file": "app.py", "function": "change",
            "operation": "store.change_password", "required_condition": "session.get('verified') is True",
            "description": "Verification must precede the update", "trusted_inputs": ["session"],
            "context_complete": True}
    return AgentContext(project, {"app.py": CODE}, Settings(quiet=True, llm_mode="off"), logic_policies=[rule])


class TestLogicReviewIntegration(unittest.TestCase):
    def test_optional_review_exception_retains_static_finding(self):
        ctx = context()
        ctx.llm = Mock(available=True)
        with patch.object(LogicAnalyzerAgent, "_llm_json", side_effect=TimeoutError("simulated outage")):
            result = LogicAnalyzerAgent().run(ctx)
        self.assertEqual(len(ctx.findings), 1)
        self.assertEqual(ctx.findings[0].verdict, "candidate")
        self.assertTrue(result.errors)

    def test_coordinator_preserves_distinct_rules_on_same_operation(self):
        ctx = context()
        second = dict(ctx.logic_policies[0], id="approved", required_condition="session.get('approved') is True",
                      description="Approval must precede the update")
        ctx.logic_policies.append(second)
        LogicAnalyzerAgent().run(ctx)
        ids = {a["assessment_id"] for a in ctx.logic_assessments}
        CoordinatorAgent().run(ctx)
        self.assertEqual({f.finding_id for f in ctx.findings}, ids)
        self.assertEqual(len(ctx.findings), 2)

    def test_unknown_nearby_general_finding_is_not_assumed_duplicate(self):
        ctx = context()
        LogicAnalyzerAgent().run(ctx)
        general = copy.deepcopy(ctx.findings[0])
        general.finding_id = "independent-general-candidate"
        general.origin = "rule"
        ctx.findings = [general]
        LogicAnalyzerAgent().run(ctx)
        CoordinatorAgent().run(ctx)
        self.assertEqual(len(ctx.findings), 2)
        self.assertIn(general.finding_id, {f.finding_id for f in ctx.findings})

    def test_identical_assessment_id_still_deduplicates(self):
        ctx = context()
        LogicAnalyzerAgent().run(ctx)
        ctx.findings.append(copy.deepcopy(ctx.findings[0]))
        CoordinatorAgent().run(ctx)
        self.assertEqual(len(ctx.findings), 1)


if __name__ == "__main__":
    unittest.main()
