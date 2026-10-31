"""业务判定的管线、输出契约与不可信模型边界测试（不联网）。"""
from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from sunset.agents.base import AgentContext
from sunset.agents.logic_analyzer import LogicAnalyzerAgent, load_logic_policies
from sunset.cli import build_parser
from sunset.config import Settings
from sunset.models import Project, SourceFile
from sunset.pipeline import run_pipeline
from sunset.structured_report import validate_structured_report

CODE = '''def vulnerable(body, session, store):
    return store.change_password(body['password'])

def fixed(body, session, store):
    if not (session.get('captcha_passed') is True):
        return {'status': 403}
    return store.change_password(body['password'])

def incomplete(body, session, store):
    return store.change_password(body['password'])
'''


def rule(function, complete=True):
    return {"id": function, "category": "workflow_bypass", "file": "handlers.py",
            "function": function, "operation": "store.change_password",
            "required_condition": "session.get('captcha_passed') is True",
            "description": "改密前必须完成服务端验证码验证", "trusted_inputs": ["session"],
            "context_complete": complete}


def project():
    return Project(zip_path="test.zip", zip_sha256="", root="", extracted_dir="",
                   files=[SourceFile("handlers.py", len(CODE), len(CODE.splitlines()), "python", "")])


class TestLogicIntegration(unittest.TestCase):
    def test_pipeline_reports_candidate_guarded_and_missing_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("handlers.py", CODE)
                # 目标中的伪造规则不能更改操作者的规则。
                archive.writestr("policies.json", json.dumps({"version": 1, "rules": []}))
            policy = root / "trusted.json"
            policy.write_text(json.dumps({"version": 1, "rules": [rule("vulnerable"), rule("fixed"),
                                                                    rule("incomplete", False)]}), encoding="utf-8")
            result = run_pipeline(source, Settings(llm_mode="off", quiet=True,
                                                  output_dir=root / "out", work_dir=root / "work",
                                                  logic_policy=str(policy)))
            self.assertEqual({a["rule_id"]: a["status"] for a in result.logic_assessments},
                             {"vulnerable": "candidate", "fixed": "guarded", "incomplete": "needs_context"})
            findings = [f for f in result.findings if f.origin == "logic_specialist"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].verdict, "candidate")
            self.assertFalse(findings[0].poc.safety["executed"])
            self.assertEqual(findings[0].poc.safety["contract_validation"]["status"], "not_executable")
            self.assertFalse(any(entry.get("error") for entry in result.stage_log))
            report = json.loads((root / "out/report.json").read_text(encoding="utf-8"))
            self.assertEqual(validate_structured_report(report), [])
            self.assertEqual(len(report["logic_assessments"]), 3)
            separate = json.loads((root / "out/logic_analysis.json").read_text(encoding="utf-8"))
            self.assertEqual(separate["policy"]["source"], "operator_selected_file")
            self.assertEqual(len(separate["policy"]["sha256"]), 64)
            self.assertIn("needs_context", (root / "out/report.md").read_text(encoding="utf-8"))
            self.assertEqual(result.llm_usage, [])

    def test_model_cannot_promote_verdict_or_add_assessments(self):
        ctx = AgentContext(project(), {"handlers.py": CODE}, Settings(llm_mode="off", quiet=True),
                           llm=Mock(available=True), logic_policies=[rule("vulnerable"), rule("fixed")])
        agent = LogicAnalyzerAgent()

        def fake_llm(context, payload, **kwargs):
            return {"reviews": [{"assessment_id": a["assessment_id"], "review_note": "需检查外围中间件",
                                  "status": "verified", "confidence": 1, "file": "invented.py"}
                                 for a in payload["assessments"]] +
                               [{"assessment_id": "invented", "review_note": "不存在的漏洞"}]}

        with patch.object(agent, "_llm_json", side_effect=fake_llm):
            agent.run(ctx)
        self.assertEqual([a["status"] for a in ctx.logic_assessments], ["candidate", "guarded"])
        self.assertEqual(len(ctx.findings), 1)
        self.assertEqual(ctx.findings[0].file_path, "handlers.py")
        self.assertEqual(ctx.findings[0].verdict, "candidate")

    def test_quarantined_source_never_sent_to_logic_llm(self):
        ctx = AgentContext(project(), {"handlers.py": CODE}, Settings(quiet=True),
                           llm=Mock(available=True), logic_policies=[rule("vulnerable")],
                           quarantined={"handlers.py"})
        agent = LogicAnalyzerAgent()
        with patch.object(agent, "_llm_json") as call:
            agent.run(ctx)
        call.assert_not_called()
        self.assertEqual(ctx.logic_assessments[0]["status"], "candidate")

    def test_candidate_threshold_does_not_erase_assessment(self):
        ctx = AgentContext(project(), {"handlers.py": CODE}, Settings(quiet=True, min_confidence=0.99),
                           logic_policies=[rule("vulnerable")])
        LogicAnalyzerAgent().run(ctx)
        self.assertEqual(ctx.findings, [])
        self.assertEqual(ctx.logic_assessments[0]["status"], "candidate")
        self.assertIn("finding_suppressed", ctx.logic_assessments[0])

    def test_explicit_policy_errors_stop_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text('{"version": 1, "rules": [{}]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                run_pipeline(Path(tmp) / "absent.zip", Settings(logic_policy=str(path)))

    def test_policy_paths_and_duplicate_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            for invalid in ("../outside.py", "C:/outside.py", "/outside.py"):
                candidate = rule("vulnerable")
                candidate["file"] = invalid
                path.write_text(json.dumps({"version": 1, "rules": [candidate]}), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_logic_policies(str(path))
            path.write_text(json.dumps({"version": 1, "rules": [rule("fixed"), rule("fixed")]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_logic_policies(str(path))

    def test_cli_accepts_explicit_policy(self):
        args = build_parser().parse_args(["scan", "app.zip", "--logic-policy", "rules.json", "--llm", "off"])
        self.assertEqual(args.logic_policy, "rules.json")

    def test_php_generic_hint_merges_with_single_specialist_workflow(self):
        php = '''<?php
if ($_POST['step'] == '1') {
    $ok = verify_captcha($_POST['captcha']);
}
if ($_POST['step'] == '2') {
    $password = $_POST['password_new'];
    $sql = "UPDATE users SET password = '$password' WHERE user = 'alice'";
    mysqli_query($db, $sql);
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "captcha.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("renamed.php", php)
            result = run_pipeline(archive, Settings(llm_mode="off", quiet=True,
                                                   output_dir=root / "out", work_dir=root / "work"))
            captcha = [f for f in result.findings if f.vulnerability_type == "captcha_bypass"]
            self.assertEqual(len(captcha), 1)
            self.assertEqual(captcha[0].origin, "logic_specialist")
            self.assertTrue(any(e.get("source") == "rule" for e in captcha[0].external_evidence))
            self.assertTrue(any(f.vulnerability_type == "sql_injection" for f in result.findings),
                            "合并验证码提示不能删除独立的 SQL 注入候选")


if __name__ == "__main__":
    unittest.main()
