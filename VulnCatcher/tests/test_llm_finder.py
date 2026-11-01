"""LLM 深挖（DeepFinder / LLM-finding）回归测试。

重点验证三件事：
1. 模型自主产出的 finding 能变成候选，并保留完整论证；
2. 请求体里没有 tools/tool_choice/function calling，模型不能要求读文件；
3. 非仓库路径、越界行号、缺 source/chain 的结论会被服务端拒绝或修正。
"""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from sunset.agents.base import AgentContext
from sunset.agents.deep_finder import DeepFinderAgent
from sunset.config import Settings
from sunset.llm import LlmClient, LlmResult
from sunset.models import Project, SourceFile
from sunset.pipeline import run_pipeline

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
TARGET_ZIP = PROJECT.parent / "lite" / "BenchmarkTest00002.zip"

JAVA = """package demo;
import javax.servlet.http.*;
public class PingServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String host = request.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
"""

FINDING = {
    "vulnerability_type": "command_injection",
    "severity": "high",
    "title": "PingServlet 命令注入",
    "description": "参数 host 未过滤直接拼进 ping 命令行，可追加 ;id。",
    "file_path": "src/PingServlet.java",
    "line_start": 5,
    "line_end": 6,
    "code_snippet": "String host = request.getParameter(\"host\");...",
    "source": "参数 `host`",
    "source_kind": "query",
    "source_name": "host",
    "tainted_expression": "request.getParameter(\"host\")",
    "sink": "Runtime.getRuntime().exec(\"ping -c 1 \" + host)",
    "endpoint": "/ping",
    "http_method": "GET",
    "exploit_chain": [
        {"step": 1, "location": "src/PingServlet.java:5", "description": "读取参数 host"},
        {"step": 2, "location": "src/PingServlet.java:6", "description": "拼接进 exec",
         "data_state": "原始字符串", "bypass_reason": "无过滤"},
    ],
    "poc": {"description": "发送 ;id", "payload": ";id", "preconditions": ["目标可达"]},
    "impact": "命令执行",
    "cve_justification": "CWE-78，远程无需认证。",
    "suggestion": "使用参数数组并白名单。",
    "confidence": 0.86,
    "needs_verification": True,
    "verdict": "candidate",
    "verification_notes": "需要确认 ping 命令实际执行。",
}


class FakeLlm:
    available = True

    def __init__(self, data):
        self.data = data
        self.calls: list[dict] = []
        self.usage: list[dict] = []

    def call_json(self, system, user, *, label="agent"):
        self.calls.append({"system": system, "user": user, "label": label})
        return LlmResult(ok=True, data=self.data, raw=json.dumps(self.data, ensure_ascii=False))


def _context(tmp: Path, files: dict[str, str], data: dict) -> tuple[AgentContext, FakeLlm]:
    project = Project(
        zip_path=str(tmp / "sample.zip"),
        zip_sha256="0" * 64,
        root=str(tmp),
        extracted_dir=str(tmp / "src"),
    )
    project.manifest["input_mode"] = "zip"
    contents: dict[str, str] = {}
    for rel_path, text in files.items():
        project.files.append(SourceFile(
            rel_path=rel_path, size=len(text.encode("utf-8")),
            lines=len(text.splitlines()), language="java", sha256="",
        ))
        contents[rel_path] = text
    project.languages = {"java": len(files)}
    settings = Settings(
        llm_mode="on", llm_api_key="test-key", llm_finding="on",
        quiet=True, output_dir=tmp / "out", work_dir=tmp / "work",
    )
    llm = FakeLlm(data)
    return AgentContext(project=project, contents=contents, settings=settings, llm=llm), llm


class TestDeepFinderAgent(unittest.TestCase):
    def test_model_output_becomes_candidate(self):
        with tempfile.TemporaryDirectory(prefix="sunset-df-") as tmp:
            data = {"findings": [FINDING], "summary": "审计了 1 个入口",
                    "coverage": {"gaps": ["未覆盖过滤器"], "audited_files": ["src/PingServlet.java"]}}
            ctx, llm = _context(Path(tmp), {"src/PingServlet.java": JAVA}, data)
            result = DeepFinderAgent().run(ctx)

            self.assertEqual(len(ctx.candidates), 1)
            candidate = ctx.candidates[0]
            self.assertEqual(candidate.origin, "llm_finding")
            self.assertTrue(candidate.candidate_id.startswith("LLM-"))
            self.assertEqual(candidate.vuln_type, "command_injection")
            self.assertEqual((candidate.line_start, candidate.line_end), (5, 6))
            self.assertIn("Runtime.getRuntime().exec", candidate.code_snippet)
            self.assertEqual(candidate.description, FINDING["description"])
            self.assertEqual(candidate.endpoint, "/ping")
            self.assertEqual(len(candidate.chain), 2)
            self.assertEqual(candidate.confidence, 0.86)
            self.assertTrue(result.used_llm)
            manifest = ctx.project.manifest["llm_finding"]
            self.assertTrue(manifest["enabled"])
            self.assertEqual(manifest["tool_calls"], 0)
            self.assertEqual(manifest["findings"], 1)
            self.assertEqual(manifest["summary"], "审计了 1 个入口")

    def test_request_has_no_tools_and_code_is_inlined(self):
        with tempfile.TemporaryDirectory(prefix="sunset-df-") as tmp:
            ctx, llm = _context(Path(tmp), {"src/PingServlet.java": JAVA}, {"findings": [], "summary": ""})
            DeepFinderAgent().run(ctx)

            self.assertEqual(len(llm.calls), 1)
            call = llm.calls[0]
            self.assertEqual(call["label"], "deep_finder:discovery")
            self.assertIn("零工具契约", call["system"])
            self.assertIn("trust=untrusted", call["user"])
            self.assertIn("Runtime.getRuntime().exec", call["user"])
            self.assertNotIn('"tools"', call["user"])
            self.assertNotIn("tool_choice", call["user"])
            self.assertNotIn("function_call", call["user"].lower())

    def test_invalid_path_clamped_and_missing_chain_rejected(self):
        with tempfile.TemporaryDirectory(prefix="sunset-df-") as tmp:
            valid_clamped = dict(FINDING, line_start=9999, line_end=9999)
            missing = dict(FINDING, source="", description="")
            outside = dict(FINDING, file_path="../../etc/passwd")
            data = {"findings": [outside, valid_clamped, missing]}
            ctx, _ = _context(Path(tmp), {"src/PingServlet.java": JAVA}, data)
            DeepFinderAgent().run(ctx)

            self.assertEqual(len(ctx.candidates), 1)
            candidate = ctx.candidates[0]
            self.assertEqual(candidate.file, "src/PingServlet.java")
            self.assertEqual(candidate.line_end, len(JAVA.splitlines()))
            self.assertEqual(ctx.project.manifest["llm_finding"]["rejected_count"], 1)

    def test_off_skips_call(self):
        with tempfile.TemporaryDirectory(prefix="sunset-df-") as tmp:
            ctx, llm = _context(Path(tmp), {"src/PingServlet.java": JAVA}, {"findings": [FINDING]})
            ctx.settings.llm_finding = "off"
            DeepFinderAgent().run(ctx)
            self.assertEqual(llm.calls, [])
            self.assertFalse(ctx.project.manifest["llm_finding"]["enabled"])


class TestDeepFinderPipeline(unittest.TestCase):
    def test_llm_finding_runs_without_rule_candidates_and_report_exposes_stats(self):
        if not TARGET_ZIP.is_file():
            self.skipTest(f"缺少目标 zip: {TARGET_ZIP}")
        with zipfile.ZipFile(TARGET_ZIP) as zf:
            names = [name for name in zf.namelist() if name.endswith("BenchmarkTest00002.java")]
        if not names:
            self.skipTest("zip 中没有 BenchmarkTest00002.java")
        # zip 里可能带顶层目录（BenchmarkTest00002/）；ingest 会剥掉它，findings 使用仓库相对路径。
        parts = names[0].split("/")
        target_file = "/".join(parts[parts.index("src"):]) if "src" in parts else names[0]

        finding = dict(
            FINDING,
            vulnerability_type="path_traversal",
            file_path=target_file,
            line_start=71,
            line_end=73,
            endpoint="/pathtraver-00/BenchmarkTest00002",
            http_method="POST",
            source="Cookie `BenchmarkTest00002`",
            source_kind="cookie",
            source_name="BenchmarkTest00002",
            title="模型发现的路径穿越",
        )
        calls: list[dict] = []

        def fake_call(self, system, user, *, label="agent"):
            calls.append({"label": label, "system": system, "user": user})
            if label.startswith("deep_finder"):
                return LlmResult(ok=True, data={"findings": [finding], "summary": "审计了入口"}, raw="{}")
            return LlmResult(ok=True, data={"notes": "stub"}, raw="{}")

        with tempfile.TemporaryDirectory(prefix="sunset-df-e2e-") as tmp:
            settings = Settings(
                llm_mode="on", llm_api_key="test-key", llm_finding="on", quiet=True,
                output_dir=Path(tmp) / "out", work_dir=Path(tmp) / "work",
                min_severity="high", min_confidence=0.6,
            )
            with mock.patch.object(LlmClient, "call_json", new=fake_call):
                result = run_pipeline(TARGET_ZIP, settings)

            findings = [item for item in result.findings if item.vulnerability_type == "path_traversal"]
            self.assertEqual(len(findings), 1, "LLM 候选应进入后续 finding")
            manifest = result.project.manifest["llm_finding"]
            self.assertTrue(manifest["enabled"])
            self.assertEqual(manifest["duplicates"], 0)
            self.assertEqual(manifest["tool_calls"], 0)
            self.assertFalse(result.project.manifest["rule_stats"]["enabled"])

            self.assertIn("deep_finder", [entry.get("agent") for entry in result.stage_log])
            finder_calls = [call for call in calls if call["label"].startswith("deep_finder")]
            self.assertTrue(finder_calls)
            self.assertNotIn('"tools"', finder_calls[0]["user"])

            report = json.loads((Path(tmp) / "out" / "report.json").read_text(encoding="utf-8"))
            self.assertTrue(report["llm"]["finding"]["enabled"])
            self.assertEqual(report["llm"]["finding"]["tool_calls"], 0)
            self.assertEqual(report["llm"]["finding"]["duplicates"], 0)


if __name__ == "__main__":
    unittest.main()
