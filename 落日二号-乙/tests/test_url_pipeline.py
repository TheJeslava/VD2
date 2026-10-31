"""URL pipeline regression tests (no live AWVS required)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sunset.config import Settings
from sunset.url_pipeline import run_url_pipeline

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
FIXTURE = PROJECT / "runtime" / "fixtures" / "awvs-00002.json"
TARGET = "https://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00002"


def _settings(root: Path) -> Settings:
    return Settings(
        input_mode="url",
        target_url=TARGET,
        llm_mode="off",
        quiet=True,
        output_dir=root / "out",
        awvs_report=str(FIXTURE),
    )


class TestUrlPipeline(unittest.TestCase):
    def test_awvs_report_becomes_url_finding_with_poc(self):
        with tempfile.TemporaryDirectory(prefix="sunset-url-") as tmp:
            root = Path(tmp)
            result = run_url_pipeline(TARGET, _settings(root))
            self.assertEqual(len(result.findings), 1)
            finding = result.findings[0]
            self.assertEqual(finding.vulnerability_type, "path_traversal")
            self.assertEqual(finding.origin, "awvs")
            self.assertEqual(finding.file_path, "")
            self.assertEqual(finding.endpoint, "/benchmark/pathtraver-00/BenchmarkTest00002")
            self.assertTrue(finding.poc.scripts)
            self.assertIn("Cookie: BenchmarkTest00002=", "\n".join(finding.poc.scripts.values()))
            self.assertIn("TARGET", "\n".join(finding.poc.scripts.values()))
            self.assertTrue(finding.poc.safety.get("target_uses_placeholder"))
            self.assertFalse(finding.poc.safety.get("executed"))

            report = json.loads((root / "out" / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["run"]["input_mode"], "url")
            self.assertEqual(report["run"]["target_url"], TARGET)
            self.assertEqual(report["findings"][0]["location"]["file"], "")
            self.assertEqual(report["findings"][0]["location"]["endpoint"], "/benchmark/pathtraver-00/BenchmarkTest00002")
            self.assertTrue((root / "out" / "awvs" / "scan.json").is_file())
            self.assertTrue((root / "out" / "awvs" / "targets.json").is_file())

    def test_zip_mode_still_uses_zip_report(self):
        # The existing test_pipeline covers 00002; here we only assert the
        # default settings still select zip mode.
        self.assertEqual(Settings().input_mode, "zip")


if __name__ == "__main__":
    unittest.main()
