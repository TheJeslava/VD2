"""Legacy dataset tool imports and CLI entry points survive the rename."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
REPOSITORY = PROJECT.parent
TOOL_NAMES = {
    "evaluate_baofeng": "dataset_evaluate",
    "generate_baofeng_manifest": "dataset_generate_manifest",
    "run_baofeng_hybrid": "dataset_run_hybrid",
    "run_baofeng_url": "dataset_run_url",
    "summarize_baofeng_url": "dataset_summarize_url",
    "summarize_baofeng_verification": "dataset_summarize_verification",
    "verify_baofeng_gold_hits": "dataset_verify_gold_hits",
    "baofeng_dvwa_adapter": "dataset_dvwa_adapter",
}


class TestDatasetToolNames(unittest.TestCase):
    def _run(self, args, cwd):
        result = subprocess.run(
            [sys.executable, *args], cwd=cwd, capture_output=True,
            encoding="utf-8", errors="replace", timeout=30,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_old_imports_expose_the_same_module_and_functions(self):
        # Both historical script imports and tools.* namespace imports are used.
        # A fresh interpreter per version avoids sharing the sunset package itself.
        code = """
import importlib, json, sys
from pathlib import Path
names = json.loads(sys.argv[1])
tools = Path.cwd() / 'tools'
sys.path.insert(0, str(tools))
for old, new in names.items():
    if not (tools / (old + '.py')).is_file():
        continue
    for prefix in ('', 'tools.'):
        legacy = importlib.import_module(prefix + old)
        canonical = importlib.import_module(prefix + new)
        assert legacy is canonical, (prefix, old)
        assert callable(legacy.main), old
        if 'adapter' in old:
            assert legacy._sample_route('/025.php') == ('025', '/vulnerabilities/exec/')
"""
        for version in range(2, 6):
            with self.subTest(version=version):
                self._run(["-c", code, json.dumps(TOOL_NAMES)],
                          REPOSITORY / f"VulnCatcher-ver{version}")

    def test_loading_two_versions_by_file_does_not_mix_evaluator_paths(self):
        code = """
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
root = Path(sys.argv[1])
for version in (2, 5, 3, 4):
    project = root / f'VulnCatcher-ver{version}'
    spec = spec_from_file_location(f'legacy_ver{version}', project / 'tools/evaluate_baofeng.py')
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.PROJECT == project, (version, module.PROJECT)
    assert module.MAPPING.is_file()
"""
        self._run(["-c", code, str(REPOSITORY)], PROJECT)

    def test_manifest_default_name_and_legacy_output_are_equivalent(self):
        with tempfile.TemporaryDirectory(prefix="dataset-manifest-") as directory:
            target = Path(directory)
            self._run([str(PROJECT / "tools/dataset_generate_manifest.py")], target)
            self._run([str(PROJECT / "tools/generate_baofeng_manifest.py"),
                       "--output", str(target / "legacy.json")], target)
            current = json.loads((target / "runtime/dataset-targets.json").read_text(encoding="utf-8"))
            legacy = json.loads((target / "legacy.json").read_text(encoding="utf-8"))
            self.assertEqual(current, legacy)
            self.assertEqual(len(current["targets"]), 58)
            self.assertEqual(len({row["dataset_category"] for row in current["targets"]}), 20)

    def test_verify_import_path_and_adapter_help_are_safe_to_load(self):
        for version in (4, 5):
            project = REPOSITORY / f"VulnCatcher-ver{version}"
            for name in ("dataset_verify_gold_hits", "verify_baofeng_gold_hits",
                         "dataset_dvwa_adapter", "baofeng_dvwa_adapter"):
                with self.subTest(version=version, tool=name):
                    result = self._run([str(project / "tools" / (name + ".py")), "--help"], project)
                    self.assertIn("usage:", result.stdout)
                    self.assertNotIn("listening on", result.stdout)
            code = """
from pathlib import Path
from tools.dataset_verify_gold_hits import VERIFIER
assert VERIFIER == Path.cwd().parent / 'VulnCatcher-Verify'
assert (VERIFIER / 'sunset_verify/pipeline.py').is_file()
"""
            self._run(["-c", code], project)


if __name__ == "__main__":
    unittest.main()
