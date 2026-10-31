"""PHP lexical/reachability regressions; input snippets are never executed."""
from __future__ import annotations

import unittest
from pathlib import Path

from sunset.logic_analysis import _php_views, analyze_logic
from sunset.models import Project


PROJECT = Project(zip_path="", zip_sha256="", root="", extracted_dir="")
BASE = '''<?php
if ($_POST['step'] == '1') {
    $ok = verify_captcha($_POST['captcha']);
    if (!$ok) { return; }
}
if ($_POST['step'] == '2') {
    $sql = "UPDATE users SET password = '$password' WHERE user = '$user'";
    mysqli_query($db, $sql);
}
?>
'''


def check(source):
    return analyze_logic(PROJECT, {"case.php": source})


class TestPhpReview(unittest.TestCase):
    def test_html_example_is_not_executable_php(self):
        self.assertEqual(check(BASE.replace("<?php", "<pre>").replace("?>", "</pre>")), [])

    def test_heredoc_nowdoc_and_unterminated_document_are_not_code(self):
        inner = BASE.replace("<?php", "").replace("?>", "")
        for opening in ("<<<'DOC'", '<<<"DOC"', "<<<DOC"):
            for closing in ("DOC;", ""):
                with self.subTest(opening=opening, closing=closing):
                    source = "<?php\n$example = " + opening + "\n" + inner + "\n" + closing
                    self.assertEqual(check(source), [])

    def test_mixed_html_and_real_php_keeps_only_real_source_lines(self):
        source = BASE.replace("<?php", "<pre>").replace("?>", "</pre>") + BASE
        results = check(source)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "candidate")
        for evidence in results[0]["evidence"]:
            self.assertGreater(evidence["line"], len(BASE.splitlines()))
            self.assertEqual(source.splitlines()[evidence["line"] - 1], evidence["code"])

    def test_views_keep_offsets_and_newlines(self):
        source = "<p>example</p>\n" + BASE + "<?php\n$x = <<<'D'\nnot code\nD;\n?>"
        for view in _php_views(source):
            self.assertEqual(len(view), len(source))
            self.assertEqual([i for i, c in enumerate(view) if c in "\r\n"],
                             [i for i, c in enumerate(source) if c in "\r\n"])

    def test_sql_assignment_inside_literal_is_not_real_assignment(self):
        source = BASE.replace(
            '''$sql = "UPDATE users SET password = '$password' WHERE user = '$user'";''',
            '''$example = '$sql = "UPDATE users SET password = 1";';''')
        self.assertEqual(check(source), [])

    def test_definite_termination_makes_operation_unreachable(self):
        for stop in ("return;", "exit();", "die();", "throw new RuntimeException();"):
            with self.subTest(stop=stop):
                self.assertEqual(check(BASE.replace("    $sql =", "    " + stop + "\n    $sql =")), [])
        self.assertEqual(check(BASE.replace("<?php", "<?php\nreturn;")), [])

    def test_literal_false_branch_does_not_produce_candidate(self):
        self.assertEqual(check(BASE.replace("if ($_POST['step'] == '2')", "if (false && $_POST['step'] == '2')")), [])
        self.assertEqual(check(BASE.replace("    $sql =", "    if (false) {\n    $sql =")
                               .replace("    mysqli_query($db, $sql);", "    mysqli_query($db, $sql);\n    }")), [])

    def test_conditional_return_does_not_hide_reachable_operation(self):
        source = BASE.replace("    $sql =", "    if ($_POST['abort']) { return; }\n    $sql =")
        self.assertEqual(check(source)[0]["status"], "candidate")

    def test_global_verification_or_helper_requires_context(self):
        for guard in ("if (!verify_captcha($_POST['captcha'])) { return; }", "enforce_workflow();"):
            with self.subTest(guard=guard):
                result = check(BASE.replace("<?php", "<?php\n" + guard))[0]
                self.assertEqual(result["status"], "needs_context")
                self.assertTrue(any("外层" in gap for gap in result["missing_evidence"]))

    def test_php_closing_tag_ends_line_comment(self):
        source = "<?php // ?>\n" + BASE.replace("<?php", "").replace("?>", "")
        self.assertEqual(check(source), [])

    def test_outer_precomputed_guard_and_unmodeled_control_flow_need_context(self):
        enclosed = "<?php\nif ($verified) {\n" + BASE.replace("<?php", "").replace("?>", "") + "\n}\n?>"
        for source in (enclosed,
                       BASE.replace("<?php", "<?php\nif (!$verified) return;"),
                       BASE.replace("    $sql =", "    goto finished;\n    $sql =")
                           .replace("    mysqli_query($db, $sql);", "    mysqli_query($db, $sql);\n    finished:;")):
            with self.subTest(source=source):
                result = check(source)[0]
                self.assertEqual(result["status"], "needs_context")
                self.assertTrue(result["missing_evidence"])

    def test_mutually_exclusive_first_stage_and_strict_equality_are_supported(self):
        self.assertEqual(check(BASE)[0]["status"], "candidate")
        self.assertEqual(check(BASE.replace(" == ", " === "))[0]["status"], "candidate")

    def test_original_samples_keep_candidates_and_exact_lines(self):
        dataset = Path(__file__).resolve().parents[2] / "暴风星云裂"
        for name in ("014.php", "015.php"):
            path = dataset / name
            if not path.is_file():
                self.skipTest("Classroom repository samples unavailable")
            source = path.read_text(encoding="utf-8")
            result = analyze_logic(PROJECT, {name: source})[0]
            self.assertEqual(result["status"], "candidate")
            for evidence in result["evidence"]:
                self.assertEqual(source.splitlines()[evidence["line"] - 1], evidence["code"])


if __name__ == "__main__":
    unittest.main()
