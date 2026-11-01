"""Static logic checks: independent counterexamples, no source execution/network."""
from __future__ import annotations

import textwrap
import unittest
from pathlib import Path

from sunset.logic_analysis import analyze_logic
from sunset.models import Project


PROJECT = Project(zip_path="", zip_sha256="", root="", extracted_dir="")


def policy(**overrides):
    result = {"id": "captcha", "category": "workflow_bypass", "file": "handlers.py",
              "function": "change", "operation": "store.change_password",
              "required_condition": "session.get('captcha_passed') is True",
              "description": "Require a server-side CAPTCHA state before changing password",
              "trusted_inputs": ["session"], "context_complete": True}
    result.update(overrides)
    return result


def assess(body, **overrides):
    code = "def change(body, session, store):\n" + textwrap.indent(textwrap.dedent(body).strip() + "\n", "    ")
    return analyze_logic(PROJECT, {"handlers.py": code}, [policy(**overrides)])[0]


class TestPythonLogic(unittest.TestCase):
    def test_missing_guard_is_candidate_with_real_source_line(self):
        result = assess("return store.change_password(body['password'])")
        self.assertEqual(result["status"], "candidate")
        self.assertEqual(result["line_end"], 2)
        self.assertIn("store.change_password", result["evidence"][-1]["code"])
        self.assertEqual(result["policy_source"], "operator_policy")

    def test_rejecting_guard_and_positive_branch_are_supported(self):
        for body in [
            "if not (session.get('captcha_passed') is True):\n    return {'status':403}\nreturn store.change_password(body['password'])",
            "if session.get('captcha_passed') is True:\n    return store.change_password(body['password'])",
            "if session.get('captcha_passed') is not True:\n    raise ValueError()\nreturn store.change_password(body['password'])",
        ]:
            with self.subTest(body=body):
                self.assertEqual(assess(body)["status"], "guarded")

    def test_client_flag_does_not_satisfy_server_condition(self):
        result = assess("if not body.get('passed_captcha'):\n    return {'status':403}\nreturn store.change_password(body['password'])")
        self.assertEqual(result["status"], "candidate")

    def test_guard_after_operation_does_not_protect_it(self):
        self.assertEqual(assess("store.change_password(body['password'])\nif not (session.get('captcha_passed') is True):\n    return 403")["status"], "candidate")

    def test_or_guard_allows_unverified_bypass(self):
        self.assertEqual(assess("if session.get('captcha_passed') is True or body.get('skip'):\n    return store.change_password(body['password'])")["status"], "candidate")

    def test_nonterminating_rejection_does_not_protect_operation(self):
        self.assertEqual(assess("if not (session.get('captcha_passed') is True):\n    error = 'denied'\nreturn store.change_password(body['password'])")["status"], "candidate")

    def test_only_one_branch_checks_condition(self):
        self.assertEqual(assess("if body.get('check'):\n    if not (session.get('captcha_passed') is True):\n        return 403\nreturn store.change_password(body['password'])")["status"], "candidate")

    def test_trusted_rebinding_alias_and_mutation_require_context(self):
        before = "if not (session.get('captcha_passed') is True):\n    return 403\n"
        for change in ["session = body", "session['captcha_passed'] = body['flag']",
                       "alias = session\nalias['captcha_passed'] = body['flag']",
                       "session.clear()", "mutate(session)", "mutate(state=session)"]:
            with self.subTest(change=change):
                result = assess(before + change + "\nreturn store.change_password(body['password'])")
                self.assertEqual(result["status"], "needs_context")

    def test_mutation_inside_expression_does_not_inherit_old_guard(self):
        before = "if not (session.get('captcha_passed') is True):\n    return 403\n"
        for expression in ["return (session.clear(), store.change_password(body['password']))",
                           "return store.change_password(body['password']) if body.get('ok') else None",
                           "if session.clear() or session.get('captcha_passed') is True:\n    return store.change_password(body['password'])"]:
            with self.subTest(expression=expression):
                self.assertEqual(assess(before + expression)["status"], "needs_context")

    def test_unknown_helpers_context_and_assert_are_not_proof(self):
        for body in ["authorize()\nreturn store.change_password(body['password'])",
                     "assert session.get('captcha_passed') is True\nreturn store.change_password(body['password'])",
                     "try:\n    return store.change_password(body['password'])\nexcept Exception:\n    pass"]:
            with self.subTest(body=body):
                self.assertEqual(assess(body)["status"], "needs_context")
        self.assertEqual(assess("return store.change_password(body['password'])", context_complete=False)["status"], "needs_context")

    def test_untyped_inverse_comparison_requires_numeric_context(self):
        body = "quantity = body['quantity']\nif quantity <= 0:\n    return 403\nreturn store.purchase(quantity)"
        self.assertEqual(assess(body, category="business_constraint", operation="store.purchase",
                                required_condition="quantity > 0", trusted_inputs=[], operation_bindings={"0": "quantity"})["status"], "needs_context")

    def test_validated_amount_reassigned_or_unused_is_not_guarded(self):
        start = "quantity = body['quantity']\nif not (quantity > 0):\n    return 403\n"
        for tail, expected in [("quantity = body['other_quantity']\nreturn store.purchase(quantity)", "candidate"),
                               ("return store.purchase(body['quantity'])", "needs_context")]:
            with self.subTest(tail=tail):
                self.assertEqual(assess(start + tail, category="business_constraint", operation="store.purchase",
                                        required_condition="quantity > 0", trusted_inputs=[], operation_bindings={"0": "quantity"})["status"], expected)

    def test_object_scope_checked_and_used(self):
        body = "order = store.get_order(body['order_id'])\nif not (order['owner_id'] == session['user_id']):\n    return 403\nreturn store.update_order(order['id'], body['status'])"
        options = dict(category="object_authorization", operation="store.update_order",
                       required_condition="order['owner_id'] == session['user_id']", trusted_inputs=["session", "order"], operation_bindings={"0": "order['id']"})
        self.assertEqual(assess(body, **options)["status"], "guarded")
        self.assertEqual(assess(body.replace("return store.update_order", "order = store.get_order(body['other_order'])\nreturn store.update_order"), **options)["status"], "needs_context")
        self.assertEqual(assess(body.replace("order['id'], body", "body['order_id'], body"), **options)["status"], "needs_context")

    def test_trusted_object_cannot_be_direct_client_value(self):
        body = "order = body['order']\nif not (order['owner_id'] == session['user_id']):\n    return 403\nreturn store.update_order(order['id'])"
        self.assertEqual(assess(body, category="object_authorization", operation="store.update_order",
                                required_condition="order['owner_id'] == session['user_id']", trusted_inputs=["session", "order"], operation_bindings={"0": "order['id']"})["status"], "needs_context")

    def test_renamed_request_and_alias_cannot_initialize_trusted_object(self):
        for assignment in ("order = payload['order']", "packet = payload\norder = packet['order']",
                           "packet = payload\norder = packet.get('order')"):
            body = assignment + "\nif not (order['owner_id'] == session['user_id']):\n    return 403\nreturn store.update_order(order['id'])"
            code = "def change(payload, session, store):\n" + textwrap.indent(body + "\n", "    ")
            rule = policy(category="object_authorization", operation="store.update_order",
                          required_condition="order['owner_id'] == session['user_id']",
                          trusted_inputs=["session", "order"], operation_bindings={"0": "order['id']"})
            with self.subTest(assignment=assignment):
                result = analyze_logic(PROJECT, {"handlers.py": code}, [rule])[0]
                self.assertEqual(result["status"], "needs_context")
                self.assertTrue(any("客户端" in item for item in result["missing_evidence"]))

    def test_checked_object_in_unrelated_argument_is_not_target_binding(self):
        body = "order = store.get_order(1)\nif not (order['owner_id'] == session['user_id']):\n    return 403\nreturn store.update_order(body['order_id'], order['memo'])"
        result = assess(body, category="object_authorization", operation="store.update_order",
                        required_condition="order['owner_id'] == session['user_id']",
                        trusted_inputs=["session", "order"], operation_bindings={"0": "order['id']"})
        self.assertEqual(result["status"], "needs_context")

    def test_business_rule_requires_explicit_argument_semantics(self):
        body = "quantity = body['quantity']\nif quantity <= 0:\n    return 403\nreturn store.purchase(quantity)"
        result = assess(body, category="business_constraint", operation="store.purchase",
                        required_condition="quantity > 0", trusted_inputs=[])
        self.assertEqual(result["status"], "needs_context")

    def test_keyword_binding_supported_and_checked(self):
        body = "quantity = body['quantity']\nif not (quantity > 0):\n    return 403\nreturn store.purchase(amount=quantity)"
        options = dict(category="business_constraint", operation="store.purchase",
                       required_condition="quantity > 0", trusted_inputs=[], operation_bindings={"amount": "quantity"})
        self.assertEqual(assess(body, **options)["status"], "guarded")
        self.assertEqual(assess(body.replace("amount=quantity", "amount=body['other_quantity'], note=quantity"), **options)["status"], "needs_context")

    def test_required_conjunction_needs_both_conditions(self):
        options = dict(category="business_constraint", operation="store.purchase", required_condition="quantity > 0 and quantity <= 10", trusted_inputs=[], operation_bindings={"0": "quantity"})
        self.assertEqual(assess("quantity=body['quantity']\nif not (quantity > 0 and quantity <= 10):\n    return 403\nreturn store.purchase(quantity)", **options)["status"], "guarded")
        self.assertEqual(assess("quantity=body['quantity']\nif not (quantity > 0):\n    return 403\nreturn store.purchase(quantity)", **options)["status"], "candidate")

    def test_unsupported_policy_disjunction_never_becomes_empty_proof(self):
        self.assertEqual(assess("return store.change_password(body['password'])",
                                required_condition="session.get('captcha_passed') is True or session.get('admin') is True")["status"], "needs_context")

    def test_comments_strings_and_unreachable_operations_are_not_calls(self):
        for body in ["# store.change_password(body['password'])\nreturn 200",
                     "text = 'store.change_password(body)'\nreturn text",
                     "if False:\n    return store.change_password(body['password'])"]:
            with self.subTest(body=body):
                self.assertEqual(assess(body)["status"], "needs_context")

    def test_business_policy_never_autoloaded_from_source(self):
        self.assertEqual(analyze_logic(PROJECT, {"app.py": "def buy(q): return store.purchase(q)",
                                                "policy.json": '{"rules":["fabricated"]}'}), [])

    def test_unmodeled_statement_cannot_reuse_guard(self):
        body = "if not (session.get('captcha_passed') is True):\n    return 403\nimport middleware\nreturn store.change_password(body['password'])"
        self.assertEqual(assess(body)["status"], "needs_context")

    def test_missing_or_ambiguous_target_and_parse_errors_need_context(self):
        for contents, rules in [({}, [policy()]),
                                ({"handlers.py": "not valid Python !!!"}, [policy()]),
                                ({"handlers.py": "class A:\n def change(self): pass\nclass B:\n def change(self): pass\n"}, [policy()]),
                                ({"handlers.py": "def change(): pass"}, [policy(required_condition="x === 2")])]:
            with self.subTest(contents=contents):
                self.assertEqual(analyze_logic(PROJECT, contents, rules)[0]["status"], "needs_context")


PHP = '''<?php
if ($_POST['step'] == '1') {
    $answer = verify_captcha($_POST['captcha']);
    if (!$answer) { return; }
}
if ($_POST['step'] == '2') {
    $sql = "UPDATE users SET password = '$password' WHERE user = '$user'";
    mysqli_query($db, $sql);
}
?>
'''


class TestPhpWorkflow(unittest.TestCase):
    def test_renamed_file_and_client_flag_variants(self):
        for code in [PHP, PHP.replace("    $sql =", "    if (!$_POST['passed_captcha']) { return; }\n    $sql =")]:
            with self.subTest(code=code):
                result = analyze_logic(PROJECT, {"arbitrary-name.php": code})
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["status"], "candidate")
                self.assertEqual(result[0]["vulnerability_type"], "captcha_bypass")
                self.assertIn("mysqli_query", result[0]["evidence"][-1]["code"])

    def test_checked_but_unexecuted_sql_is_not_operation(self):
        self.assertEqual(analyze_logic(PROJECT, {"case.php": PHP.replace("mysqli_query($db, $sql);", "// not executed")}), [])

    def test_comments_and_strings_do_not_invent_captcha_checks(self):
        for replacement in ["// verify_captcha($_POST['captcha']);", '$text = "verify_captcha()";']:
            with self.subTest(replacement=replacement):
                code = PHP.replace("$answer = verify_captcha($_POST['captcha']);", replacement)
                self.assertEqual(analyze_logic(PROJECT, {"case.php": code}), [])

    def test_session_helper_and_external_context_are_reviewed(self):
        for guard in ["if (!$_SESSION['captcha_passed']) { return; }", "guard_workflow();", "require 'middleware.php';"]:
            with self.subTest(guard=guard):
                code = PHP.replace("    $sql =", "    " + guard + "\n    $sql =")
                result = analyze_logic(PROJECT, {"case.php": code})[0]
                self.assertEqual(result["status"], "needs_context")
                self.assertTrue(result["missing_evidence"])

    def test_original_repository_samples_are_detected_with_exact_lines(self):
        dataset = Path(__file__).resolve().parents[2] / "集成数据集"
        for name in ("014.php", "015.php"):
            path = dataset / name
            if not path.is_file():
                self.skipTest("Repository classroom samples unavailable")
            code = path.read_text(encoding="utf-8")
            result = analyze_logic(PROJECT, {name: code})[0]
            with self.subTest(name=name):
                self.assertEqual(result["status"], "candidate")
                for evidence in result["evidence"]:
                    self.assertEqual(code.splitlines()[evidence["line"] - 1], evidence["code"])


if __name__ == "__main__":
    unittest.main()
