"""Independent static counterexamples found during the second review.

The snippets are parsed only; none of their functions or expressions execute.
"""
import textwrap
import unittest

from sunset.logic_analysis import analyze_logic
from sunset.models import Project


def review(body, **changes):
    rule = {"id": "review", "category": "workflow_bypass", "file": "sample.py",
            "function": "handler", "operation": "store.change_password",
            "required_condition": "session.get('captcha_passed') is True",
            "trusted_inputs": ["session"], "context_complete": True}
    rule.update(changes)
    code = "def handler(body, session, store):\n" + textwrap.indent(body, "    ")
    return analyze_logic(Project("", "", "", ""), {"sample.py": code}, [rule])


GUARD = "if not (session.get('captcha_passed') is True):\n    return 403\n"
OPERATION = "return store.change_password(body['password'])"


class TestReviewPython(unittest.TestCase):
    def test_walrus_rebinding_in_if_invalidates_prior_guard(self):
        results = review(GUARD + "if (session := body):\n    " + OPERATION)
        self.assertEqual(results[0]["status"], "needs_context")

    def test_nested_definition_default_side_effect_is_not_ignored(self):
        for definition in ("def helper(value=session.clear()):\n    pass\n",
                           "@session.clear()\ndef helper():\n    pass\n",
                           "class Helper:\n    session.clear()\n"):
            with self.subTest(definition=definition):
                self.assertEqual(review(GUARD + definition + OPERATION)[0]["status"], "needs_context")

    def test_arbitrary_get_method_not_assumed_pure(self):
        for call in ("service.get()\n", "service.get_order()\n", "int(body['amount'])\n",
                     "body = service\nbody.get('x')\n"):
            with self.subTest(call=call):
                self.assertEqual(review(GUARD + call + OPERATION)[0]["status"], "needs_context")

    def test_unknown_call_inside_operation_arguments_cannot_preserve_guard(self):
        result = review(GUARD + "return store.change_password(service.get())")
        self.assertEqual(result[0]["status"], "needs_context")

    def test_builtin_name_shadowing_does_not_gain_pure_call_privilege(self):
        for prefix in ("int = body['callback']\n", "def int(value):\n    session.clear()\n"):
            with self.subTest(prefix=prefix):
                result = review(GUARD + prefix + "int('1')\n" + OPERATION)
                self.assertEqual(result[0]["status"], "needs_context")

    def test_untyped_negated_order_comparison_not_treated_as_total_order(self):
        body = "quantity = body['quantity']\nif quantity <= 0:\n    return 403\nreturn store.purchase(quantity)"
        result = review(body, category="business_constraint", operation="store.purchase",
                        required_condition="quantity > 0", trusted_inputs=[], operation_bindings={"0": "quantity"})
        self.assertEqual(result[0]["status"], "needs_context")

    def test_direct_positive_condition_still_protects_numeric_operation(self):
        body = "quantity = body['quantity']\nif not (quantity > 0):\n    return 403\nreturn store.purchase(quantity)"
        result = review(body, category="business_constraint", operation="store.purchase",
                        required_condition="quantity > 0", trusted_inputs=[], operation_bindings={"0": "quantity"})
        self.assertEqual(result[0]["status"], "guarded")

    def test_separate_same_line_operations_keep_distinct_identifiers(self):
        results = review("store.change_password('first'); store.change_password('second')")
        self.assertEqual(len(results), 2)
        self.assertEqual(len({a['assessment_id'] for a in results}), 2)
        self.assertEqual(results[0]['status'], 'candidate')
        self.assertEqual(results[1]['status'], 'needs_context')

    def test_prior_sensitive_operation_cannot_reuse_one_time_state_proof(self):
        results = review(GUARD + "store.change_password('first')\n" + OPERATION)
        self.assertEqual([a['status'] for a in results], ['guarded', 'needs_context'])

    def test_rebinding_service_object_requires_context(self):
        self.assertEqual(review(GUARD + "store = body['store']\n" + OPERATION)[0]['status'], 'needs_context')

    def test_nested_mutable_state_alias_from_get_or_container_requires_context(self):
        condition = "session['flags']['passed'] is True"
        guard = "if not (" + condition + "):\n    return 403\n"
        for change in ("alias = session.get('flags')\nalias['passed'] = False\n",
                       "alias = {'flags': session['flags']}\nalias['flags']['passed'] = False\n"):
            with self.subTest(change=change):
                self.assertEqual(review(guard + change + OPERATION, required_condition=condition)[0]['status'], 'needs_context')

    def test_direct_api_does_not_accept_truthy_nonboolean_context(self):
        for value in ('false', 'true', 1, 0, None, []):
            with self.subTest(value=value):
                result = review(OPERATION, context_complete=value)
                self.assertEqual(result[0]['status'], 'needs_context')

    def test_direct_api_invalid_policy_shapes_do_not_raise_or_claim_candidates(self):
        for changes in ({'file': []}, {'category': []}, {'operation_bindings': []},
                        {'operation_bindings': {'0': None}}, {'operation_bindings': {0: 'quantity'}},
                        {'operation_bindings': {'0': 'not valid Python!'}}, {'trusted_inputs': ['not.identifier']}):
            with self.subTest(changes=changes):
                self.assertEqual(review(OPERATION, **changes)[0]['status'], 'needs_context')


if __name__ == '__main__':
    unittest.main()
