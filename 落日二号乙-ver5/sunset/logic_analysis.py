"""Bounded business-policy checks; no target code is imported or executed.

Python rules come from the *operator's* policy file, not from source comments.
The PHP adapter recognizes a narrow cross-request CAPTCHA/password pattern.
``guarded`` means a local dominating guard was found, never whole-system safety.
Unsupported syntax or incomplete trust context stays ``needs_context``.
"""
from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from .models import Project

CATEGORIES = {
    "workflow_bypass": "business_logic",
    "object_authorization": "idor",
    "business_constraint": "business_logic",
}


def _assessment(policy: dict, text: str, line: int = 1, **extra: Any) -> dict:
    lines = text.splitlines()
    line = min(max(1, line), max(1, len(lines)))
    key = f"{policy.get('id')}:{policy.get('file')}:{line}:{extra.get('column', 0)}"
    result = {
        "assessment_id": "BL-" + hashlib.sha256(key.encode()).hexdigest()[:14],
        "category": policy.get("category", "workflow_bypass"),
        "vulnerability_type": CATEGORIES.get(policy.get("category"), "auth_bypass"),
        "file": policy.get("file", ""), "line_start": line, "line_end": line,
        "status": "needs_context", "expected_rule": policy.get("description") or policy.get("required_condition", ""),
        "reason": "", "evidence": [], "missing_evidence": [],
        "verification_steps": [
            "在本地或授权环境准备正常用户、初始业务状态及正常请求。",
            "仅改变该规则相关的前置步骤、对象归属或边界输入，发送对照请求。",
            "核对真实数据库/业务状态的变化，不把 HTTP 200 或成功字符串单独作为证明。",
            "对修复版重复正常及异常请求，保存请求、响应与操作前后状态。",
        ],
        "confidence": 0.0, "rule_id": str(policy.get("id", "")),
        "scope_start": line, "scope_end": line,
        "policy_source": "operator_policy",
    }
    result.update(extra)
    return result


def _dump(node: ast.AST) -> str:
    return ast.dump(node, include_attributes=False)


def _names(node: ast.AST) -> set[str]:
    return {part.id for part in ast.walk(node) if isinstance(part, ast.Name)}


def _root(node: ast.AST) -> str:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _call_name(call: ast.Call) -> str:
    try:
        return ast.unparse(call.func)
    except (ValueError, RecursionError):
        return ""


_INVERSE = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Is: ast.IsNot, ast.IsNot: ast.Is,
            ast.In: ast.NotIn, ast.NotIn: ast.In}

# Negating x <= 0 does not prove x > 0 for NaN or custom comparison objects.
_EXPRESSION_CONTROL = (ast.IfExp, ast.NamedExpr, ast.Lambda, ast.comprehension,
                       ast.Await, ast.Yield, ast.YieldFrom)


def _facts(node: ast.AST, truth: bool = True) -> set[str]:
    """Only facts logically implied by this branch (never flatten a true OR)."""
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _facts(node.operand, not truth)
    if isinstance(node, ast.BoolOp):
        parts = [_facts(value, truth) for value in node.values]
        conjunction = (truth and isinstance(node.op, ast.And)) or (not truth and isinstance(node.op, ast.Or))
        return set.union(*parts) if conjunction else set.intersection(*parts)
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        if truth:
            return {_dump(node)}
        inverse = _INVERSE.get(type(node.ops[0]))
        if inverse:
            return {_dump(ast.Compare(left=node.left, ops=[inverse()], comparators=node.comparators))}
    return {("T:" if truth else "F:") + _dump(node)}


def _supported_condition(node: ast.AST) -> bool:
    if isinstance(node, ast.BoolOp):
        return isinstance(node.op, ast.And) and all(_supported_condition(x) for x in node.values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _supported_condition(node.operand)
    if isinstance(node, ast.Compare):
        return len(node.ops) == 1 and not any(isinstance(n, _EXPRESSION_CONTROL) for n in ast.walk(node))
    return isinstance(node, (ast.Name, ast.Subscript, ast.Attribute))


@dataclass
class _State:
    facts: dict[str, int] = field(default_factory=dict)
    gaps: set[str] = field(default_factory=set)
    assigned: set[str] = field(default_factory=set)
    aliases: set[str] = field(default_factory=set)
    untrusted: set[str] = field(default_factory=set)

    def copy(self) -> "_State":
        return _State(dict(self.facts), set(self.gaps), set(self.assigned), set(self.aliases), set(self.untrusted))


class _PythonCheck:
    def __init__(self, policy: dict, text: str, function: ast.FunctionDef | ast.AsyncFunctionDef, condition: ast.AST):
        self.policy, self.text, self.function = policy, text, function
        self.required = _facts(condition)
        self.depends = _names(condition)
        self.trusted = set(policy.get("trusted_inputs", []))
        self.operation = policy["operation"]
        self.receiver = self.operation.split(".", 1)[0]
        self.observations: dict[tuple[int, int], list[_State]] = {}

    def read_call(self, call: ast.Call, state: _State) -> bool:
        """Only the supported dictionary/service reads, never an arbitrary .get()."""
        if not isinstance(call.func, ast.Attribute):
            return False
        base = _root(call.func.value)
        if call.func.attr == "get":
            return base in self.trusted | {"body", "request", "form", "params"}
        return _call_name(call) == self.receiver + ".get_order"

    def record(self, node: ast.AST, states: list[_State], *, uncertain: bool = False) -> None:
        calls = [n for n in ast.walk(node) if isinstance(n, ast.Call)]
        # Evaluation order inside an expression is outside the statement checker.
        # In particular (session.clear(), protected_operation()) must not inherit
        # a guard proved before the clear().
        for call in ast.walk(node):
            if isinstance(call, ast.Call) and _call_name(call) == self.operation:
                for state in states:
                    copy = state.copy()
                    complex_call = len(calls) > 1 and any(
                        _call_name(c) != self.operation and not self.read_call(c, state) for c in calls)
                    multiple_operations = sum(_call_name(c) == self.operation for c in calls) > 1
                    if uncertain or complex_call or multiple_operations:
                        copy.gaps.add("操作位于当前分析器未完整建模的控制流中")
                    # An owner/quantity guard protects the value checked, not a
                    # fresh request value used in its place at the operation.
                    category = self.policy.get("category")
                    relevant = self.depends - {"session", "request", "body", "store"}
                    if category in {"object_authorization", "business_constraint"}:
                        bindings = self.policy.get("operation_bindings", {})
                        bound_names: set[str] = set()
                        if not bindings:
                            copy.gaps.add("需要 operation_bindings 指定敏感操作中实际对象/数值的参数位置")
                        for position, expression in bindings.items():
                            try:
                                expected = ast.parse(expression, mode="eval").body
                                bound_names.update(_names(expected))
                                if str(position).isdigit():
                                    index = int(position)
                                    actual = call.args[index] if index < len(call.args) else None
                                else:
                                    actual = next((kw.value for kw in call.keywords if kw.arg == position), None)
                                if actual is None or _dump(actual) != _dump(expected):
                                    copy.gaps.add(f"操作参数 {position} 与策略指定的检查值不一致")
                            except (SyntaxError, ValueError, TypeError):
                                copy.gaps.add("operation_bindings 包含无效的参数映射")
                        if not relevant <= bound_names:
                            copy.gaps.add("操作参数映射未覆盖规则检查的对象/数值，需要补充数据流映射")
                    self.observations.setdefault((call.lineno, call.col_offset), []).append(copy)

    def mutate(self, node: ast.AST, states: list[_State]) -> None:
        targets: list[ast.AST] = []
        value = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets, value = [node.target], node.value
        elif isinstance(node, ast.Delete):
            targets = node.targets
        writes = {_root(part) for target in targets for part in ast.walk(target)
                  if isinstance(part, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(getattr(part, "ctx", None), ast.Store)}
        if isinstance(node, ast.Delete):
            writes |= {_root(t) for t in targets}
        # In-place methods on policy inputs may invalidate a check just as assignment does.
        for call in ast.walk(node):
            if not isinstance(call, ast.Call) or _call_name(call) == self.operation:
                continue
            # Helpers may enforce or mutate business state. Without their body we
            # cannot claim either a bypass or a valid guard.
            for state in states:
                if not self.read_call(call, state):
                    state.gaps.add("存在未建模的辅助调用，需要确认其校验和副作用")
            if isinstance(call.func, ast.Attribute) and call.func.attr not in {"get", "get_order"}:
                base = _root(call.func.value)
                for state in states:
                    if base in self.depends or base in state.aliases:
                        state.facts.clear()
                        state.gaps.add("业务条件依赖的对象可能被方法调用修改")
            for state in states:
                args = [*call.args, *(kw.value for kw in call.keywords)]
                arg_names = set().union(*(_names(arg) for arg in args)) if args else set()
                if arg_names & (self.trusted | state.aliases):
                    state.facts.clear()
                    state.gaps.add("可信对象传入未建模的辅助调用，需要确认其副作用")
        for state in states:
            if writes & {"body", "request", "form", "params"}:
                state.gaps.add("请求读取对象被重新赋值，不能继续假定其 get 方法是字典读取")
            if self.receiver in writes:
                state.facts.clear()
                state.gaps.add("敏感操作的服务对象被重新绑定，调用语义需要复核")
            if writes & (self.depends | state.aliases):
                state.facts.clear()
            for name in writes & self.trusted:
                if name in state.assigned or isinstance(node, (ast.AugAssign, ast.Delete)):
                    state.gaps.add(f"可信输入 {name} 被重绑定或修改，需要重新确认来源")
                elif value is not None and (_names(value) & state.untrusted):
                    # A policy may trust a repository lookup keyed by client ID, but not
                    # direct aliases of request dictionaries or values extracted from them.
                    lookup = isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and _root(value.func.value) not in state.untrusted
                    if not lookup:
                        state.gaps.add(f"声明可信的 {name} 实际从客户端输入赋值")
            if value is not None and _names(value) & (self.trusted | state.aliases):
                # get() and shallow containers can expose the same nested
                # mutable object, so their aliases also invalidate this proof.
                state.aliases.update(writes)
            if writes & state.aliases:
                state.gaps.add("可信对象存在别名写入，需要补充数据流分析")
            # Preserve input origin through renamed dictionaries and simple
            # assignments; request data is not defined by the spelling "body".
            if value is not None and _names(value) & state.untrusted:
                lookup = isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and _root(value.func.value) not in state.untrusted
                if not lookup:
                    state.untrusted.update(writes)
            state.assigned.update(writes)
            if any(isinstance(c, ast.Call) and _call_name(c) == self.operation for c in ast.walk(node)):
                state.facts.clear()
                state.gaps.add("前一次敏感操作可能改变业务状态；后续操作需要重新确认")

    def walk(self, statements: list[ast.stmt], states: list[_State]) -> list[_State]:
        for stmt in statements:
            if not states:
                break
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Defaults, decorators and class bodies can execute now, even
                # when the newly defined function is never invoked.
                for state in states:
                    state.facts.clear()
                    state.gaps.add("嵌套定义的默认值、装饰器或类体执行效果未建模")
                continue
            if isinstance(stmt, ast.If):
                self.record(stmt.test, states, uncertain=True)
                self.mutate(stmt.test, states)
                complex_test = any(isinstance(n, _EXPRESSION_CONTROL) for n in ast.walk(stmt.test))
                if complex_test:
                    for state in states:
                        state.facts.clear()
                        state.gaps.add("条件表达式含赋值或未建模的求值顺序，不能沿用已有检查")
                branches = []
                for truth, body in ((True, stmt.body), (False, stmt.orelse)):
                    if isinstance(stmt.test, ast.Constant) and bool(stmt.test.value) != truth:
                        continue
                    opposite = _facts(stmt.test, not truth)
                    copies = [state.copy() for state in states
                              if not (len(opposite) == 1 and opposite <= state.facts.keys())]
                    for state in copies:
                        branch_facts = _facts(stmt.test, truth)
                        if any(fact.startswith("F:Compare(") and any(token in fact for token in
                               ("Lt()", "LtE()", "Gt()", "GtE()")) for fact in branch_facts):
                            state.gaps.add("数值类型未确定，不能将大小比较失败推导为相反比较成立（例如 NaN）")
                        state.facts.update({fact: stmt.lineno for fact in branch_facts})
                    branches.extend(self.walk(body, copies))
                states = branches
            elif isinstance(stmt, (ast.Return, ast.Raise)):
                unusual = any(isinstance(part, (ast.IfExp, ast.BoolOp, ast.NamedExpr, ast.Lambda, ast.comprehension, ast.Await, ast.Yield, ast.YieldFrom)) for part in ast.walk(stmt))
                self.record(stmt, states, uncertain=unusual)
                states = []
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match, ast.Assert, ast.Global, ast.Nonlocal)):
                self.record(stmt, states, uncertain=True)
                for state in states:
                    state.facts.clear()
                    state.gaps.add("存在循环、异常、上下文管理或 assert；需要完整控制流上下文")
            else:
                # Fail closed for statement forms not explicitly modeled (for
                # example imports and Python 3.11+ except* / TryStar).
                if not isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete, ast.Expr, ast.Pass)):
                    self.record(stmt, states, uncertain=True)
                    for state in states:
                        state.facts.clear()
                        state.gaps.add("存在未支持的语句类型，需要补充控制流上下文")
                    continue
                unusual = any(isinstance(part, (ast.IfExp, ast.BoolOp, ast.NamedExpr, ast.Lambda, ast.comprehension, ast.Await, ast.Yield, ast.YieldFrom)) for part in ast.walk(stmt))
                self.record(stmt, states, uncertain=unusual)
                self.mutate(stmt, states)
                if unusual:
                    for state in states:
                        state.facts.clear()
                        state.gaps.add("存在表达式内分支或赋值，需要补充路径分析")
            if len(states) > 64:
                states = [_State(gaps={"路径数量超过 64，分析预算不足"})]
        return states

    def run(self) -> list[dict]:
        parameters = {a.arg for a in self.function.args.args + self.function.args.posonlyargs + self.function.args.kwonlyargs}
        parameters.update(a.arg for a in (self.function.args.vararg, self.function.args.kwarg) if a is not None)
        receiver = self.operation.split(".", 1)[0]
        input_names = (parameters | {"body", "request", "form", "params"}) - self.trusted - {receiver}
        initial = _State(assigned=parameters, untrusted=input_names)
        if self.function.decorator_list:
            initial.gaps.add("函数含装饰器，需核对其鉴权或调用语义")
        self.walk(self.function.body, [initial])
        results = []
        lines = self.text.splitlines()
        for (line, column), states in sorted(self.observations.items()):
            gaps = sorted(set().union(*(state.gaps for state in states)))
            protected = all(self.required <= state.facts.keys() for state in states)
            if not self.policy.get("context_complete", False):
                gaps.append("策略未确认完整的调用链、认证入口和外部业务约束")
            if gaps:
                status, confidence, reason = "needs_context", 0.3, "当前源码不足以判定该业务条件是否有效保护操作。"
            elif protected:
                status, confidence, reason = "guarded", 0.85, "所有已建模的可达操作路径均受指定条件保护；仅表示此规则的局部检查成立。"
            else:
                status, confidence, reason = "candidate", 0.8, "存在到达敏感操作的路径，未发现指定业务条件在服务端强制成立；需动态对照验证。"
            evidence = [{"line": self.function.lineno, "code": lines[self.function.lineno - 1], "role": "scope"}]
            guard_lines = sorted({lineno for state in states for fact, lineno in state.facts.items() if fact in self.required})
            evidence.extend({"line": n, "code": lines[n - 1], "role": "guard"} for n in guard_lines)
            evidence.append({"line": line, "code": lines[line - 1], "role": "operation"})
            results.append(_assessment(self.policy, self.text, line, status=status, confidence=confidence,
                                       reason=reason, evidence=evidence, missing_evidence=gaps,
                                       scope_start=self.function.lineno, scope_end=self.function.end_lineno,
                                       column=column))
        return results


def _python_policy(policy: dict, contents: dict[str, str]) -> list[dict]:
    # Standalone callers bypass the CLI loader. Fail closed on invalid shapes
    # instead of accepting truthy strings or raising on unhashable file names.
    invalid = []
    for key in ("id", "category", "file", "function", "operation", "required_condition"):
        if not isinstance(policy.get(key), str) or not policy[key].strip():
            invalid.append(f"策略 {key} 必须是非空字符串")
    if type(policy.get("context_complete", False)) is not bool:
        invalid.append("context_complete 必须是布尔值，不能用字符串或数字声明可信上下文")
    trusted = policy.get("trusted_inputs", [])
    if not isinstance(trusted, list) or not all(isinstance(x, str) and x.isidentifier() for x in trusted):
        invalid.append("trusted_inputs 必须是标识符数组")
    bindings = policy.get("operation_bindings", {})
    if not isinstance(bindings, dict):
        invalid.append("operation_bindings 必须是参数映射对象")
    else:
        for position, expression in bindings.items():
            if (not isinstance(position, str) or not (position.isdecimal() or position.isidentifier())
                    or not isinstance(expression, str) or not expression.strip()):
                invalid.append("operation_bindings 的参数名和表达式必须是有效字符串")
                continue
            try:
                ast.parse(expression, mode="eval")
            except (SyntaxError, ValueError, RecursionError):
                invalid.append("operation_bindings 的表达式无法解析")
    if invalid:
        safe = {key: value for key, value in policy.items() if isinstance(value, str)}
        return [_assessment(safe, "", reason="策略输入类型或参数映射无效。", missing_evidence=invalid)]
    text = contents.get(str(policy.get("file", "")), "")
    missing = []
    if policy.get("file") not in contents:
        missing.append("策略指定的源码文件未提供")
    if policy.get("category") not in CATEGORIES:
        missing.append("不支持的策略类别")
    if not str(policy.get("file", "")).endswith(".py"):
        missing.append("显式策略目前只支持 Python AST")
    if not all(isinstance(policy.get(k), str) and policy[k].strip() for k in ("id", "function", "operation", "required_condition")):
        missing.append("策略缺少 id/function/operation/required_condition")
    if not isinstance(policy.get("trusted_inputs", []), list) or not all(isinstance(x, str) for x in policy.get("trusted_inputs", [])):
        missing.append("trusted_inputs 必须是标识符列表")
    if not isinstance(policy.get("operation_bindings", {}), dict):
        missing.append("operation_bindings 必须是参数位置到表达式的映射")
    if missing:
        return [_assessment(policy, text, reason="策略或源码不完整。", missing_evidence=missing)]
    try:
        tree = ast.parse(text)
        condition = ast.parse(policy["required_condition"], mode="eval").body
    except (SyntaxError, ValueError, RecursionError) as exc:
        return [_assessment(policy, text, reason="无法解析源码或条件。", missing_evidence=[type(exc).__name__])]
    if not _supported_condition(condition):
        return [_assessment(policy, text, reason="策略条件超出当前 AST 子集。",
                            missing_evidence=["仅支持单项比较、布尔值、取反及 AND 合取规则；复杂条件需拆为独立规则"])]
    # Namespaced methods can be selected explicitly; ambiguous bare names fail closed.
    functions: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    def visit(nodes: list[ast.stmt], prefix: str = "") -> None:
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append((prefix + node.name, node))
            elif isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + ".")
    visit(tree.body)
    matches = [node for qualified, node in functions if qualified == policy["function"] or ("." not in policy["function"] and node.name == policy["function"])]
    if len(matches) != 1:
        return [_assessment(policy, text, reason="无法唯一定位策略函数。", missing_evidence=["函数缺失或同名函数不唯一"])]
    results = _PythonCheck(policy, text, matches[0], condition).run()
    return results or [_assessment(policy, text, matches[0].lineno, reason="指定操作未出现在支持的可达路径中。",
                                    missing_evidence=["需要提供实际执行敏感操作的调用点"],
                                    scope_start=matches[0].lineno, scope_end=matches[0].end_lineno)]


def _php_views(text: str) -> tuple[str, str]:
    """Lexical views with original offsets; never interpret HTML/literal bodies.

    The first view retains ordinary SQL string literals. Both views mask HTML,
    comments and heredoc/nowdoc bodies; the second also masks quoted strings.
    This is a bounded lexer, not a PHP parser. Short tags are deliberately not
    assumed enabled. Unterminated literals consume the remainder conservatively.
    """
    cleaned, code = list(text), list(text)
    def mask(start: int, end: int, *, both: bool = True) -> None:
        for index in range(start, end):
            if text[index] not in "\r\n":
                code[index] = " "
                if both:
                    cleaned[index] = " "

    opening_tag = re.compile(r"<\?(?:php\b|=)", re.I)
    heredoc = re.compile(r"<<<[ \t]*(?:([\"'])([A-Za-z_]\w*)\1|([A-Za-z_]\w*))[ \t]*\r?\n")
    pos, in_php = 0, False
    while pos < len(text):
        if not in_php:
            tag = opening_tag.search(text, pos)
            if tag is None:
                mask(pos, len(text))
                break
            mask(pos, tag.end())
            pos, in_php = tag.end(), True
        elif text.startswith("?>", pos):
            mask(pos, pos + 2)
            pos, in_php = pos + 2, False
        elif text.startswith("/*", pos):
            end = text.find("*/", pos + 2)
            end = len(text) if end < 0 else end + 2
            mask(pos, end)
            pos = end
        elif text.startswith("//", pos) or text[pos] == "#":
            # PHP closing tags also end a single-line comment.
            newline, close_tag = text.find("\n", pos), text.find("?>", pos)
            ends = [n for n in (newline, close_tag) if n >= 0]
            end = min(ends) if ends else len(text)
            mask(pos, end)
            pos = end
        elif text.startswith("<<<", pos):
            start = heredoc.match(text, pos)
            end = len(text)
            if start is not None:
                label = start.group(2) or start.group(3)
                closing = re.compile(r"^[ \t]*" + re.escape(label) + r"(?!\w)", re.M).search(text, start.end())
                if closing is not None:
                    end = closing.end()
            mask(pos, end)
            pos = end
        elif text[pos] in "'\"`":
            quote, end = text[pos], pos + 1
            while end < len(text):
                if text[end] == "\\":
                    end = min(len(text), end + 2)
                elif text[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
            mask(pos, end, both=quote == "`")
            pos = end
        else:
            pos += 1
    return "".join(cleaned), "".join(code)


def _closing(code: str, start: int, left: str, right: str) -> int:
    depth = 0
    for i in range(start, len(code)):
        if code[i] == left:
            depth += 1
        elif code[i] == right:
            depth -= 1
            if not depth:
                return i
    return -1


def _php_brace_scope(code: str, end: int) -> tuple[int, ...]:
    stack: list[int] = []
    for index, char in enumerate(code[:end]):
        if char == "{":
            stack.append(index)
        elif char == "}" and stack:
            stack.pop()
    return tuple(stack)


def _php_terminated_before(code: str, target: int) -> bool:
    """Only direct terminating statements in the target's own/ancestor scope."""
    target_scope = _php_brace_scope(code, target)
    for match in re.finditer(r"(?:^|[;{}])\s*(return\b|throw\b|(?:exit|die)\s*(?:\(|;))", code[:target]):
        scope = _php_brace_scope(code, match.start(1))
        if target_scope[:len(scope)] == scope:
            return True
    return False


def _php_false_condition(condition: str) -> bool:
    # Recognize only unambiguous literals / AND-only false conditions. OR and
    # ternary expressions need a proper parser and must not be simplified here.
    value = condition.strip().lower()
    while value.startswith("(") and _closing(value, 0, "(", ")") == len(value) - 1:
        value = value[1:-1].strip()
    if value in {"false", "0"}:
        return True
    return (not re.search(r"\|\||\bor\b|\?", value)
            and bool(re.match(r"(?:false|0)\s*(?:&&|\band\b)", value)))


def _php_captcha(rel: str, text: str) -> list[dict]:
    cleaned, code = _php_views(text)
    checks = list(re.finditer(r"\b(?:recaptcha_check_answer|captcha_verify|verify_captcha)\s*\(", code, re.I))
    if not checks:
        return []
    branches = []
    if_blocks = []
    for match in re.finditer(r"\bif\s*\(", code):
        start = code.index("(", match.start())
        end = _closing(code, start, "(", ")")
        if end < 0:
            continue
        block = re.match(r"\s*\{", code[end + 1:])
        if not block:
            continue
        opening = end + 1 + block.end() - 1
        closing = _closing(code, opening, "{", "}")
        condition = cleaned[start + 1:end]
        if closing >= 0:
            if_blocks.append((match.start(), opening, closing, condition))
        step = re.search(r"\$_(?:POST|GET|REQUEST)\s*\[\s*['\"]step['\"]\s*\]\s*={2,3}(?!=)\s*['\"]?(\d+)", condition)
        if closing >= 0 and step:
            branches.append((match.start(), opening, closing, step.group(1)))
    results = []
    for start, opening, closing, step in branches:
        # Only infer the intended workflow when a different request branch actually
        # invokes CAPTCHA verification. A mention in HTML/comments is insufficient.
        earlier = [b for b in branches if b[3] != step and b[2] < start and any(b[1] < c.start() < b[2] for c in checks)
                   and not any(block[1] <= b[1] < block[2] and _php_false_condition(block[3]) for block in if_blocks)]
        if not earlier:
            continue
        body = cleaned[opening + 1:closing]
        body_code = code[opening + 1:closing]
        assignments = re.finditer(r"(\$\w+)\s*=\s*['\"]\s*UPDATE\s+`?\w+`?\s+SET\s+`?password`?\s*=", body, re.I)
        # Retained SQL text can contain example code. Its assignment prefix must
        # also be visible in the code-only view, rather than inside a string.
        assignment = next((m for m in assignments
                           if body_code[m.start():m.start() + len(m.group(1))] == m.group(1)), None)
        if not assignment:
            continue
        execution = re.search(r"\b(?:mysqli_query|mysql_query|query|exec)\s*\([^;]*?" + re.escape(assignment.group(1)) + r"\b", body_code[assignment.end():], re.I)
        if not execution:
            continue
        sql_pos = opening + 1 + assignment.start()
        op_pos = opening + 1 + assignment.end() + execution.start()
        if (_php_terminated_before(code, op_pos)
                or any(b[1] < op_pos < b[2] and _php_false_condition(b[3]) for b in if_blocks)):
            continue
        line = text[:op_pos].count("\n") + 1
        scope_start, scope_end = text[:start].count("\n") + 1, text[:closing].count("\n") + 1
        prefix_code, prefix = code[:op_pos], cleaned[:op_pos]
        local = cleaned[opening + 1:op_pos]
        gaps = []
        assigned_again = re.search(re.escape(assignment.group(1)) + r"\s*=(?!=)",
                                   code[opening + 1 + assignment.end():op_pos])
        if assigned_again:
            gaps.append("SQL 变量在执行前再次赋值，需要核对最终语句")
        # A session/helper guard is useful evidence but not proof of who wrote the
        # flag, its user/operation binding, and the surrounding middleware.
        if re.search(r"\$_SESSION\s*\[|\b(?:check|require|verify|authorize)\w*\s*\(", code[opening + 1:op_pos], re.I):
            gaps.append("发现服务端会话/辅助校验；需要确认状态来源、用户绑定和失败是否终止操作")
        if re.search(r"\b(?:include|require)(?:_once)?\b", prefix_code):
            gaps.append("依赖外部 include/require，需核对外层业务检查")
        if re.search(r"\b(?:function|class)\b", code):
            gaps.append("PHP 函数/类调用上下文未建模，需要确认实际入口")
        if any(opening < c.start() < op_pos for c in checks):
            gaps.append("最终操作分支存在验证码调用，需确认其返回值与失败路径")
        allowed_calls = {"if", "isset", "empty", "md5", "sha1", "is_object", "is_null", "trigger_error",
                         "mysqli_real_escape_string", "mysql_real_escape_string", "mysqli_query", "mysql_query",
                         "mysqli_error", "mysqli_connect_error", "dvwaCurrentUser", "die", "exit", "intval",
                         "password_hash", "htmlspecialchars", "query", "exec"}
        helpers = {m.group(1) for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", code[opening + 1:op_pos])} - allowed_calls
        if helpers:
            gaps.append("最终分支有未建模的辅助调用：" + ", ".join(sorted(helpers)))
        # Include earlier global guards, while excluding completed, mutually
        # exclusive step branches (the ordinary CAPTCHA stage is one of these).
        outside = list(code[:opening])
        for branch in branches:
            if branch[2] >= start or branch[3] == step:
                continue
            condition = next(b[3] for b in if_blocks if b[0] == branch[0])
            if re.search(r"\|\||\bor\b|\?", condition, re.I):
                continue
            outside[branch[0]:branch[2] + 1] = " " * (branch[2] + 1 - branch[0])
        outside_code = "".join(outside)
        outer_helpers = {m.group(1) for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", outside_code)} - allowed_calls
        if outer_helpers:
            gaps.append("外层存在未建模的前置校验/辅助调用：" + ", ".join(sorted(outer_helpers)))
        if (any(b[1] < start < b[2] for b in if_blocks)
                or re.search(r"\b(?:return|throw|exit|die)\b", outside_code)):
            gaps.append("最终步骤存在外层条件或条件终止路径，需要核对入口保护")
        if re.search(r"(?<![$\w])(?:goto|try|catch|finally|switch|case|match|yield)\b", code[opening + 1:op_pos]):
            gaps.append("最终分支包含未建模的 PHP 控制流，需要补充可达性分析")
        # Session gating of the whole script also deserves review, not a bypass claim.
        if "$_SESSION" in prefix_code[:opening] and re.search(r"\bif\s*\(", prefix_code[:opening]):
            gaps.append("外层会话条件可能保护整个脚本，需完整路径核对")
        client = re.search(r"\$_(?:POST|GET|REQUEST)\s*\[\s*['\"]passed_captcha['\"]\s*\]", local)
        policy = {"id": "php-captcha-workflow", "file": rel, "category": "workflow_bypass",
                  "description": "修改密码之前，服务端必须确认当前请求/会话已完成验证码验证。"}
        check_line = text[:next(c.start() for c in checks if earlier[0][1] < c.start() < earlier[0][2])].count("\n") + 1
        source_lines = text.splitlines()
        evidence = [{"line": check_line, "code": source_lines[check_line - 1], "role": "prerequisite"},
                    {"line": scope_start, "code": source_lines[scope_start - 1], "role": "client_selected_stage"},
                    {"line": text[:sql_pos].count("\n") + 1, "code": source_lines[text[:sql_pos].count("\n")], "role": "password_update"},
                    {"line": line, "code": source_lines[line - 1], "role": "operation"}]
        if client:
            client_line = text[:opening + 1 + client.start()].count("\n") + 1
            evidence.insert(2, {"line": client_line, "code": source_lines[client_line - 1], "role": "client_assertion"})
        reason = ("验证码校验位于另一客户端可选择的步骤；改密步骤信任客户端 passed_captcha 标记。" if client else
                  "验证码校验位于另一客户端可选择的步骤；最终改密分支未见服务端验证码状态检查。")
        reason = ("识别到分步验证码与改密操作，但需补充会话来源、辅助检查或入口上下文，才能判断保护是否有效；尚未动态验证。"
                  if gaps else reason + "静态候选，尚未动态确认。")
        results.append(_assessment(policy, text, line, vulnerability_type="captcha_bypass",
                                   status="needs_context" if gaps else "candidate", confidence=0.35 if gaps else 0.82,
                                   reason=reason, evidence=evidence,
                                   missing_evidence=gaps, scope_start=scope_start, scope_end=scope_end,
                                   policy_source="inferred_local_workflow"))
    return results


def analyze_logic(project: Project, contents: dict[str, str], policies: list[dict] | None = None) -> list[dict]:
    """Check explicit Python policies and recognize bounded PHP CAPTCHA workflows.

    Input policies must be supplied by the operator. Files inside an analyzed ZIP
    are never automatically treated as policy. Results include guarded and missing
    context assessments, so absence of a finding is not presented as safety.
    """
    del project  # source contents are the evidence; never read outside them here
    results = []
    for policy in policies or []:
        if not isinstance(policy, dict):
            raise ValueError("logic policy entries must be objects")
        results.extend(_python_policy(policy, contents))
    for rel, text in sorted(contents.items()):
        if rel.lower().endswith(".php"):
            results.extend(_php_captcha(rel, text))
    return results
